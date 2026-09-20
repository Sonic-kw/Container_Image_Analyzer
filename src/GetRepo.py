"""Krok 1 - katalog repozytoriow Docker Huba -> results/catalog.jsonl.

Dwa zrodla, jeden ksztalt rekordu:
  /v2/repositories/library/   - oficjalne, bogaty rekord
  /v2/search/repositories/    - spolecznosciowe, bez last_updated

Auth: PAT nie jest Bearer. Wymiana DOCKER_HUB_USERNAME + DOCKER_HUB_PAT
na JWT przez POST /v2/auth/token, potem Authorization: Bearer <jwt>.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

try:
    from requests_cache import CachedSession
except ImportError:
    CachedSession = None

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

HUB_API = "https://hub.docker.com/v2"
HUB_AUTH = HUB_API + "/auth/token"
HUB_LIBRARY = HUB_API + "/repositories/library/"
HUB_SEARCH = HUB_API + "/search/repositories/"

PAGE_SIZE = 100
TIMEOUT = (10, 30)
USER_AGENT = "pwr-thesis-fetcher/0.1"
MAX_PAGES = 500

# Zapytania = technologie (nie klasy utwardzenia). Uzasadnij w rozdz. 2.
SEARCH_QUERIES = ["python", "java", "nodejs"]

log = logging.getLogger("hub_catalog")


@dataclass(frozen=True, slots=True)
class Repo:
    namespace: str
    name: str
    pull_count: int | None
    star_count: int | None
    last_updated: str | None
    is_official: bool
    source: str
    query: str | None
    fetched_at: str
    raw: dict[str, Any]

    @property
    def key(self) -> str:
        return f"{self.namespace}/{self.name}"

    def to_record(self) -> dict[str, Any]:
        record = asdict(self)
        record["repo_key"] = self.key
        return record


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"Brak {name}. Ustaw w .env (patrz .env.example).")
    return value


def fetch_jwt(session: requests.Session, username: str, pat: str) -> str:
    """PAT nie wolno wysylac jako Bearer. Hub wymaga JWT z /v2/auth/token."""
    response = session.post(
        HUB_AUTH,
        json={"identifier": username, "secret": pat},
        timeout=TIMEOUT,
    )
    if response.status_code != 200:
        raise SystemExit(
            f"Logowanie Hub nieudane ({response.status_code}). "
            "Sprawdz DOCKER_HUB_USERNAME i DOCKER_HUB_PAT."
        )
    token = response.json().get("access_token") or response.json().get("token")
    if not token:
        raise SystemExit("Hub nie zwrocil access_token w odpowiedzi /v2/auth/token.")
    return token


def build_session(use_cache: bool = True, cache_name: str = "cache/hub_api") -> requests.Session:
    retry = Retry(
        total=5,
        backoff_factor=1.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET", "POST"),
        respect_retry_after_header=True,
    )

    if use_cache and CachedSession is not None:
        Path(cache_name).parent.mkdir(parents=True, exist_ok=True)
        session: requests.Session = CachedSession(
            cache_name, backend="sqlite", expire_after=24 * 3600
        )
    else:
        if use_cache:
            log.warning("requests-cache niezainstalowany - kazde uruchomienie uderza w API")
        session = requests.Session()

    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.headers.update({"User-Agent": USER_AGENT})

    jwt = fetch_jwt(session, _require_env("DOCKER_HUB_USERNAME"), _require_env("DOCKER_HUB_PAT"))
    session.headers["Authorization"] = f"Bearer {jwt}"
    return session


def _fetched_at(response: requests.Response) -> str:
    moment = getattr(response, "created_at", None) or datetime.now(timezone.utc)
    return moment.isoformat()


def _get_page(
    session: requests.Session,
    url: str,
    params: dict[str, Any] | None,
) -> tuple[dict[str, Any], str]:
    response = session.get(url, params=params, timeout=TIMEOUT)
    if response.status_code == 403 and "anonymous" in response.text:
        raise RuntimeError(
            "Hub zwrocil limit anonimowy (403) mimo JWT. "
            "Token wygasl albo Authorization nie jest ustawione."
        )
    response.raise_for_status()
    return response.json(), _fetched_at(response)


def iter_pages(
    session: requests.Session,
    url: str,
    params: dict[str, Any] | None = None,
    max_pages: int = MAX_PAGES,
) -> Iterator[tuple[dict[str, Any], str]]:
    visited: set[str] = set()
    page = 0

    while url:
        page += 1
        if page > max_pages:
            log.debug("stop po %d stronach (limit)", max_pages)
            return
        if url in visited:
            raise RuntimeError(f"paginacja zapetlona na {url}")
        visited.add(url)

        payload, moment = _get_page(session, url, params)
        log.debug("  strona %d: %d rekordow", page, len(payload.get("results") or []))
        yield payload, moment

        url = payload.get("next")
        params = None


def from_library(raw: dict[str, Any], moment: str) -> Repo:
    return Repo(
        namespace=raw.get("namespace") or "library",
        name=raw["name"],
        pull_count=raw.get("pull_count"),
        star_count=raw.get("star_count"),
        last_updated=raw.get("last_updated"),
        is_official=True,
        source="library",
        query=None,
        fetched_at=moment,
        raw=raw,
    )


def from_search(raw: dict[str, Any], query: str, moment: str) -> Repo:
    namespace, _, name = raw["repo_name"].rpartition("/")
    return Repo(
        namespace=namespace or "library",
        name=name,
        pull_count=raw.get("pull_count"),
        star_count=raw.get("star_count"),
        last_updated=None,
        is_official=bool(raw.get("is_official")),
        source="search",
        query=query,
        fetched_at=moment,
        raw=raw,
    )


def build_catalog(
    session: requests.Session,
    queries: list[str],
    out_path: Path,
    search_pages: int,
) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()

    with out_path.open("w", encoding="utf-8") as handle:

        def emit(repo: Repo) -> None:
            if repo.key in seen:
                return
            seen.add(repo.key)
            handle.write(json.dumps(repo.to_record(), ensure_ascii=False) + "\n")

        log.info("faza A: library/")
        declared: int | None = None
        for payload, moment in iter_pages(session, HUB_LIBRARY, {"page_size": PAGE_SIZE}):
            declared = payload.get("count")
            for raw in payload["results"]:
                emit(from_library(raw, moment))
        log.info("  %d repozytoriow oficjalnych (API deklaruje count=%s)", len(seen), declared)

        log.info("faza B: search/")
        for query in queries:
            before = len(seen)
            for payload, moment in iter_pages(
                session,
                HUB_SEARCH,
                {"query": query, "page_size": PAGE_SIZE},
                max_pages=search_pages,
            ):
                for raw in payload["results"]:
                    emit(from_search(raw, query, moment))
            log.info("  %-10s +%d nowych (razem %d)", query, len(seen) - before, len(seen))

    return len(seen)


def main() -> None:
    parser = argparse.ArgumentParser(description="Krok 1 - katalog repozytoriow Docker Huba")
    parser.add_argument("--out", type=Path, default=Path("results/catalog.jsonl"))
    parser.add_argument(
        "--search-pages",
        type=int,
        default=47,
        help="ile stron na zapytanie search",
    )
    parser.add_argument("--queries", nargs="*", default=SEARCH_QUERIES)
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )

    session = build_session(use_cache=not args.no_cache)
    try:
        total = build_catalog(session, args.queries, args.out, args.search_pages)
    finally:
        session.close()

    log.info("gotowe: %d unikalnych repozytoriow -> %s", total, args.out)


if __name__ == "__main__":
    main()

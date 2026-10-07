"""Wspolny klient HTTP Docker Hub / GCR: sesja, JWT, paginacja, retry."""

from __future__ import annotations

import logging
import os
from collections.abc import Iterator
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
MANIFEST_ACCEPT = (
    "application/vnd.oci.image.index.v1+json,"
    "application/vnd.docker.distribution.manifest.list.v2+json,"
    "application/vnd.docker.distribution.manifest.v2+json,"
    "application/vnd.oci.image.manifest.v1+json"
)

log = logging.getLogger("hub_http")


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"Brak {name}. Ustaw w .env (patrz .env.example).")
    return value


def fetch_jwt(session: requests.Session, username: str, pat: str) -> str:
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


def build_session(
    use_cache: bool = True,
    cache_name: str = "cache/hub_api",
    *,
    hub_auth: bool = False,
) -> requests.Session:
    retry = Retry(
        total=5,
        backoff_factor=1.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET", "POST", "HEAD"),
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

    if hub_auth:
        jwt = fetch_jwt(
            session, require_env("DOCKER_HUB_USERNAME"), require_env("DOCKER_HUB_PAT")
        )
        session.headers["Authorization"] = f"Bearer {jwt}"
    return session


def fetched_at(response: requests.Response) -> str:
    moment = getattr(response, "created_at", None) or datetime.now(timezone.utc)
    return moment.isoformat()


def get_page(
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
    return response.json(), fetched_at(response)


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

        payload, moment = get_page(session, url, params)
        log.debug("  strona %d: %d rekordow", page, len(payload.get("results") or []))
        yield payload, moment

        url = payload.get("next")
        params = None

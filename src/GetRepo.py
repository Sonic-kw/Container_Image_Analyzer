"""Katalog repozytoriow: Docker Hub (Krok 1) i GCR distroless (Krok 2).

Hub:
  /v2/repositories/library/   - oficjalne, bogaty rekord
  /v2/search/repositories/    - spolecznosciowe, bez last_updated
  Auth: PAT -> JWT (POST /v2/auth/token), potem Bearer. PAT nie jest Bearer.

GCR distroless:
  Lista obrazow z README + dzieci z gcr.io/v2/distroless/tags/list.
  API tylko potwierdza istnienie (HEAD manifests/<tag>) - bez iteracji manifest.
  Do katalogu wchodzi wylacznie tag latest; nonroot_available to wlasnosc repo.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import requests

from hub_http import (
    HUB_LIBRARY,
    HUB_SEARCH,
    MANIFEST_ACCEPT,
    PAGE_SIZE,
    TIMEOUT,
    build_session,
    fetched_at,
    iter_pages,
)

GCR_HOST = "https://gcr.io"
GCR_DISTROLESS = f"{GCR_HOST}/v2/distroless"
DISTROLESS_README = (
    "https://raw.githubusercontent.com/GoogleContainerTools/distroless/main/README.md"
)
DISTROLESS_IMAGE_RE = re.compile(r"gcr\.io/distroless/([a-zA-Z0-9][a-zA-Z0-9._-]*)")
# Jawna linia Debiana - unikamy aliasow bez sufiksu (python3 == python3-debian13).
DEBIAN_REPO_RE = re.compile(r"^.+-debian\d+$")
# Tagi odrzucane przy ewentualnej enumeracji (Krok 2: i tak bierzemy tylko latest).
REJECT_TAG_RE = re.compile(
    r"(?:\.sig|\.att)$"
    r"|^update-available-"
    r"|^sha256-"
    r"|^[0-9a-f]{40}$"
    r"|^(?:debug|debug-nonroot|nonroot)$"
    r"|-(?:amd64|arm64|arm|s390x|ppc64le|riscv64)$"
)

# Zapytania = technologie (nie klasy utwardzenia). Uzasadnij w rozdz. 2.
SEARCH_QUERIES = ["python", "java", "nodejs"]

log = logging.getLogger("getrepo")


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


@dataclass(frozen=True, slots=True)
class DistrolessRepo:

    registry: str
    namespace: str
    name: str
    tag: str
    logical_ref: str
    nonroot_available: bool
    in_readme: bool
    source: str
    fetched_at: str
    raw: dict[str, Any]

    @property
    def key(self) -> str:
        return f"{self.registry}/{self.namespace}/{self.name}"

    def to_record(self) -> dict[str, Any]:
        record = asdict(self)
        record["repo_key"] = self.key
        return record


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


def build_hub_catalog(
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


# --- Krok 2: GCR distroless -------------------------------------------------


def is_rejected_tag(tag: str) -> bool:
    return bool(REJECT_TAG_RE.search(tag))


def parse_readme_images(text: str) -> set[str]:
    return {m.group(1) for m in DISTROLESS_IMAGE_RE.finditer(text)}


def fetch_readme_images(session: requests.Session) -> set[str]:
    response = session.get(DISTROLESS_README, timeout=TIMEOUT)
    response.raise_for_status()
    names = parse_readme_images(response.text)
    log.info("README: %d nazw gcr.io/distroless/...", len(names))
    return names


def list_distroless_children(session: requests.Session) -> list[str]:
    response = session.get(f"{GCR_DISTROLESS}/tags/list", timeout=TIMEOUT)
    response.raise_for_status()
    children = list(response.json().get("child") or [])
    log.info("GCR children: %d repozytoriow pod distroless/", len(children))
    return children


def manifest_exists(session: requests.Session, name: str, tag: str) -> tuple[bool, str]:
    url = f"{GCR_DISTROLESS}/{name}/manifests/{tag}"
    response = session.head(
        url,
        headers={"Accept": MANIFEST_ACCEPT},
        timeout=TIMEOUT,
        allow_redirects=True,
    )
    if response.status_code == 200:
        return True, fetched_at(response)
    if response.status_code == 404:
        return False, fetched_at(response)
    if response.status_code in (400, 405):
        response = session.get(
            url,
            headers={"Accept": MANIFEST_ACCEPT},
            timeout=TIMEOUT,
            stream=True,
        )
        response.close()
        if response.status_code == 200:
            return True, fetched_at(response)
        if response.status_code == 404:
            return False, fetched_at(response)
    response.raise_for_status()
    return False, fetched_at(response)


def candidate_distroless_names(children: list[str], readme: set[str]) -> list[str]:
    names: set[str] = set()
    for child in children:
        if child in {"test"} or child.endswith((".sig", ".att")):
            continue
        if DEBIAN_REPO_RE.match(child):
            names.add(child)
    names.update(n for n in readme if not n.endswith((".sig", ".att")))
    return sorted(names)


def build_gcr_catalog(session: requests.Session, out_path: Path) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    readme = fetch_readme_images(session)
    children = list_distroless_children(session)
    candidates = candidate_distroless_names(children, readme)
    log.info("kandydaci do sondy: %d", len(candidates))

    written = 0
    skipped_no_latest = 0

    with out_path.open("w", encoding="utf-8") as handle:
        for name in candidates:
            ok_latest, moment = manifest_exists(session, name, "latest")
            if not ok_latest:
                skipped_no_latest += 1
                log.debug("  brak latest: %s", name)
                continue

            ok_nonroot, _ = manifest_exists(session, name, "nonroot")
            repo = DistrolessRepo(
                registry="gcr.io",
                namespace="distroless",
                name=name,
                tag="latest",
                logical_ref=f"gcr.io/distroless/{name}:latest",
                nonroot_available=ok_nonroot,
                in_readme=name in readme,
                source="gcr",
                fetched_at=moment,
                raw={
                    "discovered_via": (
                        "readme+children" if name in readme else "children"
                    ),
                },
            )
            handle.write(json.dumps(repo.to_record(), ensure_ascii=False) + "\n")
            written += 1
            log.info(
                "  %-32s latest=ok nonroot=%s readme=%s",
                name,
                ok_nonroot,
                name in readme,
            )

    log.info(
        "zapisano %d (pominieto %d bez latest)",
        written,
        skipped_no_latest,
    )
    return written


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--verbose", "-v", action="store_true")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Katalog repozytoriow: Hub (Krok 1) i GCR distroless (Krok 2)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    hub = sub.add_parser("hub", help="Krok 1 - katalog Docker Hub -> catalog.jsonl")
    hub.add_argument("--out", type=Path, default=Path("results/catalog.jsonl"))
    hub.add_argument(
        "--search-pages",
        type=int,
        default=47,
        help="ile stron na zapytanie search",
    )
    hub.add_argument("--queries", nargs="*", default=SEARCH_QUERIES)
    _add_common_args(hub)

    gcr = sub.add_parser(
        "gcr", help="Krok 2 - katalog GCR distroless (tylko latest) -> gcr_catalog.jsonl"
    )
    gcr.add_argument("--out", type=Path, default=Path("results/gcr_catalog.jsonl"))
    _add_common_args(gcr)

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.command == "hub":
        session = build_session(
            use_cache=not args.no_cache,
            cache_name="cache/hub_api",
            hub_auth=True,
        )
        try:
            total = build_hub_catalog(session, args.queries, args.out, args.search_pages)
        finally:
            session.close()
        log.info("gotowe: %d unikalnych repozytoriow -> %s", total, args.out)
        return

    if args.command == "gcr":
        session = build_session(
            use_cache=not args.no_cache,
            cache_name="cache/gcr_api",
            hub_auth=False,
        )
        try:
            total = build_gcr_catalog(session, args.out)
        finally:
            session.close()
        log.info("gotowe: %d obrazow distroless (latest) -> %s", total, args.out)
        return


if __name__ == "__main__":
    main()

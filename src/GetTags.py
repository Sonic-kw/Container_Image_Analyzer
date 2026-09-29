"""Krok 3 - tagi Hub: catalog.jsonl -> results/tags.jsonl.

Dla kazdego repo z katalogu pobiera pelna liste tagow
(GET /v2/repositories/{ns}/{name}/tags/), z cache per-repo i resume.
PAT wymagany: anonimowy offset urywa sie przed koncem list python/openjdk.
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

from hub_http import HUB_API, PAGE_SIZE, MAX_PAGES, build_session, iter_pages

log = logging.getLogger("gettags")

PREFERRED_ARCH = "amd64"
CACHE_DIR = Path("cache/hub_tags")


@dataclass(frozen=True, slots=True)
class TagRecord:
    repo_key: str
    namespace: str
    name: str
    tag: str
    logical_ref: str
    full_size: int | None
    digest: str | None
    tag_last_pushed: str | None
    arch_digest: str | None
    arch_size: int | None
    fetched_at: str

    def to_record(self) -> dict[str, Any]:
        return asdict(self)


def logical_ref(namespace: str, name: str, tag: str) -> str:
    """library/python:3.13-slim -> python:3.13-slim; inaczej ns/name:tag."""
    if namespace == "library":
        return f"{name}:{tag}"
    return f"{namespace}/{name}:{tag}"


def cache_path(cache_dir: Path, namespace: str, name: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{namespace}__{name}")
    return cache_dir / f"{safe}.json"


def pick_amd64(images: list[dict[str, Any]] | None) -> tuple[str | None, int | None]:
    if not images:
        return None, None
    for image in images:
        if image.get("architecture") == PREFERRED_ARCH and image.get("os") in (
            None,
            "linux",
        ):
            size = image.get("size")
            return image.get("digest"), int(size) if size is not None else None
    # Fallback: first amd64 regardless of os.
    for image in images:
        if image.get("architecture") == PREFERRED_ARCH:
            size = image.get("size")
            return image.get("digest"), int(size) if size is not None else None
    return None, None


def tag_from_raw(
    namespace: str,
    name: str,
    raw: dict[str, Any],
    moment: str,
) -> TagRecord:
    tag = raw["name"]
    arch_digest, arch_size = pick_amd64(raw.get("images"))
    full_size = raw.get("full_size")
    return TagRecord(
        repo_key=f"{namespace}/{name}",
        namespace=namespace,
        name=name,
        tag=tag,
        logical_ref=logical_ref(namespace, name, tag),
        full_size=int(full_size) if full_size is not None else None,
        digest=raw.get("digest"),
        tag_last_pushed=raw.get("tag_last_pushed"),
        arch_digest=arch_digest,
        arch_size=arch_size,
        fetched_at=moment,
    )


def fetch_repo_tags(
    session: requests.Session,
    namespace: str,
    name: str,
    *,
    cache_dir: Path,
    use_disk_cache: bool,
    max_pages: int = MAX_PAGES,
) -> list[TagRecord]:
    """Pobierz wszystkie tagi repo; przy hitcie dysku nie uderzaj w API."""
    path = cache_path(cache_dir, namespace, name)
    if use_disk_cache and path.is_file():
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("complete"):
            tags = [
                TagRecord(**{k: row[k] for k in TagRecord.__dataclass_fields__})
                for row in payload["tags"]
            ]
            log.info(
                "  %s/%s cache hit (%d tagow)",
                namespace,
                name,
                len(tags),
            )
            return tags

    url = f"{HUB_API}/repositories/{namespace}/{name}/tags/"
    tags: list[TagRecord] = []
    declared: int | None = None
    pages = 0

    for page, moment in iter_pages(
        session, url, {"page_size": PAGE_SIZE}, max_pages=max_pages
    ):
        pages += 1
        declared = page.get("count", declared)
        for raw in page.get("results") or []:
            tags.append(tag_from_raw(namespace, name, raw, moment))

    if declared is not None and len(tags) < declared:
        log.warning(
            "  %s/%s: pobrano %d/%d tagow (paginacja ucieta?)",
            namespace,
            name,
            len(tags),
            declared,
        )

    if use_disk_cache:
        cache_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "repo_key": f"{namespace}/{name}",
                    "count_api": declared,
                    "complete": True,
                    "pages": pages,
                    "tags": [t.to_record() for t in tags],
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

    log.info(
        "  %s/%s: %d tagow (API count=%s, stron=%d)",
        namespace,
        name,
        len(tags),
        declared,
        pages,
    )
    return tags


def load_catalog(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise SystemExit(f"Brak katalogu: {path}. Uruchom najpierw: python src/GetRepo.py hub")
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def select_repos(
    catalog: list[dict[str, Any]],
    *,
    repos: list[str] | None,
    limit: int | None,
    source: str | None = None,
    min_pulls: int | None = None,
) -> list[dict[str, Any]]:
    selected = catalog
    if source:
        selected = [row for row in selected if row.get("source") == source]
    if min_pulls is not None:
        # library/ wchodzi zawsze - progu uzywamy tylko do odsiania szumu z search/.
        selected = [
            row
            for row in selected
            if row.get("source") == "library" or (row.get("pull_count") or 0) >= min_pulls
        ]
    if repos:
        wanted = set(repos)
        selected = [
            row
            for row in catalog
            if row.get("name") in wanted or row.get("repo_key") in wanted
        ]
        missing = wanted - {
            row.get("name") for row in selected
        } - {row.get("repo_key") for row in selected}
        # Allow --repos python without catalog: synthesize library/python.
        for name in sorted(missing):
            if "/" in name:
                ns, _, nm = name.partition("/")
            else:
                ns, nm = "library", name
            log.warning("brak w katalogu: %s - dodaje syntetyczny %s/%s", name, ns, nm)
            selected.append({"namespace": ns, "name": nm, "repo_key": f"{ns}/{nm}"})
    if limit is not None:
        selected = selected[:limit]
    return selected


def build_tags(
    session: requests.Session,
    repos: list[dict[str, Any]],
    out_path: Path,
    *,
    cache_dir: Path,
    use_disk_cache: bool,
) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    missing: list[str] = []

    with out_path.open("w", encoding="utf-8") as handle:
        for index, row in enumerate(repos, start=1):
            namespace = row.get("namespace") or "library"
            name = row["name"]
            log.info("[%d/%d] %s/%s", index, len(repos), namespace, name)
            try:
                tags = fetch_repo_tags(
                    session,
                    namespace,
                    name,
                    cache_dir=cache_dir,
                    use_disk_cache=use_disk_cache,
                )
            except requests.HTTPError as error:
                # Repo z katalogu moglo zostac usuniete z Huba w miedzyczasie.
                if error.response is not None and error.response.status_code == 404:
                    log.warning("  %s/%s: 404, pomijam", namespace, name)
                    missing.append(f"{namespace}/{name}")
                    continue
                raise
            for tag in tags:
                handle.write(json.dumps(tag.to_record(), ensure_ascii=False) + "\n")
            total += len(tags)

    if missing:
        log.warning("pominieto %d repozytoriow z 404: %s", len(missing), ", ".join(missing))
    return total


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Krok 3 - tagi Hub z catalog.jsonl -> tags.jsonl"
    )
    parser.add_argument(
        "--catalog",
        type=Path,
        default=Path("results/catalog.jsonl"),
        help="wejscie z Kroku 1",
    )
    parser.add_argument("--out", type=Path, default=Path("results/tags.jsonl"))
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=CACHE_DIR,
        help="cache per-repo (resume)",
    )
    parser.add_argument(
        "--repos",
        nargs="*",
        help="tylko te nazwy (name lub namespace/name); bez katalogu dziala syntetycznie",
    )
    parser.add_argument(
        "--source",
        choices=("library", "search"),
        help="tylko repozytoria z tego zrodla Kroku 1",
    )
    parser.add_argument(
        "--min-pulls",
        type=int,
        default=None,
        help="prog pull_count dla search/ (library/ wchodzi zawsze)",
    )
    parser.add_argument("--limit", type=int, default=None, help="max repozytoriow")
    parser.add_argument(
        "--no-disk-cache",
        action="store_true",
        help="nie czytaj/pisz cache/hub_tags (nadal retry 429 w sesji)",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="wylacz requests-cache (SQLite HTTP)",
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.repos and not args.catalog.is_file():
        catalog: list[dict[str, Any]] = []
        log.warning("brak %s - uzywam tylko --repos", args.catalog)
    else:
        catalog = load_catalog(args.catalog)

    repos = select_repos(
        catalog,
        repos=args.repos,
        limit=args.limit,
        source=args.source,
        min_pulls=args.min_pulls,
    )
    if not repos:
        raise SystemExit("Brak repozytoriow do przetworzenia.")

    log.info("repozytoriow do pobrania tagow: %d", len(repos))

    # Disk cache = zrodlo prawdy dla resume; requests-cache wylaczamy przy dysku,
    # zeby nie dublowac i nie trzymac partial pages.
    session = build_session(
        use_cache=not args.no_cache and args.no_disk_cache,
        cache_name="cache/hub_tags_http",
        hub_auth=True,
    )
    try:
        total = build_tags(
            session,
            repos,
            args.out,
            cache_dir=args.cache_dir,
            use_disk_cache=not args.no_disk_cache,
        )
    finally:
        session.close()

    log.info("gotowe: %d tagow -> %s", total, args.out)


if __name__ == "__main__":
    main()

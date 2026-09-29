"""Krok 4 - klasyfikacja wariantu utwardzenia i linii OS z nazw tagow.

Wejscie: tagi Hub z Kroku 3 (tags*.jsonl) + katalog distroless z Kroku 2.
Wyjscie: results/classified.jsonl - jeden wiersz na tag, nic nie jest odrzucane;
wykluczenia (Windows, onbuild, brak amd64) trafiaja do excluded_reason, a wybor
proby nalezy do Kroku 5.

Tag bez sufiksu OS (`3.13-slim`, `latest`) dziedziczy os_line po tagu z tym samym
digestem w tym samym repozytorium (`3.13-slim-trixie`) - bez tego nie da sie
dobrac linii distroless zgodnej z baza partnera (wymog z pilotazu).
"""

from __future__ import annotations

import argparse
import itertools
import json
import logging
import re
from collections import Counter
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

log = logging.getLogger("classify")

DEBIAN_CODENAMES = {
    "forky": "debian14",
    "trixie": "debian13",
    "bookworm": "debian12",
    "bullseye": "debian11",
    "buster": "debian10",
    "stretch": "debian9",
    "jessie": "debian8",
    "wheezy": "debian7",
    "squeeze": "debian6",
}
# Nazwy galezi Debiana - tylko w library/debian; gdzie indziej "unstable" to seria deweloperska
# danego projektu (np. mongo:4.1-unstable). Wartosc: (os_line, prerelease).
DEBIAN_SUITES = {
    "sid": ("debian-sid", True),
    "unstable": ("debian-sid", True),
    "testing": ("debian-testing", True),
    "experimental": ("debian-experimental", True),
    "buggy": ("debian-experimental", True),
    "stable": ("debian-stable", False),
    "oldstable": ("debian-oldstable", False),
    "oldoldstable": ("debian-oldoldstable", False),
}
UBUNTU_CODENAMES = {
    "noble": "ubuntu24.04",
    "jammy": "ubuntu22.04",
    "focal": "ubuntu20.04",
    "bionic": "ubuntu18.04",
    "xenial": "ubuntu16.04",
    "trusty": "ubuntu14.04",
}
ALPINE_RE = re.compile(r"^alpine(\d+\.\d+)?$")
OTHER_OS_RE = re.compile(r"^(oraclelinux|ubi|centos|amazonlinux|al|rockylinux|almalinux)(\d+)$")
VERSION_RE = re.compile(r"^v?\d+(?:\.\d+)*(?:(a|b|rc|alpha|beta|pre)\d*)?$")
PRERELEASE_RE = re.compile(r"^(?:rc|alpha|beta|preview|pre|dev|nightly|edge|unstable|m)\d*$")
WINDOWS_PREFIXES = ("windowsservercore", "nanoserver", "ltsc", "windows")

# Obrazy bazowe systemu: linie OS wyznacza wersja z tagu, nie sufiks.
BASE_OS_REPOS = {"library/alpine", "library/debian", "library/ubuntu"}

# distroless: prefiks nazwy repo -> family z Huba, z ktora bedzie parowany.
DISTROLESS_FAMILY = (
    ("python", "python"),
    ("nodejs", "node"),
    ("java", "java"),
    ("static", "base"),
    ("base", "base"),
    ("cc", "base"),
)
DEBIAN_SUFFIX_RE = re.compile(r"-(debian\d+)$")


def parse_tag(tag: str, repo_key: str = "") -> dict[str, Any]:
    """Rozbij tag Huba na klase, linie OS, wersje i reszte tokenow."""
    debian_repo = repo_key == "library/debian"
    tokens = tag.lower().split("-")
    variant = "standard"
    variant_rule = "default"
    os_line: str | None = None
    version: str | None = None
    prerelease = False
    excluded: str | None = None
    leftover: list[str] = []

    for position, token in enumerate(tokens):
        if not token:
            continue
        if token.startswith(WINDOWS_PREFIXES):
            excluded = "windows"
            continue
        if token.isdigit() and len(token) == 4 and excluded == "windows":
            continue  # 1809, 1803 - numer wydania Windows
        if token == "onbuild":
            excluded = excluded or "onbuild"
            continue
        match = ALPINE_RE.match(token)
        if match:
            variant, variant_rule = "alpine", "alpine"
            if match.group(1):
                os_line = f"alpine{match.group(1)}"
            continue
        if token == "slim":
            if variant != "alpine":
                variant, variant_rule = "slim", "slim"
            continue
        if token in DEBIAN_CODENAMES:
            os_line = DEBIAN_CODENAMES[token]
            continue
        if debian_repo and token in DEBIAN_SUITES:
            os_line, suite_prerelease = DEBIAN_SUITES[token]
            prerelease = prerelease or suite_prerelease
            continue
        if token in UBUNTU_CODENAMES:
            os_line = UBUNTU_CODENAMES[token]
            continue
        other_os = OTHER_OS_RE.match(token)
        if other_os:
            os_line = f"{other_os.group(1)}{other_os.group(2)}"
            continue
        if PRERELEASE_RE.match(token):
            prerelease = True
            continue
        if token == "latest":
            continue
        version_match = VERSION_RE.match(token)
        if position == 0 and version_match:
            version = token
            if version_match.group(1):
                prerelease = True
            continue
        leftover.append(token)

    return {
        "variant": variant,
        "variant_rule": variant_rule,
        "os_line": os_line,
        "version": version,
        "prerelease": prerelease,
        "flavor": "-".join(leftover) or None,
        "excluded_reason": excluded,
    }


def base_os_line(repo_key: str, version: str | None) -> str | None:
    if not version:
        return None
    parts = version.lstrip("v").split(".")
    if repo_key == "library/alpine" and len(parts) >= 2:
        return f"alpine{parts[0]}.{parts[1]}"
    if repo_key == "library/debian":
        return f"debian{parts[0]}"
    if repo_key == "library/ubuntu" and len(parts) >= 2:
        return f"ubuntu{parts[0]}.{parts[1]}"
    return None


def classify_hub_tag(row: dict[str, Any]) -> dict[str, Any]:
    parsed = parse_tag(row["tag"], row["repo_key"])
    if row["repo_key"] in BASE_OS_REPOS:
        if row["repo_key"] == "library/alpine":
            parsed["variant"], parsed["variant_rule"] = "alpine", "base_os_repo"
        parsed["os_line"] = parsed["os_line"] or base_os_line(row["repo_key"], parsed["version"])
    if parsed["excluded_reason"] is None and not row.get("arch_digest"):
        parsed["excluded_reason"] = "no_amd64"
    return {
        "repo_key": row["repo_key"],
        "source_registry": "hub",
        "family": row["name"],
        "vendor": row["namespace"],
        "tag": row["tag"],
        "logical_ref": row["logical_ref"],
        **parsed,
        "os_line_source": "tag" if parsed["os_line"] else None,
        "digest": row.get("digest"),
        "arch_digest": row.get("arch_digest"),
        "arch_size": row.get("arch_size"),
        "full_size": row.get("full_size"),
        "tag_last_pushed": row.get("tag_last_pushed"),
    }


def _alias_key(row: dict[str, Any]) -> str | None:
    # Digest indeksu nie wystarcza: python:3.13 i python:3.13-trixie maja rozne indeksy
    # (pierwszy zawiera tez obrazy Windows), a ten sam manifest amd64.
    return row["arch_digest"] or row["digest"]


def resolve_aliases(rows: list[dict[str, Any]]) -> int:
    """Uzupelnij os_line tagom bez sufiksu na podstawie tagu z tym samym obrazem amd64."""
    known: dict[str, set[str]] = {}
    for row in rows:
        key = _alias_key(row)
        if row["os_line"] and key:
            known.setdefault(key, set()).add(row["os_line"])

    resolved = 0
    for row in rows:
        key = _alias_key(row)
        if row["os_line"] or not key:
            continue
        lines = known.get(key)
        if lines and len(lines) == 1:
            row["os_line"] = next(iter(lines))
            row["os_line_source"] = "alias"
            resolved += 1
        elif lines:
            log.warning(
                "  %s:%s - sprzeczne linie OS dla digestu: %s",
                row["repo_key"],
                row["tag"],
                sorted(lines),
            )
    return resolved


def distroless_family(name: str) -> str:
    for prefix, family in DISTROLESS_FAMILY:
        if name.startswith(prefix):
            return family
    return name


def classify_distroless(row: dict[str, Any]) -> dict[str, Any]:
    name = row["name"]
    suffix = DEBIAN_SUFFIX_RE.search(name)
    return {
        "repo_key": row["repo_key"],
        "source_registry": "gcr",
        "family": distroless_family(name),
        "vendor": "distroless",
        "tag": row["tag"],
        "logical_ref": row["logical_ref"],
        "variant": "distroless",
        "variant_rule": "gcr",
        "os_line": suffix.group(1) if suffix else None,
        "version": None,
        "prerelease": False,
        "flavor": DEBIAN_SUFFIX_RE.sub("", name),
        "excluded_reason": None,
        "os_line_source": "repo_name" if suffix else None,
        "nonroot_available": row.get("nonroot_available"),
        "digest": None,
        "arch_digest": None,
        "arch_size": None,
        "full_size": None,
        "tag_last_pushed": None,
    }


def read_jsonl(paths: Iterable[Path]) -> Iterator[dict[str, Any]]:
    for path in paths:
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    yield json.loads(line)


def classify(
    tag_paths: list[Path],
    gcr_path: Path | None,
    out_path: Path,
) -> Counter[str]:
    """Strumieniowo, repo po repo - GetTags zapisuje tagi zgrupowane per repozytorium."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    stats: Counter[str] = Counter()
    seen_repos: set[str] = set()

    with out_path.open("w", encoding="utf-8") as handle:
        rows_by_repo = itertools.groupby(read_jsonl(tag_paths), key=lambda r: r["repo_key"])
        for repo_key, raw_rows in rows_by_repo:
            if repo_key in seen_repos:
                raise SystemExit(
                    f"{repo_key} wystepuje w wejsciu nieciagle albo dwa razy - "
                    "podaj kazdy plik tagow tylko raz."
                )
            seen_repos.add(repo_key)
            rows = [classify_hub_tag(r) for r in raw_rows]
            stats["alias_resolved"] += resolve_aliases(rows)
            for row in rows:
                stats[f"variant:{row['variant']}"] += 1
                stats[f"excluded:{row['excluded_reason']}"] += 1
                if row["excluded_reason"] is None and row["os_line"] is None:
                    stats["os_line_missing"] += 1
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
            stats["hub_repos"] += 1

        if gcr_path is not None:
            for raw in read_jsonl([gcr_path]):
                row = classify_distroless(raw)
                stats["variant:distroless"] += 1
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Krok 4 - klasyfikacja tagow")
    sub = parser.add_subparsers(dest="command", required=True)

    cls = sub.add_parser("classify", help="czesc A: klasa + linia OS, offline")
    cls.add_argument(
        "--tags",
        type=Path,
        nargs="+",
        default=[Path("results/tags.jsonl")],
        help="pliki z Kroku 3 (kazde repo tylko w jednym pliku)",
    )
    cls.add_argument("--gcr", type=Path, default=Path("results/gcr_catalog.jsonl"))
    cls.add_argument("--no-gcr", action="store_true")
    cls.add_argument("--out", type=Path, default=Path("results/classified.jsonl"))
    cls.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.command == "classify":
        stats = classify(args.tags, None if args.no_gcr else args.gcr, args.out)
        for key, value in sorted(stats.items()):
            log.info("  %-28s %d", key, value)
        log.info("gotowe -> %s", args.out)


if __name__ == "__main__":
    main()

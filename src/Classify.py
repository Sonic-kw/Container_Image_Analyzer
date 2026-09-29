"""Krok 4 - klasyfikacja wariantu, linia OS i sciezka pobierania (pull_ref).

Czesc A (classify, offline):
  tagi Hub z Kroku 3 + katalog distroless z Kroku 2 -> results/classified.jsonl.
  Nic nie jest odrzucane; wykluczenia (Windows, onbuild, brak amd64) trafiaja do
  excluded_reason, a wybor proby nalezy do Kroku 5.
  Tag bez sufiksu OS (`3.13-slim`, `latest`) dziedziczy os_line po tagu z tym samym
  manifestem amd64 (`3.13-slim-trixie`) - bez tego nie da sie dobrac linii distroless
  zgodnej z baza partnera (wymog z pilotazu).

Czesc B (siec):
  assign      - pull_ref pinowany digestem amd64 -> results/refs.jsonl; dla Huba
                wstepnie przez lustro, niezweryfikowane (mirror_ok = null)
  probe-tags  - sonda per wiersz na wybranej matrycy (po Kroku 5), obowiazkowa przed
                skanem. Dostepnosc na lustrze jest wlasnoscia manifestu, nie repozytorium,
                a pierwsze 404 bywa chybieniem na zimno (lustro dociaga obraz i kolejne
                zapytanie trafia), wiec kazde 404 jest ponawiane po odczekaniu.
"""

from __future__ import annotations

import argparse
import itertools
import json
import logging
import math
import re
import time
from collections import Counter
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from hub_http import MANIFEST_ACCEPT, TIMEOUT, build_session

log = logging.getLogger("classify")

MIRROR_HOST = "mirror.gcr.io"
HUB_REGISTRY = "docker.io"
GCR_HOST = "gcr.io"
HUB_PULL_BUDGET = 200
HUB_BUDGET_WINDOW_H = 6

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


# --- Czesc B: sonda lustra i pull_ref ---------------------------------------


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def head_manifest(session: requests.Session, host: str, repo: str, reference: str) -> int:
    """HEAD na manifest; zwraca kod HTTP (200 = jest, 404 = brak)."""
    response = session.head(
        f"https://{host}/v2/{repo}/manifests/{reference}",
        headers={"Accept": MANIFEST_ACCEPT},
        timeout=TIMEOUT,
        allow_redirects=True,
    )
    if response.status_code in (200, 404):
        return response.status_code
    if 400 <= response.status_code < 500:
        log.warning("  %s/%s@%s: HTTP %d", host, repo, reference[:19], response.status_code)
        return response.status_code
    response.raise_for_status()
    return response.status_code


def resolve_gcr_digests(session: requests.Session, repo_key: str) -> tuple[str | None, str | None]:
    """(digest indeksu, digest manifestu amd64) dla gcr.io/distroless/<repo>:latest."""
    repo = repo_key.removeprefix(f"{GCR_HOST}/")
    response = session.get(
        f"https://{GCR_HOST}/v2/{repo}/manifests/latest",
        headers={"Accept": MANIFEST_ACCEPT},
        timeout=TIMEOUT,
    )
    response.raise_for_status()
    index_digest = response.headers.get("Docker-Content-Digest")
    payload = response.json()
    for manifest in payload.get("manifests") or []:
        platform = manifest.get("platform") or {}
        if platform.get("architecture") == "amd64" and platform.get("os") == "linux":
            return index_digest, manifest["digest"]
    # Pojedynczy manifest zamiast indeksu - sam jest obrazem amd64.
    return index_digest, index_digest if not payload.get("manifests") else None


def hub_pull_ref(row: dict[str, Any], via_mirror: bool) -> str | None:
    if not row["arch_digest"]:
        return None
    host = MIRROR_HOST if via_mirror else HUB_REGISTRY
    return f"{host}/{row['repo_key']}@{row['arch_digest']}"


def budget_line(hub_rows: int) -> str:
    batches = math.ceil(hub_rows / HUB_PULL_BUDGET)
    return (
        f"{hub_rows} obrazow przez Hub = {batches} partii po {HUB_PULL_BUDGET} "
        f"(~{batches * HUB_BUDGET_WINDOW_H} h)"
    )


def assign(session: requests.Session, classified_path: Path, out_path: Path) -> Counter[str]:
    stats: Counter[str] = Counter()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", encoding="utf-8") as handle:
        for row in read_jsonl([classified_path]):
            if row["source_registry"] == "gcr":
                row["digest"], row["arch_digest"] = resolve_gcr_digests(session, row["repo_key"])
                row["registry"] = "gcr"
                row["pull_ref"] = (
                    f"{row['repo_key']}@{row['arch_digest']}" if row["arch_digest"] else None
                )
            else:
                row["registry"] = "mirror"
                row["pull_ref"] = hub_pull_ref(row, via_mirror=True)
            row["mirror_ok"] = None
            row["mirror_probe"] = None
            if row["excluded_reason"] is None:
                stats[f"registry:{row['registry']}"] += 1
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    return stats


def probe_tags(
    session: requests.Session,
    in_path: Path,
    out_path: Path,
    retry_delay: float,
) -> Counter[str]:
    """Sonda per wiersz: czy lustro serwuje dokladnie ten manifest amd64.

    mirror_probe: hit (200 od razu), cold_miss (404, potem 200), miss (404 dwa razy).
    """
    rows = list(read_jsonl([in_path]))
    probed = [r for r in rows if r.get("registry") in ("mirror", "hub") and r.get("arch_digest")]
    first_miss: list[dict[str, Any]] = []

    for index, row in enumerate(probed, start=1):
        status = head_manifest(session, MIRROR_HOST, row["repo_key"], row["arch_digest"])
        row["mirror_probe"] = "hit" if status == 200 else None
        if status != 200:
            first_miss.append(row)
        if index % 500 == 0:
            log.info("  sonda %d/%d (chybien: %d)", index, len(probed), len(first_miss))

    if first_miss:
        log.info("  %d chybien - ponowienie po %.0f s", len(first_miss), retry_delay)
        time.sleep(retry_delay)
        for row in first_miss:
            status = head_manifest(session, MIRROR_HOST, row["repo_key"], row["arch_digest"])
            row["mirror_probe"] = "cold_miss" if status == 200 else "miss"

    stats: Counter[str] = Counter()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            if row.get("mirror_probe"):
                row["mirror_ok"] = row["mirror_probe"] != "miss"
                row["registry"] = "mirror" if row["mirror_ok"] else "hub"
                row["pull_ref"] = hub_pull_ref(row, via_mirror=row["mirror_ok"])
                row["mirror_probed_at"] = _now()
                stats[f"probe:{row['mirror_probe']}"] += 1
                stats[f"registry:{row['registry']}"] += 1
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    return stats


def _log_stats(stats: Counter[str]) -> None:
    for key, value in sorted(stats.items()):
        log.info("  %-28s %d", key, value)


def main() -> None:
    parser = argparse.ArgumentParser(description="Krok 4 - klasyfikacja tagow i pull_ref")
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

    asg = sub.add_parser("assign", help="czesc B: registry + pull_ref pinowany digestem")
    asg.add_argument("--in", dest="in_path", type=Path, default=Path("results/classified.jsonl"))
    asg.add_argument("--out", type=Path, default=Path("results/refs.jsonl"))
    asg.add_argument("--verbose", "-v", action="store_true")

    ptg = sub.add_parser("probe-tags", help="sonda lustra per wiersz na matrycy (po Kroku 5)")
    ptg.add_argument("--in", dest="in_path", type=Path, required=True)
    ptg.add_argument("--out", type=Path, required=True)
    ptg.add_argument(
        "--retry-delay",
        type=float,
        default=60.0,
        help="sekundy przed ponowieniem 404 (chybienie na zimno)",
    )
    ptg.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.command == "classify":
        _log_stats(classify(args.tags, None if args.no_gcr else args.gcr, args.out))
        log.info("gotowe -> %s", args.out)
        return

    # Cache HTTP zapamietalby pierwsze 404 i zamaskowal chybienie na zimno.
    session = build_session(use_cache=False, hub_auth=False)
    try:
        if args.command == "assign":
            _log_stats(assign(session, args.in_path, args.out))
            log.info("gotowe -> %s (mirror_ok niezweryfikowane - uruchom probe-tags)", args.out)
        elif args.command == "probe-tags":
            stats = probe_tags(session, args.in_path, args.out, args.retry_delay)
            _log_stats(stats)
            log.info("matryca: %s", budget_line(stats["registry:hub"]))
            log.info("gotowe -> %s", args.out)
    finally:
        session.close()


if __name__ == "__main__":
    main()

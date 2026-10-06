"""Krok 5 - matryca testowa.

candidates (offline): results/refs.jsonl z Kroku 4 -> results/candidates.jsonl
  1. filtr: library/ + distroless, bez wykluczen i prerelease, z obrazem amd64
  2. jeden wiersz na obraz amd64 (arch_digest), pozostale tagi trafiaja do aliases
  3. regula minor: najnowszy tag dla (repo, wersja X.Y, flavor, klasa, linia OS)

Potem Classify.py probe-tags na kandydatach. Do matrycy wchodza tylko obrazy, ktore ma
lustro mirror.gcr.io (albo distroless z gcr.io), wiec zaden nie jest pobierany z Docker Huba.

select (offline): kandydaci po sondzie -> results/matrix.jsonl
  4. grupy (repo, wersja X.Y, flavor, linia OS): standard + slim (+ alpine), do tego
     distroless, jesli zgadza sie technologia, wersja runtime'u i linia Debiana
  5. dwie warstwy: "pairs" - grupy sparowane, z limitem na repozytorium;
     "descriptive" - grupy bez pary, dopelniaja matryce do --target (tylko punkt 5 pracy)
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import random
from collections import Counter
from pathlib import Path

from Classify import read_jsonl

log = logging.getLogger("matrix")

# Technologia distroless -> repozytorium library/, z ktorym jest parowana.
PARTNER_REPO = {
    "python": "library/python",
    "node": "library/node",
    "java": "library/openjdk",
    "base": "library/debian",
}

# Wersja Pythona w python3-debianN, odczytana z Entrypoint w configu obrazu (01.10.2026).
PYTHON_BY_DEBIAN = {
    "debian9": "3.5",
    "debian10": "3.7",
    "debian11": "3.9",
    "debian12": "3.11",
    "debian13": "3.13",
}


def minor(version: str | None) -> str | None:
    """'3.13.2' -> '3.13', '22' -> '22'."""
    if not version:
        return None
    parts = version.lstrip("v").split(".")
    return ".".join(parts[:2])


def pushed(row: dict) -> str:
    return row.get("tag_last_pushed") or ""


def runtime_version(row: dict) -> str | None:
    """Wersja runtime'u w obrazie distroless; None, gdy obrazu nie da sie sparowac."""
    name = row["flavor"]
    if name == "python3":
        return PYTHON_BY_DEBIAN.get(row["os_line"])
    if name == "python2.7":
        return "2.7"
    if name in ("static", "base", "base-nossl", "cc"):
        return row["os_line"].removeprefix("debian")
    for prefix in ("nodejs", "java"):
        number = name.removeprefix(prefix)
        if name.startswith(prefix) and number.isdigit():
            return number
    return None  # nodejs-debian11, java-debian11, java-base-*: wersja nieznana z nazwy


def is_candidate(row: dict) -> bool:
    if row["excluded_reason"] or row["prerelease"] or not row["arch_digest"]:
        return False
    return row["vendor"] == "library" or row["source_registry"] == "gcr"


def tag_score(row: dict) -> tuple[bool, bool]:
    """Ktory z aliasow zostaje wierszem kanonicznym - wieksza wartosc wygrywa."""
    if row["source_registry"] == "gcr":
        return (runtime_version(row) is not None, False)
    return (row["version"] is not None, row["os_line_source"] == "tag")


def dedup_by_digest(rows: list[dict]) -> list[dict]:
    """Jeden wiersz na obraz amd64; tagi pozostalych wierszy trafiaja do aliases."""
    by_digest: dict[str, dict] = {}
    for row in rows:
        key = row["arch_digest"]
        if key not in by_digest:
            row["aliases"] = []
            by_digest[key] = row
            continue
        kept = by_digest[key]
        if tag_score(row) > tag_score(kept):
            row["aliases"] = kept["aliases"] + [kept["tag"]]
            by_digest[key] = row
        else:
            kept["aliases"].append(row["tag"])
    return list(by_digest.values())


def keep_newest_per_minor(rows: list[dict]) -> list[dict]:
    """Z wersji patch tej samej linii zostaje tylko ostatnio wypchnieta."""
    newest: dict[tuple, dict] = {}
    for row in rows:
        key = (row["repo_key"], minor(row["version"]), row["flavor"], row["variant"], row["os_line"])
        if key not in newest or pushed(row) > pushed(newest[key]):
            newest[key] = row
    return list(newest.values())


def newest(rows: list[dict]) -> dict | None:
    best = None
    for row in rows:
        if best is None or pushed(row) > pushed(best):
            best = row
    return best


def make_group(group_id: str, repo_key: str, version: str | None, flavor: str | None,
               rows: list[dict]) -> dict:
    return {"group_id": group_id, "repo_key": repo_key, "minor": version, "flavor": flavor,
            "rows": rows}


def standard_row(group: dict) -> dict | None:
    for row in group["rows"]:
        if row["variant"] == "standard":
            return row
    return None


def build_hub_groups(rows: list[dict]) -> list[dict]:
    """Grupa = (repo, wersja X.Y, flavor, linia OS) z obrazami standard i slim.

    standard i slim musza stac na tej samej linii, inaczej delta mierzylaby zmiane bazy.
    Po regule minor kazda para (klasa, linia) ma juz tylko jeden obraz. alpine ma wlasna
    linie, wiec dolacza do grupy z najnowszym obrazem standard tej wersji.
    """
    by_key: dict[tuple, list[dict]] = {}
    for row in rows:
        key = (row["repo_key"], minor(row["version"]), row["flavor"])
        by_key.setdefault(key, []).append(row)

    groups = []
    for (repo_key, version, flavor), members in by_key.items():
        by_line: dict[str | None, list[dict]] = {}
        alpines = []
        for row in members:
            if row["variant"] == "alpine":
                alpines.append(row)
            else:
                by_line.setdefault(row["os_line"], []).append(row)

        line_groups = []
        for line, line_rows in by_line.items():
            group_id = f"{repo_key}:{version or '-'}:{flavor or '-'}:{line or '-'}"
            line_groups.append(make_group(group_id, repo_key, version, flavor, line_rows))

        alpine = newest(alpines)
        if alpine is not None:
            target = None
            for group in line_groups:
                standard = standard_row(group)
                if standard is None:
                    continue
                if target is None or pushed(standard) > pushed(standard_row(target)):
                    target = group
            if target is not None:
                target["rows"].append(alpine)
            else:
                group_id = f"{repo_key}:{version or '-'}:{flavor or '-'}:{alpine['os_line'] or '-'}"
                line_groups.append(make_group(group_id, repo_key, version, flavor, [alpine]))

        groups += line_groups
    return groups


def version_matches(group_minor: str | None, version: str) -> bool:
    if group_minor is None:
        return False
    return group_minor == version or group_minor.startswith(version + ".")


def find_partner_group(groups: list[dict], row: dict) -> dict | None:
    """Najnowsza grupa partnera z ta sama wersja runtime'u i linia Debiana."""
    repo_key = PARTNER_REPO.get(row["family"])
    version = runtime_version(row)
    if repo_key is None or version is None:
        return None

    best = None
    best_score = None
    for group in groups:
        if group["repo_key"] != repo_key or not version_matches(group["minor"], version):
            continue
        standard = standard_row(group)
        if standard is None or standard["os_line"] != row["os_line"]:
            continue
        score = (group["flavor"] is None, pushed(standard))  # bez flavoru = obraz bazowy
        if best_score is None or score > best_score:
            best = group
            best_score = score
    return best


def attach_distroless(groups: list[dict], distroless: list[dict]) -> list[dict]:
    """Distroless dolacza do grupy partnera; bez partnera tworzy wlasna grupe."""
    alone = []
    for row in distroless:
        group = find_partner_group(groups, row)
        if group is not None:
            group["rows"].append(row)
            log.info("  %-28s -> %s", row["flavor"] + "-" + row["os_line"], group["group_id"])
        else:
            alone.append(make_group(row["repo_key"], row["repo_key"], None, row["flavor"], [row]))
            log.info("  %-28s -> brak partnera", row["flavor"] + "-" + row["os_line"])
    return alone


def mark_pairs(group: dict) -> None:
    variants = set()
    for row in group["rows"]:
        variants.add(row["variant"])
    has_standard = "standard" in variants
    group["paired"] = has_standard and len(variants) > 1
    group["triangle"] = has_standard and "distroless" in variants


def has_distroless(group: dict) -> bool:
    for row in group["rows"]:
        if row["variant"] == "distroless":
            return True
    return False


def allocate_quotas(available: dict[str, int], weights: dict[str, float], target: int) -> dict[str, int]:
    """Podzial target miedzy repozytoria proporcjonalnie do wag.

    Repozytorium, ktore nie wypelni swojej czesci, dostaje tyle, ile ma, a reszta
    jest dzielona od nowa miedzy pozostale.
    """
    quotas: dict[str, int] = {}
    active = set(available)
    remaining = target
    while active:
        total_weight = 0.0
        for repo in active:
            total_weight += weights[repo]

        too_small = []
        for repo in active:
            share = remaining * weights[repo] / total_weight
            if available[repo] <= share:
                too_small.append(repo)

        if not too_small:
            for repo in active:
                quotas[repo] = int(remaining * weights[repo] / total_weight)
            break

        for repo in too_small:
            quotas[repo] = available[repo]
            remaining -= available[repo]
            active.remove(repo)
    return quotas


def pick_groups(groups: list[dict], quota: int, rng: random.Random) -> list[dict]:
    """Grupy z distroless zawsze, pozostale w losowej kolejnosci, dopoki mieszcza sie w kwocie."""
    mandatory = []
    rest = []
    for group in groups:
        if has_distroless(group):
            mandatory.append(group)
        else:
            rest.append(group)
    rng.shuffle(rest)

    chosen = []
    used = 0
    for group in mandatory:
        chosen.append(group)
        used += len(group["rows"])
    for group in rest:
        if used + len(group["rows"]) <= quota:
            chosen.append(group)
            used += len(group["rows"])
    return chosen


def count_rows(groups: list[dict]) -> int:
    total = 0
    for group in groups:
        total += len(group["rows"])
    return total


def group_by_repo(groups: list[dict]) -> dict[str, list[dict]]:
    by_repo: dict[str, list[dict]] = {}
    for group in groups:
        by_repo.setdefault(group["repo_key"], []).append(group)
    return by_repo


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def candidates(in_path: Path, out_path: Path) -> int:
    rows = []
    for row in read_jsonl([in_path]):
        if is_candidate(row):
            rows.append(row)
    log.info("kandydaci: %d", len(rows))

    rows = dedup_by_digest(rows)
    log.info("po dedupie arch_digest: %d", len(rows))

    rows = keep_newest_per_minor(rows)
    log.info("po regule minor: %d", len(rows))

    write_jsonl(out_path, rows)
    return len(rows)


def load_probed(in_path: Path) -> list[dict]:
    """Kandydaci po sondzie lustra; obrazy dostepne tylko na Docker Hubie odpadaja."""
    rows = []
    hub_only = 0
    for row in read_jsonl([in_path]):
        if row["source_registry"] == "hub" and row.get("mirror_probe") is None:
            raise SystemExit(f"{in_path}: brak wyniku sondy - uruchom najpierw Classify.py probe-tags")
        if row["registry"] == "hub":
            hub_only += 1
            continue
        rows.append(row)
    log.info("na lustrze lub w gcr.io: %d, tylko na Docker Hubie (odrzucone): %d", len(rows), hub_only)
    return rows


def select(in_path: Path, out_path: Path, target: int, pair_cap: int, desc_cap: int,
           seed: int) -> dict:
    rows = load_probed(in_path)
    hub_rows = [r for r in rows if r["source_registry"] == "hub"]
    distroless = [r for r in rows if r["source_registry"] == "gcr"]
    groups = build_hub_groups(hub_rows)
    log.info("grupy Hub: %d", len(groups))

    log.info("parowanie distroless:")
    alone = attach_distroless(groups, distroless)
    for group in groups + alone:
        mark_pairs(group)

    rng = random.Random(seed)

    # Warstwa "pairs": grupy sparowane, do pair_cap obrazow z repozytorium.
    paired_by_repo = group_by_repo([g for g in groups if g["paired"]])
    pairs = []
    for repo in sorted(paired_by_repo):
        pairs += pick_groups(paired_by_repo[repo], pair_cap, rng)
    for group in pairs:
        group["stratum"] = "pairs"
    log.info("warstwa pairs: %d obrazow w %d grupach", count_rows(pairs), len(pairs))

    # Warstwa "descriptive": grupy bez pary dopelniaja matryce do target.
    # Distroless bez partnera wchodzi zawsze - cala klasa jest skanowana.
    other_by_repo = group_by_repo([g for g in groups if not g["paired"]])
    available = {}
    weights = {}
    for repo, repo_groups in other_by_repo.items():
        available[repo] = min(count_rows(repo_groups), desc_cap)
        weights[repo] = math.log(1 + len(repo_groups))
    free = target - count_rows(pairs) - count_rows(alone)
    if free < 0:
        log.warning("warstwa pairs przekracza --target o %d obrazow", -free)
        free = 0
    quotas = allocate_quotas(available, weights, free)

    descriptive = list(alone)
    for repo in sorted(other_by_repo):
        descriptive += pick_groups(other_by_repo[repo], quotas[repo], rng)
    for group in descriptive:
        group["stratum"] = "descriptive"
    log.info("warstwa descriptive: %d obrazow w %d grupach", count_rows(descriptive), len(descriptive))

    chosen = pairs + descriptive
    out_rows = []
    for group in chosen:
        for row in group["rows"]:
            row["group_id"] = group["group_id"]
            row["stratum"] = group["stratum"]
            row["paired"] = group["paired"]
            row["triangle"] = group["triangle"]
            out_rows.append(row)
    write_jsonl(out_path, out_rows)

    params = {"target": target, "pair_cap": pair_cap, "desc_cap": desc_cap, "seed": seed}
    return build_report(chosen, params)


def build_report(chosen: list[dict], params: dict) -> dict:
    variants: Counter[str] = Counter()
    per_stratum: Counter[str] = Counter()
    per_repo: Counter[str] = Counter()
    pairs: Counter[str] = Counter()
    repos_with_pair: dict[str, set] = {"slim": set(), "alpine": set(), "distroless": set()}
    distroless_lines: Counter[str] = Counter()
    rows = 0
    for group in chosen:
        group_variants = set()
        for row in group["rows"]:
            rows += 1
            variants[row["variant"]] += 1
            per_stratum[group["stratum"]] += 1
            per_repo[row["repo_key"]] += 1
            group_variants.add(row["variant"])
            if row["variant"] == "distroless":
                status = "z partnerem" if group["triangle"] else "bez partnera"
                distroless_lines[f"{row['family']} {row['os_line']} {status}"] += 1
        if "standard" in group_variants:
            for variant in ("slim", "alpine", "distroless"):
                if variant in group_variants:
                    pairs[variant] += 1
                    repos_with_pair[variant].add(group["repo_key"])

    return {
        "params": params,
        "rows": rows,
        "rows_per_stratum": dict(per_stratum),
        "groups": len(chosen),
        "groups_paired": sum(1 for g in chosen if g["paired"]),
        "groups_triangle": sum(1 for g in chosen if g["triangle"]),
        "pairs": dict(pairs),
        "repos_with_pair": {v: len(repos) for v, repos in repos_with_pair.items()},
        "variants": dict(variants),
        "repos": len(per_repo),
        "top_repos": per_repo.most_common(15),
        "distroless": dict(sorted(distroless_lines.items())),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Krok 5 - matryca testowa")
    sub = parser.add_subparsers(dest="command", required=True)

    cand = sub.add_parser("candidates", help="filtr, dedup i regula minor (offline)")
    cand.add_argument("--in", dest="in_path", type=Path, default=Path("results/refs.jsonl"))
    cand.add_argument("--out", type=Path, default=Path("results/candidates.jsonl"))
    cand.add_argument("--verbose", "-v", action="store_true")

    sel = sub.add_parser("select", help="grupy i losowanie w dwoch warstwach (offline)")
    sel.add_argument("--in", dest="in_path", type=Path,
                     default=Path("results/candidates_probed.jsonl"),
                     help="kandydaci po Classify.py probe-tags")
    sel.add_argument("--out", type=Path, default=Path("results/matrix.jsonl"))
    sel.add_argument("--report", type=Path, default=Path("results/matrix_report.json"))
    sel.add_argument("--target", type=int, default=10000, help="docelowa liczba obrazow")
    sel.add_argument("--pair-cap", type=int, default=99999,
                     help="limit obrazow z repozytorium w warstwie pairs "
                          "(domyslnie bez praktycznego limitu - cala pula par z lustra)")
    sel.add_argument("--desc-cap", type=int, default=150,
                     help="limit obrazow z repozytorium w warstwie descriptive")
    sel.add_argument("--seed", type=int, default=2026, help="ziarno losowania (powtarzalnosc)")
    sel.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.command == "candidates":
        candidates(args.in_path, args.out)
        log.info("gotowe -> %s (teraz Classify.py probe-tags)", args.out)
    elif args.command == "select":
        report = select(args.in_path, args.out, args.target, args.pair_cap, args.desc_cap,
                        args.seed)
        args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        log.info("wierszy: %d %s", report["rows"], report["rows_per_stratum"])
        log.info("pary: %s, repozytoriow z para: %s", report["pairs"], report["repos_with_pair"])
        log.info("klasy: %s", report["variants"])
        log.info("gotowe -> %s, raport -> %s", args.out, args.report)


if __name__ == "__main__":
    main()

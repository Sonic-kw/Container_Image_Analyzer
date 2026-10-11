"""Krok 6 - skanowanie matrycy Trivy (zamrozona baza CVE, resume, 12 kontenerow).

freeze-db  - pobranie bazy CVE/Java DB + kopia do cache per worker
split      - podzial matrix.jsonl na matrix_part_*.jsonl
run        - skan jednej czesci (jeden kontener / jeden worker)
merge      - metrics_part_*.jsonl -> results/scans.jsonl
status     - ile raportow / metryk / porazek
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import logging
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("scan")

DEFAULT_PARTS = 12
DEFAULT_TIMEOUT_S = 600
DEFAULT_TRIVY = "trivy"

# Pola z matrycy kopiowane do wiersza metryk (analiza APD 5-7).
MATRIX_KEYS = (
    "logical_ref",
    "pull_ref",
    "family",
    "variant",
    "vendor",
    "repo_key",
    "tag",
    "version",
    "flavor",
    "os_line",
    "group_id",
    "paired",
    "triangle",
    "stratum",
    "arch_digest",
    "arch_size",
    "layer_key",
    "registry",
    "source_registry",
    "mirror_probe",
    "nonroot_available",
    "tag_last_pushed",
)

SHELL_NAMES = {"bash", "sh", "dash", "ash", "zsh"}
PKG_MARKERS = {
    "has_shell": SHELL_NAMES | {"busybox"},
    "has_busybox": {"busybox"},
    "has_apt": {"apt", "apt-get", "apt-utils"},
    "has_apk": {"apk-tools", "apk"},
}


def report_id(arch_digest: str) -> str:
    return arch_digest.removeprefix("sha256:")


def report_path(reports_dir: Path, arch_digest: str) -> Path:
    return reports_dir / f"{report_id(arch_digest)}.json.gz"


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def load_metric_ids(path: Path) -> set[str]:
    ids: set[str] = set()
    for row in read_jsonl(path):
        digest = row.get("arch_digest")
        if digest:
            ids.add(digest)
    return ids


def run_trivy(args: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    log.debug("trivy %s", " ".join(args))
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def freeze_db(
    trivy: str,
    frozen_dir: Path,
    snapshot_dir: Path,
    workers: int,
    worker_root: Path,
) -> None:
    frozen_dir.mkdir(parents=True, exist_ok=True)
    for flag in ("--download-db-only", "--download-java-db-only"):
        result = run_trivy(
            [trivy, "image", "--cache-dir", str(frozen_dir), flag],
            timeout=DEFAULT_TIMEOUT_S,
        )
        if result.returncode != 0:
            raise SystemExit(
                f"trivy {flag} failed ({result.returncode}): {result.stderr.strip()}"
            )
        log.info("ok %s", flag)

    meta_src = frozen_dir / "db" / "metadata.json"
    if not meta_src.exists():
        raise SystemExit(f"brak {meta_src} po pobraniu bazy")
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(meta_src, snapshot_dir / "metadata.json")
    db_file = frozen_dir / "db" / "trivy.db"
    if db_file.exists():
        digest = hashlib.sha256(db_file.read_bytes()).hexdigest()
        (snapshot_dir / "trivy.db.sha256").write_text(digest + "\n", encoding="utf-8")
        log.info("snapshot bazy -> %s (sha256=%s…)", snapshot_dir, digest[:16])
    log.info("metadata: %s", meta_src.read_text(encoding="utf-8")[:500])

    for i in range(workers):
        dest = worker_root / f"w{i}"
        for name in ("db", "java-db"):
            src = frozen_dir / name
            if not src.exists():
                if name == "java-db":
                    log.warning("brak %s - pomijam kopie do %s", src, dest)
                    continue
                raise SystemExit(f"brak {src}")
            target = dest / name
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(src, target)
        log.info("cache workera %d -> %s", i, dest)


def split_matrix(in_path: Path, out_dir: Path, parts: int) -> list[int]:
    rows = read_jsonl(in_path)
    if not rows:
        raise SystemExit(f"pusty lub brakujacy plik: {in_path}")
    if parts < 1:
        raise SystemExit("--parts musi byc >= 1")

    out_dir.mkdir(parents=True, exist_ok=True)
    # Prosty podzial: kolejne kawałki; reszta trafia do ostatnich czesci.
    base, extra = divmod(len(rows), parts)
    counts: list[int] = []
    offset = 0
    for i in range(parts):
        size = base + (1 if i < extra else 0)
        chunk = rows[offset : offset + size]
        offset += size
        out_path = out_dir / f"matrix_part_{i}.jsonl"
        write_jsonl(out_path, chunk)
        counts.append(len(chunk))
        log.info("part %d: %d wierszy -> %s", i, len(chunk), out_path)
    log.info("razem %d wierszy w %d czesciach", len(rows), parts)
    return counts


def load_report(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, EOFError, json.JSONDecodeError) as exc:
        log.warning("zly raport %s: %s", path, exc)
        return None
    if not isinstance(data, dict):
        return None
    return data


def parse_metrics(report: dict[str, Any]) -> dict[str, Any]:
    severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    cve_total = 0
    cve_with_fix = 0
    pkg_names: set[str] = set()

    for result in report.get("Results") or []:
        for pkg in result.get("Packages") or []:
            name = (pkg.get("Name") or "").lower()
            if name:
                pkg_names.add(name)
        for vuln in result.get("Vulnerabilities") or []:
            cve_total += 1
            sev = (vuln.get("Severity") or "UNKNOWN").upper()
            if sev not in severity:
                sev = "UNKNOWN"
            severity[sev] += 1
            if vuln.get("FixedVersion"):
                cve_with_fix += 1

    flags = {key: False for key in PKG_MARKERS}
    for key, names in PKG_MARKERS.items():
        flags[key] = bool(pkg_names & names)
    # has_shell: bash/sh/... albo busybox (powloka w alpine)
    flags["has_shell"] = bool(pkg_names & SHELL_NAMES) or flags["has_busybox"]

    return {
        "cve_total": cve_total,
        "cve_critical": severity["CRITICAL"],
        "cve_high": severity["HIGH"],
        "cve_medium": severity["MEDIUM"],
        "cve_low": severity["LOW"],
        "cve_unknown": severity["UNKNOWN"],
        "cve_with_fix": cve_with_fix,
        "pkg_count": len(pkg_names),
        **flags,
    }


def metrics_row(
    matrix_row: dict[str, Any],
    metrics: dict[str, Any],
    part: int,
    scan_ok: bool,
    trivy_exit: int | None,
) -> dict[str, Any]:
    row = {key: matrix_row.get(key) for key in MATRIX_KEYS}
    row.update(metrics)
    row["part_id"] = part
    row["scan_ok"] = scan_ok
    row["trivy_exit"] = trivy_exit
    row["scanned_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return row


def scan_one(
    trivy: str,
    pull_ref: str,
    cache_dir: Path,
    reports_dir: Path,
    arch_digest: str,
    timeout: int,
) -> tuple[dict[str, Any] | None, int | None, str]:
    """Zwraca (report, exit_code, error_message)."""
    reports_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)
    out_gz = report_path(reports_dir, arch_digest)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as tmp:
        tmp_path = Path(tmp.name)

    cmd = [
        trivy,
        "image",
        "--cache-dir",
        str(cache_dir),
        "--skip-db-update",
        "--skip-java-db-update",
        "--image-src",
        "remote",
        "--scanners",
        "vuln",
        "--list-all-pkgs",
        "--format",
        "json",
        "--output",
        str(tmp_path),
        pull_ref,
    ]
    try:
        result = run_trivy(cmd, timeout=timeout)
    except subprocess.TimeoutExpired:
        tmp_path.unlink(missing_ok=True)
        return None, None, f"timeout po {timeout}s"
    except FileNotFoundError:
        tmp_path.unlink(missing_ok=True)
        return None, None, f"nie znaleziono binarium: {trivy}"

    if result.returncode != 0:
        err = (result.stderr or result.stdout or "").strip()[:500]
        tmp_path.unlink(missing_ok=True)
        return None, result.returncode, err or f"exit {result.returncode}"

    try:
        data = json.loads(tmp_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        tmp_path.unlink(missing_ok=True)
        return None, result.returncode, f"zly JSON: {exc}"

    with gzip.open(out_gz, "wt", encoding="utf-8") as handle:
        json.dump(data, handle)
    tmp_path.unlink(missing_ok=True)
    return data, result.returncode, ""


def cmd_run(
    matrix_path: Path,
    part: int,
    cache_dir: Path,
    reports_dir: Path,
    out_path: Path,
    failures_path: Path,
    trivy: str,
    timeout: int,
) -> None:
    rows = read_jsonl(matrix_path)
    if not rows:
        raise SystemExit(f"pusta czesc matrycy: {matrix_path}")

    done = load_metric_ids(out_path)
    ok = skip = fail = 0

    for index, row in enumerate(rows, start=1):
        digest = row.get("arch_digest")
        pull_ref = row.get("pull_ref")
        if not digest or not pull_ref:
            fail += 1
            append_jsonl(
                failures_path,
                {
                    "part_id": part,
                    "logical_ref": row.get("logical_ref"),
                    "error": "brak arch_digest lub pull_ref",
                },
            )
            continue

        existing = load_report(report_path(reports_dir, digest))
        if existing is not None:
            if digest not in done:
                append_jsonl(
                    out_path,
                    metrics_row(row, parse_metrics(existing), part, True, 0),
                )
                done.add(digest)
            skip += 1
            if index % 50 == 0 or index == len(rows):
                log.info(
                    "part %d postep %d/%d (ok=%d skip=%d fail=%d)",
                    part,
                    index,
                    len(rows),
                    ok,
                    skip,
                    fail,
                )
            continue

        log.info("part %d [%d/%d] %s", part, index, len(rows), row.get("logical_ref"))
        report, exit_code, err = scan_one(
            trivy, pull_ref, cache_dir, reports_dir, digest, timeout
        )
        if report is None:
            fail += 1
            append_jsonl(
                failures_path,
                {
                    "part_id": part,
                    "logical_ref": row.get("logical_ref"),
                    "pull_ref": pull_ref,
                    "arch_digest": digest,
                    "trivy_exit": exit_code,
                    "error": err,
                },
            )
            continue

        append_jsonl(out_path, metrics_row(row, parse_metrics(report), part, True, exit_code))
        done.add(digest)
        ok += 1

    log.info(
        "part %d gotowe: ok=%d skip=%d fail=%d -> %s",
        part,
        ok,
        skip,
        fail,
        out_path,
    )


def cmd_merge(parts_dir: Path, parts: int, out_path: Path, failures_out: Path) -> None:
    rows: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for i in range(parts):
        metrics_path = parts_dir / f"metrics_part_{i}.jsonl"
        fail_path = parts_dir / f"failures_part_{i}.jsonl"
        part_rows = read_jsonl(metrics_path)
        part_fails = read_jsonl(fail_path)
        rows.extend(part_rows)
        failures.extend(part_fails)
        log.info("part %d: %d metryk, %d porazek", i, len(part_rows), len(part_fails))

    write_jsonl(out_path, rows)
    write_jsonl(failures_out, failures)
    log.info("scalono %d skanow -> %s", len(rows), out_path)
    log.info("porazki: %d -> %s", len(failures), failures_out)


def cmd_status(parts: int, reports_root: Path, results_dir: Path) -> None:
    for i in range(parts):
        reports = list((reports_root / f"w{i}").glob("*.json.gz")) if (reports_root / f"w{i}").exists() else []
        metrics = read_jsonl(results_dir / f"metrics_part_{i}.jsonl")
        fails = read_jsonl(results_dir / f"failures_part_{i}.jsonl")
        matrix = read_jsonl(results_dir / f"matrix_part_{i}.jsonl")
        log.info(
            "part %2d: matrix=%d reports=%d metrics=%d failures=%d",
            i,
            len(matrix),
            len(reports),
            len(metrics),
            len(fails),
        )
    scans = read_jsonl(results_dir / "scans.jsonl")
    log.info("scans.jsonl: %d wierszy", len(scans))


def main() -> None:
    parser = argparse.ArgumentParser(description="Krok 6 - skaner Trivy")
    sub = parser.add_subparsers(dest="command", required=True)

    frz = sub.add_parser("freeze-db", help="pobierz i zamroz baze CVE, skopiuj do workerow")
    frz.add_argument("--trivy", default=DEFAULT_TRIVY)
    frz.add_argument("--frozen-dir", type=Path, default=Path("trivy_cache/frozen"))
    frz.add_argument("--snapshot-dir", type=Path, default=Path("results/db_snapshot"))
    frz.add_argument("--worker-root", type=Path, default=Path("trivy_cache"))
    frz.add_argument("--workers", type=int, default=DEFAULT_PARTS)
    frz.add_argument("--verbose", "-v", action="store_true")

    spl = sub.add_parser("split", help="podziel matryce na N kolejnych czesci")
    spl.add_argument("--in", dest="in_path", type=Path, default=Path("results/matrix.jsonl"))
    spl.add_argument("--out-dir", type=Path, default=Path("results"))
    spl.add_argument("--parts", type=int, default=DEFAULT_PARTS)
    spl.add_argument("--verbose", "-v", action="store_true")

    run_p = sub.add_parser("run", help="skanuj jedna czesc matrycy")
    run_p.add_argument("--part", type=int, required=True)
    run_p.add_argument("--matrix", type=Path, help="domyslnie results/matrix_part_{part}.jsonl")
    run_p.add_argument("--cache-dir", type=Path, help="domyslnie trivy_cache/w{part}")
    run_p.add_argument("--reports-dir", type=Path, help="domyslnie reports/w{part}")
    run_p.add_argument("--out", type=Path, help="domyslnie results/metrics_part_{part}.jsonl")
    run_p.add_argument("--failures", type=Path, help="domyslnie results/failures_part_{part}.jsonl")
    run_p.add_argument("--trivy", default=DEFAULT_TRIVY)
    run_p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_S)
    run_p.add_argument("--verbose", "-v", action="store_true")

    mrg = sub.add_parser("merge", help="scal metrics_part_* do scans.jsonl")
    mrg.add_argument("--results-dir", type=Path, default=Path("results"))
    mrg.add_argument("--parts", type=int, default=DEFAULT_PARTS)
    mrg.add_argument("--out", type=Path, default=Path("results/scans.jsonl"))
    mrg.add_argument("--failures-out", type=Path, default=Path("results/scan_failures.jsonl"))
    mrg.add_argument("--verbose", "-v", action="store_true")

    st = sub.add_parser("status", help="postep kampanii")
    st.add_argument("--parts", type=int, default=DEFAULT_PARTS)
    st.add_argument("--reports-root", type=Path, default=Path("reports"))
    st.add_argument("--results-dir", type=Path, default=Path("results"))
    st.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if getattr(args, "verbose", False) else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.command == "freeze-db":
        freeze_db(args.trivy, args.frozen_dir, args.snapshot_dir, args.workers, args.worker_root)
    elif args.command == "split":
        split_matrix(args.in_path, args.out_dir, args.parts)
    elif args.command == "run":
        part = args.part
        matrix = args.matrix or Path(f"results/matrix_part_{part}.jsonl")
        cache_dir = args.cache_dir or Path(f"trivy_cache/w{part}")
        reports_dir = args.reports_dir or Path(f"reports/w{part}")
        out_path = args.out or Path(f"results/metrics_part_{part}.jsonl")
        failures = args.failures or Path(f"results/failures_part_{part}.jsonl")
        cmd_run(
            matrix, part, cache_dir, reports_dir, out_path, failures, args.trivy, args.timeout
        )
    elif args.command == "merge":
        cmd_merge(args.results_dir, args.parts, args.out, args.failures_out)
    elif args.command == "status":
        cmd_status(args.parts, args.reports_root, args.results_dir)
    else:
        parser.error(f"nieznana komenda: {args.command}")
        sys.exit(2)


if __name__ == "__main__":
    main()

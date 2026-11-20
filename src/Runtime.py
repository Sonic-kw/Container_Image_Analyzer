"""Badanie uzupelniajace: utwardzanie konfiguracji uruchomieniowej.

Cztery obrazy z grupy library/python:3.13:-:debian13 (te same digesty co w kampanii)
dostaja aplikacje-sonde (src/runtime/app.py). Kazdy obraz jest uruchamiany
w pieciu profilach `docker run`, a sonda raportuje, co moze zrobic kod wykonany
w procesie aplikacji (symulacja zdalnego wykonania kodu).

Uzycie (z katalogu projektu, Docker Desktop uruchomiony):
  python src/Runtime.py build     # 4 obrazy cia-probe-<klasa>
  python src/Runtime.py run       # 4 obrazy x 10 profili x 3 powtorzenia -> results/runtime_probe.jsonl
  python src/Runtime.py scan      # Trivy v0.75.0 z zamrozona baza -> results/runtime_scan.jsonl
  python src/Runtime.py summary   # zestawienie + wykres figures/6_7_runtime_matrix.{pgf,png}
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("runtime")

GROUP_ID = "library/python:3.13:-:debian13"
VARIANTS = ("standard", "slim", "alpine", "distroless")
PROBE_DIR = Path("src/runtime")
PORT = 18080
CONTAINER = "cia-probe-run"
SCANNER_IMAGE = "cia-scanner"

# Profile uruchomienia, grupa 1 (narastajaco): kazdy kolejny dodaje ograniczenia
# do poprzedniego, PX to antywzorzec (tryb uprzywilejowany) jako punkt odniesienia.
P1 = ["--user", "65532:65532"]
P2 = P1 + ["--cap-drop", "ALL", "--security-opt", "no-new-privileges"]
P3 = P2 + ["--read-only", "--tmpfs", "/tmp", "--pids-limit", "64", "--memory", "256m"]
# Grupa 2 (dodana 18.11.2026): pojedyncze ustawienia nakladane osobno na
# konfiguracje domyslna P0. Uzytkownika nieuprzywilejowanego osobno mierzy juz P1.
PROFILES = {
    "P0": [],
    "P1": P1,
    "P2": P2,
    "P3": P3,
    "PX": ["--privileged"],
    "SC": ["--cap-drop", "ALL"],
    "SN": ["--security-opt", "no-new-privileges"],
    "SR": ["--read-only", "--tmpfs", "/tmp"],
    "SL": ["--pids-limit", "64", "--memory", "256m"],
    "SU": ["--security-opt", "seccomp=unconfined"],
}
CUMULATIVE = ("P0", "P1", "P2", "P3", "PX")
SINGLE = ("P1", "SC", "SN", "SR", "SL", "SU")

# Mozliwosci napastnika liczone z wyniku sondy (miara zbiorcza badania).
INDICATORS = (
    ("root", "proces działa jako root"),
    ("write_fs", "zapis do systemu plików obrazu"),
    ("shell", "powłoka"),
    ("pkg_manager", "menedżer pakietów"),
    ("downloader", "narzędzie do pobierania (curl, wget)"),
    ("compiler", "kompilator"),
    ("setuid", "pliki setuid przy braku no_new_privs"),
    ("raw_socket", "gniazdo surowe (CAP_NET_RAW)"),
    ("chown", "zmiana właściciela pliku (CAP_CHOWN)"),
    ("read_shadow", "odczyt /etc/shadow"),
    ("no_limits", "brak limitu procesów lub pamięci"),
    ("no_seccomp", "profil seccomp słabszy niż domyślny Dockera"),
)


def docker(args: list[str], check: bool = True, timeout: int = 1800) -> subprocess.CompletedProcess[str]:
    log.debug("docker %s", " ".join(args))
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, encoding="utf-8", timeout=timeout
    )
    if check and result.returncode != 0:
        raise SystemExit(f"docker {' '.join(args)} -> {result.returncode}: {result.stderr.strip()}")
    return result


def image_name(variant: str) -> str:
    return f"cia-probe-{variant}"


def load_bases(scans_path: Path) -> dict[str, dict]:
    """Obrazy bazowe grupy python:3.13 z kampanii (adres z digestem i liczby ze skanu)."""
    bases = {}
    with scans_path.open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            if row.get("group_id") == GROUP_ID and row.get("variant") in VARIANTS:
                bases[row["variant"]] = row
    missing = [v for v in VARIANTS if v not in bases]
    if missing:
        raise SystemExit(f"brak obrazow {missing} w grupie {GROUP_ID}")
    return bases


def append_jsonl(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def read_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- build ---------------------------------------------------------------


def cmd_build(scans_path: Path) -> None:
    bases = load_bases(scans_path)
    for variant in VARIANTS:
        base = bases[variant]["pull_ref"]
        log.info("budowanie %s na %s", image_name(variant), base)
        docker(["build", "-t", image_name(variant), "--build-arg", f"BASE={base}", str(PROBE_DIR)])


# --- run -----------------------------------------------------------------


def http_get(path: str) -> str | None:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}{path}", timeout=5) as resp:
            return resp.read().decode("utf-8")
    except (urllib.error.URLError, ConnectionError, TimeoutError, OSError):
        return None


def run_one(variant: str, profile: str, wait_s: int) -> dict:
    docker(["rm", "-f", CONTAINER], check=False)
    flags = PROFILES[profile]
    started = docker(
        ["run", "-d", "--name", CONTAINER, "-p", f"127.0.0.1:{PORT}:8080", *flags, image_name(variant)],
        check=False,
    )
    row = {
        "variant": variant,
        "profile": profile,
        "flags": " ".join(flags),
        "image": image_name(variant),
        "started_at": now(),
        "run_exit": started.returncode,
        "functional": False,
        "probe": None,
        "error": "",
    }
    if started.returncode != 0:
        row["error"] = started.stderr.strip()[:500]
        return row

    deadline = time.time() + wait_s
    while time.time() < deadline:
        if http_get("/") == "ok":
            row["functional"] = True
            break
        time.sleep(0.5)

    if row["functional"]:
        body = http_get("/probe")
        row["probe"] = json.loads(body) if body else None
    else:
        state = docker(["inspect", "--format", "{{.State.Status}} {{.State.ExitCode}}", CONTAINER], check=False)
        logs = docker(["logs", "--tail", "20", CONTAINER], check=False)
        row["error"] = f"{state.stdout.strip()} | {(logs.stdout + logs.stderr).strip()[:500]}"
    docker(["rm", "-f", CONTAINER], check=False)
    return row


def cmd_run(out_path: Path, repeats: int, wait_s: int) -> None:
    if out_path.exists():
        out_path.unlink()
    engine = docker(["version", "--format", "{{.Server.Version}}"]).stdout.strip()
    for repeat in range(1, repeats + 1):
        for variant in VARIANTS:
            image_id = docker(["image", "inspect", "--format", "{{.Id}}", image_name(variant)]).stdout.strip()
            for profile in PROFILES:
                row = run_one(variant, profile, wait_s)
                row.update({"repeat": repeat, "image_id": image_id, "docker_engine": engine})
                append_jsonl(out_path, row)
                log.info(
                    "powt. %d %-10s %s dziala=%s %s",
                    repeat, variant, profile, row["functional"], row["error"][:80],
                )


# --- scan ----------------------------------------------------------------


def prepare_cache(frozen_dir: Path, cache_dir: Path) -> None:
    """Kopia zamrozonej bazy z kampanii, zeby nie ruszac trivy_cache/frozen."""
    for name in ("db", "java-db"):
        target = cache_dir / name
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(frozen_dir / name, target)
    meta = json.loads((cache_dir / "db" / "metadata.json").read_text(encoding="utf-8"))
    log.info("baza podatnosci UpdatedAt=%s", meta.get("UpdatedAt"))


def cmd_scan(scans_path: Path, out_path: Path, frozen_dir: Path, cache_dir: Path) -> None:
    import Scan  # parse_metrics: te same metryki co w kampanii

    bases = load_bases(scans_path)
    prepare_cache(frozen_dir, cache_dir)
    tar_dir = Path("results/runtime_images")
    report_dir = Path("results/runtime_reports")
    tar_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        out_path.unlink()
    root = Path.cwd().resolve()

    for variant in VARIANTS:
        tar = tar_dir / f"{variant}.tar"
        report = report_dir / f"{variant}.json"
        log.info("zapis obrazu %s do %s", image_name(variant), tar)
        docker(["save", "-o", str(tar), image_name(variant)])
        # Skaner w kontenerze bez gniazda Dockera, jak w kampanii; obraz z pliku tar.
        cmd = (
            "mkdir -p /tmp/trivy && trivy image --quiet"
            f" --cache-dir {cache_dir.as_posix()} --skip-db-update --skip-java-db-update"
            " --scanners vuln --list-all-pkgs --format json"
            f" --output {report.as_posix()} --input {tar.as_posix()}"
        )
        docker([
            "run", "--rm", "-v", f"{root}:/app", "-w", "/app", "-e", "TMPDIR=/tmp/trivy",
            SCANNER_IMAGE, "bash", "-c", cmd,
        ])
        tar.unlink()
        metrics = Scan.parse_metrics(json.loads(report.read_text(encoding="utf-8")))
        campaign = bases[variant]
        row = {
            "variant": variant,
            "image": image_name(variant),
            "base_logical_ref": campaign["logical_ref"],
            "base_pull_ref": campaign["pull_ref"],
            "campaign_cve_total": campaign.get("cve_total"),
            "campaign_pkg_count": campaign.get("pkg_count"),
            "scanned_at": now(),
            **metrics,
        }
        append_jsonl(out_path, row)
        log.info(
            "%-10s CVE %s (kampania %s), pakiety %s (kampania %s)",
            variant, metrics["cve_total"], campaign.get("cve_total"),
            metrics["pkg_count"], campaign.get("pkg_count"),
        )


# --- summary -------------------------------------------------------------


def indicators(probe: dict, reference_filters: int) -> dict[str, bool]:
    """reference_filters: liczba filtrow seccomp w profilu P0 tego samego obrazu.

    W Docker Desktop (WSL2) sam silnik dziala juz pod jednym filtrem seccomp,
    wiec licznik nie spada do zera; slabszy profil to mniej filtrow niz w P0.
    """
    return {
        "root": probe["uid"] == 0,
        "write_fs": bool(probe["write_root"] or probe["write_usr"]),
        "shell": bool(probe["shells"]),
        "pkg_manager": bool(probe["pkg_managers"]),
        "downloader": bool(probe["downloaders"]),
        "compiler": bool(probe["compilers"]),
        "setuid": bool(probe["setuid_files"]) and probe["no_new_privs"] == "0",
        "raw_socket": bool(probe["raw_socket"]),
        "chown": probe["chown"] is True,
        "read_shadow": probe["read_shadow"] is True,
        "no_limits": probe["pids_max"] in (None, "max") or probe["memory_max"] in (None, "max"),
        "no_seccomp": probe["seccomp_filters"] < reference_filters,
    }


def cmd_summary(in_path: Path, out_path: Path, fig_dir: Path) -> None:
    rows = read_jsonl(in_path)
    configs: dict[tuple[str, str], list[dict]] = {}
    for row in rows:
        configs.setdefault((row["variant"], row["profile"]), []).append(row)

    summary = []
    for variant in VARIANTS:
        for profile in PROFILES:
            runs = configs.get((variant, profile), [])
            probes = [json.dumps(r["probe"], sort_keys=True) for r in runs]
            functional = [r["functional"] for r in runs]
            entry = {
                "variant": variant,
                "profile": profile,
                "repeats": len(runs),
                "functional": all(functional) if runs else None,
                "repeats_identical": len(set(probes)) == 1 and len(set(functional)) == 1,
            }
            first = runs[0]["probe"] if runs else None
            reference = configs.get((variant, "P0"), [{}])[0].get("probe") or {}
            if first:
                flags = indicators(first, reference.get("seccomp_filters", 0))
                entry.update(flags)
                entry["attacker_count"] = sum(flags.values())
                entry["probe"] = first
            summary.append(entry)

    out_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    log.info("zapisano %s", out_path)

    header = "| klasa | profil | działa | " + " | ".join(k for k, _ in INDICATORS) + " | suma |"
    print(header)
    print("|" + " --- |" * (len(INDICATORS) + 4))
    for e in summary:
        marks = " | ".join("tak" if e.get(k) else "nie" for k, _ in INDICATORS)
        print(f"| {e['variant']} | {e['profile']} | {'tak' if e['functional'] else 'nie'} | {marks} | {e.get('attacker_count', '-')} |")
    not_identical = [f"{e['variant']}/{e['profile']}" for e in summary if not e["repeats_identical"]]
    print("powtorzenia niezgodne:", not_identical or "brak")

    single = single_effects(summary)
    single_path = out_path.with_name("runtime_single_effects.json")
    single_path.write_text(json.dumps(single, ensure_ascii=False, indent=2), encoding="utf-8")
    print("\nPojedyncze ustawienia wzgledem P0 (usuniete / dodane mozliwosci):")
    for e in single:
        print(f"  {e['profile']:3} {e['variant']:10} {e['p0_count']} -> {e['count']}"
              f"  usuniete={e['removed']} dodane={e['added']}")

    plot_matrix([e for e in summary if e["profile"] in CUMULATIVE], fig_dir)


def single_effects(summary: list[dict]) -> list[dict]:
    """Ktore wskazniki zmienia kazde pojedyncze ustawienie wzgledem P0 tego samego obrazu."""
    by_key = {(e["variant"], e["profile"]): e for e in summary}
    effects = []
    for profile in SINGLE:
        for variant in VARIANTS:
            base, entry = by_key.get((variant, "P0")), by_key.get((variant, profile))
            if not base or not entry or "attacker_count" not in entry:
                continue
            keys = [k for k, _ in INDICATORS]
            effects.append({
                "profile": profile,
                "variant": variant,
                "flags": " ".join(PROFILES[profile]),
                "functional": entry["functional"],
                "p0_count": base["attacker_count"],
                "count": entry["attacker_count"],
                "removed": [k for k in keys if base[k] and not entry[k]],
                "added": [k for k in keys if entry[k] and not base[k]],
            })
    return effects


def plot_matrix(summary: list[dict], fig_dir: Path) -> None:
    import Analyze  # ten sam styl i zapis PGF/PNG co wykresy kampanii
    import numpy as np
    import matplotlib.pyplot as plt

    labels = {
        "P0": "P0\ndomyślny",
        "P1": "P1\nużytkownik",
        "P2": "P2\nbez upr.",
        "P3": "P3\nogranicz.",
        "PX": "PX\nuprzywil.",
    }
    profiles = list(CUMULATIVE)
    values = np.zeros((len(VARIANTS), len(profiles)))
    text = [["" for _ in profiles] for _ in VARIANTS]
    for e in summary:
        i, j = VARIANTS.index(e["variant"]), profiles.index(e["profile"])
        values[i, j] = e.get("attacker_count", np.nan)
        text[i][j] = str(e.get("attacker_count", "–"))
        if not e["functional"]:
            text[i][j] += "\n(nie działa)"

    fig, ax = plt.subplots(figsize=(Analyze.FIG_W, 3.0))
    im = ax.imshow(values, cmap="Reds", vmin=0, vmax=len(INDICATORS), aspect="auto")
    ax.set_xticks(range(len(profiles)), [labels[p] for p in profiles], fontsize=8)
    ax.set_yticks(range(len(VARIANTS)), list(VARIANTS))
    for i in range(len(VARIANTS)):
        for j in range(len(profiles)):
            colour = "white" if values[i, j] > len(INDICATORS) * 0.6 else "black"
            ax.text(j, i, text[i][j], ha="center", va="center", color=colour, fontsize=9)
    cbar = fig.colorbar(im, ax=ax)
    cbar.set_label(f"liczba możliwości napastnika (z {len(INDICATORS)})")
    ax.set_xlabel("profil uruchomienia")
    ax.set_ylabel("klasa obrazu")
    Analyze.savefig(fig, fig_dir, "6_7_runtime_matrix")


def main() -> None:
    parser = argparse.ArgumentParser(description="Badanie uzupelniajace: konfiguracja uruchomieniowa")
    parser.add_argument("command", choices=("build", "run", "scan", "summary"))
    parser.add_argument("--scans", type=Path, default=Path("results/scans.jsonl"))
    parser.add_argument("--out", type=Path, default=Path("results/runtime_probe.jsonl"))
    parser.add_argument("--scan-out", type=Path, default=Path("results/runtime_scan.jsonl"))
    parser.add_argument("--summary-out", type=Path, default=Path("results/runtime_summary.json"))
    parser.add_argument("--fig-dir", type=Path, default=Path("figures"))
    parser.add_argument("--frozen-dir", type=Path, default=Path("trivy_cache/frozen"))
    parser.add_argument("--cache-dir", type=Path, default=Path("trivy_cache/runtime"))
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--wait", type=int, default=20, help="limit czasu na start aplikacji [s]")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )
    if args.command == "build":
        cmd_build(args.scans)
    elif args.command == "run":
        cmd_run(args.out, args.repeats, args.wait)
    elif args.command == "scan":
        cmd_scan(args.scans, args.scan_out, args.frozen_dir, args.cache_dir)
    else:
        cmd_summary(args.out, args.summary_out, args.fig_dir)


if __name__ == "__main__":
    main()

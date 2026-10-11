"""Punkty APD 5-7: analiza scans.jsonl i wykresy matplotlib.

Wejscie: results/scans.jsonl (po Scan.py merge).
Wyjscie: figures/*.png oraz results/analysis_summary.json.

Bez notebooka. Testy: Wilcoxon / Friedman / Spearman (scipy.stats).
Glowne porownania metod na parach vs standard; Wilcoxon glownie na
medianach delt per repozytorium (1 repo = 1 obserwacja).
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np
import pandas as pd
from scipy import stats

log = logging.getLogger("analyze")

VARIANTS = ("standard", "slim", "alpine", "distroless")
HARDENED = ("slim", "alpine", "distroless")
COLORS = {
    "standard": "#4C72B0",
    "slim": "#55A868",
    "alpine": "#C44E52",
    "distroless": "#8172B3",
}

SEVERITY_COLS = ("cve_critical", "cve_high", "cve_medium", "cve_low")


def load_scans(path: Path) -> pd.DataFrame:
    df = pd.read_json(path, lines=True)
    if "scan_ok" in df.columns:
        df = df[df["scan_ok"] == True].copy()  # noqa: E712
    df["tag_last_pushed"] = pd.to_datetime(df.get("tag_last_pushed"), errors="coerce", utc=True)
    df["arch_size_mb"] = df["arch_size"] / (1024 * 1024)
    df["cve_density"] = df["cve_total"] / df["pkg_count"].replace(0, np.nan)
    return df


def savefig(fig: plt.Figure, out_dir: Path, name: str) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{name}.png"
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    log.info("zapisano %s", path)
    return path


def bootstrap_ci(values: np.ndarray, n_boot: int = 2000, alpha: float = 0.05, seed: int = 2026):
    values = np.asarray(values, dtype=float)
    values = values[~np.isnan(values)]
    if len(values) == 0:
        return float("nan"), float("nan"), float("nan")
    rng = np.random.default_rng(seed)
    medians = np.empty(n_boot)
    for i in range(n_boot):
        sample = rng.choice(values, size=len(values), replace=True)
        medians[i] = np.median(sample)
    lo = float(np.quantile(medians, alpha / 2))
    hi = float(np.quantile(medians, 1 - alpha / 2))
    return float(np.median(values)), lo, hi


def build_pairs(df: pd.DataFrame) -> pd.DataFrame:
    """Pary utwardzony vs standard w tej samej group_id (obie strony scan_ok).

    Laczymy wylacznie po group_id: alpine ma inna os_line niz standard w grupie,
    a distroless ma inny repo_key — dodatkowe klucze rozbijalyby pary.
    """
    std = df[df["variant"] == "standard"][
        ["group_id", "repo_key", "family", "os_line", "cve_total", "pkg_count", "arch_size_mb",
         "has_shell", "has_apt", "has_apk", "has_busybox", "logical_ref"]
    ].rename(
        columns={
            "repo_key": "repo_key_standard",
            "family": "family_standard",
            "os_line": "os_line_standard",
            "cve_total": "cve_standard",
            "pkg_count": "pkg_standard",
            "arch_size_mb": "size_standard",
            "has_shell": "shell_standard",
            "has_apt": "apt_standard",
            "has_apk": "apk_standard",
            "has_busybox": "busybox_standard",
            "logical_ref": "ref_standard",
        }
    )
    rows = []
    for variant in HARDENED:
        hard = df[df["variant"] == variant][
            ["group_id", "repo_key", "family", "os_line", "cve_total", "pkg_count", "arch_size_mb",
             "has_shell", "has_apt", "has_apk", "has_busybox", "logical_ref"]
        ].rename(
            columns={
                "cve_total": "cve_hard",
                "pkg_count": "pkg_hard",
                "arch_size_mb": "size_hard",
                "has_shell": "shell_hard",
                "has_apt": "apt_hard",
                "has_apk": "apk_hard",
                "has_busybox": "busybox_hard",
                "logical_ref": "ref_hard",
            }
        )
        merged = hard.merge(std, on="group_id", how="inner")
        # czynnik grupujacy w Wilcoxonie: repo partnera z Huba (nie distroless/*)
        merged["repo_key"] = merged["repo_key_standard"]
        merged["family"] = merged["family_standard"]
        merged["variant"] = variant
        merged["delta_cve"] = merged["cve_hard"] - merged["cve_standard"]
        merged["delta_pkg"] = merged["pkg_hard"] - merged["pkg_standard"]
        merged["delta_size"] = merged["size_hard"] - merged["size_standard"]
        # wzgledna: unikamy dzielenia przez 0
        merged["delta_cve_pct"] = np.where(
            merged["cve_standard"] > 0,
            merged["delta_cve"] / merged["cve_standard"],
            np.nan,
        )
        merged["delta_pkg_pct"] = np.where(
            merged["pkg_standard"] > 0,
            merged["delta_pkg"] / merged["pkg_standard"],
            np.nan,
        )
        merged["delta_size_pct"] = np.where(
            merged["size_standard"] > 0,
            merged["delta_size"] / merged["size_standard"],
            np.nan,
        )
        rows.append(merged)
    if not rows:
        return pd.DataFrame()
    return pd.concat(rows, ignore_index=True)


def repo_medians(pairs: pd.DataFrame) -> pd.DataFrame:
    """Jedna obserwacja na (repo_key, variant): mediana delt."""
    return (
        pairs.groupby(["repo_key", "variant"], as_index=False)
        .agg(
            n_pairs=("group_id", "count"),
            delta_cve=("delta_cve", "median"),
            delta_cve_pct=("delta_cve_pct", "median"),
            delta_pkg=("delta_pkg", "median"),
            delta_pkg_pct=("delta_pkg_pct", "median"),
            delta_size=("delta_size", "median"),
            delta_size_pct=("delta_size_pct", "median"),
            family=("family", "first"),
        )
    )


# --- Punkt 5 ---


def fig_cve_by_variant(df: pd.DataFrame, out_dir: Path) -> None:
    data = [df.loc[df["variant"] == v, "cve_total"].dropna().to_numpy() for v in VARIANTS]
    fig, ax = plt.subplots(figsize=(8, 5))
    bp = ax.boxplot(data, tick_labels=VARIANTS, patch_artist=True, showfliers=False)
    for patch, v in zip(bp["boxes"], VARIANTS):
        patch.set_facecolor(COLORS[v])
        patch.set_alpha(0.7)
    ax.set_yscale("log")
    ax.set_ylabel("CVE (skala log)")
    ax.set_title("Rozklad liczby CVE per klasa utwardzenia")
    ax.grid(axis="y", alpha=0.3)
    savefig(fig, out_dir, "5_1_cve_by_variant")


def fig_size_pkg_by_variant(df: pd.DataFrame, out_dir: Path) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(11, 5))
    for ax, col, title, ylabel in (
        (axes[0], "arch_size_mb", "Rozmiar obrazu", "MB"),
        (axes[1], "pkg_count", "Liczba pakietow", "pakiety"),
    ):
        data = [df.loc[df["variant"] == v, col].dropna().to_numpy() for v in VARIANTS]
        bp = ax.boxplot(data, tick_labels=VARIANTS, patch_artist=True, showfliers=False)
        for patch, v in zip(bp["boxes"], VARIANTS):
            patch.set_facecolor(COLORS[v])
            patch.set_alpha(0.7)
        ax.set_title(title)
        ax.set_ylabel(ylabel)
        ax.grid(axis="y", alpha=0.3)
    fig.suptitle("Powierzchnia ataku per klasa")
    savefig(fig, out_dir, "5_2_size_pkg_by_variant")


def fig_severity_share(df: pd.DataFrame, out_dir: Path) -> None:
    shares = []
    for v in VARIANTS:
        sub = df[df["variant"] == v]
        totals = sub[list(SEVERITY_COLS)].sum()
        s = totals.sum()
        if s == 0:
            shares.append([0, 0, 0, 0])
        else:
            shares.append((totals / s).tolist())
    shares = np.array(shares)
    fig, ax = plt.subplots(figsize=(8, 5))
    bottom = np.zeros(len(VARIANTS))
    labels = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    palette = ("#8B0000", "#D62728", "#FF7F0E", "#FFD700")
    x = np.arange(len(VARIANTS))
    for i, (lab, color) in enumerate(zip(labels, palette)):
        ax.bar(x, shares[:, i], bottom=bottom, label=lab, color=color)
        bottom += shares[:, i]
    ax.set_xticks(x)
    ax.set_xticklabels(VARIANTS)
    ax.set_ylabel("Udzial CVE")
    ax.set_ylim(0, 1)
    ax.set_title("Rozklad severity per klasa")
    ax.legend(loc="upper right")
    savefig(fig, out_dir, "5_3_severity_share")


def fig_scatter_cve(df: pd.DataFrame, out_dir: Path, xcol: str, xlabel: str, name: str) -> None:
    fig, ax = plt.subplots(figsize=(8, 6))
    for v in VARIANTS:
        sub = df[df["variant"] == v]
        ax.scatter(sub[xcol], sub["cve_total"], s=8, alpha=0.35, c=COLORS[v], label=v)
    ax.set_xlabel(xlabel)
    ax.set_ylabel("CVE")
    ax.set_title(f"CVE vs {xlabel}")
    ax.legend(markerscale=2)
    ax.grid(alpha=0.3)
    savefig(fig, out_dir, name)


def fig_cve_by_os_line(df: pd.DataFrame, out_dir: Path) -> None:
    debian = df[df["os_line"].astype(str).str.startswith("debian", na=False)].copy()
    if debian.empty:
        log.warning("brak wierszy debian* — pomijam 5_6")
        return
    order = sorted(debian["os_line"].dropna().unique(), key=lambda s: (len(s), s))
    data = [debian.loc[debian["os_line"] == o, "cve_total"].to_numpy() for o in order]
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.boxplot(data, tick_labels=order, showfliers=False)
    ax.set_yscale("log")
    ax.set_ylabel("CVE (skala log)")
    ax.set_title("CVE vs linia Debiana (caly skan)")
    ax.tick_params(axis="x", rotation=30)
    ax.grid(axis="y", alpha=0.3)
    savefig(fig, out_dir, "5_6_cve_by_debian_line")


def fig_cve_vs_age(df: pd.DataFrame, out_dir: Path) -> None:
    # distroless: tag_last_pushed moze byc puste — tylko Hub
    hub = df[df["source_registry"] == "hub"].dropna(subset=["tag_last_pushed"]).copy()
    if hub.empty:
        log.warning("brak tag_last_pushed — pomijam 5_7")
        return
    # wiek w dniach wzgledem najnowszego tagu w probie
    ref = hub["tag_last_pushed"].max()
    hub["age_days"] = (ref - hub["tag_last_pushed"]).dt.total_seconds() / 86400
    fig, ax = plt.subplots(figsize=(8, 6))
    for v in VARIANTS:
        sub = hub[hub["variant"] == v]
        if sub.empty:
            continue
        ax.scatter(sub["age_days"], sub["cve_total"], s=8, alpha=0.35, c=COLORS[v], label=v)
    ax.set_xlabel("Wiek tagu (dni wstecz od najnowszego w probie)")
    ax.set_ylabel("CVE")
    ax.set_title("CVE vs swiezosc tagu (Docker Hub)")
    ax.legend(markerscale=2)
    ax.grid(alpha=0.3)
    savefig(fig, out_dir, "5_7_cve_vs_age")


def spearman_block(df: pd.DataFrame) -> dict:
    out = {}
    for xcol, key in (("arch_size_mb", "size"), ("pkg_count", "pkg")):
        sub = df[["cve_total", xcol]].dropna()
        if len(sub) < 3:
            continue
        r, p = stats.spearmanr(sub["cve_total"], sub[xcol])
        out[key] = {"rho": float(r), "p": float(p), "n": int(len(sub))}
    return out


# --- Punkt 6 ---


def wilcoxon_report(pairs: pd.DataFrame, repo_df: pd.DataFrame) -> dict:
    report = {}
    for variant in HARDENED:
        block = {"pairs": {}, "repos": {}}
        psub = pairs[pairs["variant"] == variant]["delta_cve"].dropna()
        rsub = repo_df[repo_df["variant"] == variant]["delta_cve"].dropna()
        for label, series in (("pairs", psub), ("repos", rsub)):
            if len(series) < 3:
                block[label] = {"n": int(len(series)), "note": "za malo obserwacji"}
                continue
            # H1: delta < 0 (utwardzony ma mniej CVE)
            nonzero = series[series != 0]
            if len(nonzero) < 3:
                block[label] = {"n": int(len(series)), "note": "za malo niezerowych delt"}
                continue
            stat, p = stats.wilcoxon(nonzero, alternative="less")
            med, lo, hi = bootstrap_ci(series.to_numpy())
            med_pct, lo_pct, hi_pct = bootstrap_ci(
                pairs.loc[pairs["variant"] == variant, "delta_cve_pct"].dropna().to_numpy()
                if label == "pairs"
                else repo_df.loc[repo_df["variant"] == variant, "delta_cve_pct"].dropna().to_numpy()
            )
            block[label] = {
                "n": int(len(series)),
                "wilcoxon_stat": float(stat),
                "p_less": float(p),
                "median_delta_cve": med,
                "ci95": [lo, hi],
                "median_delta_cve_pct": med_pct,
                "ci95_pct": [lo_pct, hi_pct],
            }
        report[variant] = block
    return report


def friedman_report(df: pd.DataFrame) -> dict:
    """Grupy z standard+slim+alpine (oba skany OK)."""
    wide = (
        df[df["variant"].isin(("standard", "slim", "alpine"))]
        .pivot_table(index="group_id", columns="variant", values="cve_total", aggfunc="first")
        .dropna(subset=["standard", "slim", "alpine"])
    )
    if len(wide) < 3:
        return {"n_groups": int(len(wide)), "note": "za malo grup"}
    stat, p = stats.friedmanchisquare(wide["standard"], wide["slim"], wide["alpine"])
    return {
        "n_groups": int(len(wide)),
        "statistic": float(stat),
        "p": float(p),
        "median_cve": {
            "standard": float(wide["standard"].median()),
            "slim": float(wide["slim"].median()),
            "alpine": float(wide["alpine"].median()),
        },
    }


def fig_delta_cve_pct(pairs: pd.DataFrame, out_dir: Path) -> None:
    fig, ax = plt.subplots(figsize=(8, 5))
    data, labels = [], []
    for v in HARDENED:
        vals = pairs.loc[pairs["variant"] == v, "delta_cve_pct"].dropna() * 100
        if vals.empty:
            continue
        data.append(vals.to_numpy())
        labels.append(v)
    bp = ax.boxplot(data, tick_labels=labels, patch_artist=True, showfliers=False)
    for patch, v in zip(bp["boxes"], labels):
        patch.set_facecolor(COLORS[v])
        patch.set_alpha(0.7)
    ax.axhline(0, color="black", lw=0.8)
    ax.set_ylabel("Delta CVE wzgledem standard [%]")
    ax.set_title("Redukcja CVE: (utwardzony - standard) / standard")
    ax.grid(axis="y", alpha=0.3)
    savefig(fig, out_dir, "6_1_delta_cve_pct")


def fig_forest_effect(repo_df: pd.DataFrame, out_dir: Path) -> None:
    fig, ax = plt.subplots(figsize=(8, 4))
    ys, labels = [], []
    for i, v in enumerate(HARDENED):
        vals = repo_df.loc[repo_df["variant"] == v, "delta_cve_pct"].dropna() * 100
        if vals.empty:
            continue
        med, lo, hi = bootstrap_ci(vals.to_numpy())
        ax.errorbar(med, i, xerr=[[med - lo], [hi - med]], fmt="o", color=COLORS[v], capsize=4)
        ys.append(i)
        labels.append(f"{v} (n_repo={len(vals)})")
    ax.axvline(0, color="black", lw=0.8)
    ax.set_yticks(ys)
    ax.set_yticklabels(labels)
    ax.set_xlabel("Mediana delta CVE% (per repo) z CI 95%")
    ax.set_title("Wielkosc efektu utwardzania (poziom repozytorium)")
    ax.grid(axis="x", alpha=0.3)
    savefig(fig, out_dir, "6_2_forest_repo_effect")


def fig_delta_by_repo(pairs: pd.DataFrame, out_dir: Path, top_n: int = 15) -> None:
    """Top repo po liczbie par slim — ilustracja heterogenicznosci."""
    slim = pairs[pairs["variant"] == "slim"]
    if slim.empty:
        return
    counts = slim.groupby("repo_key").size().sort_values(ascending=False).head(top_n)
    med = slim.groupby("repo_key")["delta_cve_pct"].median() * 100
    order = counts.index
    fig, ax = plt.subplots(figsize=(9, 6))
    ax.barh([r.replace("library/", "") for r in order], med.loc[order], color=COLORS["slim"])
    ax.axvline(0, color="black", lw=0.8)
    ax.set_xlabel("Mediana delta CVE% (slim - standard)")
    ax.set_title(f"Heterogenicznosc: top {top_n} repo po liczbie par slim")
    ax.invert_yaxis()
    ax.grid(axis="x", alpha=0.3)
    savefig(fig, out_dir, "6_3_delta_cve_pct_by_repo_slim")


def fig_friedman_box(df: pd.DataFrame, out_dir: Path) -> None:
    wide = (
        df[df["variant"].isin(("standard", "slim", "alpine"))]
        .pivot_table(index="group_id", columns="variant", values="cve_total", aggfunc="first")
        .dropna(subset=["standard", "slim", "alpine"])
    )
    if wide.empty:
        return
    fig, ax = plt.subplots(figsize=(7, 5))
    data = [wide[v].to_numpy() for v in ("standard", "slim", "alpine")]
    bp = ax.boxplot(data, tick_labels=("standard", "slim", "alpine"), patch_artist=True, showfliers=False)
    for patch, v in zip(bp["boxes"], ("standard", "slim", "alpine")):
        patch.set_facecolor(COLORS[v])
        patch.set_alpha(0.7)
    ax.set_yscale("log")
    ax.set_ylabel("CVE (skala log)")
    ax.set_title(f"Friedman: grupy z kompletem slim+alpine (n={len(wide)})")
    ax.grid(axis="y", alpha=0.3)
    savefig(fig, out_dir, "6_5_friedman_triplet")


def fig_distroless_case(pairs: pd.DataFrame, out_dir: Path) -> None:
    d = pairs[pairs["variant"] == "distroless"].copy()
    if d.empty:
        log.warning("brak par distroless — pomijam 6_6")
        return
    # linia OS z wariantu utwardzonego (debianN)
    g = d.groupby(["family", "os_line"], as_index=False)["delta_cve"].median()
    labels = [f"{r.family}\n{r.os_line}" for r in g.itertuples()]
    fig, ax = plt.subplots(figsize=(max(8, len(g) * 0.7), 5))
    ax.bar(range(len(g)), g["delta_cve"], color=COLORS["distroless"])
    ax.set_xticks(range(len(g)))
    ax.set_xticklabels(labels, rotation=45, ha="right")
    ax.axhline(0, color="black", lw=0.8)
    ax.set_ylabel("Mediana delta CVE (distroless - standard)")
    ax.set_title(f"Studium distroless (n_par={len(d)})")
    ax.grid(axis="y", alpha=0.3)
    savefig(fig, out_dir, "6_6_distroless_delta_by_family")


# --- Punkt 7 ---


def fig_tradeoff_scatter(pairs: pd.DataFrame, out_dir: Path) -> None:
    fig, ax = plt.subplots(figsize=(8, 6))
    xs, ys = [], []
    for v in HARDENED:
        sub = pairs[pairs["variant"] == v]
        # redukcja CVE = -delta%; utrata pakietow = -delta_pkg%
        x = (-sub["delta_cve_pct"] * 100).to_numpy()
        y = (-sub["delta_pkg_pct"] * 100).to_numpy()
        xs.append(x)
        ys.append(y)
        ax.scatter(x, y, s=12, alpha=0.4, c=COLORS[v], label=v)
    # osie na P1–P99 — pojedyncze pary z wzrostem CVE nie zjadaja skali
    all_x = np.concatenate([a[~np.isnan(a)] for a in xs]) if xs else np.array([])
    all_y = np.concatenate([a[~np.isnan(a)] for a in ys]) if ys else np.array([])
    if len(all_x) and len(all_y):
        ax.set_xlim(np.nanpercentile(all_x, 1), np.nanpercentile(all_x, 99))
        ax.set_ylim(np.nanpercentile(all_y, 1), np.nanpercentile(all_y, 99))
    ax.axvline(0, color="gray", lw=0.6)
    ax.axhline(0, color="gray", lw=0.6)
    ax.set_xlabel("Redukcja CVE wzgledem standard [%]")
    ax.set_ylabel("Spadek liczby pakietow wzgledem standard [%]")
    ax.set_title("Bezpieczenstwo vs funkcjonalnosc (pary; osie P1–P99)")
    ax.legend()
    ax.grid(alpha=0.3)
    savefig(fig, out_dir, "7_1_tradeoff_scatter")


def fig_tradeoff_medians(repo_df: pd.DataFrame, out_dir: Path) -> None:
    fig, ax = plt.subplots(figsize=(7, 6))
    for v in HARDENED:
        sub = repo_df[repo_df["variant"] == v]
        if sub.empty:
            continue
        x_vals = (-sub["delta_cve_pct"] * 100).dropna().to_numpy()
        y_vals = (-sub["delta_pkg_pct"] * 100).dropna().to_numpy()
        if len(x_vals) == 0 or len(y_vals) == 0:
            continue
        mx, xlo, xhi = bootstrap_ci(x_vals)
        my, ylo, yhi = bootstrap_ci(y_vals)
        ax.errorbar(
            mx, my,
            xerr=[[mx - xlo], [xhi - mx]],
            yerr=[[my - ylo], [yhi - my]],
            fmt="o", color=COLORS[v], capsize=4, label=v, markersize=8,
        )
    ax.axvline(0, color="gray", lw=0.6)
    ax.axhline(0, color="gray", lw=0.6)
    ax.set_xlabel("Redukcja CVE [%] (mediana per repo)")
    ax.set_ylabel("Spadek pakietow [%] (mediana per repo)")
    ax.set_title("Trade-off metod utwardzania (CI 95%)")
    ax.legend()
    ax.grid(alpha=0.3)
    savefig(fig, out_dir, "7_2_tradeoff_medians")


def fig_runtime_features(df: pd.DataFrame, out_dir: Path) -> None:
    flags = ("has_shell", "has_apt", "has_apk", "has_busybox")
    labels = ("powloka", "apt", "apk", "busybox")
    x = np.arange(len(VARIANTS))
    width = 0.2
    fig, ax = plt.subplots(figsize=(9, 5))
    for i, (flag, lab) in enumerate(zip(flags, labels)):
        rates = [df.loc[df["variant"] == v, flag].mean() * 100 for v in VARIANTS]
        ax.bar(x + i * width, rates, width, label=lab)
    ax.set_xticks(x + 1.5 * width)
    ax.set_xticklabels(VARIANTS)
    ax.set_ylabel("% obrazow")
    ax.set_ylim(0, 105)
    ax.set_title("Cechy runtime per klasa")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    savefig(fig, out_dir, "7_3_runtime_features")


def descriptive_tables(df: pd.DataFrame) -> dict:
    rows = {}
    for v in VARIANTS:
        sub = df[df["variant"] == v]
        rows[v] = {
            "n": int(len(sub)),
            "cve_median": float(sub["cve_total"].median()),
            "cve_q1": float(sub["cve_total"].quantile(0.25)),
            "cve_q3": float(sub["cve_total"].quantile(0.75)),
            "pkg_median": float(sub["pkg_count"].median()),
            "size_mb_median": float(sub["arch_size_mb"].median()),
            "has_shell_pct": float(sub["has_shell"].mean() * 100),
            "has_apt_pct": float(sub["has_apt"].mean() * 100),
            "has_apk_pct": float(sub["has_apk"].mean() * 100),
        }
    return rows


def run(scans_path: Path, out_dir: Path, summary_path: Path) -> None:
    df = load_scans(scans_path)
    log.info("wczytano %d skanow z %s", len(df), scans_path)

    pairs = build_pairs(df)
    repo_df = repo_medians(pairs) if not pairs.empty else pd.DataFrame()
    log.info(
        "pary: slim=%d alpine=%d distroless=%d; repo-obs: %d",
        int((pairs["variant"] == "slim").sum()) if not pairs.empty else 0,
        int((pairs["variant"] == "alpine").sum()) if not pairs.empty else 0,
        int((pairs["variant"] == "distroless").sum()) if not pairs.empty else 0,
        len(repo_df),
    )

    # Punkt 5
    fig_cve_by_variant(df, out_dir)
    fig_size_pkg_by_variant(df, out_dir)
    fig_severity_share(df, out_dir)
    fig_scatter_cve(df, out_dir, "arch_size_mb", "Rozmiar [MB]", "5_4_cve_vs_size")
    fig_scatter_cve(df, out_dir, "pkg_count", "Liczba pakietow", "5_5_cve_vs_pkg")
    fig_cve_by_os_line(df, out_dir)
    fig_cve_vs_age(df, out_dir)

    # Punkt 6
    if not pairs.empty:
        fig_delta_cve_pct(pairs, out_dir)
        fig_forest_effect(repo_df, out_dir)
        fig_delta_by_repo(pairs, out_dir)
        fig_friedman_box(df, out_dir)
        fig_distroless_case(pairs, out_dir)
        fig_tradeoff_scatter(pairs, out_dir)
        fig_tradeoff_medians(repo_df, out_dir)

    # Punkt 7
    fig_runtime_features(df, out_dir)

    summary = {
        "n_scans": int(len(df)),
        "n_by_variant": {v: int((df["variant"] == v).sum()) for v in VARIANTS},
        "descriptive": descriptive_tables(df),
        "spearman": spearman_block(df),
        "pairs_n": {
            v: int((pairs["variant"] == v).sum()) if not pairs.empty else 0 for v in HARDENED
        },
        "repos_n": {
            v: int((repo_df["variant"] == v).sum()) if not repo_df.empty else 0 for v in HARDENED
        },
        "wilcoxon": wilcoxon_report(pairs, repo_df) if not pairs.empty else {},
        "friedman_slim_alpine": friedman_report(df),
        "figures_dir": str(out_dir),
    }
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    log.info("podsumowanie -> %s", summary_path)

    # krotki log wynikow testow
    for v, block in summary.get("wilcoxon", {}).items():
        repo = block.get("repos", {})
        if "p_less" in repo:
            log.info(
                "Wilcoxon %s (repo): n=%s p=%.3g mediana_delta_cve=%.1f (%.1f%%)",
                v,
                repo["n"],
                repo["p_less"],
                repo["median_delta_cve"],
                (repo["median_delta_cve_pct"] or 0) * 100,
            )
    fr = summary["friedman_slim_alpine"]
    if "p" in fr:
        log.info("Friedman slim+alpine: n=%s p=%.3g", fr["n_groups"], fr["p"])


def main() -> None:
    parser = argparse.ArgumentParser(description="APD 5-7: analiza i wykresy matplotlib")
    parser.add_argument("--in", dest="in_path", type=Path, default=Path("results/scans.jsonl"))
    parser.add_argument("--out-dir", type=Path, default=Path("figures"))
    parser.add_argument("--summary", type=Path, default=Path("results/analysis_summary.json"))
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )
    run(args.in_path, args.out_dir, args.summary)


if __name__ == "__main__":
    main()

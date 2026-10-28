"""Schemat lejka budowy matrycy testowej (rozdz. 3, rys. fig:lejek).

Wyjscie: figures/3_1_lejek.png. Schemat jakosciowy, bez liczebnosci
(liczby etapow sa w rozdz. 4 i w docs/WYNIKI.md, sekcja 3).
"""

from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import Polygon  # noqa: E402

STAGES = (
    ("Katalog repozytoriów",
     "library/ (Docker Hub) oraz gcr.io/distroless"),
    ("Tagi",
     "lista tagów z digestem manifestu amd64"),
    ("Klasyfikacja",
     "klasa i linia systemu z nazwy tagu;\n"
     "wykluczone: Windows, onbuild, brak amd64"),
    ("Filtr próby",
     "wykluczone wydania przedpremierowe\n"
     "(rc, alpha, beta, ea, …)"),
    ("Deduplikacja po digeście",
     "jeden obraz amd64, pozostałe tagi jako aliasy"),
    ("Reguła wersji minor",
     "najnowszy tag dla wersji X.Y, odmiany,\n"
     "klasy i linii systemu"),
    ("Weryfikacja dostępności",
     "tylko obrazy dostępne na serwerze\n"
     "lustrzanym mirror.gcr.io (distroless: gcr.io)"),
    ("Dobór grup",
     "warstwa par w całości; warstwa opisowa\n"
     "losowo według kwot, ziarno 2026"),
    ("Deduplikacja po warstwach",
     "identyczna lista warstw = jeden obraz"),
    ("Skan",
     "Trivy 0.75.0, zamrożona baza podatności"),
)

FILL_TOP = (0.30, 0.45, 0.69)
FILL_BOTTOM = (0.75, 0.82, 0.92)


def draw(out: Path) -> Path:
    n = len(STAGES)
    row_h, gap = 1.0, 0.12
    w_top, w_bottom = 6.0, 3.8
    cx = w_top / 2

    fig, ax = plt.subplots(figsize=(9.0, 0.62 * n + 0.4))
    for i, (name, desc) in enumerate(STAGES):
        y_top = -i * (row_h + gap)
        y_bot = y_top - row_h
        wt = w_top - (w_top - w_bottom) * i / n
        wb = w_top - (w_top - w_bottom) * (i + 1) / n
        t = i / (n - 1)
        color = tuple(a + (b - a) * t for a, b in zip(FILL_TOP, FILL_BOTTOM))
        ax.add_patch(Polygon(
            [(cx - wt / 2, y_top), (cx + wt / 2, y_top),
             (cx + wb / 2, y_bot), (cx - wb / 2, y_bot)],
            closed=True, facecolor=color, edgecolor="black", lw=0.6,
        ))
        text_color = "white" if t < 0.45 else "black"
        ax.text(cx, (y_top + y_bot) / 2, name, ha="center", va="center",
                fontsize=10, fontweight="bold", color=text_color)
        ax.text(w_top + 0.35, (y_top + y_bot) / 2, desc, ha="left",
                va="center", fontsize=9)

    ax.set_xlim(-0.1, w_top + 6.2)
    ax.set_ylim(-n * (row_h + gap) + gap - 0.05, 0.05)
    ax.axis("off")

    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out, dpi=300, bbox_inches="tight")
    plt.close(fig)
    return out


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, default=Path("figures/3_1_lejek.png"))
    args = p.parse_args()
    print(draw(args.out))


if __name__ == "__main__":
    main()

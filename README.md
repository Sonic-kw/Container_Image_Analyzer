# Container Image Analyzer

Narzędzie badawcze do **pracy inżynierskiej** na Politechnice Wrocławskiej.

| | |
| --- | --- |
| **Autor** | Kamil Wierzbicki |
| **Tytuł** | Analiza porównawcza metod utwardzania środowisk kontenerowych pod kątem bezpieczeństwa i optymalizacji powierzchni ataku |

Cel: porównać klasy baz kontenerowych (**standard / slim / alpine / distroless**) pod kątem CVE, rozmiaru i funkcjonalności runtime — oraz sformułować rekomendacje doboru obrazów bazowych.

Skaner **nie jest produktem**; służy do zebrania matrycy pomiarów pod analizę statystyczną (punkty 5–7 APD).

## Co robi potok

1. **Katalog** — oficjalne obrazy z Docker Hub (`library/`) + distroless z `gcr.io`
2. **Tagi i klasyfikacja** — wersje, klasa utwardzenia, linia OS, ścieżka pobrania przez lustro `mirror.gcr.io`
3. **Matryca** — ~10 tys. obrazów w grupach (ta sama technologia/wersja, różne warianty)
4. **Skan** — Trivy (`--image-src remote`, zamrożona baza CVE), wynik: `results/scans.jsonl`
5. **Analiza** — pary vs `standard`, Wilcoxon / Friedman / Spearman, wykresy w `figures/`

## Struktura repozytorium

```
src/
  GetRepo.py      # Kroki 1–2: katalog Hub + GCR
  GetTags.py      # Krok 3: tagi
  Classify.py     # Krok 4: klasa, pull_ref, sonda lustra
  Matrix.py       # Krok 5: matryca
  Scan.py         # Krok 6: Trivy
  Analyze.py      # punkty APD 5–7: statystyka + wykresy
docs/
  PLAN.md         # metodyka, decyzje, plan analizy pod rozdz. 5–7
  KOD.md          # opis kodu i uruchomienia
figures/          # PNG z Analyze.py
```

`results/`, cache i raporty Trivy **nie są w gicie** (odtwarzalne z kodu).

## Szybki start

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Do Kroków 1–4 potrzebny jest `.env` z tokenem Docker Hub (wzór: `.env.example`).  
Kampania skanowania: obraz Docker `cia-scanner` + `Scan.py` / `run_scan_workers.ps1` — szczegóły w [`docs/KOD.md`](docs/KOD.md).

Analiza na gotowym `results/scans.jsonl`:

```powershell
.\.venv\Scripts\python.exe src\Analyze.py
```

## Dokumentacja

- [`docs/PLAN.md`](docs/PLAN.md) — plan pracy, rejestry, matryca, kampania, **przepis analizy**
- [`docs/KOD.md`](docs/KOD.md) — jak działa kod krok po kroku

## Stos

Python 3, `requests` / `pandas` / `scipy` / `matplotlib`, Aqua Trivy w kontenerze Dockera, źródła: Docker Hub + `mirror.gcr.io` + `gcr.io/distroless`.

## Współautorstwo narzędziowe

Kod potoku (fetcher, matryca, skaner, analiza), dokumentacja w `docs/` oraz ten README powstały przy wsparciu **Cursor** (asystent AI w edytorze). Decyzje metodyczne, przebieg kampanii i treść pracy inżynierskiej należą do autora.

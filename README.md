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

Osobno od potoku: **badanie konfiguracji uruchomieniowej** (17–18.11.2026, po uwagach promotora). Cztery obrazy grupy `python:3.13` (po jednym z każdej klasy, te same digesty co w kampanii) z aplikacją-sondą uruchomiono w 10 profilach `docker run`, po 3 razy. Sonda sprawdza, co może zrobić kod wykonany w procesie aplikacji: uprawnienia, zapis do systemu plików, dostępne narzędzia, limity. Wynik: `results/runtime_*.json*`, opis w [`docs/KOD.md`](docs/KOD.md) §15 i [`docs/WYNIKI.md`](docs/WYNIKI.md) §11.

## Struktura repozytorium

```
src/
  GetRepo.py      # Kroki 1–2: katalog Hub + GCR
  GetTags.py      # Krok 3: tagi
  Classify.py     # Krok 4: klasa, pull_ref, sonda lustra
  Matrix.py       # Krok 5: matryca
  Scan.py         # Krok 6: Trivy
  GcrMeta.py      # rozmiar i data wgrania distroless z gcr.io (po skanie)
  Analyze.py      # punkty APD 5–7: statystyka + wykresy
  Funnel.py       # schemat lejka matrycy (figures/3_1_lejek.png)
  hub_http.py     # wspólny klient HTTP dla kroków 1–4
  Runtime.py      # badanie konfiguracji uruchomieniowej: build, run, scan, summary
  runtime/
    app.py        # aplikacja-sonda (tylko biblioteka standardowa Pythona)
    Dockerfile    # obraz sondy na obrazie bazowym wskazanym digestem
docs/
  PLAN.md         # metodyka, decyzje, plan analizy pod rozdz. 5–7
  KOD.md          # opis kodu i uruchomienia
  WYNIKI.md       # wyniki skryptów, tabele i omówienia punktów APD 5–7
  PISANIE.md      # plan pisania pracy według rozdziałów
  LITERATURA.md   # streszczenia źródeł i mapowanie tez na rozdziały
  POPRAWKI.md     # uwagi promotora (11.2026), plan i dziennik poprawek
figures/          # PNG i PGF z Analyze.py i Runtime.py
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

Badanie konfiguracji uruchomieniowej (wymaga uruchomionego Docker Desktop, obrazu `cia-scanner`, `results/scans.jsonl` i zamrożonej bazy w `trivy_cache/frozen`):

```powershell
.\.venv\Scripts\python.exe src\Runtime.py build
.\.venv\Scripts\python.exe src\Runtime.py run
.\.venv\Scripts\python.exe src\Runtime.py scan
.\.venv\Scripts\python.exe src\Runtime.py summary
```

`run` i `scan` nadpisują poprzednie wyniki (szczegóły w [`docs/KOD.md`](docs/KOD.md) §15).

## Dokumentacja

- [`docs/PLAN.md`](docs/PLAN.md) — plan pracy, rejestry, matryca, kampania, **przepis analizy**
- [`docs/KOD.md`](docs/KOD.md) — jak działa kod krok po kroku
- [`docs/WYNIKI.md`](docs/WYNIKI.md) — wszystkie liczby, tabele i omówienia wyników
- [`docs/PISANIE.md`](docs/PISANIE.md) — plan pisania pracy według rozdziałów
- [`docs/LITERATURA.md`](docs/LITERATURA.md) — streszczenia sześciu źródeł z APD i literatury uzupełniającej
- [`docs/POPRAWKI.md`](docs/POPRAWKI.md) — uwagi promotora, plan poprawek i dziennik zmian w pracy

## Stos

Python 3, `requests` / `pandas` / `scipy` / `matplotlib`, Aqua Trivy w kontenerze Dockera, źródła: Docker Hub + `mirror.gcr.io` + `gcr.io/distroless`.

## Współautorstwo narzędziowe

Kod potoku (fetcher, matryca, skaner, analiza), dokumentacja w `docs/` oraz ten README powstały przy wsparciu **Cursor** (asystent AI w edytorze). Kod badania konfiguracji uruchomieniowej (`Runtime.py`, `src/runtime/`) i część dokumentacji z listopada 2026 powstały przy wsparciu **Claude Code**. Decyzje metodyczne, przebieg kampanii i treść pracy inżynierskiej należą do autora.

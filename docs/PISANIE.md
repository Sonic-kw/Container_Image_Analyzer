# Plan pisania pracy — co w którym rozdziale

Rozpiska pod obowiązujący spis treści (7 rozdziałów, Wstęp i Podsumowanie liczone jako
rozdziały). Dla każdego podrozdziału: co napisać, na czym się oprzeć, jakie rysunki i tabele
wstawić, czego unikać.

Materiał źródłowy:

| Plik | Do czego |
| --- | --- |
| [`LITERATURA.md`](LITERATURA.md) | streszczenia 6 źródeł z APD, tabele „teza → rozdział”, „czego nie wyciągać” |
| [`WYNIKI.md`](WYNIKI.md) | wszystkie liczby, tabele i wykresy z omówieniem |
| [`PLAN.md`](PLAN.md) | decyzje metodyczne i ich uzasadnienie |
| [`KOD.md`](KOD.md) | opis skryptów, formatów plików i przebiegu potoku |

Oznaczenia źródeł w tekście poniżej: **[Rice]**, **[Vehent]**, **[NIST]**, **[Distroless]**,
**[CVSS]**, **[SLSA]**.

---

## Zasady na całą pracę

- **Taksonomia jest Twoja.** `standard` / `slim` / `alpine` / `distroless` nie pochodzi z żadnego
  źródła. Literatura daje cel (mniejsza powierzchnia ataku), dokumentacja Docker Hub i Distroless
  daje nazwy wariantów, a podział na cztery klasy to decyzja metodyczna pracy.
- **Każde z 6 źródeł APD musi być zacytowane w tekście** i być w `bibliography.bib`.
- **Liczby tylko z kampanii** (Trivy `v0.75.0`, baza z 10.10.2026), nie z pilotażu.
- **„0 CVE” to „brak dopasowania w bazie skanera”**, nie „obraz bez podatności”.
- **Wynik główny = mediany per repozytorium**, wynik na wszystkich parach jest pomocniczy.
- **Nie powtarzaj tabel.** Liczba pojawia się raz z tabelą, potem tylko odwołanie.
- Literówki w spisie treści: „runtime**a**” w 6.1 i „rozwiązani” w 6.3.

### Szacunkowa objętość

| Rozdział | Strony |
| --- | --- |
| 1. Wstęp | 2–3 |
| 2. Podstawy | 8–10 |
| 3. Metodyka | 7–9 |
| 4. Implementacja | 6–8 |
| 5. Wyniki | 12–15 |
| 6. Rekomendacje | 4–6 |
| 7. Podsumowanie | 2–3 |

Rozdział 5 jest najważniejszy (punkty APD 5 i 6) i powinien być najdłuższy.

### Kolejność pisania

1. Rozdział 5 (wyniki są gotowe, liczby w `WYNIKI.md`).
2. Rozdział 3 (metodyka — wyjaśnia to, co pokazuje rozdz. 5).
3. Rozdział 4 (implementacja).
4. Rozdział 2 (teoria — wiesz już, czego potrzebujesz pod wyniki).
5. Rozdział 6 (rekomendacje z rozdz. 5).
6. Rozdział 7 i Wstęp na końcu.

---

## 1. Wstęp

Masz już trzy akapity wprowadzenia (chmura i obraz bazowy, warianty z Docker Hub i distroless
Google, łańcuch dostaw). Wstaw je na początek rozdziału, **przed** 1.1, bez nagłówka
podrozdziału. Spis treści nie ma osobnego „Wprowadzenia”.

### 1.1 Cel i struktura pracy

**Co napisać:**

1. Problem w jednym akapicie: obraz bazowy przenosi do każdego kontenera wszystkie swoje pakiety
   i ich podatności, a wybór wariantu (`slim`, `alpine`, distroless) jest decyzją, którą zespół
   podejmuje zwykle bez danych.
2. Cel pracy: porównanie metod utwardzania obrazów bazowych pod względem liczby znanych podatności
   i kosztu funkcjonalnego, na dużej próbie obrazów oficjalnych.
3. Cele szczegółowe = punkty APD, napisane jako zdania:
   - przegląd metod utwardzania i zagrożeń (rozdz. 2);
   - projekt i implementacja środowiska do automatycznego pozyskiwania i skanowania obrazów
     (rozdz. 3–4);
   - analiza podatności zbioru obrazów (rozdz. 5);
   - porównanie metod względem obrazu standardowego (rozdz. 5);
   - ocena kompromisu bezpieczeństwo–funkcjonalność i rekomendacje (rozdz. 6).
4. Zakres: Docker Official Images (`library/`) i `gcr.io/distroless`, architektura amd64, jedna
   zamrożona baza podatności, ~10 tys. obrazów. Bez konfiguracji uruchomienia, bez runtime'u,
   bez weryfikacji podpisów.
5. Struktura pracy: jeden akapit, po jednym zdaniu na rozdziały 2–7 (masz już wersję z
   wcześniejszej rozmowy, dopasowaną do 7 rozdziałów).

**Czego nie robić:** nie podawaj wyników (−91% itd.) — to Podsumowanie. Nie rozpisuj teorii.

### 1.2 Wykorzystanie AI

Sekcja obowiązkowa w szablonie WIT. Masz gotowy akapit z wcześniejszej rozmowy. Treść: AI
(Cursor) służyło do pomocy w rozumowaniu, planowaniu kroków, przeglądzie kodu i dokumentacji
technicznej repozytorium; tekst pracy został napisany samodzielnie; wszystkie liczby pochodzą z
uruchomionych skryptów i zostały zweryfikowane. Wymień konkretne zastosowania (projekt potoku,
diagnoza porażek kampanii, przegląd literatury), bez ogólników.

---

## 2. Podstawy bezpieczeństwa kontenerów i metody utwardzania

Cel rozdziału: dać czytelnikowi pojęcia potrzebne do zrozumienia rozdz. 3 i 5. Każdy
podrozdział kończy się zdaniem, które łączy teorię z badaniem.

### 2.1 Architektura i izolacja

**Co napisać:**

- Kontener = proces na wspólnym jądrze hosta, odizolowany przez przestrzenie nazw (namespaces),
  cgroups i warstwowy system plików **[Rice]** **[NIST 2.2]**.
- Porównanie z maszyną wirtualną: słabsza granica izolacji, bo wspólne jądro **[Rice]**
  **[NIST]**. Maszyny wirtualne i kontenery często występują razem.
- Obraz = warstwy tylko do odczytu + manifest + konfiguracja; kontener dostaje kopię obrazu;
  aktualizacja = nowy obraz i ponowne wdrożenie, nie łatanie kontenera **[NIST 2.3]**.
- Tag vs digest. Tag to przesuwalna etykieta (`latest` nie gwarantuje świeżości **[NIST 4.2.2]**),
  digest to skrót SHA-256 manifestu, który jednoznacznie wskazuje zawartość **[Rice]**.
- Opcjonalnie jedno zdanie o Scope w CVSS: ucieczka z kontenera = przekroczenie granicy władzy
  bezpieczeństwa **[CVSS 2.2]** (zaznacz, że to Twoja interpretacja).

**Zdanie łączące:** izolacja jest tłem; praca bada zawartość obrazu, nie mechanizmy izolacji.

**Rysunek (opcjonalny, własny):** schemat warstw obrazu (baza → runtime → aplikacja).

### 2.2 Powierzchnia ataku obrazów

**Co napisać:**

- Definicja powierzchni ataku: wszystkie drogi, którymi napastnik może dotrzeć do podatności
  **[NIST 3.5]**. Przeniesienie na obraz: każdy pakiet, biblioteka, powłoka i menedżer pakietów to
  potencjalny element ataku lub narzędzie po przejęciu kontenera **[Rice]**.
- Ryzyka obrazu wg **[NIST 3.1]**: podatności (główna metryka pracy), błędy konfiguracji (root,
  SSH), złośliwe oprogramowanie, sekrety, niezaufane obrazy. Zaznacz, które praca mierzy (tabela w
  `LITERATURA.md`, sekcja NIST).
- Podatność obrazu rośnie w czasie przy niezmienionym obrazie — nowe CVE są publikowane dla
  starych wersji pakietów **[NIST]** **[Rice, rozdz. 7]**. Stąd zamrożona baza w metodyce.
- CVE jako identyfikator, CVSS jako skala krytyczności: trzy grupy metryk, skala jakościowa
  (0,1–3,9 niska … 9,0–10,0 krytyczna) **[CVSS 1.1, 5]**. CVSS opisuje powagę podatności, nie ryzyko
  wdrożenia.
- Łańcuch dostaw: obraz bazowy jest zależnością każdego obrazu zbudowanego przez `FROM`; rejestr
  to jedno ogniwo **[Vehent, rozdz. 2]** **[SLSA, zagrożenie D]**.

**Zdanie łączące:** praca mierzy powierzchnię przez liczbę znanych CVE i liczbę pakietów.

### 2.3 Metody utwardzania

**Co napisać:**

- Ogólna zasada: mniej zbędnego kodu = mniejsza powierzchnia; budowa wieloetapowa; minimalny obraz
  bazowy, `scratch` lub distroless **[Rice, rozdz. 6]**; minimalistyczne bazy typu Alpine
  **[NIST 4.1.2]**.
- Cztery klasy pracy, po akapicie:
  - **`standard`** — pełny obraz dystrybucji, w obrazach języków często na `buildpack-deps` z
    kompilatorami;
  - **`slim`** — okrojony wariant tej samej dystrybucji (Debian), z powłoką i `apt`;
  - **`alpine`** — inna dystrybucja: musl zamiast glibc, BusyBox, `apk`;
  - **`distroless`** — tylko aplikacja i zależności runtime, bez powłoki i menedżera pakietów
    **[Distroless]**; warianty `static`, `base`, `cc`, runtime'y; `nonroot` i `debug`.
- Wyraźnie: podział na cztery klasy jest operacyjną taksonomią pracy; literatura nie definiuje
  poziomów utwardzenia (Rice i Vehent tego nie robią — sprawdzone).
- Koszt każdej metody (krótko, szczegóły w rozdz. 6): brak powłoki, inna libc, wektorowy
  `ENTRYPOINT` w distroless **[Distroless]**.

**Tabela:** porównanie klas — powłoka / menedżer pakietów / libc / dostępność dla technologii.
Dane: `WYNIKI.md` sekcja 7.2 i `LITERATURA.md` sekcja Distroless.

### 2.4 Standardy i ramy

**Co napisać:** po jednym akapicie na ramę, każdy zakończony „w pracy wykorzystano…”.

- **NIST SP 800-190** — pięć warstw, cykl życia obrazu, przeciwdziałania: skan w cyklu życia,
  bramka z progiem CVSS, zaufane rejestry, niezmienne nazwy. W pracy: uzasadnienie zawężenia próby
  do oficjalnych obrazów i pinowania.
- **CVSS v3.1** — skala, wektor, ocena bazowa vs środowiskowa. W pracy: interpretacja etykiet
  krytyczności z Trivy; ograniczenie — kampania nie liczy oceny środowiskowej.
- **SLSA** — poziomy Build L0–L3, pochodzenie, weryfikacja artefaktu po digeście, brak
  przechodniości poziomów. W pracy: uzasadnienie pinu digestem; poziom SLSA obrazów nie był
  oceniany.
- **Docker Content Trust / podpisy** — krótko, jako mechanizm dostępny i nieużyty
  **[Vehent, rozdz. 6]** **[Distroless — cosign]**.

**Czego nie robić:** nie pisz, że pin digestem „spełnia SLSA”.

---

## 3. Koncepcja i metodyka badania

Cel rozdziału: opisać badanie tak, żeby ktoś mógł je powtórzyć. Tu są decyzje i ich
uzasadnienie, w rozdz. 4 — jak je zrealizowano w kodzie.

### 3.1 Cel praktyczny badania i kryteria oceny

**Co napisać:**

- Pytania badawcze (proponowane):
  1. Jak rozkłada się liczba znanych podatności w oficjalnych obrazach bazowych w zależności od
     klasy, rozmiaru, liczby pakietów i świeżości bazy?
  2. O ile każda metoda utwardzania zmniejsza liczbę CVE względem obrazu standardowego tej samej
     technologii i wersji?
  3. Jaki jest koszt funkcjonalny każdej metody?
- Kryteria: liczba CVE (`cve_total`) i udział krytyczności; liczba pakietów i rozmiar jako miary
  powierzchni; powłoka, `apt`, `apk`, BusyBox jako miary funkcjonalności.
- Jednostka porównania: para obraz utwardzony – `standard` w tej samej grupie; delta bezwzględna
  i procentowa. Formuły z `PLAN.md` („Formuły delt”).
- `standard` jako punkt odniesienia (`PLAN.md`, „Punkt 7: standard jako baseline”).

### 3.2 Taksonomia klas i dobór próby

**Co napisać:**

- Reguły przypisania klasy z tagu (`PLAN.md`, „Reguły klasyfikacji tagów”): tokeny `slim`,
  `alpine`, rejestr distroless; wykluczenia (`windows`, `onbuild`, brak amd64, wydania
  przedpremierowe, `ea`).
- Populacja: 181 repozytoriów `library/` (wyliczone w całości, nie próbkowane) + 56 repozytoriów
  distroless. Repozytoria z wyszukiwania tylko jako spis populacji — uzasadnienie w `PLAN.md`
  (decyzja 2 z 01.10).
- Distroless: tylko `latest`; `nonroot` ma identyczne warstwy (flaga), `debug` ma powłokę
  (wykluczony). `PLAN.md`, „Konsekwencja 1 i 2”.
- Niezależność obserwacji: dedup po digeście amd64, reguła minor (jeden tag na wersję `X.Y`),
  dedup po liście warstw.
- Grupa = technologia + wersja + wariant + linia OS; losowanie całymi grupami, ziarno 2026;
  limit 150 obrazów w warstwie opisowej; dwie warstwy `pairs` i `descriptive`.
- Parowanie distroless po technologii, wersji runtime'u i linii Debiana — uzasadnij pilotażem
  (`WYNIKI.md`, sekcja 1a: `python3-debian12` miał więcej CVE niż `slim`).

**Tabela:** przykład grupy (`python:3.13-trixie` / `-slim-trixie` / `-alpine3.22` /
`distroless/python3-debian13`) — `PLAN.md`, „Jednostka matrycy”.

### 3.3 Źródła danych i ścieżki pobierania

**Co napisać:**

- Trzy hosty i trzy role: Docker Hub API (katalog, tagi), `mirror.gcr.io` (pobieranie obrazów
  Huba), `gcr.io/distroless` (katalog i pobieranie distroless). `PLAN.md`, „Rejestry i ścieżki
  pobierania”.
- Rozdzielenie odkrywania i pobierania: `logical_ref` (co opisujemy) vs `pull_ref` (skąd Trivy
  pobiera, pinowane digestem).
- Limity Docker Hub i dlaczego lustro (`PLAN.md`, „Trzy różne limity”).
- „Czy GCR nie zostało wyłączone?” — usługa tak, domena nadal działa przez Artifact Registry
  **[Distroless FAQ]**. Gotowa odpowiedź w `PLAN.md`.
- Decyzja „tylko lustro” i jej koszt: 58% kandydatów niedostępnych na lustrze, próba przesunięta
  w stronę nowszych obrazów.

### 3.4 Projekt matrycy testowej

**Co napisać:**

- Schemat wiersza matrycy (kolumny i znaczenie) — `PLAN.md`, „Schemat matrycy testowej”.
- Kwoty proporcjonalne do `log(liczba grup)`, cała pula par, limit dla warstwy opisowej.
- Docelowe ~10 tys. obrazów i dlaczego końcowe N jest liczone, a nie wymuszane.
- Uczciwy strop distroless: ile par jest możliwych (`PLAN.md`, „Uczciwy strop dla distroless”).

**Rysunek (własny):** schemat lejka od katalogu do matrycy (liczby w rozdz. 4.4).

### 3.5 Narzędzia pomiarowe i metryki

**Co napisać:**

- Trivy: dlaczego (otwarty, obsługuje zdalne rejestry, `--list-all-pkgs`), wersja `v0.75.0`,
  skan `--image-src remote` bez demona Dockera, `--scanners vuln`.
- Zamrożona baza podatności — **najważniejsza decyzja metodyczna**: bez niej różnica klas byłaby
  częściowo różnicą dnia skanu. Baza odświeżana co ~24 h. `UpdatedAt` 2026-10-10T12:33Z.
  **[Rice]** zaleca regularne reskanowanie — u Ciebie jedno zdanie, że to zalecenie operacyjne,
  a jedna baza to warunek porównania.
- Metryki z wiersza `scans.jsonl`: `cve_total`, `cve_critical`…`cve_unknown`, `cve_with_fix`,
  `pkg_count`, `has_shell`, `has_apt`, `has_apk`, `has_busybox` (`KOD.md` §14).
- Skąd etykiety krytyczności: pole `Severity` w Trivy, nie zawsze ocena bazowa NVD **[CVSS]**.
  Sprawdź w dokumentacji Trivy przed oddaniem.
- Metody statystyczne: Wilcoxon (pary, jednostronny), Friedman (trójki), Spearman (korelacje),
  bootstrap mediany (CI 95%, 2 000 prób). Dlaczego nieparametryczne: rozkłady CVE są skośne
  (rozrzut ponad rząd wielkości). Dlaczego per repozytorium: `node` i `debian` to 27% próby.

---

## 4. Projekt i implementacja środowiska badawczego

Cel rozdziału: jak zrealizowano metodykę. Kod pokazuj fragmentami, tylko tam, gdzie coś jest
nieoczywiste.

### 4.1 Architektura systemu

**Co napisać:**

- Potok w 6 krokach: `GetRepo.py` → `GetTags.py` → `Classify.py` → `Matrix.py` → `Scan.py` →
  `Analyze.py`, dane przekazywane plikami JSONL (`KOD.md` §1).
- Dlaczego JSONL: zapis wiersz po wierszu przetrwa przerwanie, łatwy podgląd, jeden format w
  całym potoku; odrzucone Parquet i CSV (`PLAN.md`, decyzje Kroku 6).
- Cache żądań HTTP i wznawianie (`KOD.md` §12).
- Stos technologiczny (`PLAN.md`, „Stos technologiczny”; wersje w `WYNIKI.md` sekcja 1).

**Rysunek (własny, obowiązkowy):** diagram potoku: skrypty, pliki pośrednie, rejestry.

### 4.2 Konteneryzacja i skanowanie

**Co napisać:**

- Obraz skanera: `python:3.11-slim` + Trivy `v0.75.0`, wersja sprawdzana przy budowie (stare
  wydania Trivy znikają z GitHub Releases — tak padł build z `v0.45.1`).
- Odrzucone warianty: pobranie wszystkich obrazów z góry, `docker pull` → skan → `docker rmi`
  (`PLAN.md`, „Architektura kampanii skanowania”).
- Wybrane: `--image-src remote` — warstwy strumieniowane z rejestru, bez demona i bez gniazda
  Dockera w kontenerze (izolacja).
- 12 kontenerów, każdy z własną częścią matrycy i własnym cache; podział na kolejne kawałki, bez
  balansowania; scalenie po kampanii (`KOD.md` §14).
- Odporność: limit czasu 600 s, kod wyjścia, każda porażka zapisana, wznawianie po raporcie.
  Kontrast z PoC (75 raportów ze 100 — `WYNIKI.md` sekcja 1a).

### 4.3 Klasyfikacja wariantów i budowa matrycy

**Co napisać:**

- Rozbiór tagu (`parse_tag`): wersja, flavor, klasa, linia OS; rozwiązywanie aliasów po wspólnym
  digeście (39 558 aliasów) (`KOD.md` §7).
- Pinowanie digestem amd64 z indeksu wieloarchitekturowego (`KOD.md` §8).
- Sonda lustra: `HEAD` na manifest, `hit` / `cold_miss` / `miss`, ponowienie po 60 s (`KOD.md` §9).
- `select` i `layers` (`KOD.md` §10): grupy, kwoty, losowanie, drugi stopień deduplikacji.
- Przypadki brzegowe warte wzmianki: `ea` jako prerelease w `openjdk` (87% tagów), sprzeczne linie
  OS dla jednego digestu, wyzerowane daty distroless (`KOD.md` §13, `PLAN.md`).

### 4.4 Przebieg kampanii pomiarowej

**Co napisać:**

- Tabela czasów etapów — `WYNIKI.md` sekcja 2 (pierwsza tabela).
- Tabela lejka — `WYNIKI.md` sekcja 3.
- Kampania: 10.10 17:24 – 11.10 02:42 UTC, 9 h 18 min, 80,8 h pracy workerów, ~29 s na obraz;
  nierówne części (3,9–9,3 h) przez różną sumę rozmiarów — `WYNIKI.md` sekcja 2 (druga tabela,
  można dać do załącznika).
- Wynik: 9 755 OK, 168 porażek (1,7%), distroless 55/55. Taksonomia porażek w skrócie (tabela z
  `PLAN.md`, „Wyjaśnienie 168 porażek” — w pracy 3 kolumny: klasa, N, przyczyna).
- Wpadki operacyjne jako lekcje (TMPDIR, PowerShell) — dwa zdania, bez szczegółów.

---

## 5. Wyniki pomiarów i ich ocena

Cel rozdziału: punkty APD 5 i 6. Każdy podrozdział: tabela lub wykres → co widać → co to znaczy
→ zastrzeżenie. Wszystkie liczby i omówienia są w `WYNIKI.md`.

Numeracja rysunków w pracy jest inna niż nazwy plików. Mapowanie:

| Plik | Podrozdział pracy |
| --- | --- |
| `5_1_cve_by_variant.png` | 5.2 |
| `5_2_size_pkg_by_variant.png` | 5.2 |
| `5_3_severity_share.png` | 5.2 |
| `5_4_cve_vs_size.png`, `5_5_cve_vs_pkg.png` | 5.2 (jeden z dwóch, drugi do załącznika) |
| `5_6_cve_by_debian_line.png` | 5.2 |
| `5_7_cve_vs_age.png` | 5.2 |
| `6_1_delta_cve_pct.png` | 5.3 |
| `6_2_forest_repo_effect.png` | 5.3 (rysunek główny wyniku) |
| `6_3_delta_cve_pct_by_repo_slim.png` | 5.3 |
| `6_5_friedman_triplet.png` | 5.3 |
| `6_6_distroless_delta_by_family.png` | 5.4 |
| `7_1_tradeoff_scatter.png`, `7_2_tradeoff_medians.png`, `7_3_runtime_features.png` | 6.1 |

Podpisy rysunków po polsku. Tytuły w plikach PNG nie mają polskich znaków — jeśli to
przeszkadza, popraw je w `Analyze.py` i wygeneruj wykresy ponownie.

### 5.1 Charakterystyka zbioru wyników

**Co napisać:**

- Tabela klas × warstwy × skan OK / porażki — `WYNIKI.md` sekcja 4 (pierwsza tabela).
- Rodziny systemów, rok tagu (26% z 2026 r. — skutek sondy lustra), największe repozytoria
  (`node` + `debian` = 27%) — `WYNIKI.md` sekcja 4.
- Liczba par po skanie: 1 507 / 1 315 / 40, repozytoria 21 / 53 / 4.
- Ubytek przez porażki: głównie `standard` i warstwa opisowa — pary prawie nie ucierpiały.

**Wniosek do zapisania:** próba jest duża, ale niezrównoważona — stąd analiza per repozytorium.

### 5.2 Analiza podatności i powierzchni ataku *(APD 5)*

Pięć części, każda z rysunkiem:

1. **CVE per klasa** (rys. `5_1`, tabela z `WYNIKI.md` 5.1). Mediany 595 / 366 / 98 / 70.
   Porządek monotoniczny; `standard` ma rozrzut ponad rząd wielkości. Zaznacz: porównanie całych
   klas miesza technologie — test jest w 5.3.
   **Zastrzeżenie o zerach:** 386 obrazów z 0 CVE, w tym 121 bez rozpoznanych pakietów
   (`archlinux`, `busybox`, `fedora`) i ~150 z testowych wydań Debiana.
2. **Rozmiar i pakiety** (rys. `5_2`). `slim` i `alpine` mają ten sam rozmiar (~66 MB), ale
   `alpine` ma dwa razy mniej pakietów. Distroless: 13 pakietów, najwyższa gęstość CVE na pakiet
   (4,96). Brak rozmiaru distroless — ograniczenie.
3. **Krytyczność** (rys. `5_3`). `alpine` ma wyższy *udział* HIGH/CRITICAL, ale mniej poważnych CVE
   bezwzględnie (mediana CRITICAL 3 vs 9). Udział CVE z poprawką 99% vs ~50% — **asymetria źródeł
   porad** (Alpine secdb vs Debian Security Tracker); odwołaj się do **[Rice]** i **[CVSS]**.
4. **Korelacje** (rys. `5_4` lub `5_5`, tabela Spearmana z `WYNIKI.md` 5.4–5.5). ρ ≈ 0,6 —
   umiarkowana. Wewnątrz `alpine` rozmiar prawie nie ma znaczenia (ρ = 0,17). Wniosek: „mniejszy =
   bezpieczniejszy” to uproszczenie.
5. **Świeżość** (rys. `5_6`, `5_7`). `debian11` w `standard` ma medianę 7 398 (pełne obrazy
   `bullseye`); distroless spada 144 → 70 → 33 od `debian11` do `debian13`. Wiek tagu słabo
   skorelowany (ρ = 0,10), bo obrazy układają się w gałęzie technologii. `debian14` = 0 to brak
   danych.

### 5.3 Porównanie metod utwardzania względem standard *(APD 6)*

**Co napisać:**

1. Definicja pary i delty (krótko, odwołanie do 3.1).
2. **Wynik główny** — tabela per repozytorium (`WYNIKI.md` 6.2) i rys. `6_2`:
   `slim` −53% [−85; −35], `alpine` −91% [−96; −86], distroless −91% [−99; −85]; p dla
   `slim` i `alpine` < 10⁻⁵, distroless p = 0,0625 (minimum dla n = 4).
3. Wynik pomocniczy na wszystkich parach (`WYNIKI.md` 6.3) i rys. `6_1`.
4. **Heterogeniczność `slim`** (rys. `6_3`, ranking z `WYNIKI.md` 6.4) — najważniejsza obserwacja
   rozdziału: `slim` języków usuwa pakiety (−85…−96%), `debian:*-slim` usuwa tylko pliki (0%
   zmiany CVE przy −43% rozmiaru). 29% par ma deltę zero.
5. **Heterogeniczność `alpine`** (`WYNIKI.md` 6.5): gorzej w 62 parach, gdy `standard` stoi na
   `scratch` (`nats`) albo UBI (`gradle`). Pary między dystrybucjami nie mierzą utwardzania jednej
   bazy.
6. **Friedman** (rys. `6_5`, `WYNIKI.md` 6.6): porządek `standard` > `slim` > `alpine` w 288 z 300
   grup; zastrzeżenie — tylko 8 repozytoriów.

### 5.4 Studium przypadku: Distroless

**Co napisać:**

- Dlaczego studium, a nie trzecia metoda: 40 par, 4 repozytoria partnera; brak partnera dla Javy
  17+ na nowszym Debianie (`openjdk` przestarzałe) — `WYNIKI.md` 6.7, `PLAN.md`.
- Tabela per partner (`node`, `python`, `debian`, `openjdk`) i wybrane pary (`WYNIKI.md` 6.7).
- Rys. `6_6`.
- Obserwacje: żadna para gorsza; najmniejszy zysk `base`/`cc` na `debian10` (−6…−15%), bo
  zostaje glibc i libssl; największy przy runtime'ach; zależność od linii Debiana (480 → 291 → 168
  dla `python3`); 5 starych obrazów Pythona ma powłokę.
- Powiązanie z literaturą: definicja i cel **[Distroless]**; harmonogram wsparcia i stare linie
  bez aktualizacji (`SUPPORT_POLICY.md`).
- `nonroot`: identyczne warstwy, różni się tylko użytkownik — zalecenie **[NIST 4.1.2]** spełnione
  bez kosztu w CVE (51 z 56 repozytoriów).

---

## 6. Rekomendacje inżynierskie

Cel rozdziału: punkt APD 7 — co z wyników wynika dla praktyka. Mniej liczb, więcej decyzji.

### 6.1 Bezpieczeństwo a funkcjonalność runtime

**Co napisać:**

- Rys. `7_2` (główny) i `7_3`, opcjonalnie `7_1`. Tabela z `WYNIKI.md` 7.1–7.2.
- Trzy punkty kompromisu:
  - `slim`: najmniejszy koszt (powłoka, `apt`, glibc zostają), zysk zależny od technologii;
  - `alpine`: zysk jak distroless przy zachowaniu powłoki, koszt — musl i `apk`;
  - distroless: −93% pakietów, zysk jak `alpine`, koszt — brak powłoki, wektorowy `ENTRYPOINT`,
    debug przez wariant `debug`, dostępność dla kilku technologii **[Distroless]**.
- Kluczowa obserwacja: `alpine` i distroless mają prawie tę samą redukcję CVE, a różnią się o ~30
  pp. utraty pakietów.

### 6.2 Wytyczne doboru obrazów bazowych

**Co napisać** (lista rekomendacji, każda z uzasadnieniem z rozdz. 5):

1. Unikaj pełnych obrazów języków na `buildpack-deps` w produkcji — to one mają najwięcej CVE.
2. Dla obrazów języków `slim` to zysk 85–96% przy minimalnym koszcie; dla samego `debian` `slim`
   nie zmienia profilu CVE.
3. `alpine` gdy aplikacja nie zależy od glibc; sprawdź zależności natywne.
4. Distroless gdy jest dostępny dla technologii i aplikacja nie potrzebuje powłoki; zawsze
   najnowsza linia Debiana, jawnie (`-debian13`) **[Distroless]**; wariant `nonroot`.
5. Nie zakładaj, że obraz już minimalny (`scratch`, UBI) poprawi się po przejściu na `alpine`.
6. Pinuj digestem, skanuj regularnie, bo liczba CVE rośnie z czasem **[NIST]** **[Rice]**
   **[SLSA]**.
7. Liczba CVE to nie ryzyko — priorytet ustalaj z kontekstem wdrożenia **[CVSS]**.

### 6.3 Ograniczenia opracowanego rozwiązania

**Co napisać** — lista z `WYNIKI.md` sekcja 9 (10 punktów), pogrupowana:

- **Dane:** punkt w czasie (jedna baza); 0 CVE ≠ bezpieczny; asymetria źródeł porad; liczba
  pakietów obejmuje pakiety języków; brak rozmiaru i wieku distroless.
- **Próba:** tylko lustro (58% odrzuconych, przesunięcie w stronę nowych tagów); 168 porażek;
  tylko `library/` i amd64; distroless tylko na Debianie, 4 repozytoria; Friedman z 8.
- **Metoda:** pary między dystrybucjami w `alpine`; brak oceny środowiskowej CVSS; tylko
  podatności znane (bez zero-day **[Rice]**); bez weryfikacji podpisów i pochodzenia **[SLSA]**;
  jeden skaner.

---

## 7. Podsumowanie i Wnioski

Wymóg WIT: najważniejsze wnioski, możliwości dalszego rozwinięcia, potencjalne zastosowania. Bez
nowych liczb poza tymi z rozdz. 5, bez tabel.

### 7.1 Najważniejsze wnioski

**Co napisać:** 4–6 akapitów, każdy = jeden wniosek. Punkt wyjścia: akapit z `WYNIKI.md`
sekcja 10. Kolejność:

1. Wszystkie trzy metody istotnie zmniejszają liczbę CVE (liczby per repozytorium).
2. `slim` to dwie różne operacje — rozmiar bez usunięcia pakietów nie zmienia CVE.
3. `alpine` i distroless dają podobną redukcję przy różnym koszcie funkcjonalnym.
4. Liczba CVE zależy bardziej od bazy i jej świeżości niż od samego rozmiaru.
5. Cele pracy (z 1.1) osiągnięte — po jednym zdaniu na cel.

### 7.2 Możliwości dalszego rozwinięcia

**Co napisać:**

- Powtórzenie kampanii w kilku datach bazy (zmiana w czasie, a nie punkt).
- Drugi skaner (Grype) do porównania wyników i oceny asymetrii źródeł.
- Rozszerzenie na obrazy distroless-like spoza Debiana: Chainguard / Wolfi, Ubuntu chiselled
  (`PLAN.md`, „Poza zakresem”).
- Inne architektury (arm64) i repozytoria spoza `library/`.
- Ocena osiągalności podatności (czy podatny pakiet jest używany) i oceny środowiskowej CVSS.
- Weryfikacja podpisów i pochodzenia (cosign, SLSA) jako dodatkowa oś.
- Ponowny skan 168 porażek z dłuższym limitem czasu.

### 7.3 Potencjalne zastosowania

**Co napisać:**

- Wytyczne doboru obrazu bazowego dla zespołów DevOps (rozdz. 6.2).
- Potok jako narzędzie: cykliczny pomiar ekosystemu obrazów, bramka w CI/CD z progiem CVE
  **[NIST 4.1.1]**.
- Materiał dydaktyczny do zajęć z bezpieczeństwa kontenerów.
- Dane (`scans.jsonl`) jako zbiór do dalszych analiz.

---

## Załączniki (propozycja)

| Załącznik | Zawartość | Źródło |
| --- | --- | --- |
| A | Parametry kampanii: wersje, baza CVE, flagi Trivy | `WYNIKI.md` sekcja 1, `KOD.md` §14 |
| B | Czasy workerów | `WYNIKI.md` sekcja 2 |
| C | Pełna taksonomia 168 porażek | `PLAN.md` |
| D | Pełne rankingi repozytoriów `slim` i `alpine` | `WYNIKI.md` 6.4–6.5 |
| E | Wykresy pomocnicze (`5_4`/`5_5`, `7_1`) | `figures/` |
| F | Repozytorium kodu (link) i instrukcja odtworzenia | `README.md`, `KOD.md` §2 |

---

## Checklist przed oddaniem

- [ ] Każde z 6 źródeł APD zacytowane co najmniej raz.
- [ ] Wszystkie liczby z kampanii, nie z pilotażu.
- [ ] Wersja Trivy i data bazy podane w rozdz. 3.5 i załączniku A.
- [ ] Wynik główny raportowany per repozytorium, z CI 95%.
- [ ] Distroless nazwany studium przypadku, z n = 4 i p = 0,0625.
- [ ] Zastrzeżenie o zerach CVE i o asymetrii źródeł porad.
- [ ] Każdy rysunek ma podpis po polsku i odwołanie w tekście.
- [ ] Sprawdzone w dokumentacji Trivy: skąd pole `Severity` i dlaczego wydania testowe Debiana
      dają 0 CVE.
- [ ] Literówki w spisie treści (6.1, 6.3) poprawione.
- [ ] Sekcja 1.2 o AI zgodna z wymogami WIT.

# Plan poprawek pracy po uwagach promotora

Zatwierdzony przez autora 17.11.2026. Źródło uwag: `Poprawki.txt` od promotora (9 punktów). Postęp prac zaznaczać w tym pliku.

> **Nazewnictwo (19.11.2026):** w tekście pracy „badanie uzupełniające” nazywa się **„badanie konfiguracji uruchomieniowej”** (decyzja autora: stara nazwa sugerowała badanie robione na szybko). Etykiety LaTeX (`sec:badanie-uzupelniajace` itd.) bez zmian. W tym pliku i w pozostałych `docs/` stara nazwa została w opisach historycznych.

## Stan prac

| Krok | Stan (18.11.2026) |
| --- | --- |
| -1. Plan w `docs/POPRAWKI.md`, link w `CLAUDE.md` | zrobione |
| 0. Szkic wiadomości do promotora | zrobione: `szkice/Wiadomosc_do_promotora.txt`; wysyła autor |
| 1. Pamięć i dokumentacja | zrobione (`CLAUDE.md` §5–6, pamięć, `PLAN.md`) |
| 2. Badanie uzupełniające | zrobione: 60 uruchomień, wyniki w `WYNIKI.md` §11, kod w `KOD.md` §15 |
| 2a. Rozszerzenie badania uzupełniającego (18.11.2026) | zrobione: profile z pojedynczymi ustawieniami (SC, SN, SR, SL, SU), 120 uruchomień, `WYNIKI.md` §11.6; tekst rozdz. 3–6 zapisany w Overleaf (commit 7c0f56d) |
| 3. Literatura | zrobione: bibliografia w Overleaf (39 wpisów, commity e3f54e2 i b99a32f), 10 z 11 artykułów sprawdzonych w pełnych tekstach, notatki w `LITERATURA.md` §7; brakuje PDF Confine i CIS Docker Benchmark |
| 4. Rozdziały w Overleaf (2 → 3 → 4 → 5 → 6 → 1) | rozdz. 2–6 zapisane (szczegóły w dzienniku niżej); rozdz. 1 gotowy w `szkice/Rozdzial1_v2.tex`, przegląda autor; potem preambuła i załączniki |
| 5. Streszczenie i abstract | do zrobienia |
| 6. Kontrola spójności | do zrobienia |

## Dziennik wprowadzonych zmian (stan 18.11.2026)

### Zapisy w Overleaf

Wszystkie zapisy autor zaakceptował wcześniej. Przed każdym zapisem projekt był kompilowany lokalnie (MiKTeX, pdflatex + biber) bez błędów i bez niezdefiniowanych odsyłaczy. Po zapisie plik w Overleaf porównano z wersją lokalną.

| Commit | Data | Pliki | Co zmieniono | Uwagi promotora |
| --- | --- | --- | --- | --- |
| e3f54e2 | 17.11 | `bibliography.bib` | 37 wpisów: 10 dotychczasowych (uporządkowane), 11 artykułów naukowych, 16 źródeł normatywnych i dokumentacji; usunięte wpisy z szablonu | 2 |
| b4b4ab3 | 17.11 | `settings.tex`, `Rozdzial2.tex` | znaczniki szkicu (`szkic`, `\szk`, przełącznik `\szkictrue`/`\szkicfalse`) i akapit testowy | — |
| 82b8365 | 17.11 | `Rozdzial2.tex` | nowe 2.5 „Utwardzanie pozostałych warstw środowiska kontenerowego” z tab. warstw; nowe 2.6 „Przegląd dotychczasowych badań”; CVSS v4.0 i uzasadnienie v3.1; akapit o kierunkach zarządzania podatnościami (EPSS, KEV, SBOM); poprawki merytoryczne; etykiety i odsyłacze; tab. klas; korekta językowa | 2, 3, 4, 5, 8, 9 |
| b99a32f | 17.11 | `Rozdzial3.tex`, `Rozdzial2.tex`, `bibliography.bib` | nowe 3.6 „Badanie uzupełniające”; pytanie badawcze 4 i czwarta oś kryteriów; przegląd skanerów (APD zad. 2); NIST bez nadinterpretacji; tab. grupy z rzeczywistymi wersjami; data zamknięcia GCR i limit Docker Hub ze źródłami (2 nowe wpisy bib); szerokość tabel i rysunku; korekta językowa; 2 odsyłacze w rozdz. 2 | 2, 3, 4, 5, 6, 8, 9 |
| e03bb12 | 17.11 | `Rozdzial4.tex` | nowe 4.5 „Implementacja badania uzupełniającego”; wiersze w tab. potoku i stosu; wyjaśnienie 213 z 214 repozytoriów (`owncloud`); limit czasu zgodny z rozdz. 3; szerokość tabel; korekta językowa | 3, 5, 6, 9 |
| 110c93e | 18.11 | `Rozdzial5.tex`, `figures/6_7_runtime_matrix.{pgf,-img0.png,-img1.png}` | distroless jako 5.4; nowe 5.5 „Wyniki badania uzupełniającego” z tab. i rys. macierzy; rozbiór 386 zer (nowa tab.); poprawione zdania o `slim` (8/10/3) i medianach `alpine` (79/971); dopisek do tab. linii Debiana; złagodzone wnioski przyczynowe; nowa wytyczna o konfiguracji uruchomieniowej; korekta językowa | 3, 4, 5, 6, 7, 9 |
| c821895 | 18.11 | `zakonczenie.tex` | nowe 6.1 „Odpowiedzi na pytania badawcze”; „Realizacja celów pracy”; wniosek o obrazie i konfiguracji uruchomieniowej; ograniczenia i dalsze kierunki uzupełnione o badanie uzupełniające; tytuł „Podsumowanie i wnioski”; korekta językowa | 3, 5, 7 |
| a8ea050 | 18.11 | `Rozdzial2.tex` | **zmiany autora w Overleaf**: nowy wstęp rozdz. 2, usunięta część znaczników szkicu i komentarz `% TODO` przy rysunku z książki Rice'a | — |
| 7c0f56d | 18.11 | `Rozdzial3.tex`, `Rozdzial4.tex`, `Rozdzial5.tex`, `zakonczenie.tex` | profile z pojedynczymi ustawieniami: tab. profili (3.6), 120 uruchomień (4.5), część „Pojedyncze ustawienia konfiguracji” z tab. (5.5), zalecenie łączenia ustawień (5.6), odpowiedź na pytanie 4 (6.1) | 5 |
| 5edf004 | 18.11 | `Rozdzial2.tex` | **zmiana autora w Overleaf**: przeredagowany akapit o mechanizmach izolacji i zawartości obrazu (koniec 2.1) | — |
| 185ce20 | 18.11 | `settings.tex`, `Rozdzial2.tex`, `figures/rys_kontenery_gospodarz.tex`, `figures/rys_warstwy_obrazu.tex` | rys. 2.1 i 2.2 jako opracowanie własne w TikZ zamiast rysunku z książki Rice'a (s. 51) i rysunku z devopscube.com; rys. 2.2 pokazuje rzeczywiste warstwy i konfigurację obrazu sondy `slim` (`docker history`, `docker image inspect`); pakiet TikZ w `settings.tex`; dwa zdania o warstwach i konfiguracji obrazu (`\szk`); literówka „kontenerm” | 3, 8, 9 |
| de83ae5, e7f298a | 18.11 | `Rozdzial2.tex` | **zmiany autora w Overleaf**: zaakceptowane (zdjęte `\szk`) dwa zdania o warstwach obrazu; zredagowane zdanie o programie CVE i format `CVE-YYYY-NNNN+` | — |
| 965b32a | 18.11 | `Rozdzial2.tex`–`Rozdzial5.tex`, `zakonczenie.tex` | **przywrócenie brzmienia autora** na jego prośbę: zdania przeredagowane 17–18.11 tylko językowo wróciły do wersji sprzed poprawek (wersje bazowe: rozdz. 2 `2a7c54d`, 3 `ee8ed42`, 4 `ae7c774`, 5 i 6 `81ced66`); zostały tylko konieczne poprawki (fakty, liczby, odsyłacze, wnioski, źródła), oznaczone `\szk{}` w zdaniach autora (86 miejsc poza blokami `szkic`); nagłówki `\paragraph` w brzmieniu autora; w rozdz. 6 akapit autora o medianach wrócił w 6.1 (pytanie 1); lista w `szkice/przywrocenie_zmiany.md` | 3, 4, 5, 6, 7, 8, 9 |
| 4581e24 | 18.11 | `Rozdzial2.tex`, `Rozdzial3.tex` | **zmiany autora w Overleaf**: zaakceptowane fragmenty (zdjęte `\szk` i część środowisk `szkic`), przeredagowane zdania w 2.2, 2.4 i 2.5, położenie rys. 2.1 i 2.2 | — |
| ec76192 | 18.11 | `Rozdzial2.tex`–`Rozdzial5.tex`, `zakonczenie.tex` | **literówki** za zgodą autora: 174 wyrazy (znaki diakrytyczne, przestawione, brakujące i nadmiarowe litery, sklejone wyrazy), każdy w `\szk{}`; formy gramatyczne i szyk bez zmian; nałożone na wersję 4581e24; lista w `szkice/literowki_poprawione.md` | 3 |
| 2c92859 | 18.11 | `Rozdzial2.tex` | **zmiany autora w Overleaf** (rozdz. 2) | — |
| 8d0acaf | 19.11 | `Rozdzial2.tex`–`Rozdzial5.tex`, `zakonczenie.tex` | **zmiana nazwy** na prośbę autora: „badanie uzupełniające” → „badanie konfiguracji uruchomieniowej” (31 wystąpień, tytuły 3.6, 4.5 i 5.5, podpisy); nowe `\szk{}` w 3 miejscach tekstu autora; 4 moje zdania przeredagowane, aby uniknąć powtórzeń; etykiety LaTeX bez zmian; szkic wstępu `szkice/Rozdzial1_v2.tex` zaktualizowany lokalnie | 5 |
| f4b36ca, ff80b07 | 19.11 | `Rozdzial2.tex` | **zmiany autora w Overleaf** (rozdz. 2) | — |
| db0d930 | 19.11 | `Rozdzial3.tex` | **poprawka błędu w 3.6** (w środowisku `szkic`): zdanie, że grupa `python:3.13` jest jedyną z czterema klasami, było fałszywe. W kampanii jest 8 takich grup: 6 Node.js (wersje 14–26), Python 2.7 i Python 3.13 (zliczenie z `results/scans.jsonl`, nowa liczba). Dopisano uzasadnienie wyboru jednej technologii: Python 2.7 wycofany i z powłoką w distroless; sonda musi być w języku obrazu, więc jedna technologia oznacza jedno narzędzie pomiaru; uprawnienia procesu zależą od silnika i jądra, a nie od języka | 5, 8 |
| b527f09, 1a9df14 | 19.11 | `Rozdzial2.tex`, `Rozdzial3.tex` | **zmiany autora w Overleaf** (rozdz. 3, m.in. akceptacja zdań z `\szk`) | — |
| 1742376 | 19.11 | `Rozdzial2.tex`, `Rozdzial3.tex`, `bibliography.bib` | **„ocena własna” w tab. 3.9 zastąpiona źródłami**: wskaźnik 5 (`curl`/`wget`) → MITRE ATT&CK T1105; wskaźnik 10 (`/etc/shadow`) → `shadow(5)` i ATT&CK T1003.008. Usuwa to sprzeczność z akapitem „Miary” (każdy wskaźnik ma oparcie w literaturze). W 2.2 nowe zdania w `\szk` wprowadzające ATT&CK i obie techniki; 4 nowe wpisy bibliografii (`mitreAttack`, `attackT1105`, `attackT1003`, `manShadow`), notatki w `LITERATURA.md` 7.4 | 2, 8 |
| be81019 | 19.11 | `Rozdzial2.tex` | **zmiany autora w Overleaf**: nowe brzmienie zdań o ATT&CK w 2.2 | — |
| a721052 | 19.11 | `Rozdzial2.tex` | **przeniesienie zdań o ATT&CK** na prośbę autora: wprowadzenie bazy i T1105 (`curl`/`wget`) jako osobny akapit 2.2 przed podsumowaniem („Powierzchnię ataku obrazu w niniejszej pracy…”), z nowym zdaniem otwierającym; `/etc/shadow` (T1003.008, `shadow(5)`) w 2.5, po zdaniu o procesie działającym jako `root`. Brzmienie autora z be81019 zachowane (z literówkami „w która” i podwójnym „m.in.”, które autor poprawia sam); zmienione tylko „Pierwszą technikę” → „Technikę tę” | 2, 8 |

### Stan uwag promotora

| Pkt | Uwaga | Stan | Gdzie |
| --- | --- | --- | --- |
| 1 | brak streszczenia | **do zrobienia** | `abstract.tex` |
| 2 | brak przeglądu literatury i artykułów | zrobione | bibliografia (39 wpisów, 11 artykułów), 2.6, cytowania w rozdz. 2, 3, 5, 6 |
| 3 | błędy językowe | częściowo: 18.11 przywrócono brzmienie autora w rozdz. 2–6 (965b32a) i poprawiono 174 literówki (ec76192); **formy gramatyczne do decyzji autora** (np. „taga”, „wyjściu”, „rodzaji”, „inna niż root”); wstęp i streszczenie do zrobienia | wszystkie rozdziały |
| 4 | struktura i odsyłacze | zrobione w rozdz. 2–6; **opis układu we wstępie do zapisania** | etykiety podrozdziałów, distroless jako 5.4, rekomendacje jako 5.6 |
| 5 | tytuł a zakres badania | zrobione w rozdz. 2–6; **akapit „Zakres pracy” we wstępie do zapisania** | 2.5, 3.1, 3.6, 4.5, 5.5, 5.6, 6.1–6.3 |
| 6 | wyjaśnienia nie obejmują pełnej liczby | zrobione w tekście; **załączniki z pełnymi zestawieniami do zrobienia** | tab. zer (5.2), 213/214 (4.4), `slim` i `alpine` (5.3), tab. grupy (3.2), tab. linii Debiana (5.2) |
| 7 | wnioski a treść | zrobione; **cele szczegółowe we wstępie do zapisania** | 6.1, 6.3, macierz wniosków (koniec pliku) |
| 8 | błędy merytoryczne | zrobione | 2.1 (jądro, PID, przestrzenie nazw, cgroups, `pivot_root`, Rice rozdz. 5), 2.2 (CVE Program, format CVE), 2.4 (CVSS v4.0, NIST), 3.2 (NIST), 3.3 (GCR) |
| 9 | rysunki i tabele | zrobione w rozdz. 2–5, w tym własne rys. 2.1 i 2.2; **do zrobienia: odsyłacze małą literą, łamanie URL w bibliografii** | tabele i rysunki rozdz. 2–5 |

### Zmiany poza Overleaf

- **Kod:**
  - `src/Runtime.py`, `src/runtime/app.py`, `src/runtime/Dockerfile`: badanie uzupełniające, 10 profili, wykres;
  - `figures/6_7_runtime_matrix.{pgf,png}` z plikami `-img0.png` i `-img1.png`;
  - wyniki w `results/` (katalog poza repozytorium): `runtime_probe.jsonl`, `runtime_scan.jsonl`, `runtime_summary.json`, `runtime_single_effects.json` oraz kopia przebiegu z 17.11.
- **Dokumentacja:**
  - `WYNIKI.md` §11 (badanie uzupełniające, z §11.6), §12 (wersje CVSS), §13 (rozbiór zer);
  - `KOD.md` §15; 20.11 uzupełniony: nagłówek, spis treści, nowa nazwa badania, kolejność i nadpisywanie wyników w `run`/`scan`, formaty wszystkich plików `runtime_*` (z archiwum z 17.11), definicje 12 wskaźników;
  - `README.md` (20.11): badanie konfiguracji uruchomieniowej w opisie, strukturze repozytorium i szybkim starcie; `POPRAWKI.md` na liście dokumentacji; Claude Code obok Cursora we współautorstwie narzędziowym;
  - `PLAN.md` (decyzje dotyczące badania uzupełniającego);
  - `LITERATURA.md` §7 (11 artykułów sprawdzonych w pełnych tekstach, dokumentacja, rozdziały Rice'a);
  - `CLAUDE.md` §5–6 (6 rozdziałów, link do tego pliku);
  - pamięć asystenta (zakres badania uzupełniającego).
- **Szkice** (`szkice/`, poza repozytorium):
  - wiadomość do promotora;
  - propozycja bibliografii;
  - wersje rozdziałów `Rozdzial*_v2.tex` i `Rozdzial2_poprawki.tex`;
  - skrypty `cvss_versions.py` i `zeros_breakdown.py`;
  - pełne teksty artykułów w `szkice/literatura/`;
  - źródła rys. 2.1 i 2.2 w TikZ oraz podgląd stron z rysunkami w `szkice/rysunki/`;
  - podgląd pracy w PDF.
- **Incydent:** 17.11 plik `szkice/Rozdzial3_poprawki.tex` z 7.11 został przez pomyłkę nadpisany. Odtworzono go z zapisu sesji z 7.11, a nowe wersje rozdziałów mają odtąd nazwy `*_v2.tex`.
- Zmian w repozytorium kodu nie zatwierdzono w gicie.

### Nowe liczby spoza `analysis_summary.json`

Policzone z istniejących danych, bez ponownego skanowania:
- wersje CVSS w raportach: v3.x 89,4%, v4.0 3,6% dopasowań (`WYNIKI.md` §12);
- rozbiór 386 zer: 121 + 192 + 73 (`WYNIKI.md` §13);
- 213 z 214 repozytoriów po skanowaniu, ubytek `owncloud`;
- wszystkie wyniki badania uzupełniającego (`WYNIKI.md` §11).

### Pozostało do zrobienia

1. Wstęp (rozdz. 1): gotowy w `szkice/Rozdzial1_v2.tex`, przegląda autor. Przy zapisie zmienić w rozdz. 6 odsyłacz „Cele postawione we wstępie” na `\ref{sec:cel-zakres}`.
2. Preambuła:
   - `\crefname` małymi literami (`rys.`, `tab.`);
   - łamanie długich adresów URL w bibliografii (liczniki `biburllcpenalty` i `biburlucpenalty` w `main.tex`);
   - słowa kluczowe;
   - ewentualnie akronimy EPSS, KEV i SBOM.
3. Załączniki (pkt 6): pełny ranking `alpine`, wszystkie 40 par distroless, surowe wyniki badania uzupełniającego.
4. Streszczenie i abstract (pkt 1).
5. Kontrola końcowa: kompilacja w Overleaf, usunięcie znaczników szkicu po akceptacji promotora (`\szkicfalse` albo usunięcie znaczników).
6. Do decyzji autora:
   - wysłanie wiadomości do promotora;
   - formy gramatyczne pominięte przy poprawie literówek (uwaga promotora 3) i literówki w nowych zmianach autora z 4581e24 („przejecie”, „Tą warste można utwardzic” w 2.5); w rozdz. 4 tag `python:3.10.21-alpine3.24` wystaje ok. 6 mm poza margines;
   - usunięcie z Overleaf nieużywanych plików `figures/ContainerOnHost.png` i `figures/docker-layers.png` (rys. 2.1 i 2.2 zastąpione własnymi 18.11, commit 185ce20);
   - wersja CIS Docker Benchmark i data dostępu wytycznych WIT w bibliografii;
   - potwierdzenie treści sekcji 1.2 o AI;
   - zatwierdzenie zmian w repozytorium w gicie.

## Kontekst

Promotor przesłał 9 uwag (`Desktop/Poprawki.txt`). Najpoważniejsza (pkt 5): tytuł zapowiada utwardzanie **środowisk kontenerowych**, a badanie dotyczy tylko wyboru obrazu bazowego. Ustalenia z autorem (17.11.2026):

- tytułu **nie można zmienić**, bo jest zatwierdzony przez komisję. Jedyna droga to uzupełnienie pracy **i badań** tak, żeby pasowały do tytułu;
- zostaje **6 rozdziałów**, a wstęp ma to opisywać poprawnie;
- zmiany w Overleaf zapisuję **po akceptacji każdego rozdziału**: najpierw lista zmian, po „tak” zapis przez MCP.

Główna kampania (9 755 obrazów) pozostaje zamknięta i nie będzie powtarzana. Dochodzi jedno **małe badanie uzupełniające** na warstwie środowiska uruchomieniowego. Jest to zmiana względem wcześniejszej decyzji „bez ponownego badania”, więc w pamięci zapisuję nową regułę.

Stan pracy (przeczytany przez MCP): `wstep`, `Rozdzial2`–`Rozdzial5`, `zakonczenie`, `abstract` (wciąż tekst z szablonu), `bibliography.bib` (9 pozycji, żadnego artykułu naukowego, do tego śmieci z szablonu: Knuth, Chord i inne). Większość poprawek ze `szkice/Poprawki_merytoryczne.md` jest już naniesiona. Nadal brakuje W3 (sekcja 1.2 o AI).

---

## Część A: punkt 5, dopasowanie pracy do tytułu (priorytet)

**Najmocniejszy argument: opis pracy w APD.** Opis zatwierdzony razem z tytułem sam określa zakres na poziomie obrazów:
- cel to „techniki minimalizacji podatności **w obrazach kontenerowych**” i „dobór **baz systemowych**”;
- część praktyczna to „analiza **statyczna** artefaktów”;
- zadanie 6 wymienia Slim, Alpine i Distroless względem wersji standardowych.

Praca realizuje więc zatwierdzony opis. Rozjazd jest między tytułem a samym APD, a nie między APD a pracą. Wykorzystanie:
- **w pracy:** nowy akapit „Zakres pracy” w 1.1. Definiuje, co w pracy znaczy utwardzanie środowiska kontenerowego (warstwy według NIST), mówi, która warstwa jest badana i jaką metodą, oraz dlaczego pomiar dotyczy obrazu. Bez powoływania się na APD w tekście;
- **w wiadomości do promotora:** cytaty z APD jako argument.

Uzupełnienie badania ma się mieścić w APD, więc wiążę je z zadaniem 6 („wpływ na **funkcjonalność runtime**” i „redukcja powierzchni ataku”) oraz z zadaniem 7 (bilans bezpieczeństwa i użyteczności). Dziś praca przyznaje, że „nie uruchamiano kontenerów i nie testowano działania aplikacji”, czyli ta część zadania 6 jest pokryta tylko pośrednio, przez listę pakietów.

Rama dla całej pracy, oparta na NIST SP 800-190, który już jest cytowany. Środowisko kontenerowe składa się z warstw: **obraz → rejestr → kontener (środowisko uruchomieniowe) → orkiestrator → host**. Praca robi trzy rzeczy:

1. **jakościowe porównanie** metod utwardzania na wszystkich warstwach (literatura);
2. **ilościowe porównanie** metod na warstwie obrazu (istniejąca kampania);
3. **eksperymentalne porównanie** metod na warstwie konfiguracji uruchomieniowej oraz ich połączenia z wyborem obrazu (nowe badanie uzupełniające).

Orkiestrator i host zostają opisane jakościowo i jawnie wyłączone z pomiaru, z uzasadnieniem.

### A1. Badanie uzupełniające: utwardzanie konfiguracji uruchomieniowej

Projekt (mały, deterministyczny, lokalnie na Docker Desktop):

- **Obrazy:** grupa `library/python:3.13:-:debian13` z kampanii, ta sama co w `tab:grupa`, pobrana po digestach z `results/scans.jsonl`:
  - `python:3.13.16-trixie` (`standard`, 3 248 CVE);
  - `-slim-trixie` (`slim`, 172);
  - `-alpine3.23` (`alpine`, 7);
  - `distroless/python3-debian13` (`distroless`, 168).

  Liczby CVE pochodzą już z kampanii.
- **Aplikacja-sonda** `src/runtime/app.py`: tylko biblioteka standardowa Pythona, więc działa na wszystkich czterech obrazach, także na distroless. Udostępnia dwa adresy:
  - `GET /` zwraca kontrolę działania aplikacji, czyli koszt funkcjonalny;
  - `GET /probe` zwraca JSON z tym, co może zrobić kod wykonany w procesie aplikacji. Jest to symulacja zdalnego wykonania kodu (RCE).
- **Sprawdzenia w `/probe`:**
  - `uid`;
  - liczba uprawnień `CapEff` oraz pola `NoNewPrivs` i `Seccomp` z `/proc/self/status`;
  - czy da się zapisać w `/` i w `/usr`;
  - obecność powłoki, `apt`/`apk`, `curl`/`wget` i kompilatora;
  - liczba plików z bitem setuid;
  - czy da się otworzyć gniazdo surowe (`CAP_NET_RAW`) i wykonać `chown`;
  - czy da się odczytać `/etc/shadow`;
  - wartości `pids.max` i `memory.max`.
- **Profile uruchomienia** (flagi `docker run`):
  - P0 domyślny;
  - P1 `--user 65532:65532`;
  - P2 = P1 + `--cap-drop ALL --security-opt no-new-privileges`;
  - P3 = P2 + `--read-only --tmpfs /tmp --pids-limit 64 --memory 256m`;
  - PX `--privileged` jako antywzorzec, czyli punkt odniesienia dla najgorszego przypadku.
- **Przebieg:** 4 obrazy × 5 profili = 20 konfiguracji, każda uruchomiona 3 razy (kontrola powtarzalności). Do tego skan 4 obrazów aplikacji Trivy `v0.75.0` z zamrożoną bazą `trivy_cache/frozen` (`UpdatedAt` 2026-10-10T12:33:35Z, sprawdzone, że istnieje). Ma to potwierdzić, że warstwa aplikacji nie zmienia liczby CVE.
- **Miara zbiorcza:** liczba możliwości dostępnych dla napastnika (suma sprawdzeń z wynikiem „tak”). Jest to własna, operacyjna miara pracy, tak jak taksonomia klas. Każde sprawdzenie ma uzasadnienie w literaturze (Rice rozdz. 2, 8, 9; NIST 4.4; CIS Docker Benchmark; strony podręcznika `capabilities(7)` i `seccomp(2)`).
- **Pliki:**
  - nowe: `src/runtime/app.py`, `src/runtime/Dockerfile` (`ARG BASE` = digest, `COPY app.py`), `src/Runtime.py` (budowanie, uruchamianie profili, odpytanie `/probe`, zapis do `results/runtime_probe.jsonl`, skan Trivy) oraz jeden wykres macierzy obraz × profil (PNG i PGF, w stylu `Analyze.py`);
  - ponownie użyte: odczyt digestów z `results/scans.jsonl`, obraz skanera z `Dockerfile` i zamrożona baza z `trivy_cache/frozen`.
- **Dokumentacja:** nowe sekcje w `docs/PLAN.md` (decyzja i projekt), `docs/KOD.md` (skrypt) i `docs/WYNIKI.md` (wyniki).

Hipotezę (do sprawdzenia, nie do zapisania z góry) można sformułować tak: utwardzanie obrazu usuwa narzędzia napastnika (powłoka, menedżer pakietów, kompilator, pliki setuid), a utwardzanie konfiguracji odbiera mu uprawnienia (root, uprawnienia jądra, zapis do systemu plików). Metody byłyby więc komplementarne. Wnioski piszę dopiero z danych.

Szacunek pracy: około 1–1,5 dnia na kod i uruchomienia.

### A2. Tekst: gdzie trafia uzupełnienie

| Miejsce | Zmiana |
| --- | --- |
| 1.1 Cel i struktura | cel obejmuje warstwy środowiska: porównanie jakościowe dla wszystkich warstw, ilościowe dla obrazu, eksperymentalne dla konfiguracji uruchomieniowej; jawne uzasadnienie zakresu pomiaru; opis 6 rozdziałów |
| Rozdz. 2, nowy podrozdział | „Warstwy środowiska kontenerowego i metody ich utwardzania” według warstw NIST: uprawnienia jądra (capabilities), seccomp, `no-new-privileges`, użytkownik nieuprzywilejowany, system plików tylko do odczytu, limity cgroups, `--privileged` i `docker.sock` jako antywzorce, orkiestrator (Pod Security Standards), host (system przeznaczony dla kontenerów). Zawiera tabelę porównawczą: warstwa → zagrożenie → metody → koszt → czy praca to mierzy |
| Rozdz. 2, nowy podrozdział | „Przegląd literatury i stan badań”: badania podatności w Docker Hub, debloating, redukcja wywołań systemowych, porównania skanerów. Pozycjonuje wkład pracy (pkt 2) |
| 3.1 | pytanie badawcze nr 4, sformułowane tak, żeby mieściło się w zadaniach 6–7 APD (czynnikiem jest klasa obrazu, a profil uruchomienia jest warunkiem): „Jak klasa utwardzenia obrazu bazowego wpływa na powierzchnię ataku i działanie aplikacji w uruchomionym kontenerze, przy domyślnej i przy ograniczonej konfiguracji uruchomieniowej?”; oś kryteriów „uprawnienia procesu” |
| Rozdz. 3, nowy podrozdział | metodyka badania uzupełniającego (obrazy, profile, sprawdzenia, miara, kryterium działania aplikacji) |
| Rozdz. 4, nowy podrozdział | implementacja: sonda, skrypt, środowisko (wersja Dockera, data) |
| Rozdz. 5, nowy podrozdział (przed rekomendacjami) | wyniki: tabela 20 konfiguracji, wykres macierzy, interpretacja |
| Rekomendacje (5.x) | wytyczne dla kolejnych warstw: obraz + profil uruchomienia; tabela wytycznych rozszerzona o konfigurację; oznaczenie, co wynika z pomiaru, a co z literatury |
| Rozdz. 6 | odpowiedzi na 4 pytania; ograniczenia (jedna aplikacja, jedna technologia, Docker Desktop, orkiestrator i host bez pomiaru); dalsze prace (Kubernetes, profile seccomp dla aplikacji) |

---

## Część B: pozostałe uwagi promotora

**Pkt 1. Streszczenie.** Napisać streszczenie PL i abstract EN (cel, metody, wyniki obu badań; razem jedna strona) w `abstract.tex`, **na końcu**, gdy treść jest już stabilna.

**Pkt 2. Literatura.** Docelowo co najmniej 20 pozycji, w tym co najmniej 8–10 recenzowanych artykułów. Istnienie i dane bibliograficzne artykułów poniżej sprawdzono 17.11.2026 (DOI, miejsce publikacji). Wist i in. (preprint arXiv, bez wersji recenzowanej) usunięto decyzją autora. Treść przed cytowaniem czyta autor, a do `LITERATURA.md` trafia notatka z sekcją „czego nie wyciągać”. Kandydaci:
- Shu i in. 2017 (CODASPY), Zerouali i in. 2019 (SANER), Liu i in. 2020 (ESORICS), Martin i in. 2018 (Computer Communications);
- Combe i in. 2016 (IEEE Cloud Computing), Sultan i in. 2019 (IEEE Access), Lin i in. 2018 (ACSAC);
- Ghavamnia i in. 2020 (Confine, RAID), Rastogi i in. 2017 (Cimplifier, FSE);
- Javed i Toor 2021, Shamim i in. 2020;
- źródła normatywne i dokumentacja: CIS Docker Benchmark, strony podręcznika Linuksa `namespaces(7)` i `capabilities(7)`, dokumentacja Dockera (capabilities, seccomp), FIRST CVSS v4.0 (2023), dokumentacja CVE Program.

Dodatkowo: usunąć wpisy z szablonu, ujednolicić `@online`/`urldate` (distroless bez daty), dopisać streszczenia z sekcją „czego nie wyciągać” do `docs/LITERATURA.md`. Numery rozdziałów Rice'a sprawdzono w spisie treści (`LITERATURA.md` §7.5): nadzorca i porównanie z VM to **rozdz. 5**, więc `\cite[rozdz.6]{rice2020}` przy nadzorcy w rozdz. 2 pracy trzeba poprawić na rozdz. 5; rysunek z s. 51 pochodzi z rozdz. 4.

**Pkt 3. Język.** Korekta łączona z poprawkami merytorycznymi przy edycji każdego rozdziału (jeden zapis na rozdział):
- końcówki „-ę” (np. „powierzchnię”, „liczbę”, „warstwę”, „powłokę”, „uwagę”);
- polskie znaki i literówki („wyłącznie”, „od razu”, „Linuksa”, „Docker Hub”, „Dockerfile”, „pojedynczy”, „distroless”, „rejestrów”, „obrazu:”);
- „ilość” → „liczba” dla rzeczy policzalnych;
- składnia;
- terminologia z `CLAUDE.md` §3 („runtime'u” → „środowiska uruchomieniowego”, „build'ów” → „budowań”, „developera” → „programisty”);
- tytuł „Podsumowanie i wnioski” (małe „w”).

**Pkt 4. Struktura (6 rozdziałów).**
- Opis układu we wstępie na 6 rozdziałów.
- „Studium przypadku: Distroless” jako `\section` (obecnie `\subsection*` z etykietą, przez co odsyłacz wskazuje 5.3).
- Etykietę `chapt:Rekomendacje inżynierskie` zamienić na `sec:rekomendacje` i poprawić wszystkie odwołania („podrozdział”, właściwy cel). Odwołania do ograniczeń mają prowadzić do `sec:ograniczenia`, a te o asymetrii źródeł porad do `sec:analiza-podatnosci`.
- Etykiety `\subsection*` (`sec:funkcjonalnosc`, `sec:wytyczne`) zamienić na numerowane albo usunąć.
- Dodać `\label` do podrozdziałów rozdz. 2 i zastąpić wpisane na sztywno numery („2.1”, „2.3”, „2.4”, „rozdziale 3”) przez `\ref`, bo nowe podrozdziały przesuną numerację.

**Pkt 5.** Część A.

**Pkt 6. Wyjaśnienia nie obejmują pełnej liczby.** Moja interpretacja (warto potwierdzić u promotora): wyliczenia nie sumują się do całości, a pełnych zestawień brakuje. Znalezione miejsca:
- zera CVE: tekst wyjaśnia 121 + 192 z 386. Dane w `scans.jsonl`: 121 bez pakietów, 154 `debian`, 111 pozostałych (`openjdk` 16, `amazoncorretto` 15, `eclipse-temurin` 9, `java` 8 i inne). Liczba „192” nie ma źródła w `WYNIKI.md`, więc to rozbieżność do wyjaśnienia;
- `slim`: zdanie o 8/3/10 repozytoriach jest zbudowane błędnie;
- 214 repozytoriów w matrycy wobec 213 po skanie: nie ma wyjaśnienia;
- zdanie o medianach 79 i 971 w `alpine` porównuje różne wielkości;
- tabela linii Debiana obejmuje tylko obrazy z rozpoznaną linią i tego nie mówi;
- `tab:grupa` podaje `alpine3.22`, a dane mają `python:3.13.16-alpine3.23`.

Do tego załączniki (dziś `\appendix` jest pusty): pełny ranking `alpine` (53 repozytoria), wszystkie 40 par distroless, pełny rozbiór zer, surowe wyniki badania uzupełniającego, link do repozytorium kodu.

**Pkt 7. Wnioski a treść.** Zbudować macierz „wniosek → sekcja, tabela lub rysunek” i usunąć albo złagodzić wnioski bez pokrycia. Przykłady:
- „głównie wtedy, gdy obraz domyślny jest już mały” wobec zróżnicowanej listy 62 par;
- kategoryczne „przyczyną … jest” przy zerach (powinno być „prawdopodobną przyczyną”);
- spekulacja o „niepoprawnie oznaczonych” obrazach `jetty`/`maven`.

W rozdz. 6 dodać „Odpowiedzi na pytania badawcze” i zestawienie „cel z 1.1 → realizacja”.

**Pkt 8. Merytoryka ogólna.**
- jądro nie jest „warstwą sprzętową”;
- „własne drzewo procesów (przestrzeń nazw PID)” zamiast „własnej liczby procesów”;
- lista przestrzeni nazw uzupełniona o `time`;
- „przestrzenie nazw (ang. namespaces)”;
- identyfikatory nadaje CVE Program (prowadzony przez MITRE) i CNA;
- format `CVE-YYYY-NNNN…` (co najmniej 4 cyfry);
- wzmianka o CVSS v4.0 (2023) i uzasadnienie użycia v3.1: ta sama skala jakościowa, źródło dokumentu APD, oceny w źródłach skanera. Obsługę v4 w Trivy sprawdzić przed napisaniem;
- „zgodne z zaleceniami NIST” (s. 15 i akapit NIST w 2.4) zamienić na „odpowiada ogólnemu zaleceniu korzystania z zaufanych źródeł; NIST nie wskazuje konkretnych źródeł”;
- grupy kontrolne „ograniczają i rozliczają”, a nie tylko „monitorują”;
- `chroot` a `pivot_root`;
- fakty o wyłączeniu GCR (sprawdzić w dokumentacji Google).

Dalej pełne sprawdzenie faktów w rozdz. 2 i 3. Lista promotora urywa się przecinkiem, więc mogła mieć dalsze punkty: warto dopytać.

**Pkt 9. Rysunki i tabele.**
- `\crefname` małymi literami (`rys.`, `tab.`) w `settings.tex`, bo w środku zdania drukuje się „na Rys.”;
- goły `\ref{fig:Digest}`;
- `tab:klasy-utwardzenia` bez odwołania w tekście, bez `\textbf` w nagłówku, bez `\hline` po wierszach, skrót „pckgs.”;
- `tab:grupa` i `tab:trivy` w tym samym formacie;
- literówka „Żródło”;
- „\texttt{przypadku alpine}” w rozdz. 5;
- rysunki z Rice'a (s. 51) i z devopscube: prawo do użycia albo własne rysunki (decyzja autora);
- polskie znaki w tytułach wykresów PGF (sprawdzić w PDF);
- opcjonalnie `\listoffigures` i `\listoftables`.

**Luki względem APD** (promotor ich nie wymienił, ale komisja porówna pracę z kartą):
- Zadanie 2, „przegląd i wybór dostępnych narzędzi do skanowania statycznego”: praca tylko uzasadnia wybór Trivy. Dodać krótkie porównanie jakościowe skanerów (Trivy, Grype, Clair, Docker Scout) w 3.5, z literaturą (np. Javed i Toor 2021), oraz „metody optymalizacji artefaktów” (budowa wieloetapowa, debloating).
- Zadanie 1, „aktualne trendy w zarządzaniu podatnościami”: brak. Dodać akapit w rozdz. 2: CVSS v4.0, EPSS, katalog KEV, SBOM/VEX. Łączy się z uwagą promotora o CVSS v4.0.
- Literatura APD poz. 5 to „Specification Guide”, a bibliografia ma „Specification Document”. Ujednolicić.

**Dodatkowo.**
- Sekcja 1.2 o AI zgodna z rzeczywistym przebiegiem pracy (Cursor, Claude Code, w tym ta sesja i badanie uzupełniające). Treść potwierdza autor.
- Słowa kluczowe dopasowane do rozszerzonego zakresu.

---

## Oznaczanie wstawianego tekstu w Overleaf

Na prośbę autora nowy i merytorycznie przepisany tekst jest oznaczony w PDF. Overleaf nie pokaże zmian wysłanych przez MCP jako „Track changes” (to działa tylko przy edycji w edytorze), dlatego znaczniki są w LaTeX-u.

Definicja w `settings.tex` (blok „Dodane przeze mnie (KW)”; pakiet `xcolor` jest już załadowany):

```latex
%%% ZNACZNIKI SZKICU: \szkicfalse = wersja końcowa (znaczniki znikają, tekst zostaje)
\newif\ifszkic
\szkictrue
\newenvironment{szkic}[1][]%
  {\ifszkic\par\textcolor{red}{\footnotesize\textbf{[SZKIC #1]}}\par\color{blue}\fi}%
  {\ifszkic\par\textcolor{red}{\footnotesize\textbf{[KONIEC SZKICU]}}\par\fi}
\newcommand{\szk}[1]{\ifszkic\textcolor{blue}{#1}\else#1\fi}
```

Użycie:
- nowe akapity i podrozdziały w środowisku `\begin{szkic}[pkt 5] … \end{szkic}`, z pustą linią przed i po. W nawiasie numer uwagi promotora;
- przepisane zdanie w istniejącym akapicie: `\szk{…}`;
- ~~korekta językowa nie jest oznaczana~~ **zmiana 18.11.2026 na prośbę autora:** korekta językowa też jest oznaczana `\szk{}` na poziomie zdania, podobnie przeredagowane podpisy (`\caption{\szk{...}}`). Bez koloru zostają tylko zdania identyczne z wersją autora i zdania, z których autor sam zdjął znacznik (zaakceptowane);
- nowe tabele i rysunki: `[SZKIC]` na początku podpisu.

Zamiana na zwykły tekst:
1. **Akceptacja pojedynczego fragmentu:** usunąć dwie linie `\begin{szkic}[…]` i `\end{szkic}` albo samo opakowanie `\szk{` i `}`. Tekst w środku zostaje bez zmian.
2. **Wszystko naraz w PDF:** w `settings.tex` zmienić `\szkictrue` na `\szkicfalse`. Kolory i etykiety znikają, tekst zostaje (znaczniki zostają tylko w źródle).
3. **Końcowe sprzątanie przed oddaniem:** na prośbę autora usuwam przez MCP wszystkie znaczniki i definicję z `settings.tex`. Ręcznie: w Overleaf Ctrl+Shift+F, szukać `szkic` i `\szk{`.

Pierwszy zapis w Overleaf to sam blok w `settings.tex` z jednym testowym akapitem. Autor kompiluje i potwierdza wygląd przed dalszymi zmianami.

## Kolejność prac

-1. Zapisuję ten plan jako `docs/POPRAWKI.md` (na prośbę autora) i dodaję link w tabeli materiałów w `CLAUDE.md` §6.
0. (Zalecane) Szkicuję krótką wiadomość do promotora. Treść: (a) zakres pracy wynika z zatwierdzonego opisu APD (cytaty z celu i zadania 6); (b) proponowane uzupełnienie: rama warstw środowiska według NIST, jakościowe porównanie metod oraz eksperyment z działaniem kontenerów pod zadanie 6; (c) prośba o potwierdzenie, że to wystarczy. Wysyła autor.
1. Pamięć i dokumentacja: aktualizacja `bez-ponownego-badania`, nowa notatka „tytuł niezmienny, 6 rozdziałów”, `CLAUDE.md` §5 (6 rozdziałów), sekcja w `docs/PLAN.md`.
2. Badanie uzupełniające A1: kod, 20 konfiguracji × 3 powtórzenia, skan, wykres, `WYNIKI.md`.
3. Literatura: wyszukanie i weryfikacja DOI, `bibliography.bib`, `LITERATURA.md`.
4. Po jednym rozdziale (lista zmian → akceptacja → zapis przez MCP), za każdym razem z korektą językową, merytoryką, odsyłaczami, rysunkami i tabelami: **rozdz. 2 → 3 → 4 → 5 → 6 → 1**. Potem `settings.tex`, `acronyms.tex` i załączniki.
5. Streszczenie i abstract.
6. Końcowa kontrola spójności.

## Weryfikacja

- Badanie uzupełniające:
  - 3 powtórzenia każdej konfiguracji muszą dać identyczny wynik;
  - kontrola znanych wartości: P0 ma 14 uprawnień `CapEff` i `Seccomp: 2`, P2 ma `CapEff` 0 i `NoNewPrivs: 1`, PX ma pełny zestaw uprawnień (41) i słabszy seccomp. W Docker Desktop zostaje jeden filtr silnika, więc `Seccomp: 0` nie występuje (`WYNIKI.md` §11.5);
  - skan obrazów aplikacji daje te same liczby CVE co obrazy bazowe z kampanii.
- Liczby w tekście z `analysis_summary.json`, `WYNIKI.md` i `runtime_probe.jsonl`; każde wyliczenie sumuje się do całości.
- Po każdym zapisie: ponowny odczyt pliku przez MCP i porównanie z planowaną zmianą. Autor kompiluje w Overleaf i sprawdza brak niezdefiniowanych odwołań i cytowań (MCP nie kompiluje).
- Każda nowa pozycja bibliografii ma potwierdzony DOI lub URL i co najmniej jedno `\cite` w tekście.
- Końcowa tabela: 9 uwag promotora → miejsce i sposób poprawki, do odesłania promotorowi.

---

## Macierz wniosków (uwaga promotora pkt 7, stan 18.11.2026)

Każdy wniosek z rozdz. 6 ma pokrycie w treści pracy:

| Wniosek w rozdz. 6 | Źródło w pracy |
| --- | --- |
| mediany CVE 595 / 366 / 98 / 70 | tab. `tab:cve-klasy` (5.2) |
| ρ ≈ 0,6 z rozmiarem i pakietami, ρ = 0,105 z wiekiem | tab. `tab:spearman`, akapit o świeżości (5.2) |
| baza i jej linia mają duże znaczenie | tab. `tab:debian`, `tab:distroless-pary` (5.2, 5.4) |
| 386 zer: brak pakietów lub testowy Debian | tab. `tab:zera` (5.2) |
| redukcja −53,1% / −90,9% / −90,6% | tab. `tab:wynik-glowny` (5.3) |
| `slim`: od 0 do −96,1%; 407 par bez zmiany pakietów i CVE | tab. `tab:slim`, tekst 5.3 |
| `alpine` gorszy w 62 parach, zwykle mały lub inny obraz domyślny | lista i mediany 79 / 971 (5.3) |
| distroless: 0 par gorszych, 4 technologie | 5.4 |
| koszt funkcjonalny klas, ~93% pakietów w distroless | tab. `tab:koszt`, `tab:kompromis` (5.6) |
| uprawnienia zależą od profilu, narzędzia od klasy obrazu | tab. `tab:uprawnienia-profili`, `tab:zawartosc-obrazow` (5.5) |
| distroless P0 (5) > `slim` P3 (2); `alpine` ma mniej CVE, ale nie mniej narzędzi niż `slim` | rys. `fig:runtime-macierz` (5.5) |
| ograniczenia nie zakłóciły działania aplikacji | 5.5 (60 uruchomień) |
| ochronę przed eskalacją dają głównie mechanizmy jądra | literatura: Lin i in. (2.5) |

Usunięte lub złagodzone wnioski bez pokrycia:
- „głównie wtedy, gdy obraz domyślny jest już mały” → „zwykle wtedy, gdy obraz domyślny ma niewiele podatności albo jest oparty na innej dystrybucji niż Debian” (5.3);
- „Przyczyną liczby 0 jest…” → „Prawdopodobną przyczyną…” (5.2);
- przypuszczenie o „niepoprawnie oznaczonych” parach `jetty`/`maven` → „przyczyny nie badano” (5.3).

# Plan pracy inżynierskiej — analizator obrazów kontenerowych

Dokument odtworzony z rozmów z 21–23.08.2026 po zmianie nazwy katalogu projektu
(`C:\Projects\PRACA_IN\Code` → `C:\Projects\Container_Image_Anylyzer`), która odcięła historię
czatu. Źródłem są pliki planów `~/.cursor/plans/fetcher_matrycy_92879bdc.plan.md`
(wersja obowiązująca) oraz `~/.cursor/plans/inteligentny_fetcher_2bcd6835.plan.md`
(wcześniejsza, zastąpiona).

Rozdział [Rejestry i ścieżki pobierania](#rejestry-i-ścieżki-pobierania) oraz
[Warianty distroless](#warianty-distroless--dowody-pomiarowe) zawierają **korekty ustaleń
z 13.09.2026**, zweryfikowane empirycznie. Poprawiają one dwa błędy poprzednich planów.

## Dane oficjalne (APD)

- **Autor:** Kamil Wierzbicki, Wydział Informatyki i Telekomunikacji, Politechnika Wrocławska
- **Promotor:** mgr inż. Jakub Tomaszewski
- **Tytuł (PL):** Analiza porównawcza metod utwardzania środowisk kontenerowych pod kątem
  bezpieczeństwa i optymalizacji powierzchni ataku
- **Tytuł (EN):** Comparative analysis of container environment hardening methods for security
  and attack surface optimization
- **Cel:** kompleksowa analiza porównawcza skuteczności technik minimalizacji podatności
  (redukcja CVE i powierzchni ataku) oraz sformułowanie inżynierskich rekomendacji doboru
  baz systemowych.

Skaner jest **narzędziem badawczym**, nie produktem. Ciężar pracy leży w punktach 5–7.

### Zakres zatwierdzony

1. Wprowadzenie do aspektów bezpieczeństwa łańcucha dostaw i izolacji.
2. Przegląd narzędzi do skanowania i zdefiniowanie kryteriów doboru próby badawczej.
3. Zbudowanie systemu orkiestracji (pobieranie, skanowanie, parsowanie do analizy).
4. Zaprojektowanie i uruchomienie „matrycy testowej" (warianty o różnym stopniu utwardzenia).
5. Wielowymiarowa analiza statystyczna podatności (CVE, rozmiar, komponenty).
6. Porównanie wyników metod utwardzania (Slim, Alpine, Distroless vs Standard).
7. Wyciągnięcie wniosków (balans bezpieczeństwo vs funkcjonalność runtime).

### Jak zakres APD ma się do kroków implementacji

Częste zamieszanie: „Kroki 0–6" z rozdziału [Mikro-kroki](#mikro-kroki) **nie są** alternatywnym
planem pracy. To rozpisanie na zadania programistyczne **wyłącznie punktów 3 i 4** zatwierdzonego
zakresu. Pozostałe punkty albo poprzedzają kod, albo następują po nim.

| Punkt APD | Czym jest | Kroki kodu |
| --- | --- | --- |
| 1. Wprowadzenie, łańcuch dostaw, izolacja | tekst, literatura | brak — pisanie |
| 2. Przegląd narzędzi, kryteria doboru próby | tekst oparty na pomiarach | dane z Kroku 0 i 1 |
| 3. System orkiestracji | **kod** | Kroki 1, 2, 3, 6 |
| 4. Projekt i uruchomienie matrycy | **kod** | Kroki 4, 5 |
| 5. Analiza statystyczna | praca na wynikach | brak — po Kroku 6 |
| 6. Porównanie metod utwardzania | praca na wynikach | brak — po Kroku 6 |
| 7. Wnioski, balans bezpieczeństwo/funkcjonalność | praca na wynikach | brak — po Kroku 6 |

Wniosek, który warto mieć z tyłu głowy przy planowaniu czasu: **kroki kodu kończą się tam, gdzie
zaczyna się właściwy ciężar pracy**. Krok 6 produkuje tabelę z liczbami, a punkty 5–7 dopiero
z niej powstają. Rozbudowywanie skanera ponad to, czego wymaga matryca, nie przybliża do obrony.
Metody dla punktów 5–7: [Plan analizy statystycznej](#plan-analizy-statystycznej-punkty-57).

### Literatura

1. Rice L., *Container Security*, O'Reilly 2020
2. Vehent J., *Securing DevOps*, Manning 2018
3. NIST SP 800-190, *Application Container Security Guide*
4. Google Cloud, *Distroless Container Images*
5. FIRST, *CVSS v3.1 Specification Guide*
6. *SLSA Framework* documentation

### Stos technologiczny

- **Architektura:** narzędzia (Trivy, Python, zależności) zamknięte w kontenerze, żeby nie
  instalować ich na maszynie hosta. Pierwotnie w modelu Docker-out-of-Docker z mapowaniem
  `/var/run/docker.sock`; przy `--image-src remote` montowanie gniazda przestaje być potrzebne —
  patrz [Kontener orkiestrujący](#kontener-orkiestrujący-po-co-był-dood-i-co-z-niego-zostaje)
- **Język:** Python — `requests`, `pandas`, `tqdm`, `subprocess`
- **Skaner:** Aqua Security Trivy (wyniki JSON)
- **Źródła:** API Docker Hub oraz Google Container Registry

## Rejestry i ścieżki pobierania

To rozdział najczęściej mylony. Trzy różne hosty, trzy różne role.

### Trzy hosty, trzy role

| Host | Czym jest | Rola w badaniu |
| --- | --- | --- |
| `registry-1.docker.io` (Docker Hub) | kanoniczne źródło obrazów oficjalnych `library/*` i społecznościowych | **źródło** klas `standard`, `slim`, `alpine` |
| `mirror.gcr.io` | pull-through cache **Docker Huba**, hostowany na Artifact Registry | **wyłącznie ścieżka pobierania** dla obrazów z Huba |
| `gcr.io/distroless` | kanoniczny dom obrazów distroless Google | **źródło** klasy `distroless` |

**`mirror.gcr.io` to lustro Docker Huba, nie lustro distroless.** To jego jedyne przeznaczenie.
Nie zawiera obrazów distroless. `gcr.io/distroless` nie jest lustrem czegokolwiek — to
oryginalne, kanoniczne miejsce publikacji obrazów distroless.

Weryfikacja (13.09.2026):

```
mirror.gcr.io/v2/distroless/python3-debian12/manifests/latest  -> 404
gcr.io/v2/distroless/python3-debian12/manifests/latest         -> 200
```

`404` na lustrze jest dowodem rozdzielności: lustro widzi tylko Docker Huba.

### „Czy GCR nie zostało wyłączone?" — odpowiedź na obronę

Pytanie prawdopodobne na obronie, więc warto mieć gotową odpowiedź z cytatami. Mylone są
**usługa** i **domena**:

- **Wyłączona została usługa Container Registry** — z dniem 18.03.2025 nie da się już
  *zapisywać* obrazów do Container Registry, a stara infrastruktura składowania (kubełki Cloud
  Storage) jest wygaszona.
- **Domena `gcr.io` działa dalej**, obsługiwana teraz przez Artifact Registry. Dokumentacja
  Google stwierdza wprost: *„`gcr.io` URLs hosted on Artifact Registry, including Google-owned
  images with `gcr.io` URLs, are **not affected** by the Container Registry shutdown."*

Projekt distroless **celowo pozostaje na `gcr.io`**. Jego README zawiera osobny wpis FAQ
dokładnie na to pytanie:

> *Why is distroless still using `gcr.io` instead of `pkg.dev`? Distroless's serving
> infrastructure has moved to artifact registry but we still use the `gcr.io` domain. Users will
> get the benefits of the newer infrastructure without changing their builds.*

W wątku migracyjnym `GoogleContainerTools/distroless#1630` utrzymujący dodają: *„`gcr.io/distroless`
is now served by the AR infrastructure. The GCR infra is shutting down but the domain `gcr.io`
will continue to be served by AR"*, oraz że referencje obrazów pozostają bez zmian
i **uwierzytelnianie nie jest wymagane** do pobierania.

**Nie „modernizować" adresów na `pkg.dev`.** `pkg.dev/distroless/...` nie działa (wymaga
uwierzytelnienia i innej struktury ścieżek) — jedyną poprawną formą jest `gcr.io/distroless/...`.

Weryfikacja dostępności (13.09.2026) — wszystkie 12 repozytoriów bieżącej linii `debian13`
odpowiadają `200` bez uwierzytelniania:

```
static-debian13     200     java17-debian13     200     nodejs22-debian13   200
base-debian13       200     java21-debian13     200     nodejs24-debian13   200
base-nossl-debian13 200     java25-debian13     200     nodejs26-debian13   200
cc-debian13         200     java-base-debian13  200     python3-debian13    200
```

Linia `debian12` również pozostaje dostępna (`static`, `base`, `python3`, `nodejs22`, `java21`,
`cc` — wszystkie `200`), co daje starsze obserwacje bez dodatkowego ryzyka. Projekt jest aktywnie
utrzymywany (bieżące PR-y podbijające wersje pakietów, wrzesień 2026); harmonogramy wsparcia
poszczególnych linii są w `SUPPORT_POLICY.md` w repozytorium upstream — to źródło kryterium
„która wersja jest wspierana" do rozdz. 2.

**Zabezpieczenie metodologiczne niezależne od losu rejestru.** Praca jest pomiarem
punktu w czasie. Każdy obraz w matrycy jest pinowany digestem i datą pobrania (zgodnie z SLSA),
więc wynik pozostaje cytowalny i weryfikowalny nawet gdyby adresy kiedyś się zmieniły. Ryzyko
rejestru nie jest ryzykiem trafności wyników.

### Discovery vs pull — rozdzielenie, które trzeba utrzymać

Obrazy w badaniu pochodzą **zawsze z dwóch źródeł równolegle**: Docker Hub daje
`standard` / `slim` / `alpine`, GCR daje `distroless`. Lustro nie zmienia składu próby — jest
wyłącznie szczegółem transportowym mówiącym, skąd Trivy ściąga warstwy.

- `logical_ref` — obraz, który opisujesz w pracy (`python:3.11-slim`)
- `pull_ref` — skąd faktycznie lecą warstwy (`mirror.gcr.io/library/python:3.11-slim`)
- `registry` — `hub` / `gcr` / `mirror`

Zmiana `pull_ref` nigdy nie zmienia `logical_ref`. Ten sam obraz logiczny nie może wejść do
matrycy dwa razy (Hub + lustro = 1 wiersz).

### Trzy różne limity — nie mylić w pracy

| Limit | Czego dotyczy | Obejście |
| --- | --- | --- |
| API listowania | search, endpoint tagów; Hub zwraca `429` | cache + backoff + token PAT |
| **Offset paginacji** | **głębokość stronicowania dla żądań anonimowych; Hub zwraca `403`** | **token PAT; dla `library/` trik z `ordering`** |
| Pull warstw | `docker pull` / Trivy; konto darmowe ok. **200 pulli / 6 h** | lustro `mirror.gcr.io` |

#### Limit offsetu — odkryty 18.09.2026, zmienia wykonalność Kroku 3

Hub odmawia anonimowego stronicowania poniżej pewnej głębokości, zwracając `403` z treścią:

```
{"message":"pagination offset too large for anonymous requests; sign in to page further"}
```

Limit dotyczy **offsetu**, nie numeru strony (`page=2&page_size=50` przechodzi, `page=2&page_size=100`
już nie), i jest **różny dla różnych endpointów**. Zmierzone progi:

| Endpoint | Ostatni działający offset | Pierwszy zablokowany |
| --- | --- | --- |
| `/v2/repositories/library/` | 90 | 100 |
| `/v2/search/repositories/` | 100 | 200 |
| `/v2/repositories/{ns}/{name}/tags/` | 900 | 1000 (29.09.2026; wcześniej sprawdzono tylko 3900) |

Sprawdzone: zjawisko **nie zależy** od `User-Agent` ani od biblioteki klienckiej (identyczne
wyniki dla `requests` i `urllib`, dla nagłówka własnego i przeglądarkowego), więc nie jest to
wykrywanie bota, tylko celowa polityka API.

**Obejście dla `library/` bez tokenu.** Repozytoriów jest 181, a anonimowo widać najwyżej
pierwszą setkę. Dwa żądania z przeciwnych końców sortowania pokrywają jednak cały zbiór —
`ordering=pull_count` (malejąco) plus `ordering=-pull_count` (rosnąco) dają część wspólną
19 pozycji i sumę **dokładnie 181**, zgodną z deklarowanym `count`. Odwrócona semantyka
`ordering` przestaje więc być ciekawostką, a staje się narzędziem.

**Konsekwencja dla Kroku 3: token PAT jest wymagany, nie opcjonalny.** Tagów `python` jest
3923, czyli powyżej progu 3900 — ostatnia strona odpadnie. Dla `openjdk` (17 042 tagi)
anonimowo zobaczymy kilka procent zbioru, co uniemożliwiłoby deduplikację i dobór próby.

Przy 10 tys. skanów sam Hub to ~12,5 doby. Dokumentacja Google potwierdza, że pobrania przez
`mirror.gcr.io` **nie są liczone do limitu Docker Huba**. Lustro jest więc **częścią metodyki**,
nie optymalizacją „na później".

Wyłączenie Container Registry (18.03.2025) **nie dotyczy** ani `mirror.gcr.io`, ani obrazów
Google z adresami `gcr.io` — jedno i drugie działa dalej na Artifact Registry.

### Pokrycie lustra — szersze niż zakładał poprzedni plan, ale z dziurami

Poprzedni plan twierdził, że lustro obejmuje tylko `library/*` i ostrzegał „nie udawaj, że
`mirror.gcr.io` ma cały Hub". Pomiar (13.09.2026) pokazuje, że **przestrzenie nieoficjalne też
działają**:

```
mirror.gcr.io/bitnami/nginx      -> 200      mirror.gcr.io/library/nginx     -> 200
mirror.gcr.io/grafana/grafana    -> 200      mirror.gcr.io/library/postgres  -> 200
mirror.gcr.io/prom/prometheus    -> 200      mirror.gcr.io/library/redis     -> 200
mirror.gcr.io/jenkins/jenkins    -> 200      mirror.gcr.io/library/memcached -> 200
                                             mirror.gcr.io/library/traefik   -> 200
                                             mirror.gcr.io/library/caddy     -> 200
```

Stare, niszowe tagi również są dostępne, co przeczy obawie, że cache trzyma tylko obrazy
„frequently requested":

```
mirror.gcr.io/library/python:3.13-slim          -> 200
mirror.gcr.io/library/python:3.10.21-alpine3.24 -> 200
```

**Ale są dziury, i jedna trafia prosto w plan.** `openjdk` — wskazany w poprzednim planie jako
jedno z dwóch dominujących repozytoriów (17 042 tagi) — nie ma na lustrze żadnego z typowych
tagów (pomiar 29.09.2026 wykazał, że obecne są pojedyncze tagi EA, więc nie jest to dziura
całego repozytorium, tylko jego głównych manifestów):

```
mirror.gcr.io/library/openjdk:latest   -> 404
mirror.gcr.io/library/openjdk:17       -> 404
mirror.gcr.io/library/openjdk:21       -> 404
mirror.gcr.io/library/openjdk:17-slim  -> 404
mirror.gcr.io/library/openjdk:24-jdk   -> 404
```

**Konsekwencja projektowa:** fetcher nie może stosować bezwarunkowej reguły przepisywania
`library/{name}` → `mirror.gcr.io/library/{name}`. Musi **sondować dostępność** (`HEAD` na
manifest) i zapisywać wynik w matrycy, z jawnym fallbackiem na Hub. Obrazy spadające na Hub
obciążają licznik 200/6 h, więc muszą być budżetowane osobno.

**Dostępność jest cechą manifestu, nie repozytorium** (pomiar 29.09.2026). Repozytorium
`python` jest na lustrze, a mimo to bardzo stary tag z niego wypadł:

```
mirror.gcr.io/library/python:3.13.0a1-slim  -> 200   (2023)
mirror.gcr.io/library/python:2.7.9-wheezy   -> 404   (2015)
```

Do tego lustro to pull-through cache: **pierwsze 404 bywa chybieniem na zimno** — lustro
pobiera wtedy manifest z Huba i kolejne zapytanie zwraca 200 (zaobserwowane m.in. dla świeżych
tagów `jenkins`, `semeru`, `unit`, `spark`). Część braków jest natomiast trwała
(`openjdk:17`, `python:2.7.9-wheezy`, `java:8`, stare tagi `mysql`, `redis`, `wordpress`).
Sonda per repozytorium (jeden reprezentatywny tag) myliła się więc w obie strony i została
odrzucona.

Stąd sonda **per wiersz matrycy**: `HEAD mirror.gcr.io/v2/<repo>/manifests/<digest amd64>`,
chybienia ponawiane po odczekaniu (`--retry-delay`), wynik zapisywany jako `mirror_probe` =
`hit` / `cold_miss` / `miss`; tylko `miss` kieruje obraz na Hub. Uruchamiana jest dopiero na
wybranej matrycy (po Kroku 5), żeby nie odpytywać setek tysięcy tagów, które i tak odpadną,
i bez cache HTTP, który utrwaliłby pierwsze 404.

Dodatkowo dokumentacja Google zaznacza, że obraz usunięty z Huba może pozostać w cache
**do kilku dni**. To kwestia trafności: teoretycznie można przeskanować obraz, którego już nie
ma w źródle. Do zapisania jako ograniczenie metodologiczne.

**Zabezpieczenie: porównanie digestów.** Lustro zwraca nagłówek `Docker-Content-Digest`, który
dla sprawdzonych tagów jest identyczny z `digest` z API Huba (np. `python:3.13-slim` →
`sha256:7c61056e…` w obu). Sonda per tag porównuje oba digesty, a `pull_ref` jest pinowany
digestem, nie tagiem — dzięki temu skanowany jest dokładnie artefakt opisany w matrycy,
niezależnie od stanu cache lustra.

## Ustalenia zweryfikowane empirycznie

Fakty do zacytowania w rozdz. 2 (kryteria doboru próby):

- Populacja `library/` liczy **181 repozytoriów** — tyle deklaruje `count` i tyle daje suma
  dwóch przebiegów po `ordering` (zweryfikowane 18.09.2026). Pierwotny `page_size=100`
  w `scanner.py` obcinał ją arbitralnie. Uwaga: zwykła paginacja **nie wystarczy**, bo
  anonimowy offset jest ograniczony — patrz [Limit offsetu](#limit-offsetu--odkryty-18092026-zmienia-wykonalność-kroku-3).
- `page_size` jest **po cichu ścinany do 100**. Przy `page_size=1000` Hub zwraca 100 rekordów,
  ale odsyła `page_size=1000` w polu `next`, więc nic nie sygnalizuje obcięcia. Nie wolno liczyć
  oczekiwanej liczby stron jako `count / page_size` z inną wartością.
- API Docker Hub ma **odwróconą semantykę sortowania**: `ordering=pull_count` zwraca malejąco,
  `ordering=-pull_count` rosnąco. Przy sortowaniu wyników polegamy na kliencie, ale sama
  dwukierunkowość jest wykorzystana celowo jako obejście limitu offsetu (patrz wyżej).
- **Dwa endpointy Kroku 1 mają prawie rozłączne pola.** Wspólne są tylko `pull_count`
  i `star_count`:

  | | `/repositories/library/` | `/search/repositories/` |
  | --- | --- | --- |
  | nazwa | `name` + `namespace` | `repo_name` (sklejone) |
  | opis | `description` | `short_description` |
  | data | `last_updated`, `date_registered` | **brak** |
  | oficjalność | brak (wszystko jest oficjalne) | `is_official` |
  | rozmiar | `storage_size` | brak |

  Konsekwencje: potrzebne są **dwie funkcje normalizujące** do wspólnego rekordu; `repo_name`
  wymaga rozbicia, bo oficjalne przychodzą jako `nginx`, a pozostałe jako `bitnami/nginx`
  (bez tego klucz deduplikacji się rozjeżdża i to samo repo wchodzi dwa razy); `last_updated`
  dla wyników z wyszukiwania zostaje puste i jest uzupełniane w Kroku 3.
- **Kolejność źródeł w Kroku 1 jest nośna.** Ponieważ rekord z `library/` jest bogatszy,
  przetwarzamy go **przed** wyszukiwaniem i pomijamy klucze już widziane. Dzięki temu nie
  trzeba pisać logiki scalania rekordów. Weryfikacja przebiegu z 18.09.2026: 1764 unikalne
  repozytoria, zero duplikatów, `last_updated` obecne w dokładnie 181 rekordach.
- **Liczba 1764 była artefaktem limitu anonimowego, nie kryterium doboru.** Przebieg z tokenem
  (29.09.2026, 47 stron na zapytanie) daje **12 971** repozytoriów: 181 oficjalnych + 12 790
  z wyszukiwania `python` / `java` / `nodejs`. Wyszukiwarka zwraca głównie szum — rozkład
  `pull_count` dla wyników z wyszukiwania:

  | Próg `pull_count` | Repozytoriów |
  | --- | --- |
  | ≥ 0 | 12 790 |
  | ≥ 1 000 | 2 535 |
  | ≥ 10 000 | 645 |
  | ≥ 100 000 | 172 |
  | ≥ 1 000 000 | 58 |

  Próg popularności musi więc być jawnym, zapisanym kryterium doboru próby (rozdz. 2),
  a nie skutkiem ubocznym limitu paginacji. Katalog z Kroku 1 zostaje pełny (to spis populacji),
  próg stosuje Krok 3 (`GetTags.py --min-pulls`).
- Populacja tagów to ~700 tys. (`openjdk` 17042, `node` 9036, `python` 3911). Deduplikacja
  redukuje ją o ~2/3 (100 tagów `python` = 33 unikalne obrazy).
- Endpoint tagów zwraca `full_size`, `digest`, `tag_last_pushed` oraz tablicę `images[]`
  z rozmiarem i digestem per architektura. **Wymiar „rozmiar" z pkt 5 dostajemy bez pobierania
  obrazów.**
- `gcr.io/distroless` zawiera tylko ~7 rodzin: `static`, `base`, `cc`, `java` (11/17/21/25),
  `nodejs` (14–26), `python3`, `dotnet` (przestarzały). Distroless dla `nginx`, `postgres`,
  `redis`, `mysql`, `php`, `ruby` **nie istnieje** — to ograniczenie metodologiczne do opisania
  w pracy, nie brak w kodzie.
- Każde repo distroless ma **4 stabilne aliasy**: `latest`, `debug`, `nonroot`, `debug-nonroot`
  (pozostałe ~13 tys. tagów to identyfikatory commitów). Do badania bierzemy **wyłącznie
  `latest`** — patrz Konsekwencje 1 i 2.
- Rozmiary referencyjne `python`: `3.10.21-alpine` ~20 MB, `3.10.21-slim` ~45 MB,
  `latest` ~415 MB.

## Warianty distroless — dowody pomiarowe

Poprzedni plan opisywał cztery aliasy jako **układ czynnikowy 2×2** (powłoka × użytkownik).
Pomiar manifestów `gcr.io/distroless/python3-debian12` (13.09.2026) pokazuje, że to
uproszczenie:

| Tag | Liczba warstw | Różnica względem `latest` |
| --- | --- | --- |
| `latest` | 43 | — (config `2352e7d5…`) |
| `nonroot` | 43 | **warstwy identyczne co do bajta**; różni się tylko config (`8dc1c27e…`) |
| `debug` | 44 | dokładnie **jedna dodatkowa warstwa, 740 164 B** (busybox); config `eca33119…` |
| `debug-nonroot` | 44 | warstwy identyczne z `debug`; różni się tylko config (`61f2d137…`) |

Cztery tagi to zatem **tylko dwa różne inwentarze pakietów**: `{latest, nonroot}` oraz
`{debug, debug-nonroot}`.

Odczyt configu potwierdza, że jedyną różnicą `latest` vs `nonroot` jest użytkownik:

```
python3-debian12:latest   ->  User = "0"
python3-debian12:nonroot  ->  User = "65532"
```

### Pułapka: distroless ma wyzerowane znaczniki czasu

Config obrazów distroless raportuje `created = 1970-01-01T00:00:00Z`. To celowy efekt budowania
reprodukowalnego (Bazel zeruje znaczniki czasu dla determinizmu), nie błąd rejestru.

**Konsekwencja:** pola `created` z configu **nie wolno** używać jako zmiennej „wiek obrazu" ani
jako kryterium świeżości — dla całej klasy `distroless` byłoby stałą równą epoce, co
systematycznie zaburzyłoby każdą analizę korelującą wiek z liczbą CVE. Wiek obrazów z Huba
bierzemy z `tag_last_pushed` z API, a dla distroless trzeba albo zrezygnować z tego wymiaru,
albo wziąć datę z metadanych rejestru (`timeUploaded`), nie z configu. Do zapisania jako
ograniczenie w rozdz. 5.

### Konsekwencja 1 — skanujemy tylko `latest` (decyzja podjęta)

Identyczne warstwy to identyczny inwentarz pakietów, czyli **identyczny zbiór CVE**. Skanowanie
obu wariantów byłoby więc pobraniem tej samej informacji dwa razy.

**Decyzja:** z każdego repozytorium distroless bierzemy **wyłącznie tag `latest`** — jeden wiersz
matrycy na repozytorium. `nonroot` nie jest skanowany.

**Dlaczego `latest`, a nie `nonroot`.** Wybór nie jest dowolny, mimo że dla CVE oba są
równoważne. Obrazy z Huba w klasach `standard`, `slim` i `alpine` domyślnie działają jako root.
Gdybyśmy jako reprezentanta distroless wzięli `nonroot` (`User = "65532"`), do delty
`distroless − standard` wszedłby **dodatkowy czynnik: zmiana użytkownika**, którego pozostałe
klasy nie mają. `latest` ma `User = "0"`, czyli identycznie jak warianty z Huba, więc uprzywilejowanie
pozostaje **stałą w całym porównaniu** i delta mierzy wyłącznie różnice w userlandzie i zestawie
pakietów. To eliminuje confounder, którego inaczej trzeba by tłumaczyć w rozdz. 6.

**`nonroot` nadal jest treścią pracy — tylko nie obserwacją.** Jego właściwości są udowodnione
inspekcją manifestów, bez żadnego skanu: identyczne warstwy, `User = "0"` vs `User = "65532"`.
Wynika z tego wniosek wart osobnego akapitu w punkcie 7: **utwardzenie użytkownika jest w
distroless darmowe** — realizuje zalecenie NIST SP 800-190 o nieuruchamianiu jako root przy
zerowej zmianie liczby CVE i zerowej utracie funkcjonalności. To jedyny punkt w całym badaniu,
gdzie utwardzanie nic nie kosztuje, co dobrze kontrastuje z pozostałymi klasami, gdzie redukcja
CVE zawsze wiąże się z utratą możliwości runtime.

W matrycy odnotowujemy to kolumną `nonroot_available` (własność repozytorium), a nie osobnym
wierszem.

### Konsekwencja 2 — `debug` wyłączony ze zbioru (decyzja podjęta)

**Decyzja:** warianty `debug` i `debug-nonroot` **nie wchodzą do badania**. Nie są rekomendowane
produkcyjnie, więc nie reprezentują realnej metody utwardzania.

Łącznie z Konsekwencją 1 daje to jedną regułę dla całego GCR: **z czterech aliasów zostaje
wyłącznie `latest`**. Fetcher odfiltrowuje `debug`, `debug-nonroot` i `nonroot` już na etapie
enumeracji GCR (Krok 2), a nie dopiero w analizie.

Wiersze `debug` w tabeli powyżej zostają w dokumencie **wyłącznie jako dowód pomiarowy** — to
one pokazują, że aliasy distroless redukują się do dwóch inwentarzy pakietów, co uzasadnia
Konsekwencje 1 i 3. Nie są elementem próby.

Skutkiem jest brak kontrastu wewnątrz identycznej bazy, więc punkt 7 opiera się na innym
schemacie — patrz [Punkt 7: standard jako baseline](#punkt-7-standard-jako-baseline).

### Konsekwencja 3 — błąd w regule deduplikacji

Poprzedni plan deduplikował **po digescie manifestu**. Para `latest` / `nonroot` pokazuje, że to
niewystarczające: mają **różne digesty manifestu i identyczne warstwy**, więc deduplikacja po
digescie ich nie sklei i N spuchnie o duplikaty profili CVE — dokładnie ta pseudoreplikacja,
której plan miał zapobiegać.

W samym GCR problem znika przez decyzję z Konsekwencji 1 (bierzemy tylko `latest`), ale reguła
zostaje potrzebna **po stronie Huba**, gdzie skala jest znacznie większa: aliasy w rodzaju
`3.10-alpine`, `3.10.21-alpine` i `3.10.21-alpine3.24` wskazują ten sam obraz, a część tagów
różni się wyłącznie metadanymi.

**Poprawka:** kluczem deduplikacji dla analizy CVE musi być **lista warstw** (albo `diff_ids`
z rootfs), nie digest manifestu. Digest manifestu zostaje jako identyfikator artefaktu do
cytowania w pracy (pinowanie zgodne z SLSA), ale nie jako klucz niezależności obserwacji.

**Digest indeksu to nie digest obrazu amd64** (pomiar 29.09.2026). `python:3.13`
i `python:3.13-trixie` mają **różne digesty indeksu**, bo pierwszy indeks zawiera dodatkowo
obrazy Windows, ale wskazują **ten sam manifest amd64**. `python:3.13-slim` i
`python:3.13-slim-trixie` są z kolei zwykłymi aliasami z identycznym digestem. Dlatego fetcher
zapisuje obok `digest` (indeks) także `arch_digest` (manifest amd64) i to on jest pierwszym,
tanim stopniem deduplikacji — na próbie `library/` + wyszukiwanie 271 884 wierszy daje tylko
146 894 unikalnych obrazów amd64. `layer_key` pozostaje drugim stopniem, dla obrazów o różnych
manifestach i identycznych warstwach. `pull_ref` jest pinowany właśnie `arch_digest`, więc
skanowany jest dokładnie ten obraz, który został zdeduplikowany.

## Taksonomia utwardzania

Wersja obowiązująca używa **czterech klas** z flagami jako osobnymi wymiarami:

- `standard` — pełny userland dystrybucji (`latest`, `3.13`, `3.13-trixie`)
- `slim` — `-slim`, `-slim-bookworm`; nadal `apt` i powłoka
- `alpine` — `-alpine`, `-alpine3.24`; musl libc, busybox, apk
- `distroless` — brak menedżera pakietów i powłoki

Taksonomia nie ma czynników ortogonalnych — klasa jednoznacznie opisuje obraz. Uprzywilejowanie
jest **stałą całego badania** (wszystkie skanowane obrazy działają jako root, `User = "0"`), co
jest celowe: dzięki temu delty z punktu 7 nie są zanieczyszczone zmianą użytkownika
(patrz Konsekwencja 1).

Aliasy `debug`, `debug-nonroot` i `nonroot` są **odfiltrowywane na etapie pobierania** i nie mają
reprezentacji w taksonomii (Konsekwencje 1 i 2). Dostępność wariantu `nonroot` jest zapisywana
jako `nonroot_available` i omawiana jakościowo, bez skanu.

### Reguły klasyfikacji tagów (Krok 4, `src/Classify.py`)

Klasa i linia systemu są wyprowadzane **z samej nazwy tagu**, tokenami po `-`. Reguły są
deterministyczne i zapisane w kodzie, żeby dało się je przytoczyć w rozdziale 2:

- **Wykluczenia** (`excluded_reason`, wiersz zostaje w pliku, ale nie trafia do matrycy):
  `windows` (tokeny `windowsservercore`, `nanoserver`, `ltsc…`), `onbuild` (obraz-szablon,
  nie baza) oraz `no_amd64` (indeks bez obrazu linux/amd64 — skanujemy jedną architekturę).
- **`alpine` wygrywa ze `slim`** — tag `…-slim-alpine` to alpine.
- W repozytoriach bazowych (`library/alpine`, `library/debian`, `library/ubuntu`) linia systemu
  pochodzi z wersji repozytorium (`alpine:3.22` → `alpine3.22`), a `library/alpine` jest
  zawsze klasy `alpine`.
- Nazwy suit Debiana (`sid`, `testing`, `stable`, `oldstable`…) są interpretowane **tylko
  w `library/debian`** — w innych repozytoriach `unstable` oznacza kanał wydań aplikacji
  (np. `mongo`), nie Debiana.
- Rozpoznawane linie: kodowe nazwy Debiana (`squeeze`…`forky` → `debianN`), Ubuntu, `alpineX.Y`
  oraz bazy firmowe (`oraclelinux`, `ubi`, `centos`, `amazonlinux`, `rockylinux`, `almalinux`).
- **`prerelease`** to flaga, nie klasa: `rc`, `alpha`, `beta`, `preview`, `dev`, `nightly`,
  `edge`, `ea` (buildy early access Javy) i wersje z sufiksem tego typu.
  Wydania przedpremierowe **nie wchodzą do próby** (decyzja Kroku 5, 01.10.2026).
- **Linia systemu z aliasu.** Tag bez sufiksu systemu (`python:3.13`, `latest`) dziedziczy linię
  od tagu o tym samym `arch_digest` (`3.13-trixie` → `debian13`), ale tylko gdy wszystkie aliasy
  wskazują jedną linię. Przy sprzeczności (np. obrazy `docker` z dwiema liniami alpine, `gradle`
  z dwiema liniami Ubuntu) pole zostaje puste zamiast zgadywać. Pochodzenie zapisuje
  `os_line_source`.

`family` to dla Huba nazwa repozytorium, a dla distroless nazwa mapowana na technologię
partnera: `python3-*` → `python`, `nodejs*` → `node`, `java*` → `java`, a `static`, `base`
i `cc` → `base`. `vendor` to przestrzeń nazw (`library`, `bitnami`, `distroless`…).

## Punkt 7: standard jako baseline

Wobec wyłączenia wariantów `debug` punkt 7 (balans bezpieczeństwo vs funkcjonalność runtime)
realizowany jest przez **porównanie każdej klasy utwardzenia do klasy `standard` tej samej
technologii**. `standard` jest kategorią referencyjną, a wynikiem są przyrosty względem niej.

### Schemat

Dla każdej technologii `family`, która ma wariant `standard` (na Hubie ma go zawsze) liczymy
delty:

```
delta(slim)       = metryka(slim)       - metryka(standard)
delta(alpine)     = metryka(alpine)     - metryka(standard)
delta(distroless) = metryka(distroless) - metryka(standard)
```

To schemat **sparowany wewnątrz technologii**, co jest jego główną zaletą: `python:3.13-slim`
porównujemy z `python:3.13`, nie ze średnią po wszystkich obrazach. Znika przez to wpływ tego,
jaka technologia trafiła do próby, a kolumna `paired` wskazuje wiersze zdatne do analizy.

### Dwie osie metryk

Sam spadek liczby CVE nie odpowiada na pytanie „kiedy utwardzanie zaczyna przeszkadzać" —
potrzebna jest druga oś. Obie pochodzą z tego samego skanu Trivy z `--list-all-pkgs`, bez
uruchamiania kontenerów:

- **Bezpieczeństwo:** liczba CVE (łącznie i w rozbiciu na severity wg CVSS v3.1), gęstość CVE
  na pakiet, rozmiar obrazu.
- **Funkcjonalność:** liczba pakietów w SBOM, obecność powłoki (`bash`, `sh`, `busybox`),
  obecność menedżera pakietów (`apt`, `apk`), obecność narzędzi diagnostycznych.

Wykres przyrostów na tych dwóch osiach (redukcja CVE vs utrata możliwości runtime) jest
bezpośrednią odpowiedzią na punkt 7 i podstawą rekomendacji doboru baz.

### Ograniczenie do zapisania w pracy

Kontrast `distroless` vs `standard` zmienia jednocześnie bazę systemową, implementację libc
(glibc vs musl przy alpine), zestaw pakietów i obecność powłoki. Zmierzona delta jest więc
**zagregowanym efektem całego podejścia do utwardzania**, a nie efektem jednego czynnika.

Trzeba to napisać wprost i nie twierdzić, że wyizolowano wpływ pojedynczej zmiennej (np. samej
obecności powłoki) — do takiego wniosku potrzebny byłby kontrast w obrębie identycznej bazy,
którego świadomie nie uwzględniamy. Dla celu pracy, czyli **rekomendacji doboru baz systemowych**,
efekt zagregowany jest właściwą jednostką: inżynier wybiera cały obraz bazowy, nie pojedynczą
warstwę.

Dodatkowe zawężenie: distroless istnieje tylko dla ~5 rodzin (`python`, `nodejs`, `java`, `cc`,
`static`), więc trójkąt `standard`–`slim`/`alpine`–`distroless` domyka się dla kilku technologii.
Dla pozostałych porównanie sięga tylko `slim` i `alpine`. Liczebność obu podzbiorów raportujemy
osobno.

## Plan analizy statystycznej (punkty 5–7)

Ustalone 01.10.2026. Analiza powstaje po Kroku 6, na tabeli wyników skanu. Wszystkie testy są
w `scipy.stats` (`wilcoxon`, `friedmanchisquare`, `spearmanr`).

### Para — jednostka porównania

Para to dwa obrazy **tej samej technologii, w tej samej wersji i na tej samej bazie**, różniące
się tylko metodą utwardzenia. Grupa z matrycy (Krok 5):

| Obraz | Klasa |
| --- | --- |
| `python:3.13.15-trixie` | `standard` — punkt odniesienia |
| `python:3.13.15-slim-trixie` | `slim` |
| `python:3.13.15-alpine3.23` | `alpine` |
| `gcr.io/distroless/python3-debian13` | `distroless` |

daje trzy pary: `slim`–`standard`, `alpine`–`standard`, `distroless`–`standard`. Dla każdej
liczymy deltę metryki.

Para jest potrzebna, bo **średnie klas nie są porównywalne**. Do `standard` wpadają `wordpress`,
`archlinux` czy `gradle`, do `alpine` inny zestaw technologii — różnica średnich mierzyłaby
skład klasy, nie utwardzenie (paradoks Simpsona). W parze technologia i wersja są stałe.
Porównań średnich klas **nie wykonujemy**.

### Dane z jednego skanu

- **Bezpieczeństwo:** liczba CVE łącznie i per severity (`CRITICAL` / `HIGH` / `MEDIUM` /
  `LOW`), CVE z dostępną poprawką, gęstość CVE na pakiet.
- **Powierzchnia ataku:** rozmiar obrazu (`arch_size` z API Huba), liczba pakietów.
- **Funkcjonalność:** obecność powłoki (`bash`, `sh`, `busybox`), menedżera pakietów
  (`apt`, `apk`), narzędzi diagnostycznych.

### Punkt 5 — wielowymiarowa analiza podatności (cała matryca)

- **Statystyki opisowe per klasa:** mediana, kwartyle, rozstęp CVE, rozmiaru i liczby pakietów.
  Mediana zamiast średniej, bo rozkład CVE jest skrajnie skośny (pilotaż: 3 612 vs 20).
- **Korelacja Spearmana** CVE z rozmiarem i liczbą pakietów — czy większy obraz to więcej CVE.
  Spearman, bo zależności nie są liniowe, a dane mają wartości skrajne.
- **Świeżość bazy:** CVE względem linii systemu (`debian9`…`debian13`) i `tag_last_pushed`.
  Pilotaż pokazał, że świeżość bazy potrafi przeważyć liczbę pakietów.
- **Rozkład severity** per klasa — udział `CRITICAL` i `HIGH`.

Tu wchodzą też obrazy bez pary — dają obraz całego ekosystemu oficjalnych obrazów.

### Punkt 6 — porównanie metod utwardzania (tylko pary)

- **Delta względna:** `(CVE_utwardzony − CVE_standard) / CVE_standard`; to samo dla rozmiaru
  i liczby pakietów. Względna, bo spadek o 200 CVE znaczy co innego przy 300 i przy 3 600.
- **Test Wilcoxona dla par** (*signed-rank*), osobno dla `slim`, `alpine`, `distroless`:
  czy obraz utwardzony ma systematycznie mniej CVE niż jego `standard`. Nieparametryczny
  odpowiednik testu t dla par — dane nie mają rozkładu normalnego.
- **Wielkość efektu:** mediana delt z przedziałem ufności. Przy tysiącach par test prawie
  zawsze wyjdzie istotny, więc ważniejsze jest *o ile* spada liczba CVE.
- **Zależność obserwacji.** Pary z jednego repozytorium nie są niezależne (np. 783 pary `slim`
  z zaledwie 25 repozytoriów). Główny test wykonujemy na **medianach delt per repozytorium** —
  jedno repozytorium = jedna obserwacja. Wynik na wszystkich parach raportujemy pomocniczo.
- **Porównanie metod między sobą:** **test Friedmana** na grupach z kompletem wariantów
  (pomiary powtarzane, bez założenia normalności) — np. czy `alpine` redukuje CVE bardziej
  niż `slim`. Główny kontrast metod to grupy `alpine`+`slim`+`standard` (bez wymogu
  distroless). Pełny czworokąt z distroless jest za rzadki na filar wnioskowania — patrz
  [Niepełne grupy](#niepełne-grupy--jak-analizować-w-inżynierce).
- **Distroless jako studium przypadku.** Po przebiegu 06.10.2026: **27 par** w 4 technologiach
  (`python`, `node`, `openjdk`, `debian`) — za mało na mocne uogólnienie. Tabela delt per
  technologia i linia Debiana, bez przedstawiania tego jako reprezentatywnej próby ekosystemu.

### Niepełne grupy — jak analizować w inżynierce

Ustalenie 06.10.2026 po matrycy z lustra. **Analiza nie wymaga pełnego układu czterech klas
w każdej grupie.** `standard` jest w grupie **raz** (jeden skan); delty `slim`/`alpine`/
`distroless` liczą się względem tego samego baseline. Nie buduje się osobnych par
„utwardzony vs utwardzony” (np. `distroless`–`alpine`) jako jednostki losowania ani skanu.

**Rozkład składu grup (matryca 06.10.2026, 7 016 grup):**

| Skład grupy | Liczba | Rola w analizie |
| --- | --- | --- |
| sam `standard` | 3 797 | tylko punkt 5 (opis ekosystemu) |
| `slim`+`standard` | 1 209 | Wilcoxon slim |
| `alpine`+`standard` | 1 034 | Wilcoxon alpine |
| `alpine`+`slim`+`standard` | 294 | Friedman slim vs alpine (główny kontrast metod) |
| `distroless`+`slim`+`standard` | 18 | studium distroless |
| pełne 4 klasy | **8** | Friedman z distroless — wynik pomocniczy / ilustracja |
| sam `alpine` / sam `slim` / sam `distroless` | 470+168+15 | descriptive lub bez pary |
| `distroless`+`standard` (bez slim/alpine) | 1 | para distroless |
| `alpine`+`slim` bez `standard` | 2 | descriptive, bez delty |

Wśród 2 564 grup `paired`: brak distroless w 2 537, brak alpine w 1 228, brak slim w 1 035.
To odzwierciedla podaż wariantów, nie błąd matrycy.

**Mapowanie na punkty APD:**

1. **Punkt 5** — cała matryca (~9,9 tys. obrazów), w tym samotne `standard`. Pełna grupa
   niepotrzebna.
2. **Punkt 6 — slim / alpine vs `standard`** — Wilcoxon osobno na parach (1 529 slim,
   1 336 alpine). Główny wynik: **mediana delt per repozytorium** (21 repo ze `slim`,
   53 z `alpine`); wynik na wszystkich parach tylko pomocniczo.
3. **Punkt 6 — slim vs alpine** — Friedman (lub porównanie delt) na **294** grupach
   z oboma wariantami + `standard`. To filar „która metoda redukuje CVE bardziej”.
4. **Punkt 6 — distroless** — studium przypadku na 27 parach / 4 technologiach; tabela,
   nie uogólnienie na ekosystem. Zdanie do ograniczeń: Google nie publikuje distroless
   dla nginx, postgres, redis itd.
5. **Punkt 6 — pełne czwórki (8 grup)** — ostrożny wynik pomocniczy przy Friedmanie
   z udziałem distroless; **nie** filar obrony.
6. **Punkt 7** — wykres dwóch osi per para względem `standard`; rekomendacje z delt
   slim/alpine (mocne N) + akapit o distroless i `nonroot` (jakościowo).

**Czego nie robić w pracy:** uśredniać klasy globalnie (paradoks Simpsona); udawać, że
N=8 czwórek = mocny test czterech metod; mieszać delt distroless z deltami slim w jednym
„rankingu” bez zastrzeżenia liczebności; skanować `standard` wielokrotnie pod każdą parę.

**Zdanie do rozdz. 2 / ograniczeń:** *Utwardzone warianty nie są standardem ekosystemu;
pełny trójkąt lub czworokąt zamyka się dla nielicznych technologii. Porównania metod
prowadzimy na parach względem `standard`; distroless raportujemy osobno jako studium
przypadku.*

### Punkt 7 — bezpieczeństwo vs funkcjonalność

- **Wykres dwóch osi** per para: redukcja CVE względem `standard` vs utrata funkcjonalności
  (spadek liczby pakietów, brak powłoki, brak menedżera pakietów). Każda klasa to osobna chmura.
- **Tabela cech runtime'u** per klasa: odsetek obrazów z powłoką, `apt`/`apk`, narzędziami
  diagnostycznymi. Bez testów — cechy wynikają wprost z budowy obrazów (distroless nie ma
  powłoki z definicji).
- **Rekomendacje doboru baz** z obu osi (np. „`slim` daje X% redukcji CVE przy zachowaniu
  powłoki i `apt`”) plus wniosek o `nonroot`: utwardzenie użytkownika przy zerowej zmianie CVE.

### Rozkład klas w matrycy — jak to opisać

`standard` stanowi ok. 64% obrazów w matrycy z 06.10.2026 (6 361 z 9 923) — nadal większość,
bo tak wygląda podaż na Hubie. Wynika to z tego, że na repozytoriach `library/` tylko część
oferuje `slim` lub `alpine` (`slim` 21 repo z parą, `alpine` 53). To wynik sam w sobie
(rozdz. 2 / 6): **utwardzone warianty nie są standardem ekosystemu.**

Dla punktów 6–7 udział klasy nie ma znaczenia — liczy się liczba par i liczba repozytoriów
z parą, raportowane osobno per klasa. Zdanie do pracy: *rozkład klas odzwierciedla podaż
wariantów w ekosystemie obrazów oficjalnych; porównania metod utwardzania prowadzone są
wyłącznie na parach w obrębie tej samej technologii i wersji.*

**Losowanie w dwóch warstwach (decyzja 05.10.2026, korekta `pair_cap` 06.10.2026).** Pierwsza
wersja losowania brała tylko 783 z 3 392 dostępnych par `slim`, bo limit 150 ciął repozytoria
z największą liczbą par (`python`, `node`, `openjdk`), a miejsce zajmowały grupy z samym
`standard`. Matryca ma dwie warstwy, zapisane w kolumnie `stratum`:

- **`pairs`** — grupy sparowane. Limit na repozytorium: najpierw 300 (05.10), potem
  **bez praktycznego limitu** (`--pair-cap 99999`, domyślnie w `Matrix.py`) — inaczej
  ~1,9 tys. obrazów w parach zostawało poza matrycą (głównie `library/node` i
  `library/debian`). Do punktów 6–7. Dominacja `node`/`debian` w N jest OK, bo główny test
  to mediana delt **per repozytorium**.
- **`descriptive`** — grupy bez pary, limit 150, dopełniają matrycę do 10 tys. **Wyłącznie do
  punktu 5** (opis ekosystemu); nie wchodzą do porównań metod utwardzania.

**Przebieg 06.10.2026 (po sondzie lustra) + `layers` 07.10.2026:** 9 923 obrazów — `pairs`
5 469 (1 529 par `slim`, 1 336 `alpine`, 27 `distroless`) i `descriptive` 4 454. Klasy:
6 361 `standard`, 1 808 `alpine`, 1 699 `slim`, 55 `distroless`. Sonda: 9 459 `hit`,
2 206 `cold_miss`, **16 377 `miss`** (~58% kandydatów tylko na Hubie — odrzucone). Do targetu
10 tys. brakuje 77 obrazów (wyczerpana pula `descriptive` pod `desc_cap`). `layers`: wszystkie
9 923 manifesty z listą warstw, **0** kolizji `layer_key`, N bez zmian. Symulacja sprzed
sondy nie obowiązuje — obowiązują liczby po `miss` i po `layers`.

## Pilotaż weryfikujący metodykę (13.09.2026)

Pięć obrazów przeskanowanych Trivy `v0.74.0` z zamrożoną bazą, `--image-src remote`,
`--scanners vuln --list-all-pkgs`, **bez demona Dockera**. Cel: sprawdzić architekturę i schemat
delt, zanim uruchomimy 10 tys. skanów.

| Obraz | OS wg Trivy | CVE | Pakiety |
| --- | --- | --- | --- |
| `python:3.13` (standard) | debian 13.6 | 3612 | 488 |
| `python:3.13-slim` | debian 13.6 | 181 | 106 |
| `distroless/python3-debian13` | debian 13.6 | **151** | 38 |
| `distroless/python3-debian12` | debian 12.13 | **258** | 34 |
| `alpine:latest` | alpine 3.22 | 20 | 16 |

### Co pilotaż potwierdził

- **Architektura działa.** Skany przez `mirror.gcr.io` i `gcr.io/distroless` wykonały się bez
  demona Dockera, wyłącznie po HTTPS. Czasy 2–7 s na obraz przy ciepłym cache warstw, więc
  10 tys. skanów jest realne w godzinach, nie dniach.
- **`--skip-db-update` działa** — kampania na zamrożonej bazie jest wykonalna.
- **Obie osie z jednego skanu.** `--list-all-pkgs` daje liczbę pakietów obok liczby CVE, czyli
  metryka funkcjonalności z pkt 7 nie wymaga uruchamiania kontenerów.
- **Porządek delt jest monotoniczny — ale tylko na tej samej bazie:** 3612 → 181 → 151 CVE przy
  488 → 106 → 38 pakietach.

### Wymóg, który z tego wynika: dopasowanie linii Debiana

Wariant `-debian12` **łamie porządek**: ma 258 CVE, czyli **więcej niż `slim`** (181), mimo
**trzykrotnie mniejszej liczby pakietów** (34 vs 106). Powód nie jest związany z utwardzaniem —
to inna, starsza baza (debian 12.13 vs 13.6).

**Wniosek dla fetchera:** przy parowaniu trzeba dobierać **linię distroless zgodną z bazą
wariantu z Huba**. Dla `python:3.13` (debian 13.6) partnerem jest `python3-debian13`, nie
`python3-debian12`. Wrzucenie obu linii do jednej klasy `distroless` bez kontroli wersji bazy
odwróciłoby wniosek pkt 6 — distroless wypadłby gorzej od `slim`.

Konkretnie: albo ograniczamy distroless do linii zgodnej z bazą partnera, albo wprowadzamy wersję
bazy jako **jawny czynnik** w modelu. Pierwsze jest prostsze i wystarczające.

### Wynik uboczny wart opisania w pracy

**Mniej pakietów nie znaczy mniej CVE.** `distroless-debian12` ma 34 pakiety i 258 CVE, a
`python:3.13-slim` 106 pakietów i 181 CVE. Świeżość bazy systemowej dominuje nad samą liczbą
komponentów. To osłabia potoczne założenie „mniejszy obraz = bezpieczniejszy" i jest dobrym
materiałem do rekomendacji z pkt 7: liczy się nie tylko *ile* pakietów, ale *jak świeże* są ich
wersje.

> Wcześniejszy plan proponował skalę porządkową `H0`–`H4` (STANDARD / SLIM / ALPINE /
> DISTROLESS / STATIC) z `has_shell` i `nonroot` jako czynnikami ortogonalnymi. Został
> zastąpiony wariantem 4-klasowym. Jeśli wrócimy do pięciostopniowej skali, trzeba to
> rozstrzygnąć raz i zapisać, bo przesądza o kształcie analizy w pkt 5–6.

## Schemat matrycy testowej

| Kolumna | Znaczenie |
| --- | --- |
| `family` | technologia znormalizowana — czynnik grupujący w analizie |
| `variant` | klasa utwardzenia (`standard` / `slim` / `alpine` / `distroless`) |
| `logical_ref` | obraz opisywany w pracy |
| `pull_ref` | skąd Trivy ściąga warstwy |
| `registry` | `hub` / `gcr` / `mirror` |
| `mirror_ok` | czy lustro miało ten obraz (sondowane, nie zakładane) |
| `mirror_probe` | `hit` / `cold_miss` / `miss` — wynik sondy z ponowieniem |
| `nonroot_available` | czy repozytorium oferuje wariant `nonroot` (własność, nie osobny wiersz) |
| `layer_key` | klucz deduplikacji dla analizy CVE |
| `group_id` | grupa: technologia w jednej wersji i na jednej linii OS (`library/python:3.13:-:debian13`) |
| `aliases` | pozostałe tagi wskazujące ten sam obraz amd64 |
| `paired` | czy grupa ma `standard` + ≥1 klasę utwardzoną (warunek analizy z pkt 6–7) |
| `triangle` | czy grupa ma `standard` i distroless |
| `stratum` | `pairs` (porównania, pkt 6–7) / `descriptive` (opis ekosystemu, tylko pkt 5) |

### Przepływ danych

```mermaid
flowchart LR
  hub["Docker Hub search plus tagi"] --> classify["4 klasy"]
  gcr["GCR distroless katalog"] --> classify
  classify --> cand["Kandydaci po regule minor"]
  cand --> probe["Sonda dostepnosci lustra"]
  probe -->|"hit / cold_miss"| matrix["Matryca: pairs plus descriptive"]
  probe -->|"404 po ponowieniu"| dropped["Odrzucony, bez pobierania z Huba"]
  matrix --> mirror["Pull przez mirror.gcr.io"]
  matrix --> gcrPull["Pull z gcr.io distroless"]
  mirror --> trivy["Trivy wsady"]
  gcrPull --> trivy
```

### Kwoty i niezależność obserwacji

- N łącznie ≈ 10 000 skanów; 25% dla klas rzadszych to aspiracja, nie twardy wymóg.
- Distroless wchodzi w całości (55 obrazów — cała populacja, nie próba), reszta losowana.
- Nierówny rozkład jest OK. Rozkład klas ma być **policzony, nie wymuszony** — uzasadnienie
  w [Rozkład klas w matrycy](#rozkład-klas-w-matrycy--jak-to-opisać).
- Twardy limit 150 obrazów na repozytorium plus alokacja proporcjonalna do
  `log(liczba grup)` — bez tego `openjdk` i `node` zdominowałyby próbę.
- Reguła tagów (decyzja Kroku 5): **jeden obraz na wersję minor** (najnowszy patch) dla każdej
  klasy i linii OS. Wiele wersji patch tej samej bazy puchłoby N i psuło niezależność
  obserwacji. Repozytorium jest czynnikiem grupującym w analizie, co zabezpiecza przed
  zarzutem, że N=10000 to nie 10 tys. niezależnych obserwacji.

### Uczciwy strop dla distroless

Katalog Distroless to **dziesiątki obrazów × kilka tagów**, nie 2500 niezależnych aplikacji.
Bieżąca linia `debian13` to 12 repozytoriów, wszystkie potwierdzone jako dostępne
(patrz [odpowiedź na obronę](#czy-gcr-nie-zostało-wyłączone--odpowiedź-na-obronę)):
`static`, `base`, `base-nossl`, `cc`, `java-base`, `java17`, `java21`, `java25`,
`nodejs22`, `nodejs24`, `nodejs26`, `python3`.

Przy jednym tagu na repozytorium (`latest`, patrz Konsekwencja 1) to **12 obrazów = 12 skanów
= 12 niezależnych profili CVE**. Bez sztucznego mnożenia tagów to jest realny strop tej klasy
i trzeba go w pracy podać wprost, zamiast maskować liczbą `image_ref`.

Linia `debian12` (również dostępna) podwaja tę liczbę do 24 i daje dodatkowo wymiar „starsza vs
nowsza baza Debiana" — przy czym wersja bazy jest wtedy zmienną, więc obserwacje z `debian12`
i `debian13` nie są niezależne w obrębie tej samej technologii i wymagają traktowania
technologii jako czynnika grupującego.

**Decyzja Kroku 5 (01.10.2026): wszystkie linie `debian9`–`debian13`.** Daje to 55 unikalnych
obrazów (56 repozytoriów, dwa wskazują ten sam obraz). Partnera z tą samą wersją runtime'u
i linią Debiana ma 41 z nich, w 28 grupach i 4 technologiach (`python`, `node`, `openjdk`,
`debian`) — szczegóły w wynikach `select` Kroku 5.

**To jest najostrzejsze ograniczenie liczebnościowe całej pracy.** Klasy `standard`, `slim`
i `alpine` mają po kilka tysięcy kandydatów, a `distroless` kilkanaście. Żadne warstwowanie tego
nie naprawi — asymetria wynika z tego, że distroless po prostu istnieje dla ~5 technologii.
Wniosek: porównania z udziałem distroless opieramy na **analizie sparowanej w obrębie tych kilku
technologii**, a nie na testach porównujących liczne grupy o skrajnie różnych liczebnościach.

Sufiksy architektury (`amd64`, `arm64`, `arm`, `s390x`, `ppc64le`, `riscv64`) **nie** mnożą
wierszy — `latest` jest indeksem manifestów, więc bierzemy jedną architekturę (amd64) na skan.

Żeby N distroless urósł: albo dodajesz starsze linie debianowe jako osobne obserwacje, albo
dodajesz pokrewne korpusy (Chainguard / Wolfi) i piszesz w pracy „distroless-like", nie udając
że to ten sam Distroless Google.

## Architektura kampanii skanowania

Pytanie „pobrać 10 tys. obrazów naraz i karmić Trivy, czy pobierać–skanować–usuwać po jednym"
ma trzecią odpowiedź, lepszą od obu.

### Odrzucone: pobranie całej bazy z góry

~10 tys. obrazów to ok. 1,2 TB surowo, po deduplikacji warstw realnie 400–600 GB. Przy 178 GB
wolnych na C: to nie wchodzi w grę. Odpada bez dalszej analizy.

### Odrzucone: `docker pull` → skan → `docker rmi` po każdym obrazie

Zużycie dysku jest ograniczone, ale ten wariant ma trzy wady:

1. **Niszczy współdzielenie warstw.** `docker rmi` usuwa warstwy, do których nie ma już
   referencji. `python:3.13` i `python:3.13-slim` dzielą warstwy bazowe Debiana — po usunięciu
   pierwszego obrazu drugi ściąga je ponownie. Przy 10 tys. obrazów o silnie współdzielonych
   bazach zwielokrotnia to transfer.
2. **Wymaga demona Dockera** i montowania `/var/run/docker.sock` do samego skanowania.
3. **Ściąga cały obraz**, choć Trivy potrzebuje wyłącznie metadanych pakietów.

### Wybrane: `trivy image --image-src remote`

Trivy sięga po warstwy prosto do rejestru, bez demona i bez lokalnego składowania obrazów.
Dokumentacja: *„When scanning images from a container registry, Trivy processes each layer by
**streaming**, loading only the necessary files for the scan into memory and discarding
unnecessary files."*

Trzy zalety rozstrzygające przy tej skali:

- **Cache po warstwach działa między obrazami.** Trivy kluczuje cache po `image ID` i `layer ID`,
  co *„enables faster scans of the same container image **or different images that share
  layers**"*. Tysiące obrazów z Huba dzielą te same bazy `debian` i `alpine`, więc analiza bazy
  wykonuje się raz. To dokładnie odwrotność wady wariantu z `docker rmi`.
- **Znika potrzeba montowania gniazda Dockera.** Skaner nadal działa w kontenerze — patrz
  [Kontener orkiestrujący](#kontener-orkiestrujący-po-co-był-dood-i-co-z-niego-zostaje) — ale
  przestaje potrzebować `/var/run/docker.sock`.
- **Ścieżka pobierania jest sterowalna.** `pull_ref` wskazujący `mirror.gcr.io` omija limit
  200/6 h Docker Huba.

### Kontener orkiestrujący: po co był DooD i co z niego zostaje

Pod nazwą „DooD" kryły się **dwie niezależne rzeczy**, które trzeba rozdzielić, bo tylko jedna
z nich odpada:

1. **Trivy i orkiestrator działają w kontenerze**, żeby nie instalować skanera, Pythona
   i zależności na maszynie i nie zaśmiecać systemu. **To był powód sięgnięcia po kontener i to
   zostaje bez zmian.**
2. **Montowanie `/var/run/docker.sock`** do tego kontenera, żeby Trivy w środku mógł rozmawiać
   z demonem Dockera hosta i wykonywać `docker pull` oraz czytać lokalne obrazy. **Tylko ten
   element odpada.**

Przy `--image-src remote` kontener nie potrzebuje demona hosta — komunikuje się bezpośrednio
z rejestrami po HTTPS. Cel „nie zaśmiecać komputera" jest więc realizowany **lepiej niż wcześniej**:
na hoście nie ma ani skanera, ani obrazów badanych, ani warstw w lokalnym storage Dockera.

#### To jest dodatkowo argument merytoryczny do pracy

Zamontowanie `/var/run/docker.sock` w kontenerze jest równoważne **oddaniu temu kontenerowi
uprawnień roota na hoście** — proces w środku może utworzyć dowolny kontener z dowolnym
montowaniem. NIST SP 800-190 wskazuje to wprost jako antywzorzec, podobnie Liz Rice w kontekście
ucieczek z kontenera.

Rezygnacja z tego montowania oznacza więc, że **narzędzie badawcze samo przestaje łamać zasady,
których skuteczność praca mierzy**. Warto to opisać w pracy jako świadome zastosowanie badanych
reguł do własnego laboratorium — dobrze wygląda przy pkt 1 (izolacja) i jest uczciwsze niż
opisywanie DooD jako „modelu izolacji", którym nigdy nie był.

#### Co kontener potrzebuje w zamian

Zamiast gniazda Dockera potrzebne są dwie rzeczy:

- **Sieć wychodząca** do `mirror.gcr.io`, `gcr.io`, Docker Huba i GHCR (baza Trivy).
- **Trwałe montowanie** katalogów `trivy_cache/`, `reports/`, `results/` i pliku `lab.db`.

**To nie jest PVC.** `PersistentVolumeClaim` to obiekt Kubernetesa; tutaj działamy na czystym
Dockerze na stacji roboczej, więc odpowiednikiem jest **bind mount** (`-v <host>:<kontener>`)
albo named volume. Kubernetes nie wchodzi do projektu — patrz
[Czego nie dodawać](#czego-nie-dodawać).

Co ważne, **ten wymóg jest już spełniony**: kod działa dziś wyłącznie z montowania katalogu
roboczego, a wszystkie cztery ścieżki leżą w tym katalogu. Nie ma tu nic do dobudowania,
wystarczy tego montowania nie usuwać. Trwałość jest krytyczna, nie kosmetyczna: gdyby cache
siedział w warstwie zapisywalnej kontenera, jego odtworzenie kasowałoby zarówno przypiętą bazę
CVE (rozjeżdżając [zamrożenie wersji](#krytyczne-zamrożenie-bazy-cve-na-czas-kampanii)), jak
i cache warstw, czyli główną oszczędność czasu, a kolejka SQLite traciłaby postęp kampanii.

Uprawnienia kontenera schodzą więc do zwykłego procesu z dostępem do sieci i kilku montowań —
bez `--privileged`, bez gniazda Dockera, bez potrzeby roota.

#### Zmiany w `Dockerfile`

Stan obecny i co z nim zrobić, w kolejności ważności:

1. **Dodać `--image-src remote` do wywołania Trivy** (to zmiana w kodzie, nie w `Dockerfile`,
   ale jest źródłem problemu). Domyślna kolejność źródeł w Trivy to
   `docker,containerd,podman,remote`, więc **demon hosta jest odpytywany pierwszy**. To dokładnie
   dlatego obrazy badane lądowały w lokalnym storage Dockera i zaśmiecały komputer. Jawne
   `--image-src remote` wycina tę ścieżkę.
2. **Usunąć `RUN apt-get install -y docker.io`.** Pakiet dostarcza Docker CLI, którego
   **nic nie używa** — PoC `scanner.py` wywoływał wyłącznie `trivy`, nigdy `docker`. Był potrzebny
   tylko przy założeniu DooD. Zysk: mniejszy obraz narzędzia i brak klienta Dockera w środku, co
   jest spójne z tematem pracy.
3. **Podbić wersję Trivy — `v0.45.1` nie jest już do pobrania.** To nie jest kwestia „starej,
   ale działającej" wersji: **aquasecurity/trivy usuwa binaria starych wydań z GitHub Releases.**
   Tagi gita zostają (`refs/tags/v0.45.1` istnieje), ale plików nie ma. Z 92 opublikowanych wydań
   pozostały `v0.0.1`–`v0.0.5` oraz dopiero `v0.69.2` i nowsze — **cała seria 0.4x zniknęła**.
   `install.sh` zwraca w tej sytuacji kod `1`, więc `docker build` **padał** na tej warstwie
   (dobra wiadomość: głośno, nie po cichu obrazem bez skanera). Przypięto `v0.74.0`, zweryfikowane
   jako instalowalne i działające. Do `RUN` dodano `trivy --version`, żeby przyszłe usunięcie
   wydania było widoczne od razu przy budowaniu. **Użytą wersję trzeba zapisać w pracy**, bo
   wpływa na wyniki skanów.
4. **Dodać `COPY` źródeł** — potrzebne, ale **nie pilne**. Dziś obraz kopiuje tylko
   `requirements.txt`, a kod jest dostępny wyłącznie przez montowanie; `CMD` uruchamia powłokę
   (do 29.09.2026 uruchamiał usunięty `scanner.py`).
   Do rozwoju (Kroki 1–6) montowanie jest wygodniejsze, bo nie wymaga przebudowy po każdej
   zmianie. `COPY` i bind mount **nie kolidują** — montowanie przesłania skopiowaną warstwę, więc
   można mieć oba: `COPY` daje odtwarzalny artefakt do opisania w pracy, mount zostaje trybem
   roboczym. Termin: przed pisaniem rozdziału o narzędziu, nie przed Krokiem 1.
5. **Przypiąć wersje w `requirements.txt`** i dodać `pyarrow` (patrz
   [Dług techniczny PoC](#dług-techniczny-poc--wymagania-dla-kroku-6)).

### Krytyczne: zamrożenie bazy CVE na czas kampanii

To ważniejsze niż samo zarządzanie dyskiem i łatwo to przeoczyć, bo nie objawia się błędem.

**Baza podatności Trivy jest przebudowywana co 6 godzin, a klient odświeża ją samoczynnie
zgodnie z polem `NextUpdate` w `metadata.json`** — zmierzone: `UpdatedAt 2026-09-13T19:03Z`,
`NextUpdate 2026-09-14T19:03Z`, czyli **co ~24 h**, nie co 6 h. Kampania trwająca kilka dni
oznacza więc, że obrazy skanowane pierwszego dnia są oceniane wobec **innej bazy CVE** niż
skanowane trzeciego. Delta `distroless − standard` zaczyna wtedy częściowo odzwierciedlać
**moment skanowania**, a nie stopień utwardzenia. Jest to systematyczny confounder unieważniający
porównania z pkt 6 i 7 — niezależnie od tego, czy odświeżanie jest co 6, czy co 24 godziny.

Obowiązkowa procedura — baza pobrana raz, potem zamrożona:

```bash
# raz, na starcie kampanii
trivy image --cache-dir ./trivy_cache --download-db-only
trivy image --cache-dir ./trivy_cache --download-java-db-only

# archiwizacja do zalacznika i do odtworzenia wynikow
cp ./trivy_cache/db/metadata.json ./trivy_cache/db/trivy.db  results/db_snapshot/

# wszystkie 10 tys. skanow
trivy image --cache-dir ./trivy_cache \
            --skip-db-update --skip-java-db-update \
            --image-src remote --scanners vuln --list-all-pkgs \
            --format json --output <raport> <pull_ref>
```

W pracy trzeba podać **wersję bazy i datę jej pobrania** z `metadata.json`. Baza Java DB jest
przebudowywana raz na dobę i ma znaczenie, bo `java` jest jedną z rodzin distroless.

Uwaga na rozmiar: pobranie to ~113 MiB skompresowane, ale **`trivy.db` zajmuje ~1,3 GB**
na dysku. Do załącznika pracy nie nadaje się sam plik — archiwizujemy skompresowany artefakt
albo zapisujemy jego digest wraz z `metadata.json`.

### Pozostałe decyzje operacyjne

- **`--scanners vuln`.** Domyślnie Trivy włącza też skaner sekretów, który jest kosztowny
  czasowo i nieistotny dla pytania badawczego. Wyłączamy go jawnie.
- **`--list-all-pkgs`.** Konieczne dla osi funkcjonalności z pkt 7 (liczba pakietów, obecność
  `bash`/`busybox`/`apt`/`apk`).
- **Nie włączać `--sbom-sources`.** Jeśli Trivy znajdzie atestację SBOM, skanuje **SBOM zamiast
  obrazu**. Część obrazów miałaby wtedy SBOM, a część nie, czyli byłyby mierzone **dwiema różnymi
  metodami** — to zabija porównywalność. Flaga jest opcjonalna i eksperymentalna, więc wystarczy
  jej nie dodawać, ale należy to zapisać jako świadomą decyzję.
- **Zrównoleglenie — uwaga na konflikt z cache.** Dokumentacja zaleca `--cache-backend memory`
  do równoległego uruchamiania, ale ten backend **nie utrwala wyników**, więc współdzielone
  warstwy byłyby analizowane od nowa przy każdym obrazie, co likwiduje główną oszczędność.
  Osobny `--cache-dir` per worker też nie jest rozwiązaniem, bo każdy katalog ściąga własną kopię
  bazy (i psuje zamrożenie wersji, o ile nie skopiujemy tam przypiętej bazy). Realne opcje:
  umiarkowana równoległość na jednym cache'u albo `--cache-backend redis` jako cache wspólny.
  Nie zrównoleglać bezrefleksyjnie.
- **`TMPDIR` na pojemnym dysku.** Duże pliki potrzebne do analizy (JAR-y, binaria) Trivy zapisuje
  tymczasowo na dysk. Obrazy `java` będą generować szczyty zużycia. `TMPDIR` kierujemy na D:
  i monitorujemy.
- **Kompresja raportów w locie.** ~10 tys. raportów JSON to 15–20 GB; gzip natychmiast po skanie.

## Mikro-kroki

Rola asystenta w tym planie: **drogowskaz**. Kod pisze student, commit po każdym kroku.

### Łańcuch zależności — po co jest każdy krok

Kroki dzielą się na trzy fazy i **nie da się żadnej przeskoczyć**: nie zeskanujesz obrazu,
o którym nie wiesz, że istnieje, i nie porównasz `slim` ze `standard`, jeśli wcześniej nikt
ich nie sparował.

| Faza | Kroki | Pytanie, na które odpowiada |
| --- | --- | --- |
| Znajdź | 1, 2, 3 | co w ogóle istnieje |
| Poukładaj | 4, 5 | co z czym porównać |
| Zmierz | 6 | ile jest CVE i pakietów |

**Krok 0 — rozejrzenie się.** Sprawdzenie ręcznie, czy potrzebne dane są w ogóle dostępne, zanim
powstanie linijka kodu. Stąd wiemy, że oficjalnych repozytoriów jest 181, że `python` ma ~4 tys.
tagów i że distroless istnieje tylko dla kilku technologii. Te liczby są cytowane w punkcie 2.

**Krok 1 — spis repozytoriów z Huba.** Lista **nazw**, nie obrazów: `python` to repozytorium,
`python:3.13-slim` to obraz w środku. Osobny krok, bo źródła są dwa (lista oficjalnych i
wyszukiwarka) i mają prawie rozłączne schematy odpowiedzi — patrz
[Ustalenia zweryfikowane empirycznie](#ustalenia-zweryfikowane-empirycznie) — więc trzeba je
sprowadzić do wspólnego kształtu rekordu.

**Krok 2 — spis distroless z GCR.** Distroless nie mieszka na Hubie, więc Krok 1 go nie zobaczy.
Inny rejestr, inne API, inne reguły filtrowania. Tu odpadają aliasy `debug`, `debug-nonroot`
i `nonroot`, bo cztery tagi to tylko dwa inwentarze pakietów (Konsekwencje 1 i 2) — bez tego
ten sam profil CVE policzyłby się kilka razy.

**Krok 3 — tagi, czyli konkretne wersje.** Zamienia nazwę `python` na listę faktycznych obrazów.
**To moment, w którym z ~1,8 tys. repozytoriów robią się dziesiątki tysięcy obrazów** — i dlatego
dopiero tutaj pojawia się potrzeba cache, backoffu i tokenu.

**Krok 4 — klasyfikacja i ścieżka pobierania.** Dwie rzeczy naraz. Przypisanie klasy utwardzenia
z nazwy tagu — to ta jedna kolumna, wokół której kręci się cała analiza z punktów 5–7. Oraz
ustalenie, skąd obraz ściągnąć: przez lustro (nie liczy się do limitu 200/6 h) czy z Huba,
sprawdzane **per manifest**, bo lustro ma dziury i chybienia na zimno.

**Krok 5 — złożenie matrycy.** Sklejenie obu katalogów i doprowadzenie do stanu zdatnego do
analizy: deduplikacja (trzy tagi potrafią wskazywać ten sam obraz i udawać trzy niezależne
obserwacje), limity na repozytorium (`openjdk` i `node` same by zdominowały próbkę) oraz
oznaczenie technologii mających komplet wariantów do porównań parami.

**Krok 6 — skanowanie.** Trivy przechodzi przez matrycę i zapisuje liczbę CVE oraz pakietów.
Dwie rzeczy przesądzają o wartości wyniku: [zamrożenie bazy CVE](#krytyczne-zamrożenie-bazy-cve-na-czas-kampanii),
bez którego różnice między klasami częściowo odzwierciedlałyby datę skanowania, oraz skanowanie
prosto z rejestru, bo kilkuset gigabajtów obrazów nie ma gdzie trzymać.

- [x] **Krok 0 — obserwacja (bez kodu).** Zamknięty: library `count=181`; search alpine
  `count=103978` + `next`; tagi python (alpine/slim/standard + rozmiary); allowlist Distroless
  z README.
- [x] **Krok 1 — katalog Hub.** Kilka query, paginacja po `next`, dedup, `results/catalog.jsonl`.
  Pełną listę `library/` zdobywa się **dwoma przebiegami po `ordering`**, nie paginacją —
  anonimowy offset jest ograniczony. Wyszukiwanie daje anonimowo najwyżej 2 strony na zapytanie.
  `feat(fetcher): paginowany katalog Hub z kilku zapytan`
  Zamknięty: `src/GetRepo.py hub`, z tokenem (JWT z PAT), więc zwykła paginacja wystarcza
  i trik z `ordering` zostaje wyłącznie jako obejście anonimowe. Wynik 29.09.2026: 181
  oficjalnych (`count=181`) + 12 790 z wyszukiwania = 12 971 repozytoriów.
- [x] **Krok 2 — katalog GCR distroless.** Lista obrazów i dozwolonych tagów z README; API GCR
  tylko potwierdza istnienie. **Nie iterować całego `manifest`.** Filtr odrzuca: końcówki
  `.sig` / `.att`, prefix `update-available-`, tagi będące samym digestem / `sha256-...`,
  oraz **`debug`, `debug-nonroot` i `nonroot`** (Konsekwencje 1 i 2). **Zostaje wyłącznie
  `latest`** — jeden wiersz na repozytorium. Obecność wariantu `nonroot` zapisujemy jako
  `nonroot_available`, bez pobierania obrazu.
  `feat(fetcher): enumeracja GCR distroless, tylko tag latest`
  Zamknięty: `src/GetRepo.py gcr` → `results/gcr_catalog.jsonl`. Kandydaci to README (12 obrazów
  `debian13`) plus dzieci `gcr.io/v2/distroless/tags/list` z jawnym sufiksem `-debianN`; aliasy
  bez sufiksu (`python3`, `base`) są pomijane, bo wskazują te same warstwy co `-debian13`.
  Istnienie `latest` i `nonroot` potwierdzane przez `HEAD` na manifest. Wynik 29.09.2026:
  56 repozytoriów (linie `debian9`–`debian13`), 51 z `nonroot_available`. Wybór linii zgodnej
  z bazą partnera z Huba należy do Kroku 5.
- [x] **Krok 3 — tagi Hub + cache + backoff.** Token Hub tylko do API, **nie commitować**.
  Token jest tu **wymagany, nie opcjonalny**: anonimowy offset urywa się przed końcem listy
  tagów `python` (3923) i odcina większość tagów `openjdk` (17 042).
  `feat(fetcher): tagi Hub z cache i backoff przy 429`
  Zamknięty: `src/GetTags.py` → `results/tags.jsonl`, cache per repozytorium w
  `cache/hub_tags/` (wznowienie bez ponownych zapytań). Pilot `python`: 3923/3923 tagów
  w 40 stronach, czyli pełna lista powyżej progu anonimowego.
  Pełny przebieg 29.09.2026: 179 repozytoriów `library/` (187 879 tagów) oraz repozytoria
  z wyszukiwania z `pull_count` ≥ 10 000 — 645 repozytoriów (146 698 tagów), próg przyjęty
  jako jawne kryterium doboru próby do rozdziału 2.
- [x] **Krok 4 — klasyfikacja + `pull_ref` + sonda lustra.** Dla każdego obrazu sprawdzić
  dostępność na `mirror.gcr.io` i zapisać `mirror_ok`; fallback na Hub z osobnym budżetem.
  **Nie** stosować bezwarunkowego przepisywania URL (patrz przypadek `openjdk`).
  `feat(fetcher): mapowanie pull_ref z sonda dostepnosci lustra`
  Zamknięty: `src/Classify.py`. `classify` → `results/classified.jsonl` (wariant, linia OS,
  wersja, `prerelease`, `excluded_reason` = `windows` / `onbuild` / `no_amd64`; linia OS
  aliasów rozwiązywana po wspólnym digeście amd64). `assign` → `results/refs.jsonl`
  (`pull_ref` pinowany digestem amd64; distroless z indeksu OCI w `gcr.io`). `probe-tags`
  weryfikuje lustro per wiersz i **musi zostać uruchomiony na matrycy po Kroku 5**.
  Wynik dla `library/` + wyszukiwania + GCR: 253 563 standard, 25 179 slim, 55 835 alpine,
  56 distroless (licząc z wykluczonymi); wykluczone 40 945 `no_amd64`, 20 526 `windows`,
  1 278 `onbuild`, zostaje 271 884 wierszy. Linii OS
  nie da się ustalić dla 40% wierszy `library/` i 82% wierszy z wyszukiwania (tagi bez
  sufiksu systemu, np. `flywheel/python`, `amazon/aws-lambda-*`).
- [x] **Krok 5 — matryca ~10 tys.** Merge Hub + GCR, sonda lustra, `select` w dwóch warstwach,
  `layers` (`layer_key`), wyliczenie `paired`. **Zamknięty 07.10.2026:** `matrix.jsonl` =
  **9 923** wierszy z wypełnionym `layer_key`; drugi stopień dedupu nie usunął żadnego
  wiersza (0 kolizji warstw przy 0 fallbackach) — patrz wynik `layers` niżej.
  `feat(fetcher): matryca wielorejestrowa do 10 tys. skanow`
  Szczegóły: [Krok 5 — decyzje i rozpisanie](#krok-5--decyzje-i-rozpisanie).
  Analiza przy niepełnych grupach: [Niepełne grupy](#niepełne-grupy--jak-analizować-w-inżynierce).
- [ ] **Krok 6 — skaner.** Trivy na `pull_ref` z `--image-src remote`, **baza CVE zamrożona
  przed startem kampanii** (`--download-db-only`, potem `--skip-db-update`), partie poniżej
  limitu, resume gdy JSON raportu istnieje. Szczegóły i uzasadnienie:
  [Architektura kampanii skanowania](#architektura-kampanii-skanowania).
  `feat(scanner): skan pull_ref z resume, image-src remote i zamrozona baza CVE`

### Krok 5 — decyzje i rozpisanie

#### Jednostka matrycy: grupa technologii w jednej wersji

Matryca nie jest listą niezależnie losowanych tagów, tylko zbiorem **grup**. Grupa to jedna
technologia w jednej wersji, a w środku jej warianty utwardzenia:

| Klasa | Obraz | Linia |
| --- | --- | --- |
| `standard` | `python:3.13-trixie` | `debian13` |
| `slim` | `python:3.13-slim-trixie` | `debian13` |
| `alpine` | `python:3.13-alpine3.22` | `alpine3.22` |
| `distroless` (jeśli istnieje) | `gcr.io/distroless/python3-debian13` | `debian13` |

`standard` jest punktem odniesienia, delty z punktu 7 liczone są względem niego. Większość
grup ma tylko trzy pierwsze wiersze — distroless istnieje dla kilku technologii.

#### Decyzje (01.10.2026)

1. **Wydania przedpremierowe są wykluczone**, łącznie z buildami EA. `PRERELEASE_RE`
   w `Classify.py` nie rozpoznaje tokenu `ea`, przez co `openjdk:28-ea-slim-trixie` był
   traktowany jako stabilny — dotyczy to 8 884 z 10 196 zakwalifikowanych tagów
   `library/openjdk` (87%). Poprawione w Kroku 4 (01.10.2026); po ponownym `classify`
   i `assign` `openjdk` ma 1 312 stabilnych tagów (451 unikalnych obrazów amd64).
2. **Tylko `library/` (Docker Official Images) plus `gcr.io/distroless`.** Repozytoria
   z wyszukiwania nie wchodzą do matrycy. Powody: oficjalne obrazy mają jawny, publiczny proces
   budowania i przeglądu, co łatwo opisać i obronić w rozdz. 2; wyszukiwanie dokłada głównie
   szum (`flywheel/python` 7 807 unikalnych obrazów, `ccitest/python` 3 448) przy zaledwie
   ~1 400 dodatkowych grupach z parą. Katalog z wyszukiwania (Kroki 1 i 3) zostaje jako spis
   populacji i jest opisywany jako świadome zawężenie próby. Znika przy tym problem duplikatów
   `amd64/*` i normalizacji nazw typu `aws-lambda-python`.
3. **Wszystkie linie Debiana distroless** (`debian9`–`debian13`), ale dopasowanie partnera po
   **(technologia, wersja, linia Debiana)**, nie po samej linii — patrz niżej.
4. **Twardy limit 150 obrazów na repozytorium**, docelowo ~10 tys. obrazów. Pomiar na danych
   z 29.09.2026 (bez prerelease, po dedupie `arch_digest`, reguła minor): `library/` daje
   31 544 kandydatów, limit 150 przycina do ~12 100. Do 10 tys. schodzimy alokacją
   proporcjonalną do `log(liczba grup)` w repozytorium. Końcowy N jest liczony, nie wymuszony —
   drugi stopień deduplikacji (`layer_key`) może go jeszcze obniżyć.
   **Zmienione 05.10.2026:** limit 300 dla grup sparowanych, 150 dla warstwy opisowej.
   **Zmienione 06.10.2026:** `pair_cap` domyślnie bez praktycznego limitu (99999) — cała
   pula par z lustra; inaczej ~2 tys. par odpadało przez cap na `node`/`debian`. Patrz
   [losowanie w dwóch warstwach](#rozkład-klas-w-matrycy--jak-to-opisać).
5. **Bez pobierania z Docker Huba (05.10.2026).** Do matrycy wchodzą tylko obrazy, które ma
   lustro `mirror.gcr.io` (oraz distroless z `gcr.io`). Sonda lustra idzie więc **przed**
   losowaniem, na kandydatach po regule minor (~28 tys.), a nie na gotowej matrycy — inaczej
   wylosowane pary rozpadałyby się po odrzuceniu brakującego obrazu. Ścieżka Hub i budżet
   200 / 6 h znikają z kampanii. Ograniczenie do opisania: odpadają głównie stare tagi,
   których lustro nie przechowuje. Przebieg 06.10.2026: spośród ~28 tys. sondowanych obrazów
   Hub **58% `miss`** (16 377) — wyraźnie więcej niż wcześniejsza próba 300 z 14%; próba jest
   przesunięta w stronę nowszych obrazów mocniej niż zakładano.

#### Dlaczego distroless tylko z Debianem i tylko po wersji

Google buduje distroless **wyłącznie na Debianie** — wszystkie 56 repozytoriów z Kroku 2 ma
sufiks `-debianN`. Pozostałe linie systemów (Ubuntu, alpine, UBI, Oracle Linux…) wchodzą do
matrycy normalnie i biorą udział w porównaniach `standard` / `slim` / `alpine`; po prostu nie
mają partnera distroless. Przykład: `eclipse-temurin` stoi na Ubuntu, więc nie sparuje się
z distroless `java`.

Obraz distroless zawiera **systemową wersję runtime'u z Debiana**, nie dowolną.
`python3-debian13` pasuje więc tylko do grupy `python` 3.13 na `trixie`, `nodejs22-debian13`
tylko do `node` 22 na `trixie`, `java21-debian13` tylko do Javy 21 na `trixie`. Wersje runtime'u
w obrazach distroless trzeba odczytać przy implementacji (np. z configu obrazu), nie zakładać.

Mapowanie technologii distroless na repozytorium `library/` (jawna tabela w kodzie):

| distroless | partner w `library/` | uwaga |
| --- | --- | --- |
| `python3-*` | `python` | |
| `nodejs*` | `node` | |
| `java*` | `openjdk` | `library/java` jest przestarzałe (220 starych tagów); `eclipse-temurin` i `amazoncorretto` nie mają linii Debiana |
| `static`, `base*`, `cc` | `debian` | `debian:13` vs `debian:13-slim` vs `base-debian13` |

Ograniczenie do zapisania: `openjdk` jest na Hubie oznaczone jako przestarzałe i nie ma
stabilnych tagów Javy 17 na `debian12`/`debian13` ani w ogóle Javy 21 i 25 (sprawdzone
01.10.2026 — wynik parowania niżej).

#### Rozpisanie — `src/Matrix.py`

1. [x] **Poprawka Kroku 4** (przed wszystkim): `ea` do tokenów prerelease, ponowne `classify`
   (offline) i `assign`.
2. [x] **`Matrix.py select`** — od 05.10.2026 podzielony na `candidates` (punkty 1–3 poniżej,
   wejście `results/refs.jsonl`) i `select` (punkty 4–5, wejście: kandydaci po sondzie):
   1. Filtr: `vendor = library` albo `source_registry = gcr`; bez `excluded_reason`;
      bez `prerelease`; niepusty `arch_digest`.
   2. Pierwszy stopień deduplikacji po `arch_digest`. Zostaje jeden tag kanoniczny (ten
      z sufiksem linii OS, jeśli jest), reszta trafia do kolumny `aliases` — informacja
      zostaje, ale obraz liczy się raz.
   3. **Reguła minor:** dla (repozytorium, wersja `X.Y`, `flavor`, klasa, linia OS) zostaje
      tylko ostatnio wypchnięty tag (`tag_last_pushed`). 199 wersji patch `python` sprowadza
      się do 17 linii minor — to główne zabezpieczenie niezależności obserwacji.
   4. Grupy: `group_id = (repo_key, minor, flavor, linia OS)` z obrazami `standard` i `slim`
      tej samej linii; `alpine` (najnowsza linia alpine) dołącza do grupy z najnowszym
      `standard` danej wersji. Distroless dołącza wg tabeli i dopasowania (technologia,
      wersja, linia Debiana). Grupy bez linii OS wchodzą do matrycy, ale bez distroless.
   5. Losowanie **całymi grupami**, nie wierszami — inaczej pary by się rozpadały. Distroless
      wchodzi w całości jako pierwszy; kwoty repozytoriów ∝ `log(liczba grup)`, limit 150.
      Losowanie z ustalonym ziarnem (powtarzalność), ok. 5% zapasu na drugi stopień dedupu.

   Zrobione (01.10.2026, ziarno 2026, pierwsza wersja bez sondy): 136 792 kandydatów → 69 722
   po dedupie `arch_digest` → 27 916 po regule minor → 19 129 grup. Wylosowano **9 975
   obrazów** — liczby historyczne, zastąpione przebiegiem niżej.

   **Przebieg 06.10.2026** (świeże Kroki 1–4 + sonda + `select --pair-cap 99999`, ziarno 2026):
   katalog Hub 13 516 repo; tagi library 188 688 + search 148 726; candidates 28 097;
   po sondzie na lustrze/GCR 11 720 (odrzucone Hub-only 16 377). Matryca: **9 923 obrazów**
   w 7 016 grupach (214 repo): pairs 5 469 / descriptive 4 454; klasy 6 361 `standard`,
   1 808 `alpine`, 1 699 `slim`, 55 `distroless`; pary 1 529 `slim` / 1 336 `alpine` /
   27 `distroless`; repo z parą 21 / 53 / 4; grup z pełnymi 4 klasami **8**; trójkątów
   `alpine`+`slim`+`standard` 294. Parowanie distroless jak wyżej (partnerzy bez zmian
   jakościowych względem 01.10).

   Linia OS jest w kluczu grupy, bo `python:3.11` na `bookworm` i na `trixie` to różne
   obrazy — bez tego `python3-debian12` nie miałby partnera (pierwsza wersja kodu zachowywała
   tylko najnowszą linię).

   Wersje runtime'u distroless odczytane z configów obrazów: Python z `Entrypoint`
   (`debian9`–`debian13` → 3.5 / 3.7 / 3.9 / 3.11 / 3.13), Java z `JAVA_VERSION`, Node
   z nazwy (`nodejs22`). Wynik parowania:
   - `python` 7/7 i `base`/`static`/`cc` 18/18 mają partnera;
   - `node` 13/16 — bez partnera tylko `nodejs-debian9/10/11` (brak wersji w nazwie);
   - `java` 3/14 — partnera mają tylko `java11-debian10/11` i `java17-debian11`.
     **To ograniczenie danych, nie kodu:** `library/openjdk` ma stabilne tagi Javy 17 tylko
     do `debian11`, a dla 21 i 25 wyłącznie buildy EA (wykluczone). Distroless Java 17+ na
     `debian12`/`debian13` nie ma oficjalnego partnera na Debianie (`eclipse-temurin` stoi na
     Ubuntu). Do opisania w rozdz. 6.

   Zapas 5% pod ubytek z `layers` nie był potrzebny w przebiegu 07.10 (0 usunięć) i nie jest
   losowany w `select` — matryca i tak jest poniżej targetu 10 tys.
3. [x] **`Matrix.py layers`** (sieć, zrobione 07.10.2026): `GET mirror.gcr.io/v2/<repo>/manifests/<arch_digest>`,
   `layer_key = sha256(lista digestów warstw)`; distroless z `gcr.io`. **Nie z Docker Huba**.
   Przy chybieniu: `layer_key = arch_digest` (`layer_key_source = arch_digest_fallback`).
   Dedup po `layer_key`; przy kolizji wygrywa wiersz z `stratum=pairs`, odrzucone
   `logical_ref` → `layer_dupes`. Zapasu dobierającego nie było.

   **Wynik 07.10.2026** (~24 min, 9 923 `GET` manifestów):
   - `layer_key` z listy warstw: **9 923 / 9 923** (fallback: **0**)
   - po dedupie: **9 923 → 9 923** (usunięte duplikaty profilu CVE: **0**)
   - pary / klasy / stratum bez zmian względem `select`

   **Wniosek do pracy:** w tej matrycy (po dedupie `arch_digest`, regule minor i filtrze
   lustra) nie wystąpiły pary obrazów o różnych manifestach amd64 i identycznych warstwach.
   Drugi stopień nie zmniejszył N, ale dostarczył jawny `layer_key` i empiryczny dowód, że
   stopień pierwszy wystarczał dla niezależności obserwacji CVE w tej próbie. Reguła
   `layer_key` zostaje w metodyce (Konsekwencja 3) — na wypadek innych przebiegów / korpusów.
4. **`paired`** po końcowym dedupie: grupa ma `standard` i ≥ 1 klasę utwardzoną. Dodatkowo
   `triangle`: grupa z distroless. Przeliczane ponownie w `layers`.
5. **Raport** `results/matrix_report.json` + log: rozkład klas, liczba grup, liczebność
   podzbiorów `paired` i `triangle`, distroless per technologia i linia; po `layers` także
   `rows_before` / `dropped_layer_dupes` / `layer_key_fallback`.
6. **`Classify.py probe-tags` na kandydatach, przed `select`** (decyzja 5). Pełna sonda
   ~28 tys. obrazów trwa ok. 2–4 h (po kolei; faza ponowień chybień bez logu co 500).
   **Zrobione 06.10.2026** → `results/candidates_probed.jsonl`. Kolejność:

   ```bash
   python src/Matrix.py candidates
   python src/Classify.py probe-tags --in results/candidates.jsonl --out results/candidates_probed.jsonl
   python src/Matrix.py select
   python src/Matrix.py layers
   ```
7. Dokumentacja: decyzje tutaj, opis kodu w `KOD.md`.

Aktualny `results/matrix.jsonl` pochodzi z przebiegu **06–07.10.2026** (`select` + `layers`).

#### Stan po przebiegu 07.10.2026

Ostatni zrobiony krok: `Matrix.py layers` → `results/matrix.jsonl` (**9 923** wierszy z
`layer_key`) + `matrix_report.json`. **Krok 5 zamknięty.** Następny: Krok 6 (skaner Trivy).

Dane `results/` i `cache/` nie są w gicie. Logi: `results/run_*.log`, `results/probe.log`,
`results/run_k5_layers.log`. Na Windowsie: `.venv\Scripts\python.exe`. Analiza niepełnych grup:
[Niepełne grupy](#niepełne-grupy--jak-analizować-w-inżynierce).

#### Wznowienie pracy na innym komputerze (stan 05.10.2026 — historyczne)

Poniżej procedura z chwili, gdy lokalnie było tylko `candidates.jsonl`. Po 07.10.2026 na
maszynie z pełnym `results/` (matryca po `layers`) wystarczy Krok 6; przy braku `results/` —
nowy przebieg jak w `KOD.md` §2.

1. **Dane.** `results/` i `cache/` nie są w gicie (`.gitignore`). Obie drogi są poprawne,
   warunek: wszystkie pliki z **jednego** przebiegu (nie mieszać starych i nowych), a w pracy
   podana data zebrania danych.
   - **Kopia** z komputera z przebiegiem 06.10: cały `results/` (matryca + katalogi + sonda).
   - **Nowy przebieg** Kroków 1–4 i `candidates` (pełny przebieg w `KOD.md`, rozdział 2;
     potrzebny `.env` z PAT): świeższe tagi; liczby w tym planie trzeba wtedy podmienić.
2. **Środowisko:** `.venv` według `KOD.md` §2. `.env` z PAT tylko do Kroków 1–4.
3. **Sonda (~2–4 h):** na Windowsie w tle z logiem do `results/probe.log`; postęp co 500,
   potem długa cisza na ponowieniach `miss`.
4. **Losowanie + layers:** `python src/Matrix.py select -v`, potem `python src/Matrix.py layers`.
   Oczekiwać ~9,9 tys. obrazów przy miss ≈ 58%; w przebiegu 07.10 `layers` nie zmienił N
   (0 kolizji `layer_key`). Liczby dopisać tutaj i w `KOD.md` (rozdział 10).

Zasady pracy: kod prosty, na poziomie studenta 3. roku, bez sztuczek; osobny commit na każdą
zmianę; bez trailera `Co-authored-by: Cursor` w commitach (w razie potrzeby usuwany
`git filter-branch --msg-filter` przed pushem); push tylko na prośbę; dokumentacja po polsku.

#### Poza zakresem (świadomie)

- **`no_amd64`** (40 945) — głównie przestrzenie per architektura i `chainguard` (7 115).
  Chainguard / Wolfi oraz Ubuntu chiselled to kandydaci na korpus „distroless-like” dla
  baz innych niż Debian; poza obecnym zakresem.
- **Wiersze bez linii OS** (40% `library/`) — nie są odrzucane, tylko nie parują się
  z distroless. Uzupełnienie linii z wyniku skanu (Trivy podaje OS) jest możliwe po Kroku 6.

### Cel akceptacji

- Matryca zawiera kolumny z sekcji [Schemat matrycy testowej](#schemat-matrycy-testowej).
- Dwa kanały discovery: Hub + GCR distroless — **oba obowiązkowe**.
- Pull oficjalnych wyłącznie przez lustro (sonda przed losowaniem); liczba odrzuconych
  obrazów dostępnych tylko na Hubie policzona i zaraportowana. Ścieżki Hub w kampanii nie ma
  (decyzja 05.10.2026), więc limit 200 / 6 h nie dotyczy skanów.
- Rozkład klas policzony, nie wymuszony.
- Deduplikacja po `layer_key`, nie po digescie manifestu.

### Czego nie dodawać

Sztucznego doważania klas, crawla **całego** GCR (tylko projekt `distroless`), bazy danych,
UI, statystyk CVE na tym etapie, jednego przebiegu 10 tys. pulli przez Hub bez lustra.

## Dług techniczny PoC — wymagania dla Kroku 6

PoC `scanner.py` został usunięty z repozytorium (29.09.2026, commit `57ef163`; osiągalny
w historii gita). Błędy znalezione w nim przy rekonesansie zostają jako **wymagania dla skanera
z Kroku 6**:

- Wywołanie Trivy musi mieć `timeout`, a jego wynik musi być sprawdzany — w PoC brak obu dał
  75 raportów zamiast 100 zadanych, czyli ~25 **cichych porażek**.
- Klient HTTP PoC miał `timeout=10` i gołe `except Exception` zwracające `None`, po czym
  `len(images)` wysypywało się na `None`. Fetcher już to rozwiązuje (`hub_http.build_session`:
  `urllib3.Retry(total=5, backoff_factor=1.5, status_forcelist=[429,500,502,503,504],
  respect_retry_after_header=True)` i timeouty `(connect=10, read=30)`).
- PoC budował DataFrame z listy wszystkich rekordów naraz. 75 obrazów dało 39,5 tys. wierszy,
  więc 10 tys. obrazów da ~5 mln wierszy i wyczerpie RAM. Potrzebny zapis przyrostowy do Parquet.
- Skan musi używać `--list-all-pkgs`, co da liczbę pakietów oraz wykrycie
  `bash`/`busybox`/`apt`/`apk` — to metryka funkcjonalności do pkt 7.
- Skan musi przekazywać `--image-src remote`; PoC tego nie robił, więc Trivy odpytywał najpierw
  demona hosta i ściągał obrazy do lokalnego storage Dockera — źródło zaśmiecania maszyny.
- `Dockerfile` nie zawiera `COPY` źródeł — kod działa wyłącznie z montowania. Szczegóły
  i priorytety: [Zmiany w `Dockerfile`](#zmiany-w-dockerfile).
- `requirements.txt` zawiera już tylko zależności fetchera (`requests`, `requests_cache`,
  `python-dotenv`), wciąż bez przypiętych wersji; do przypięcia wszystkie, a przy Kroku 6
  do dołożenia `pyarrow`.

### Rozmiar danych i dysk

Przy 10 tys. obrazów: ~15–20 GB surowego JSON-a (obecnie 75 raportów = ~130 MB, sam
`report_iojs.json` ma 12 MB). Dysk w chwili planowania: C: 178 GB wolnego, D: 715 GB;
`reports/` 115 MB, `trivy_cache/` 2,3 GB.

Kluczowe: obrazy badane **nie trafiają na dysk hosta ani do lokalnego storage Dockera** —
zostają tylko raporty i cache analizy. Wybór trybu pobierania omawia
[Architektura kampanii skanowania](#architektura-kampanii-skanowania).

## Stan repozytorium

Repozytorium zawiera `Dockerfile` (środowisko Trivy), `requirements.txt`, dokumentację
w `docs/` (ten plan i opis kodu [`KOD.md`](KOD.md)) oraz fetcher w `src/`: `hub_http.py` (wspólny klient HTTP), `GetRepo.py` (Kroki 1 i 2),
`GetTags.py` (Krok 3), `Classify.py` (Krok 4: `classify`, `assign`, `probe-tags`) i `Matrix.py`
(Krok 5: `candidates`, `select`, `layers`). Wyniki
(`results/`) i cache (`cache/`) nie są wersjonowane — są odtwarzalne z kodu i pinowanych
digestów. PoC `scanner.py` został usunięty (commit `57ef163`); jego błędy są spisane jako
[wymagania dla Kroku 6](#dług-techniczny-poc--wymagania-dla-kroku-6). **Kroki 1–5 zamknięte**;
następny jest Krok 6 (skaner).

### Implementacja fetchera z sierpnia — wątek zamknięty

Implementacja z 21.08 nie została zacommitowana, a pliki `.py` zniknęły przy przenoszeniu
katalogu; w `src/` zostało wyłącznie bytecode, które paradoksalnie było jedyną wersjonowaną
częścią katalogu.

**Decyzja: ta implementacja jest ignorowana.** Nie jest punktem odniesienia, nie odtwarzamy jej
z bytecode'u i nie porównujemy z nią nowego kodu. Jedyną obowiązującą ścieżką są Kroki 1–6
z tego dokumentu. Bytecode został usunięty z drzewa (commit `1ca3271`); pozostaje osiągalny
w historii gita pod `dee4fa8`, ale wyłącznie jako ślad, nie jako materiał do pracy.

Z całego epizodu zostaje **jeden wniosek operacyjny**, niezależny od wartości tamtego kodu:
plik nieobjęty gitem nie istnieje. `__pycache__/` i `*.py[cod]` są ignorowane, żeby układ
„zacommitowane `.pyc`, niezacommitowane `.py`" nie mógł się powtórzyć, a kod każdego kroku
wchodzi do repozytorium wraz z zamknięciem tego kroku.

## Jak odtworzyć pomiary z tego dokumentu

Wszystkie liczby w sekcjach [Rejestry](#rejestry-i-ścieżki-pobierania) i
[Warianty distroless](#warianty-distroless--dowody-pomiarowe) są odtwarzalne bez pobierania
obrazów:

```bash
A='Accept: application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json'

# lustro nie zawiera distroless
curl -s -o /dev/null -w '%{http_code}\n' -H "$A" \
  https://mirror.gcr.io/v2/distroless/python3-debian12/manifests/latest   # 404
curl -s -o /dev/null -w '%{http_code}\n' -H "$A" \
  https://gcr.io/v2/distroless/python3-debian12/manifests/latest          # 200

# dziura w pokryciu lustra
curl -s -o /dev/null -w '%{http_code}\n' -H "$A" \
  https://mirror.gcr.io/v2/library/openjdk/manifests/17                   # 404

# gcr.io/distroless dziala bez uwierzytelniania (biezaca linia debian13)
for r in static base base-nossl cc java-base java17 java21 java25 \
         nodejs22 nodejs24 nodejs26 python3; do
  printf '%-20s ' "$r-debian13"
  curl -s -o /dev/null -w '%{http_code}\n' -H "$A" \
    "https://gcr.io/v2/distroless/$r-debian13/manifests/latest"           # 200
done

# warstwy wariantow distroless: dowod, ze 4 aliasy = 2 inwentarze pakietow
# (warianty debug sluza tu wylacznie jako dowod, do proby nie wchodza)
for t in latest nonroot debug debug-nonroot; do
  curl -s -H "$A" "https://gcr.io/v2/distroless/python3-debian12/manifests/$t"
done
```

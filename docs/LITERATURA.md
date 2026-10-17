# Streszczenie literatury z planu pracy

Notatki do rozdziałów, nie tekst do wklejenia w pracy. Każdy akapit jest omówieniem, nie cytatem. Przy pisaniu podawaj rozdział książki i pozycję z `bibliography.bib`.

Klasy `standard` / `slim` / `alpine` / `distroless` są własną taksonomią badania. Żadne z sześciu źródeł jej nie definiuje i nie porównuje tych czterech klas na zbiorze obrazów.

| # | Źródło | Stan notatki | Gdzie w pracy |
| --- | --- | --- | --- |
| 1 | Rice, *Container Security*, 2020 | opracowane | rozdz. 2, część metodyki |
| 2 | Vehent, *Securing DevOps*, 2018 | opracowane | rozdz. 1–2, integralność artefaktu |
| 3 | NIST SP 800-190, 2017 | opracowane | rozdz. 2.4, ograniczenia |
| 4 | Distroless (Google) | opracowane (README, `SUPPORT_POLICY.md`, `base/README.md`, stan 10.2026) | rozdz. 2.3, 3, studium w rozdz. 5 |
| 5 | CVSS v3.1 (FIRST), 2019 | opracowane | rozdz. 3 i 5 |
| 6 | SLSA (slsa.dev, spec v1.0 i v1.2) | opracowane | rozdz. 2.4, metodyka (digest, punkt w czasie) |

---

## 1. Liz Rice, *Container Security* (O'Reilly, 2020)

Książka tłumaczy, z czego składa się kontener i które właściwości tego składu da się wykorzystać albo zepsuć. Nie jest rankingiem obrazów bazowych. Alpine pojawia się jako przykład lekkiego systemu użytego do demonstracji oraz jako jedna z małych baz w checkliście na końcu. Distroless i `scratch` pojawiają się jako zalecenie mniejszej bazy. Nie ma klasy `slim` i nie ma pomiaru CVE między wariantami.

### Model zagrożeń

Rice rozdziela ryzyka według miejsca, w którym atakujący może wejść. Dla tej pracy liczą się dwa.

Pierwszy to łańcuch obrazu. Po zbudowaniu obraz leży w rejestrze i stamtąd jest pobierany do uruchomienia. Kto podmieni obraz między buildem a wdrożeniem, uruchamia własny kod. To jest zapowiedź rozdziału o obrazach: integralność, rejestr, podpis, wskazanie konkretnej wersji.

Drugi to zawartość samego obrazu i hosta. Na hoście ma być mało oprogramowania, bo host i kontenery dzielą jądro. Osobno wymienia źle ustawione uprawnienia kontenera, sekrety w obrazie, sieć i błędy ucieczki z kontenera (przykład CVE-2019-5736 w runc). Te wątki wyjaśniają, czym praca się nie zajmuje: nie mierzy konfiguracji uruchomienia, sieci ani ucieczki na hosta.

### Zasady, z których wynika powierzchnia ataku

Rozdział 1 podaje kilka zasad i od razu mówi, że przy kontenerach łatwo je zepsuć złą konfiguracją albo złą higieną obrazu.

- Najmniejsze uprawnienie: kontener dostaje tylko to, czego potrzebuje do swojej funkcji.
- Obrona w głąb: kilka niezależnych warstw ochrony.
- Mniejsza powierzchnia ataku: mniej punktów dostępu, mniej uprawnionych podmiotów, mniej kodu. Im więcej złożoności, tym więcej miejsc do ataku.
- Ograniczenie zasięgu szkody: podział na małe części, żeby kompromitacja jednej nie oddała całości. Kontener może być taką granicą.
- Rozdział obowiązków: sekrety i uprawnienia trafiają tylko do tego kontenera, który ich potrzebuje.

Przy powierzchni ataku Rice zaznacza kontrargument: pocięcie systemu na mikroserwisy może uprościć interfejsy, ale warstwa orkiestracji dokładana do koordynacji kontenerów sama jest nową powierzchnią. W pracy chodzi o powierzchnię obrazu bazowego (pakiety i znane podatności), nie o powierzchnię orkiestratora.

### Izolacja kontenera i różnica wobec maszyny wirtualnej

Rozdziały 3–5 są tłem do podrozdziału o architekturze. Kontener nie jest małą maszyną wirtualną. Od środka tak wygląda, bo ma własną listę procesów, sieć i katalog główny, ale proces kontenera jest zwykłym procesem Linuksa widocznym z hosta pod innym PID.

Mechanizmy:

- cgroups ograniczają zasoby (pamięć, CPU), nie widoczność;
- przestrzenie nazw (UTS, PID, montowania, sieć, użytkownik, IPC, cgroup) ograniczają to, co proces widzi;
- zmiana katalogu głównego sprawia, że proces widzi tylko wycinek systemu plików.

Rice pokazuje to na Alpine: po `chroot` do pustego katalogu nie ma nawet powłoki, dopóki w nowym katalogu głównym nie leży system plików. Obraz kontenera jest właśnie tym systemem plików plus konfiguracją uruchomienia. Stąd później wniosek, że brak narzędzia w obrazie oznacza brak możliwości jego uruchomienia. To jest język, którym da się opisać distroless, ale sama książka nie robi z tego klasy badawczej.

Izolacja jest słabsza niż w maszynie wirtualnej, bo kontenery dzielą jądro. Nadzorca maszyny wirtualnej jest mniejszy i prostszy (Rice porównuje rząd wielkości kodu jądra Linuksa i Xen), więc ma mniejszą powierzchnię i uchodzi za mocniejszą granicę. Kontener startuje jak proces, nie jak osobne jądro, dlatego nadaje się do częstych wydań. Wybór między nimi jest kompromisem wydajności, ceny, wygody i wymaganej siły granicy. Książka wprost mówi, że samej izolacji kontenera nie uważa za wystarczającą do twardej wielodostępności.

Dla pracy: rozdział o izolacji ma oddzielić „kontener izoluje proces od hosta” od „skład obrazu jest osobnym problemem”. Pomiar dotyczy składu.

### Z czego składa się obraz

Rozdział 6. Obraz ma dwie części: katalog główny oraz konfigurację (użytkownik, porty, zmienne, przestrzenie nazw, limity). Instrukcje `FROM`, `ADD`, `COPY` i `RUN` zmieniają system plików. `USER`, `ENV` i podobne zmieniają konfigurację. Standard OCI opisuje format obrazu i to, jak runtime (runc) dostaje rozpakowany `rootfs` oraz `config.json`.

Obraz w rejestrze jest rozbity na warstwy. Każda warstwa jest blobem identyfikowanym hashem treści. Manifest wskazuje zestaw blobów. Hash manifestu jest digestem całego obrazu. Zmiana czegokolwiek w obrazie zmienia digest.

Adres obrazu to rejestr, właściciel, nazwa oraz albo tag, albo digest. Brak adresu rejestru oznacza Docker Hub (`docker.io`). Tag jest etykietą, którą można przenieść na inny obraz. Tego samego obrazu może dotyczyć wiele tagów. Digest wynika z treści, więc wskazuje tę samą zawartość przy kolejnym pobraniu.

Rice rozróżnia dwa legalne użycia. Tag wersji głównej i mniejszej bywa celowo przesuwany na poprawkę, żeby odbiorca dostał łatę. Zapis skanu albo decyzja „wdrożono dokładnie ten artefakt” musi używać digestu, bo tag nie gwarantuje, że jutro pod tą nazwą leży to samo. To jest bezpośrednie uzasadnienie pinowania digestem w metodyce. Książka nie zna jeszcze zamrożonej bazy CVE jako osobnej osi; mówi o tożsamości obrazu.

### Higiena Dockerfile i mała baza

Zalecenia z rozdziału 6, które wchodzą do opisu metod utwardzania:

- baza z zaufanego rejestru; obce bazy mogą nieść obcy kod; część organizacji dopuszcza tylko zatwierdzone obrazy bazowe;
- im mniejsza baza, tym mniej zbędnego kodu i mniejsza powierzchnia; Rice wymienia `scratch` (pusty obraz pod samodzielny plik binarny) oraz distroless; mniejszy obraz jest też szybszy w przesyle;
- wskazanie bazy digestem poprawia odtwarzalność buildu, a tag zwiększa szansę na późniejsze łaty; brakujące łatki i tak ma złapać skan gotowego obrazu;
- build wieloetapowy zostawia w obrazie końcowym wynik kompilacji, nie kompilator i narzędzia budowania;
- `USER` inny niż root, jeśli proces nie musi być rootem;
- `RUN` jest dowolnym poleceniem, więc prawo edycji Dockerfile jest prawem wykonania kodu na infrastrukturze budowania;
- sekret zapisany w warstwie zostaje w obrazie nawet po usunięciu pliku w kolejnej warstwie, bo warstwy są przechowywane osobno;
- unikać binariów setuid i pakietów, które nie są potrzebne w czasie działania;
- wszystko, czego proces potrzebuje, ma być w obrazie w chwili buildu, a nie dociągane po starcie.

Checklist na końcu książki wymienia obok siebie `scratch`, distroless, Alpine i minimalne obrazy RHEL jako sposoby zmniejszenia zawartości. To lista opcji, nie wynik porównania. Alpine jest w książce także konkretnym przykładem małego systemu (minirootfs przy ćwiczeniu ze zmianą katalogu głównego) oraz dystrybucją, której kanał porad bezpieczeństwa zmieniał się w czasie i przez to psuł skanery.

### Rejestr, podpis, wdrożenie

Wypchnięcie obrazu to push, pobranie to pull. Podmiana obrazu w rejestrze oznacza uruchomienie cudzego kodu. Własny rejestr albo rejestr dostawcy chmury daje kontrolę nad tym, kto pcha i kto ciągnie, i utrudnia podstawienie adresu przez DNS. Rice wymienia Docker Hub oraz rejestry chmurowe, w tym Google Container Registry, jako zwykłe miejsca składowania.

Podpis wiąże obraz z tożsamością wydawcy. W 2020 roku typową implementacją jest Notary i The Update Framework; Rice opisuje Notary jako trudne w użyciu i zapowiada wersję 2. Obok podpisów stawia in-toto: łańcuch kroków budowania, w którym da się sprawdzić, że właściwe osoby wykonały właściwe kroki na właściwym wejściu. To jest język integralności łańcucha dostaw, starszy niż SLSA w brzmieniu z planu. SLSA w pracy uzasadnia pin punktu w czasie; Rice uzasadnia, po co w ogóle przejmować się tożsamością obrazu między buildem a uruchomieniem.

Przy wdrożeniu zły plik definicji (YAML) jest tak samo groźny jak zły obraz: zmiana jednego znaku w adresie rejestru wystarczy, żeby wstał inny artefakt. Admission control może przepuścić tylko obraz przeskanowany, podpisany, z zaufanego rejestru i zatwierdzony.

Maszyna budująca ma być traktowana jak produkcja. Rootowy daemon Dockera na tej maszynie oznacza, że kto może zlecić build, może też uruchomić dowolny kontener. Stąd narzędzia budowania bez demona. To tłumaczy, czemu w pracy kontener skanera nie montuje gniazda Dockera: dostęp do gniazda jest dostępem do demona.

### Podatności w obrazach i skanowanie

Rozdział 7. Podatność to znana wada, którą da się wykorzystać. Identyfikator CVE nadaje system MITRE (i upoważnione CNA). NVD mapuje CVE na pakiety i wersje. Sama lista NVD nie wystarcza, bo dystrybucja często nakłada łatę na swoją wersję pakietu bez zmiany numeru, który widzi NVD. Przykład Rice: bash na Ubuntu wygląda na podatny na Shellshock według NVD, a biuletyn Ubuntu mówi, że łatka już weszła. Skaner bez kanału danej dystrybucji daje fałszywe alarmy. Rice każe sprawdzić, czy skaner obsługuje wybraną bazę, i wymienia tu także distroless.

Źródła różnic między skanerami, ważne przy opisie Trivy:

- sam NVD kontra biuletyn dystrybucji;
- przestarzały kanał (Alpine przeniosło porady z alpine-secdb do aports; część skanerów została na starym);
- podatności, których maintainer nie będzie łatał: jedni je pokazują, inni ukrywają, bo nie ma akcji naprawczej;
- podpakiety (dokumentacja zamiast binarium) i inne nazwy binariów niż nazwa pakietu źródłowego;
- błędy samego skanera i błędy w danych.

Rice wymienia skanery: Trivy, Clair, Anchore oraz produkty komercyjne i skan wbudowany w rejestry. Nie porównuje ich skuteczności na zbiorze obrazów. Wniosek książki: lepiej mieć skaner niż nie mieć, świadomie licząc się z fałszywymi alarmami i z tym, że „poprawny” zestaw CVE nie istnieje.

Skanować należy obraz, nie każdą uruchomioną instancję, o ile kontener jest niezmienny. Niezmienność oznacza, że po starcie nie dociąga się pakietów. Inaczej skan obrazu nie opisuje tego, co naprawdę działa, a dwóch instancji nie da się porównać. Regularny reskan jest osobną osią: kod obrazu może stać, a wczoraj ogłoszono CVE w jego zależności. Typowy rytm operacyjny u Rice to skan przy buildzie i ponowny przegląd wdrożonych obrazów co około dobę.

Miejsca skanu w potoku: u dewelopera, zaraz po buildzie (próg krytyczności może przerwać potok), w rejestrze dla obrazów, których nikt od dawna nie przebudował. Skan w chwili każdego uruchomienia jest marnotrawstwem, jeśli instancje pochodzą z jednego obrazu. Sam wynik skanu nie zatrzymuje wdrożenia; potrzebna jest kontrola przyjęcia, która odrzuca obraz bez aktualnego skanu.

Zero-day jest poza bazą: skaner dopasowuje znane identyfikatory. Dopóki nie ma wpisu, dopasowanie nic nie pokaże. To ograniczenie każdego wyniku opartego na CVE, także kampanii w tej pracy.

Osobna oś to podatności bibliotek aplikacji (npm, pip, Maven) oraz binariów, w których zależności są wlinkowane. Samodzielny plik binarny na `scratch` nie ma pakietów systemowych do skanowania. Skaner pakietów wtedy milczy, co nie znaczy, że kod jest bez wad. W pracy metryką jest inwentarz pakietów widziany przez Trivy, więc ten przypadek trzeba umieć nazwać: brak pakietów w raporcie nie jest dowodem braku błędów w aplikacji.

### Jak to rozłożyć na rozdziały

| Teza z książki | Rozdział pracy |
| --- | --- |
| Kontener izoluje proces słabiej niż maszyna wirtualna, bo dzieli jądro | 2.1 Architektura i izolacja |
| Mniej kodu to mniejsza powierzchnia; zła higiena obrazu tę korzyść znosi | 2.2 Powierzchnia ataku |
| `scratch`, distroless, mała baza, build wieloetapowy, brak zbędnych pakietów | 2.3 Metody utwardzania, jako literatura, nie jako taksonomia badania |
| CVE, NVD kontra biuletyn dystrybucji, ograniczenia skanera | 2.4 i metodyka skanowania |
| Warstwy, tag kontra digest, rejestr | metodyka, pin digestem |
| Skan obrazu niezmiennego, różnice między skanerami, zero-day | ograniczenia wyników |

### Czego z Rice nie wyciągać

- rankingu `standard` / `slim` / `alpine` / `distroless`;
- tezy „mniejszy obraz ma mniej CVE” jako faktu już zmierzonego; książka stawia ją jako zasadę, pomiar jest w tej pracy;
- opisu CVSS; książka mówi o krytyczności jako progu w potoku, bez skali FIRST;
- twierdzenia, że sam fakt użycia Trivy daje „prawdziwą” liczbę podatności; Rice właśnie tłumaczy, czemu dwa skanery się rozjadą.

---

## 2. Julien Vehent, *Securing DevOps* (Manning, 2018)

Książka jest o bezpieczeństwie w potoku, który sam buduje i wdraża usługę. Przykładem jest aplikacja „invoicer”: kod w GitHubie, testy i build w CircleCI, obraz na Docker Hub, uruchomienie na AWS. Bezpieczeństwo ma wejść w ten potok jako testy, kontrola dostępu i reakcja na incydenty, a nie jako osobny przegląd na końcu.

Nie ma tu taksonomii utwardzania obrazów bazowych. Jedyne „minimalne” baza w przykładzie to BusyBox pod statyczny plik binarny.

### DevOps jako potok

Rozdział 1 składa potok z trzech kawałków.

- Ciągła integracja: małe zmiany, gałąź, przegląd przez drugą osobę, automatyczne testy, włączenie do głównej linii. Duże paczki zmian łatwiej psują produkt, więc cykl ma być krótki.
- Ciągłe dostarczanie: wdrożenie jest zaprogramowane. Po złączeniu zmian potok pakuje oprogramowanie i stawia środowisko. Jeśli krok zawiedzie, wydanie staje.
- Infrastruktura jako usługa: centrum danych, sieć i serwery są u dostawcy i da się je opisać kodem oraz API. Operator pisze kod infrastruktury zamiast przekładać kable.

Na rysunku potoku obok testów funkcjonalnych stoją automatyczne testy bezpieczeństwa. Vehent nazywa to bezpieczeństwem sterowanym testami: kontrola ma być mała i sprawdzalna („wymuś HTTPS z takimi szyframi”), a nie hasłem („szyfruj ruch”). Testy idą w tym samym potoku co build, więc brak kontroli widać przed klientem. Większość produktów dzieli infrastrukturę bazową, więc raz napisany zestaw testów da się użyć wielokrotnie.

To jest rama „łańcucha dostaw” w tej książce: droga od zmiany w repozytorium kodu do działającej usługi, z automatycznymi bramkami po drodze. Rejestr obrazów jest jednym z przystanków tej drogi.

### Docker Hub w przykładzie potoku

Rozdział 2 stawia konkretny łańcuch: GitHub powiadamia CircleCI webhookiem, CircleCI odpala testy, po złączeniu do gałęzi głównej buduje kontener i pcha go na Docker Hub. Dalej wdrożenie ściąga ten kontener na AWS.

Vehent tłumaczy, po co w ogóle kontener w takim potoku. Wspólne biblioteki systemowe są wygodne, dopóki dwie aplikacje nie chcą dwóch wersji tej samej biblioteki (przykład: OpenSSL 1.2 na systemie z OpenSSL 0.9). Kontener pakuje zależności aplikacji osobno od reszty systemu. To jest ten sam problem, który Rice opisuje od strony systemu plików obrazu: każda aplikacja niesie własny zestaw pakietów. U Vehenta wniosek jest organizacyjny (potok może wydać działający artefakt setki razy dziennie). U Rice wniosek jest bezpieczeństwem zawartości (te pakiety trzeba skanować i ograniczać).

Rejestr może być publicznym Docker Hub albo prywatnym Docker Registry za własnym GitLabem i Jenkinsem. Vehent mówi wprost, że idea potoku się nie zmienia: przy każdej zmianie kodu test i paczka dzieją się automatycznie. Publiczny Hub w przykładzie jest miejscem, z którego „każdy może pobrać” zbudowany kontener. Stąd w pracy da się powiedzieć, że publiczne repozytorium jest przystankiem dystrybucji, bez utożsamiania Huba z całym łańcuchem.

Hasła do Huba nie powinny być prywatnym kontem o pełnych prawach. Vehent odsyła to do rozdziału 6 i każe trzymać sekrety w zmiennych środowiska CI tak, żeby nie wyciekły do pull requestów z forków.

### Minimalny obraz w przykładzie: BusyBox

Dockerfile invoicera zaczyna się od `FROM busybox:latest`. Vehent opisuje BusyBox jako minimalny zestaw zwykłych narzędzi Linuksa. Dalej dokłada użytkownika `app` bez powłoki logowania (`/sbin/nologin`), kopiuje statycznie zlinkowany plik binarny, przełącza użytkownika i ustawia punkt wejścia.

To jest ilustracja małej bazy i procesu bez roota, z 2018 roku, na tagu `latest`. Nie ma pomiaru, ile podatności taki wybór usuwa. Tag `latest` jest właśnie tym, przed czym Rice ostrzega przy tożsamości artefaktu: jutro pod tą nazwą może leżeć inna treść. W pracy pin digestem jest świadomym zaostrzeniem wobec przykładu z Vehenta.

### Uprawnienia do rejestru

Rozdział 6.2 traktuje rejestr jak magazyn, którego kompromitacja podmienia kontener produkcyjny. CircleCI dostaje osobnego użytkownika Docker Hub z prawem zapisu tylko do jednego repozytorium, przez zespół organizacji. Jeden wyciek ma zepsuć jeden obraz, nie całą organizację. To jest zasada najmniejszego uprawnienia zastosowana do konta, które pcha artefakt, a nie do pakietów wewnątrz obrazu.

### Docker Content Trust

DCT, w stanie z 2018 roku, pozwala wydawcy podpisać obraz przed wysłaniem na Hub. Klient z włączonym DCT sprawdza podpis przy pobraniu. Pod spodem jest The Update Framework: podpisywane są metadane z hashami obrazów i znacznikami czasu. Zaufanie jest przy pierwszym użyciu. Klient zapamiętuje klucz przy pierwszym pobraniu i później odrzuca aktualizację podpisaną innym kluczem. Pierwsze pobranie złośliwego obrazu TOFU nie zatrzyma.

Vehent nazywa DCT eksperymentem: koncepcja mocna, mało praktyki, domyślnie wyłączone, wpięcie w CI/CD trudne. Dwa problemy w jego modelu:

- klucz podpisu musi trafić do CircleCI; wyciek repozytorium kodu zmusza do rotacji klucza;
- przy infrastrukturze stawianej od zera maszyna widzi obraz raz, a DCT porównuje kolejną wersję z poprzednią; jednej wersji nie ma z czym zestawić.

Sens DCT, który zostaje po tych zastrzeżeniach: kompromitacja repozytorium nie powinna móc wypchnąć obcego kodu do systemów, które już ufają wydawcy. Vehent stawia to na końcu listy, po prostszej kontroli uprawnień. W pracy podpisów się nie sprawdza. Integralność punktu pomiaru jest zrobiona digestem i jedną bazą podatności. DCT jest w rozdziale o standardach nazwą mechanizmu, którego badanie nie wykonuje, oraz powodem, dla którego sam tag na Hubie nie jest dowodem pochodzenia.

### Jak to rozłożyć na rozdziały

| Teza z książki | Rozdział pracy |
| --- | --- |
| Potok CI/CD przenosi zmianę kodu do działającej usługi przez automatyczne bramki | wstęp i rozdz. 2, rama łańcucha dostaw |
| Rejestr (Docker Hub albo prywatny) jest przystankiem, z którego wdrożenie pobiera artefakt | wstęp, definicja rejestru |
| Kontener izoluje zależności aplikacji od wspólnych bibliotek systemu | rozdz. 2, po co w ogóle obraz |
| BusyBox, użytkownik bez powłoki, statyczny plik binarny | rozdz. 2.3, przykład małej bazy, nie klasa `slim` |
| Osobne, wąskie konto do push na Hub | rozdz. 2, uprawnienia przy publikacji |
| DCT i TUF, wraz z ograniczeniami z 2018 roku | rozdz. 2.4, integralność; metodyka tłumaczy, czemu zamiast DCT jest digest |

### Czego z Vehenta nie wyciągać

- opisu klas `slim`, `alpine`, `distroless`;
- tezy, że Hub sam w sobie jest łańcuchem dostaw; u niego Hub jest jednym pudełkiem na rysunku potoku;
- instrukcji stawiania invoicera na AWS; to studium potoku, nie materiał pomiarowy;
- twierdzenia, że DCT jest dziś wdrożonym standardem; książka sama nazywa go wtedy eksperymentem.

---

## 3. NIST SP 800-190, *Application Container Security Guide* (2017)

Autorzy: Souppaya, Morello, Scarfone. Wytyczne NIST dla organizacji, które planują, wdrażają i utrzymują kontenery. Dokument jest katalogiem ryzyk i przeciwdziałań, ułożonym według warstw architektury. Nie jest pomiarem, nie wymienia narzędzi z nazwy jako zalecanych i nie zna podziału tagów Docker Hub na `slim` czy `alpine` jako klas.

### Architektura i cykl życia obrazu

NIST dzieli środowisko na pięć warstw: systemy deweloperów, systemy testów i akredytacji (walidują obraz i go podpisują), rejestry, orkiestratory oraz hosty. Obraz przechodzi przez trzy fazy: utworzenie, testy i akredytację; składowanie i pobranie; wdrożenie i zarządzanie. Dokument podkreśla, że te fazy biegną równolegle dla wielu aplikacji naraz, a nie po kolei jako etapy dojrzałości.

Obraz to paczka wszystkich plików potrzebnych do uruchomienia kontenera. Zgodnie z NIST powinien zawierać tylko pliki wykonywalne i biblioteki potrzebne aplikacji, bo resztę funkcji systemu daje jądro hosta. Najniższa warstwa obrazu to warstwa bazowa, zwykle zminimalizowana dystrybucja systemu bez jądra. Użytkownik dokłada na niej frameworki i własny kod.

Rejestr przechowuje obrazy, nadaje im tagi do wersjonowania i pozwala pobierać obrazy przygotowane przez innych. Może być własny albo usługowy. NIST wymienia Docker Hub obok rejestrów Amazona, Docker Trusted Registry i Quay. Rejestr ma API, więc potok może sam wypchnąć obraz po testach, a wdrożenie może samo ruszyć po pojawieniu się nowej wersji. Wdrożenie nie zmienia obrazu: kontener dostaje jego kopię. Aktualizacja polega na zbudowaniu nowego obrazu i ponownym wdrożeniu, nie na łataniu działającego kontenera.

### Izolacja

Kontenery dzielą jądro hosta, a runtime daje im osobny widok systemu przez trzy mechanizmy: izolację przestrzeni nazw (system plików, sieć, IPC, nazwa hosta, użytkownicy, procesy), przydział zasobów (cgroups) i wirtualizację systemu plików (warstwy, copy-on-write). NIST pisze wprost, że izolacja kontenera jest mocna, ale nie daje tak wyraźnej granicy jak maszyna wirtualna z nadzorcą. Kontenery mogą działać z różnymi uprawnieniami, więc źle skonfigurowane środowisko pozwala im wpływać na siebie i na hosta znacznie łatwiej niż kilku maszynom wirtualnym. Maszyny wirtualne i kontenery nie wykluczają się: często kontenery biegną wewnątrz maszyn wirtualnych.

To samo stanowisko co u Rice. Do pracy: izolacja jest tłem; pomiar dotyczy obrazu.

### Ryzyka obrazu (rozdz. 3.1)

| Ryzyko | Sens | Czy praca to mierzy |
| --- | --- | --- |
| Podatności obrazu | Obraz jest statycznym archiwum. Obraz świeży w dniu buildu po dniach lub tygodniach ma już znane podatności. Łatać trzeba u źródła i wdrażać od nowa | **tak**, to główna metryka |
| Błędy konfiguracji obrazu | Np. brak użytkownika innego niż root, demon SSH w obrazie | nie; wszystkie obrazy w badaniu działają jako root, to stała |
| Wbudowane złośliwe oprogramowanie | Obraz to zbiór plików; źródłem może być warstwa bazowa o nieznanym pochodzeniu | nie |
| Sekrety jawnym tekstem w obrazie | Każdy z dostępem do obrazu je odczyta | nie |
| Niezaufane obrazy | Łatwość ponownego użycia kusi do uruchamiania obcych obrazów | pośrednio: próba ogranicza się do Docker Official Images i `gcr.io/distroless` |

Zdanie o podatnościach jest najważniejsze dla rozdziału 2: liczba CVE obrazu jest funkcją czasu, nawet gdy obraz się nie zmienia. To samo, co Rice mówi o regularnym reskanie.

### Ryzyka rejestru (rozdz. 3.2)

- Nieszyfrowane połączenie z rejestrem: wyciek treści obrazu, kradzież poświadczeń, podsunięcie fałszywego albo starego obrazu.
- Stare obrazy w rejestrze: same nie atakują, ale zwiększają szansę, że ktoś przypadkiem wdroży znaną podatną wersję.
- Słabe uwierzytelnianie i autoryzacja: rejestr jest traktowany jako źródło zatwierdzonego oprogramowania, więc jego kompromitacja przenosi się na wszystkie kontenery i hosty, które z niego pobierają.

Punkt o starych obrazach jest bezpośrednio związany z próbą badawczą. Matryca zawiera tagi z wielu lat, a lustro i Hub nadal je serwują. NIST nazywa to ryzykiem przypadkowego wdrożenia, a w pracy jest to źródło wysokich wartości CVE w starszych grupach i powód analizy świeżości (wykresy 5.6 i 5.7).

### Ryzyka hosta (rozdz. 3.5)

Powierzchnia ataku hosta to wszystkie drogi, którymi napastnik może dotrzeć do podatności systemu; każda usługa sieciowa jest kolejnym wejściem. Systemy pisane specjalnie pod kontenery (NIST wymienia CoreOS Container Linux, Project Atomic, Google Container-Optimized OS) nie mają menedżerów pakietów ani bibliotek do uruchamiania aplikacji bezpośrednio, mają tylko część narzędzi administracyjnych i często system plików tylko do odczytu. Dlatego ich powierzchnia jest mniejsza. Wspólne jądro i tak daje większą powierzchnię między obiektami niż nadzorca maszyn wirtualnych.

To jest definicja powierzchni ataku na poziomie hosta. W pracy ta sama logika jest przeniesiona na obraz bazowy: brak menedżera pakietów i zbędnych bibliotek jako wskaźnik mniejszej powierzchni. Przeniesienie jest analogią autora, nie stwierdzeniem NIST o obrazach.

### Przeciwdziałania dla obrazów (rozdz. 4.1)

Podatności obrazu wymagają narzędzi przystosowanych do kontenerów. Klasyczne skanery zakładają długowieczne serwery z tym samym zestawem aplikacji i często nie widzą podatności w kontenerach. Według NIST dobre narzędzie:

1. obejmuje cały cykl obrazu, od buildu przez rejestr do uruchomienia;
2. widzi podatności we wszystkich warstwach, nie tylko w warstwie bazowej, ale też we frameworkach i własnym kodzie;
3. pozwala ustawić bramki jakości, np. zatrzymać obraz z podatnością powyżej wybranego progu CVSS.

Ostatni punkt łączy NIST z CVSS: krytyczność jest progiem decyzji, nie tylko opisem.

Przy konfiguracji obrazu NIST zaleca m.in. uruchamianie jako użytkownik nieuprzywilejowany oraz **warstwy bazowe tylko z zaufanych źródeł, częstą aktualizację warstw bazowych i wybór minimalistycznych technologii, takich jak Alpine Linux i Windows Nano Server, w celu zmniejszenia powierzchni ataku**. To jedyne miejsce w sześciu źródłach, gdzie Alpine jest wprost zalecane jako metoda utwardzania obrazu. Distroless ani `slim` NIST nie wymienia. W kontenerach nie wolno włączać SSH ani innych zdalnych powłok, bo kontener ma być niezmienny; zarządzanie idzie przez API runtime'u.

Przy niezaufanych obrazach: utrzymać listę zaufanych obrazów i rejestrów, identyfikować każdy obraz podpisem kryptograficznym, uruchamiać tylko obrazy z listy, sprawdzać podpis przed uruchomieniem i na bieżąco aktualizować zawartość tych repozytoriów.

### Przeciwdziałania dla rejestru (rozdz. 4.2)

- Tylko szyfrowane połączenia z rejestrem.
- Stare obrazy: czyścić rejestr z niebezpiecznych wersji oraz wskazywać obraz niezmienną nazwą konkretnej wersji, a nie samą nazwą repozytorium. Tag `latest` jest tylko etykietą i nie gwarantuje świeżości, więc nie należy mu nadmiernie ufać.
- Zapis do rejestru tylko po uwierzytelnieniu, dla konkretnych repozytoriów. Obraz trafia do rejestru po skanie podatności i ocenie zgodności.

NIST w 2017 roku pisze o „niezmiennych nazwach” w rodzaju `my-app:2.3`, nie o digestach. Pin digestem w metodyce jest mocniejszą formą tej samej zasady: tag wersji nadal da się przesunąć, digest nie (Rice, rozdz. 6).

### Scenariusze (rozdz. 5)

Pierwszy scenariusz to wykorzystanie podatności w obrazie: aplikacja z podatnością zostaje przejęta, a napastnik rozpoznaje sieć, podnosi uprawnienia albo używa kontenera do dalszych ataków. Pierwszą linią obrony jest wykrycie podatnego obrazu wcześnie w potoku i niedopuszczenie go do wdrożenia. Trzeci scenariusz to zatruty obraz: obrazy pobiera się łatwo z publicznych miejsc o nieznanym pochodzeniu, więc napastnik może podrzucić złośliwą wersję obrazu, którego używa cel. Obrona: do rejestrów organizacji trafiają tylko obrazy sprawdzone, przetestowane i podpisane.

### Jak to rozłożyć na rozdziały

| Teza NIST | Rozdział pracy |
| --- | --- |
| Pięć warstw i trzy fazy cyklu obrazu; rejestr jako warstwa | wstęp, rozdz. 2.4 |
| Kontener daje słabszą granicę niż maszyna wirtualna | 2.1 |
| Podatności obrazu rosną z czasem, łata u źródła i ponowne wdrożenie | 2.2, ograniczenia (punkt w czasie) |
| Minimalistyczna baza (Alpine) zmniejsza powierzchnię | 2.3, jedyne zalecenie normatywne dla jednej z czterech klas |
| Bramka z progiem CVSS | 2.4 i 3 (metryki) |
| Stare obrazy w rejestrze, `latest` bez gwarancji świeżości | metodyka (pin), 5 (świeżość) |
| Lista zaufanych rejestrów i obrazów | uzasadnienie zawężenia próby do Official Images i distroless |

### Czego z NIST nie wyciągać

- zalecenia distroless ani `slim`; tych nazw w dokumencie nie ma;
- liczb; dokument nie podaje żadnych pomiarów;
- tezy, że NIST wymaga konkretnego skanera albo konkretnego progu CVSS; pokazuje mechanizm bramki, próg wybiera organizacja;
- rozdziałów o orkiestratorze, sieci i sprzęcie (TPM) jako materiału wyników; to tło, którego praca nie bada.

---

## 4. Google, *Distroless Container Images* (github.com/GoogleContainerTools/distroless)

Dokumentacja projektu, nie publikacja naukowa. Stan treści: README, `SUPPORT_POLICY.md` i `base/README.md` z października 2026. Dokumentacja się zmienia, więc w bibliografii potrzebna jest data dostępu, a w tekście warto zaznaczyć, że opis dotyczy stanu z okresu kampanii.

### Definicja

Obrazy distroless zawierają tylko aplikację i jej zależności czasu wykonania. Nie mają menedżera pakietów, powłoki ani innych programów, których zwykle oczekuje się w dystrybucji Linuksa. To jest definicja klasy `distroless` w pracy. Dla odróżnienia: `slim` i `alpine` zachowują powłokę i menedżer pakietów, więc różnica nie jest tylko różnicą rozmiaru.

### Uzasadnienie według autorów

Ograniczenie zawartości kontenera do dokładnie tego, czego potrzebuje aplikacja, przedstawiane jest jako praktyka stosowana od lat przez Google i inne duże firmy. Projekt podaje dwa skutki:

- lepszy stosunek sygnału do szumu w skanerach (np. CVE), czyli mniej zgłoszeń z pakietów, których aplikacja nie używa;
- mniejszy zakres, dla którego trzeba ustalać pochodzenie.

Drugi skutek łączy distroless z łańcuchem dostaw (SLSA): im mniej składników, tym mniej do sprawdzenia.

Rozmiar według README: najmniejszy obraz, `gcr.io/distroless/static-debian13`, ma około 2 MiB; README porównuje to z około 5 MiB dla `alpine` i 124 MiB dla `debian`. To deklaracja projektu, nie pomiar tej pracy. W danych kampanii rozmiar części obrazów distroless z GCR jest pusty (`arch_size`), więc porównania rozmiaru distroless nie należy opierać na własnej tabeli bez uzupełnienia źródła.

### Warianty i to, co zawierają

Bieżąca linia to Debian 13. README wymienia dwanaście obrazów, każdy z tagami `latest`, `nonroot`, `debug` i `debug-nonroot`:

| Grupa | Obrazy | Zawartość (wg `base/README.md`) |
| --- | --- | --- |
| bez libc | `static` | certyfikaty CA, wpis roota w `/etc/passwd`, `/tmp`, tzdata; pod statyczne pliki binarne (Go) |
| z glibc | `base-nossl`, `base`, `cc` | `base-nossl` = `static` + glibc; `base` dokłada libssl (w Debianie 13 także zlib i libzstd); `cc` pod programy wymagające biblioteki C++ |
| z runtime'em | `java-base`, `java17`, `java21`, `java25`, `nodejs22`, `nodejs24`, `nodejs26`, `python3` | systemowa wersja runtime'u z Debiana |

Wnioski do metodyki, które wynikają z tej tabeli:

- Distroless istnieje dla kilku technologii (Java, Node.js, Python) i dla baz pod języki kompilowane. Dla nginx, postgres czy redis odpowiednika nie ma. To tłumaczy, czemu w pracy distroless jest studium przypadku (40 par, 4 repozytoria partnera), a nie trzecia metoda o liczebności `slim` i `alpine`.
- `static`, `base`, `base-nossl` i `cc` nie mają runtime'u języka, więc w matrycy partnerem jest `library/debian`. Kilka obrazów distroless dzieli wtedy jedną grupę z jednym `debian:N`.
- Obraz z runtime'em zawiera wersję języka z Debiana tej linii, nie dowolną. Dlatego parowanie idzie po technologii, wersji i linii Debiana.

Tag `debug` dodaje powłokę BusyBox do diagnostyki. `nonroot` to wariant z użytkownikiem innym niż root. W pracy oba są odfiltrowane: `debug` łamie definicję klasy (ma powłokę), a `nonroot` ma ten sam inwentarz pakietów co `latest`, więc dublowałby obserwację. Dostępność `nonroot` jest zapisana jako flaga.

### Linie Debiana i wsparcie

Obrazy są oznaczane sufiksem wersji Debiana (`-debian13`). Nazwa bez sufiksu wskazuje dziś Debiana 13, ale ma kiedyś przejść na nowszego, więc projekt zaleca podawanie wersji jawnie. README traktuje inne tagi niż wymienione jako przestarzałe i już nieaktualizowane.

`SUPPORT_POLICY.md`: distroless idzie za standardowym harmonogramem wsparcia Debiana. Obrazy `static`, `base`, `base-nossl` i `cc` na Debianie 13 mają być wspierane do roku po wydaniu Debiana 14; obrazy z Javą, Node.js i Pythonem do trzech miesięcy po tym wydaniu. Java obejmuje tylko bieżące LTS dystrybuowane przez Debiana, Node.js tylko parzyste wersje w fazie aktywnej lub LTS.

Aktualizacje bezpieczeństwa: projekt śledzi wydania Debiana, a akcje GitHuba automatycznie otwierają pull request przy nowych pakietach.

Dla pracy to ważne z dwóch powodów:

1. Starsze linie (`debian9`–`debian12`) nadal da się pobrać, ale nie są według README aktualizowane. Pilotaż pokazał 258 CVE dla `python3-debian12` wobec 151 dla `python3-debian13`. Wynik klasy distroless zależy więc od linii, nie tylko od braku powłoki.
2. Uzasadnia regułę parowania po linii Debiana: wynik ma porównywać utwardzenie, a nie wiek bazy.

### `gcr.io`, a nie `pkg.dev`

FAQ: infrastruktura serwowania przeszła na Artifact Registry, ale projekt zostaje przy domenie `gcr.io`, żeby użytkownicy nie musieli zmieniać buildów. To odpowiedź na pytanie o wyłączenie Container Registry. Usługa została wygaszona, a domena nadal działa.

### Weryfikacja obrazów

Wszystkie obrazy distroless są podpisane narzędziem cosign w trybie bez klucza (keyless, klucze efemeryczne), a projekt zaleca weryfikację każdego obrazu przed użyciem jako bazy. README podaje polecenie `cosign verify` z wystawcą OIDC Google i tożsamością konta usługi distroless. W kampanii podpisów nie weryfikowano. W rozdziale o łańcuchu dostaw da się to napisać jako mechanizm dostępny, którego badanie nie używa, obok DCT z Vehenta.

### Konsekwencje użycia

- `ENTRYPOINT` i `CMD` muszą być w postaci wektorowej (`["myapp"]`). Postać napisowa wymaga powłoki, której nie ma. To konkretny koszt funkcjonalny braku powłoki, przydatny w rozdziale 6 obok liczby pakietów.
- Projekt zaleca budowanie wieloetapowe: etap budowy z pełnym narzędziem, a do distroless kopiowany tylko wynik. Rice zaleca to samo.
- Diagnostyka wymaga obrazu `debug` albo dołożenia narzędzi; README zauważa, że nawet `ldd` nie ma, bo jest skryptem powłoki.
- Obrazy są budowane Bazelem, ale można ich używać z dowolnego narzędzia.

### Użytkownicy

README wymienia m.in. Kubernetes (od 1.15), Knative, Tekton i Teleport. To lista z dokumentacji projektu, nie niezależne badanie adopcji.

### Jak to rozłożyć na rozdziały

| Teza z dokumentacji | Rozdział pracy |
| --- | --- |
| Definicja: aplikacja + zależności, bez powłoki i menedżera pakietów | 2.3, definicja klasy `distroless` |
| Lepszy sygnał w skanerach, mniej do ustalania pochodzenia | 2.3, motywacja; 2.4, łańcuch dostaw |
| Lista obrazów, `static`/`base`/`cc`/runtime | 3.2 (taksonomia), 3.4 (mapowanie partnerów) |
| Linie Debiana, harmonogram wsparcia, stare tagi nieaktualizowane | 3.4 (parowanie po linii), 5.4 (studium) |
| `gcr.io` zostaje mimo wyłączenia Container Registry | 3.3 (źródła danych) |
| `debug` i `nonroot` | 3.2, uzasadnienie wykluczenia |
| Wektorowy `ENTRYPOINT`, brak `ldd`, budowanie wieloetapowe | 6.1, koszt funkcjonalny |
| Podpis cosign keyless | 2.4, mechanizm nieweryfikowany w badaniu |

### Czego z dokumentacji distroless nie wyciągać

- tezy, że distroless ma mniej CVE niż `alpine` czy `slim`; dokumentacja mówi o rozmiarze i stosunku sygnału do szumu, nie o porównaniu liczby CVE;
- rozmiarów 2 / 5 / 124 MiB jako wyniku pracy;
- opisu `slim`; ten wariant należy do obrazów Docker Official Images.

---

## 5. FIRST, *Common Vulnerability Scoring System v3.1: Specification Document* (2019)

Specyfikacja skali krytyczności podatności. Rewizja 1. Opisuje metryki, wzory i zapis wektora. Nie mówi nic o kontenerach ani o utwardzaniu obrazów; w pracy służy do zinterpretowania kolumn krytyczności z Trivy.

### Czym CVSS jest i czym nie jest

CVSS opisuje główne techniczne cechy podatności i daje liczbę od 0,0 do 10,0, która mówi, jak poważna jest podatność **względem innych podatności**. Specyfikacja oddziela tę liczbę od ryzyka organizacji. Liczba klientów, straty finansowe, zagrożenie życia czy rozgłos to czynniki spoza CVSS, które organizacja ma doliczyć we własnym procesie zarządzania podatnościami.

Do pracy: liczba CVE i ich rozkład krytyczności opisują obraz, a nie ryzyko konkretnego wdrożenia. To zdanie powinno być w ograniczeniach.

### Trzy grupy metryk

- **Bazowe**: cechy podatności stałe w czasie i wspólne dla wszystkich środowisk; zakłada się rozsądnie najgorszy skutek.
- **Czasowe**: cechy, które zmieniają się w czasie, ale nie zależą od środowiska, np. pojawienie się exploita albo oficjalnej łaty.
- **Środowiskowe**: cechy konkretnego środowiska użytkownika, np. istniejące zabezpieczenia i znaczenie systemu.

Ocenę bazową zwykle publikuje opiekun produktu albo ktoś w jego imieniu. Zwykle publikuje się tylko ją, bo nie zależy od czasu ani środowiska. Ocenę czasową i środowiskową powinien uzupełnić użytkownik. Specyfikacja zakłada też, że oceniający przyjmuje, iż napastnik już zlokalizował podatność.

### Metryki bazowe

Część wykonalności (opisuje komponent podatny):

| Metryka | Wartości | Sens |
| --- | --- | --- |
| Wektor ataku (AV) | sieć, sąsiednia sieć, lokalnie, fizycznie | im dalej może być napastnik, tym wyżej |
| Złożoność ataku (AC) | niska, wysoka | warunki poza kontrolą napastnika |
| Wymagane uprawnienia (PR) | brak, niskie, wysokie | uprawnienia przed atakiem |
| Interakcja użytkownika (UI) | brak, wymagana | czy potrzebna jest akcja innej osoby |

Zakres (S): czy wykorzystanie podatności w jednym komponencie sięga do zasobów pod inną władzą bezpieczeństwa. Specyfikacja definiuje władzę bezpieczeństwa jako mechanizm, który egzekwuje kontrolę dostępu (aplikacja, system, firmware, piaskownica). Zmiana zakresu podnosi ocenę. Ucieczka z kontenera na hosta jest typowym przykładem przekroczenia takiej granicy. To przydatne zdanie łączące CVSS z rozdziałem o izolacji, ale jest to interpretacja autora, nie przykład ze specyfikacji.

Część skutków (opisuje komponent, który ponosi najgorszy skutek): poufność, integralność, dostępność, każda w skali wysoki / niski / brak. Liczy się tylko przyrost dostępu wywołany atakiem i stan końcowy.

### Metryki czasowe i środowiskowe

Czasowe: dojrzałość kodu exploita, poziom naprawy (oficjalna łata, tymczasowa, obejście, brak), pewność raportu. Brak wartości (`X`) nie zmienia oceny.

Środowiskowe: wymagania poufności, integralności i dostępności dla danego zasobu oraz zmodyfikowane wersje metryk bazowych, które opisują lokalne zabezpieczenia. Przykład ze specyfikacji: usługa domyślnie działająca jako administrator, a u danego użytkownika z niższymi uprawnieniami, może dostać niższe skutki.

To jest jedyny mechanizm, przez który CVSS uwzględnia konfigurację uruchomienia. Kampania tego nie liczy. Wszystkie obrazy oceniono jako artefakty, bez środowiska.

### Wzór i skala jakościowa

Ocena bazowa składa się z podwyniku skutków i podwyniku wykonalności. Wzór zależy od tego, czy zakres się zmienia, a wynik jest zaokrąglany w górę do jednego miejsca po przecinku i ucinany do 10,0. Ocena czasowa mnoży ocenę bazową przez trzy współczynniki czasowe.

Skala jakościowa (tabela 14 specyfikacji):

| Ocena | Zakres |
| --- | --- |
| brak | 0,0 |
| niska | 0,1–3,9 |
| średnia | 4,0–6,9 |
| wysoka | 7,0–8,9 |
| krytyczna | 9,0–10,0 |

Specyfikacja zaznacza, że użycie tej skali jest opcjonalne i ma pomagać w ustalaniu priorytetów.

### Wektor

Wektor zapisuje wszystkie wartości metryk, np. `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N`. Metryki bazowe są obowiązkowe, czasowe i środowiskowe nie. Specyfikacja zaleca, żeby wektor zawsze towarzyszył liczbie.

### Most do danych kampanii

`Scan.py` liczy kolumny `cve_critical`, `cve_high`, `cve_medium`, `cve_low` i `cve_unknown` z pola `Severity` w raporcie Trivy. Nazwy etykiet pokrywają się z jakościową skalą CVSS, ale trzeba to opisać ostrożnie:

- Etykieta w raporcie Trivy pochodzi ze źródła danych, które Trivy wybiera dla danego pakietu (np. biuletyn dystrybucji albo NVD). Nie musi to być ocena bazowa CVSS v3.1 policzona przez NVD. Mechanizm doboru źródła trzeba sprawdzić w dokumentacji Trivy v0.75.0 przed napisaniem rozdziału 3.
- `UNKNOWN` nie jest kategorią CVSS. To brak przypisanej oceny.
- Kampania nie liczy ocen czasowych ani środowiskowych. Wykres 5.3 pokazuje udział etykiet krytyczności, nie ryzyko.

Rice opisuje ten sam problem od strony skanera: różne źródła i porady dystrybucji dają różne wyniki dla tej samej podatności.

### Jak to rozłożyć na rozdziały

| Teza ze specyfikacji | Rozdział pracy |
| --- | --- |
| CVSS mierzy krytyczność względem innych podatności, nie ryzyko | 2.4, ograniczenia |
| Grupy bazowa / czasowa / środowiskowa | 2.4 |
| Skala jakościowa 0,1–3,9 … 9,0–10,0 | 3.5 (metryki), 5.2 (rozkład krytyczności) |
| Zakres i władza bezpieczeństwa | 2.1, opcjonalnie przy izolacji |
| Ocena środowiskowa jako jedyne miejsce na konfigurację | ograniczenia: kampania liczy artefakt, nie wdrożenie |

### Czego z CVSS nie wyciągać

- tezy, że etykieta z Trivy to zawsze ocena bazowa CVSS v3.1;
- ważenia obrazów sumą ocen CVSS; specyfikacja niczego takiego nie definiuje, a kampania liczy wystąpienia CVE;
- czegokolwiek o utwardzaniu.

---

## 6. SLSA, *Supply-chain Levels for Software Artifacts* (slsa.dev)

Specyfikacja OpenSSF, rozwijana przez międzyorganizacyjną grupę sterującą. W październiku 2026 bieżącą wersją jest **v1.2**, ze ścieżką Build i ścieżką Source. Strony v1.0, z których pochodzi część opisu poniżej, mają status „Retired”. W pracy trzeba cytować wersję, na którą się powołujesz, z datą dostępu.

### Czym jest

SLSA to zestaw wytycznych bezpieczeństwa łańcucha dostaw, wdrażanych stopniowo i uzgodnionych w branży. Producent dostaje listę kontrolną zabezpieczeń, a odbiorca sposób oceny, czy ufać danej paczce. Specyfikacja daje też wspólne słownictwo do rozmowy o łańcuchu dostaw.

Uzasadnienie: ataki takie jak SolarWinds czy Codecov pokazały, że ryzyko leży nie tylko w kodzie, ale na każdym kroku drogi od źródła przez build, pakowanie i dystrybucję. Skan podatności i analiza kodu są potrzebne, ale nie wystarczają. Jeśli łańcuch ma słabe ogniwo, nie wiadomo, czy uruchamiany kod jest tym samym kodem, który przeskanowano. SLSA ma śledzić drogę od źródła do pliku binarnego tak, żeby analiza kodu źródłowego nadal dotyczyła artefaktu po buildzie i dystrybucji.

Analogia z dokumentacji: SBOM jest jak lista składników produktu spożywczego, a SLSA jak zasady bezpiecznego wytwarzania i plomby, dzięki którym tej liście da się wierzyć.

### Integralność i dostępność

Główny cel SLSA to integralność, czyli ochrona przed podmianą lub nieautoryzowaną zmianą na każdym etapie, a cel drugorzędny to dostępność. Integralność dzieli się na:

- integralność źródła: zmiany w kodzie odpowiadają intencji producenta (w praktyce: zatwierdzenie przez dwie upoważnione osoby);
- integralność buildu: paczka jest zbudowana z właściwych, niezmienionych źródeł i zależności według przepisu producenta, a artefakt nie zmienia się między etapami.

### Zagrożenia w łańcuchu (A–H)

| | Zagrożenie | Przykład ze strony | Czy dotyczy pracy |
| --- | --- | --- | --- |
| A | nieautoryzowana zmiana w repozytorium | SushiSwap | nie |
| B | kompromitacja repozytorium źródeł | serwer git PHP | nie |
| C | build ze zmienionych źródeł | Webmin | nie |
| D | skompromitowana zależność | event-stream | pośrednio: obraz bazowy jest zależnością każdego obrazu z `FROM` |
| E | kompromitacja procesu buildu | SolarWinds | nie |
| F | wgranie zmienionej paczki | Codecov | nie |
| G | kompromitacja rejestru paczek | złośliwe lustra rejestrów | pośrednio: kampania pobiera przez `mirror.gcr.io` |
| H | użycie podrobionej paczki | typosquatting Browserify | nie |

Zagrożenie dostępności: zależność znika z repozytorium (przykład Mimemagic). SLSA tego nie rozwiązuje. W kampanii to zjawisko widać wprost: 168 nieudanych skanów, w tym brakujące bloby na lustrze.

Punkt G jest ciekawy dla pracy, bo przykładem są lustra rejestrów. Kampania używa lustra jako drogi pobrania i chroni się przez porównanie digestu z lustra z digestem z API Huba, nie przez weryfikację pochodzenia SLSA.

### Ścieżka Build i poziomy

| Poziom | Wymaganie | Przed czym chroni |
| --- | --- | --- |
| Build L0 | brak | – |
| Build L1 | istnieje pochodzenie (provenance): kto zbudował, jakim procesem, z jakich wejść | pomyłki, dokumentacja; łatwe do podrobienia |
| Build L2 | podpisane pochodzenie z hostowanej platformy buildu | podmiana po buildzie |
| Build L3 | utwardzona platforma buildu: przebiegi nie wpływają na siebie, klucz podpisu niedostępny dla kroków użytkownika | podmiana w trakcie buildu |

Pochodzenie opisuje build, a nie zawartość. Poziom dotyczy jednego artefaktu. Specyfikacja mówi wprost, że poziom SLSA nie jest przechodni: poziom artefaktu nie mówi nic o poziomie jego zależności. Uzasadnienie: gdyby był przechodni, wdrożenie musiałoby zaczynać od początku łańcucha, od komponentów najmniej ryzykownych.

Dla obrazów kontenerów oznacza to, że nawet obraz aplikacji na Build L3 nie dziedziczy niczego po poziomie obrazu bazowego, z którego powstał.

W v1.2 doszła ścieżka Source z własnymi poziomami: historia zmian i pochodzenie rewizji, potem stałe egzekwowanie kontroli technicznych w repozytorium.

### Weryfikacja artefaktu

Pochodzenie nic nie daje, dopóki ktoś go nie sprawdzi. Weryfikacja według SLSA:

1. sprawdzić podpis pochodzenia względem skonfigurowanych korzeni zaufania (lista zaufanych platform buildu i poziomów);
2. sprawdzić, że `subject` w pochodzeniu odpowiada **digestowi** danego artefaktu;
3. sprawdzić, że pochodzenie odpowiada oczekiwaniom: platforma buildu, kanoniczne repozytorium źródeł, typ buildu, parametry zewnętrzne;
4. opcjonalnie, rekurencyjnie: zależności.

Oczekiwania można budować przez zaufanie przy pierwszym użyciu (jak TUF w DCT u Vehenta), przez deklarację producenta albo przez źródło. Weryfikacja może się dziać w ekosystemie przy publikacji, u odbiorcy przy pobraniu albo w monitorze, który stale sprawdza zbiór paczek.

Punkt 2 łączy SLSA z metodyką pracy. Tożsamość artefaktu w SLSA to digest, nie nazwa ani tag.

### SBOM, in-toto, odtwarzalność

- SBOM opisuje składniki artefaktu i służy m.in. do oceny znanych podatności i licencji. Pochodzenie SLSA opisuje build, bardziej zgrubnie. Według FAQ to różne poziomy abstrakcji; SBOM może być częścią przyszłej ścieżki podatności. Lista pakietów z Trivy (`--list-all-pkgs`) jest w tym słowniku inwentarzem bliskim SBOM, nie pochodzeniem.
- in-toto jest ogólną warstwą do zapisu atestacji łańcucha dostaw, a SLSA mówi, co w niej musi być dla danego poziomu. Rice wymienia in-toto w 2020 roku; SLSA jest dziś kontekstem, w którym się go używa.
- Odtwarzalny build (te same wejścia, bit w bit to samo wyjście) i build weryfikowany odtwarzalnie (dwie niezależne platformy) są opcją realizacji wymagań, ale SLSA ich nie wymaga i nie uważa za pełne rozwiązanie.

### Czego SLSA nie obejmuje

- jakości kodu i bezpiecznego programowania;
- producenta, który celowo wydaje złośliwe oprogramowanie;
- przechodniego zaufania do zależności.

Brakuje tu też tego, co mierzy praca: liczby znanych podatności w artefakcie. SLSA mówi, czy artefakt jest tym, za co się podaje. Nie mówi, czy jest bezpieczny w sensie CVE.

### Jak to rozłożyć na rozdziały

| Teza z SLSA | Rozdział pracy |
| --- | --- |
| Ryzyko na każdym ogniwie: źródło, build, pakowanie, dystrybucja | wstęp, 2.4 |
| Skan jest potrzebny, ale nie mówi, czy uruchamiany kod to kod przeskanowany | wstęp, uzasadnienie integralności artefaktu |
| Tożsamość artefaktu = digest (`subject`) | 3.3 i metodyka: pin digestem |
| Poziomy Build L0–L3, ścieżka Source w v1.2 | 2.4, kontekst; nie oceniane w badaniu |
| Poziom nie jest przechodni | 2.4: wybór bazy jest osobną decyzją od poziomu buildu aplikacji |
| Zagrożenie G (lustra rejestrów) i dostępność | 3.3 i ograniczenia: lustro, porównanie digestów, 168 porażek |
| SBOM ≠ pochodzenie | 3.5: lista pakietów Trivy jako inwentarz, nie atestacja |

### Czego z SLSA nie wyciągać

- poziomu SLSA badanych obrazów; nie był oceniany;
- tezy, że pin digestem „spełnia SLSA”; pin wykorzystuje tę samą tożsamość artefaktu, ale bez pochodzenia i bez podpisu żaden poziom nie jest osiągnięty;
- czegokolwiek o wariantach `slim`, `alpine`, `distroless`.

---

## Zderzenie źródeł z pomiarem

### Książki

Obie książki mówią, że mniej zbędnego kodu zmniejsza powierzchnię, i obie każą uważać, skąd obraz pochodzi. Żadna nie mierzy, o ile spada liczba CVE po wyborze wariantu oficjalnego obrazu, ani co znika razem z pakietami. To jest luka, którą wypełnia kampania.

Rice każe skanować wielokrotnie, bo baza podatności rośnie przy nieruchomym obrazie. Kampania robi odwrotnie na czas porównania: jedna zamrożona baza, żeby różnica klas nie była różnicą dnia skanu. W pracy trzeba powiedzieć oba zdania. Regularny reskan jest zaleceniem operacyjnym. Jedna data bazy jest warunkiem porównania.

Rice każe wskazywać obraz digestem, gdy liczy się konkretna treść. Vehent w przykładzie dydaktycznym używa `busybox:latest` i opisuje DCT jako osobny, wtedy jeszcze niewygodny mechanizm. Metodyka pracy bierze z Rice digest, a z Vehenta świadomość, że rejestr jest przystankiem potoku, nie całym łańcuchem. Podpisów nie weryfikuje.

### Wytyczne i specyfikacje

NIST jako jedyne źródło zaleca wprost jedną z czterech klas: minimalistyczną bazę w rodzaju Alpine. Uzasadnia to powierzchnią ataku, ale nie podaje liczb. Distroless definiuje własną klasę i mówi o lepszym sygnale w skanerach, ale też nie porównuje liczby CVE z `alpine` ani `slim`. Kampania sprawdza oba twierdzenia na tej samej próbie i tej samej bazie podatności.

NIST, Rice i SLSA zgodnie traktują znane podatności jako stan zmienny w czasie, a tożsamość artefaktu jako coś, co nie może zależeć od tagu. Metodyka bierze z tego dwie decyzje: pin digestem (SLSA: `subject` = digest; NIST: `latest` nie gwarantuje świeżości) i jedną zamrożoną bazę (NIST i Rice: liczba CVE rośnie przy nieruchomym obrazie).

Distroless pokazuje, że wynik klasy zależy od linii bazy. Stare linie Debiana nadal da się pobrać, ale nie są aktualizowane, i pilotaż to potwierdza (`python3-debian12`: 258 CVE, `python3-debian13`: 151). To uzasadnia parowanie po linii Debiana i osobną analizę świeżości.

CVSS ustawia granice interpretacji. Etykiety krytyczności w danych opisują podatność względem innych podatności, a nie ryzyko wdrożenia. Ocena środowiskowa, jedyne miejsce na konfigurację uruchomienia, nie jest liczona. Dlatego rozdział 5 pokazuje rozkład etykiet, a nie „ryzyko klasy”.

SLSA wyznacza, czego praca nie robi. Mierzy zawartość artefaktu w jednym punkcie czasu, a nie integralność jego drogi. Mniejsza baza zmniejsza zbiór składników do sprawdzenia (argument distroless), ale nie podnosi poziomu SLSA, bo poziomy nie są przechodnie.

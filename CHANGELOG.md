# Changelog

## 0.28 – w przygotowaniu

- **C-LAPS-NONE**: zgłaszane (High) także wtedy, gdy schemat ma atrybuty LAPS, ale żaden aktywny komputer Windows nie ma hasła LAPS (np. schemat Windows LAPS rozszerzony aktualizacją DC bez wdrożenia). Wcześniej wynik to C-LAPS-MISSING (Medium) z listą wszystkich komputerów.
- DC-SMB1: naprawa uzupełniona o `Uninstall-WindowsFeature FS-SMB1` dla Windows Server.
- Raport HTML: pola macierzy ryzyka ze znaleziskami rozwijają się po kliknięciu i pokazują listę znalezisk z odnośnikami do szczegółów; każde znalezisko ma odnośnik powrotny „↑ Macierz ryzyka”.
- **D-DCSYNC**: zestaw praw replikacji liczony dla podmiotu łącznie z jego grupami (rekursywnie, z grupą podstawową, Everyone i Authenticated Users). DCSync („pełny”) wymaga DS-Replication-Get-Changes i -Get-Changes-All, także z różnych wpisów lub grup; wcześniej sam wpis Get-Changes-All dawał Critical. Niepełny zestaw – Medium; nowa kolumna Zestaw. Gdy grup podmiotu nie da się odczytać, zestaw jest „nieustalony” i traktowany jak pełny.
- D-ACL-DOMAIN: sam wpis DS-Replication-Get-Changes-In-Filtered-Set nie jest już zgłaszany jako Critical „przejęcie obiektu domeny” – trafia do D-DCSYNC.
- Członkostwo w grupach uprzywilejowanych uwzględnia grupę podstawową (primaryGroupID) grupy i grup w niej zagnieżdżonych. Konto z primaryGroupID=512 (administrator domeny niewidoczny w liście członków) nie było dotąd traktowane jako uprzywilejowane.
- D-GPO-LLMNR, D-GPO-PSLOG: ustawienie obecne tylko w GPO podlinkowanych do OU lub lokacji daje status „Zaliczony warunkowo” z listą miejsc podlinkowania (wcześniej „Zaliczony”); GPO nieczytelne dla konta przeglądu – „Nierozstrzygnięty”. Tabele obiektów mają kolumnę Podlinkowane. Zakres oceny w raporcie podaje liczbę reguł zaliczonych warunkowo.
- DC-SMB1: przekroczenie czasu lub inny błąd odczytu odpowiedzi sondy daje wynik nierozstrzygnięty (DC-UNKNOWN) zamiast „SMB1 wyłączony”. Zerwanie połączenia po negocjacji SMB1 nadal oznacza „wyłączony”.
- `-Previous`: plik sprawdzany na starcie (struktura raportu ADCheck, zgodna główna wersja `SchemaVersion`), a nie po zakończeniu przeglądu.
- Brak odpowiedzi LDAP Who am I: ostrzeżenie na konsoli i w nagłówku raportu, że ocena konta przeglądu opiera się na koncie procesu.
- Windows 11 26H2: data końca wsparcia oznaczona jako szacunek (kolumna KoniecWsparcia „(szacunek)”); szacowane daty nie generują C-OS-FEATURE.
- Plan naprawczy: zastrzeżenie, że szacunki nie są wyceną ani zobowiązaniem realizacyjnym.
- **Klasa ekspozycji A–E** zamiast „Poziomu dojrzałości 1–5” (Critical = E, High = D, Medium = C, Low = B, brak = A). Wskaźnik opisuje stan techniczny AD w zakresie testów, a nie dojrzałość procesów bezpieczeństwa – stara nazwa sugerowała ocenę organizacji. Karty znalezisk nie powtarzają już poziomu (wynika z wagi). JSON: nowe pole `Meta.KlasaEkspozycji`; `Meta.Dojrzalosc` (1–5) zostaje dla zgodności.
- Wynik przy limicie 100: karta wyniku i konsola podają pełną sumę punktów najgorszego obszaru, a porównanie z `-Previous` – zmianę sumy, gdy któryś wynik przekracza limit (wcześniej 4 i 10 znalezisk Critical dawały ten sam wynik i zmianę 0). JSON: nowe pole `Meta.ObszaryBezLimitu`; obiekt `-Silent`: `WynikBezLimitu`, `KlasaEkspozycji`.
- JSON: pole `SchemaVersion` (`1.0`) na początku pliku – zmiana główna oznacza niezgodną zmianę struktury, drugorzędna nowe pola.
- CI: GitHub Actions (Windows PowerShell 5.1 i PowerShell 7) – PSScriptAnalyzer (Warning, Error), testy Pester i kontrola kodowania UTF-8 z BOM plików `*.ps1`.
- C-LAPS-EXPIRED pomija komputery nieużywane dłużej niż `-StaleDays` (są w C-STALE), tak jak C-LAPS-MISSING.
- Nagłówek raportu: tryb testów DC opisany jako „bez -UseWinRM” zamiast „zwykłe konto” (mylące przy przeglądzie kontem uprzywilejowanym).
- Załącznik B (metodyka): aktualny zakres – AD CS jest oceniany.
- D-ADCS-ESC4, D-ADCS-ESC5: domyślne prawo Enroll/AutoEnroll (edytor szablonów zapisuje je jako odczyt + zapis + prawo rozszerzone z GUID-em prawa) nie jest już zgłaszane jako „zapis atrybutu”. Wcześniej domyślne szablony User, Machine i EFS dawały fałszywe Critical ESC4.
- Kolumna Czlonkowie (testy ACL i AD CS) uwzględnia członkostwo przez grupę podstawową (primaryGroupID), więc Domain Users i Domain Computers nie pokazują już „(brak aktywnych kont)”.
- **D-ADCS-ORPHAN** (High/Medium): CA wycofane, ale zarejestrowane w AD (brak, wyłączone lub nieużywane konto komputera serwera CA), z informacją, czy certyfikat CA jest nadal w NTAuthCertificates (High). Dla takich CA nie są wykonywane sondy ESC6/7/8/11; gdy wszystkie CA są wycofane, reguły mają status „Nie dotyczy (tylko wycofane CA)” zamiast „Nierozstrzygnięty”.
- D-ADCS-ESC1/2/3/4/9: szablony opublikowane wyłącznie na wycofanym CA nie podnoszą wagi do najwyższej (kolumna TylkoWycofaneCA).
- Kolumna Czlonkowie: SID domeny bez obiektu w AD opisany jako „(SID nierozwiązany - obiekt usunięty?)”; ESC5 oznacza obiekt wycofanego CA.
- Przegląd kontem uprzywilejowanym na samym DC bez „Uruchom jako administrator”: ostrzeżenie na konsoli i w nagłówku raportu. UAC zostawia wtedy grupy administracyjne i Pre-Windows 2000 Compatible Access tylko do odmowy, więc konto widzi mniej niż zwykły użytkownik; INFO-USERS-UNREADABLE wskazuje tę przyczynę.
- D-FGPP-WEAK: nieczytelny kontener PSO (0x8007200A) daje status „Pominięty (kontener PSO niewidoczny dla konta przeglądu)” zamiast błędu testu.
- C-OS-W10 i C-OS-FEATURE pomijają komputery nieużywane dłużej niż `-StaleDays` (są w C-STALE), tak jak C-LAPS-EXPIRED; plan naprawczy nie proponuje już migracji systemów, których nie ma.
- D-PREWIN2000: opis, zalecenie i polecenia naprawcze zależne od członków grupy. Przy samym Authenticated Users raport mówi wprost, że to zmiana o niskim priorytecie wymagająca testu aplikacji, i podaje polecenie wycofania.
- D-DNS-CREATECHILD: strefa z nieczytelnymi uprawnieniami nie jest już po cichu zaliczana - trafia do ERR-DNS-ZONES, a reguła bez znaleziska ma status „Nierozstrzygnięty”.
- Testy kont użytkowników pomijają konta z nieczytelnym userAccountControl (wpis Deny w uprawnieniach), które wcześniej trafiały do U-STALE jako aktywne bez dat. Takie konta są wymienione w nowym znalezisku Info INFO-USERS-UNREADABLE.

## 0.27 – 2026-11-07

- **D-ADCS-ESC6**, **-ESC7**, **-ESC11**: ustawienia i uprawnienia samego CA odczytywane przez interfejs administracyjny CA (ICertAdmin2, prawo Read domyślnie dla Authenticated Users), z limitem czasu 30 s na CA. ESC7 jest Critical przy roli ManageCA lub szerokiej grupie.
- Nowy status reguły „Nierozstrzygnięty”: gdy serwer CA nie odpowiada (np. zapora), D-ADCS-ESC8 i reguły ESC6/7/11 nie są już zaliczane. Przyczyna dla każdego CA trafia do znaleziska INFO-ADCS-UNVERIFIED, a liczba – do zakresu oceny na początku raportu. Odrzucone połączenie na TCP 80 (brak usługi WWW) jest traktowane jako rozstrzygnięte.
- P-ACL-TIER0: jeden wiersz na podmiot (liczba obiektów Tier 0, przykłady, suma praw) z priorytetem 1–3 (szeroka grupa / prawo przejęcia / tylko zapis SPN); pełna lista obiektów nadal w `_obiekty.csv`.

## 0.26 – 2026-11-07

- **P-ACL-TIER0** (Critical/High): niebezpieczne uprawnienia i nietypowi właściciele na kontach i grupach uprzywilejowanych, kontach komputerów DC i OU Domain Controllers. Pomijane są wpisy skopiowane z AdminSDHolder (zgłasza je D-ACL-ADMINSDHOLDER) i podmioty, które już są uprzywilejowane.
- **DC-RBCD** (Critical): RBCD ustawione na koncie kontrolera domeny.
- **D-KCD-DC** (Critical/High): delegacja ograniczona do usług DC, z rozróżnieniem przejścia protokołu.
- Wszystkie testy ACL rozpoznają też zapis msDS-KeyCredentialLink (Shadow Credentials), msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD) i servicePrincipalName (celowany Kerberoasting).
- **P-KeyAdmins**, **P-EnterpriseKeyAdmins** (Medium): niepuste grupy Key Admins / Enterprise Key Admins; ich członkowie są traktowani jak konta uprzywilejowane. Domyślne prawa tych grup do msDS-KeyCredentialLink (Windows Hello for Business) nie są już zgłaszane jako fałszywe alarmy w D-ACL-DOMAIN i P-ACL-TIER0.
- Nazwy grup wbudowanych istniejących tylko na DC (np. Pre-Windows 2000 Compatible Access) są ustalane z LDAP, gdy przegląd działa ze stacji roboczej (wcześniej w raporcie zostawał sam SID).
- C-LAPS-READABLE: przy przeglądzie kontem uprzywilejowanym status „Pominięty (konto uprzywilejowane)” zamiast „Zaliczony”; konto sprawdzane po tożsamości LDAP, a nie procesu (poprawny wynik przy `runas /netonly`).
- **Usługi certyfikatów (AD CS)**, nowa kategoria: CA i opublikowane szablony z partycji konfiguracji. Reguły D-ADCS-ESC1, -ESC2, -ESC3, -ESC9, -ESC13 (flagi, EKU i prawo Enroll szablonów dla nie-administratorów), -ESC4 (prawa zapisu do opublikowanych szablonów), -ESC5 (prawa do obiektów PKI i konta serwera CA) i -ESC8 (sonda HTTP `/certsrv/` z NTLM). Bez AD CS reguły mają status „Nie dotyczy”. ESC6, ESC7, ESC10 i ESC11 nie są oceniane.
- **P-GMSA-READ** (Critical/High): kto może pobrać hasło gMSA – szerokie grupy oraz serwery spoza Tier 0 przy gMSA w grupach uprzywilejowanych.
- **C-RBCD** (Critical/Medium/Low): RBCD ustawione na kontach poza DC, z oznaczeniem kont uprzywilejowanych i podmiotów utworzonych przez MachineAccountQuota.
- **U-SPN-WEAK** (High): konta z SPN z hasłem starszym niż 3 lata i bez AES – priorytet przy Kerberoastingu.
- **D-FGPP-WEAK** (High/Medium): PSO słabsze od polityki haseł domeny, z listą objętych kont i grup. Gdy konto przeglądu nie widzi PSO, reguła ma status „Pominięty”, a nie „Zaliczony”.
- **D-TRUST-STALE** (Medium) i **D-TRUST-SELAUTH** (Low): relacje zaufania bez zmiany hasła od ponad 90 dni i bez uwierzytelniania selektywnego. Bez relacji zaufania obie reguły mają status „Nie dotyczy”.
- **D-SPN-DUP**, **D-UPN-DUP** (Low): zduplikowane SPN i UPN w domenie.
- **D-GPO-UNLINKED** (Low): GPO bez aktywnych łączy do domeny, OU lub lokacji.
- C-LAPS-MISSING pomija komputery bez LAPS nieużywane dłużej niż `-StaleDays` (są w C-STALE); ich liczba jest podana w opisie znaleziska.
- Czytelny komunikat na starcie przy błędnym haśle (0x8007052E) i zablokowanym koncie (0x80070775).

## 0.25 – 2026-11-07

- Poprawka regresji z 0.24: błąd odczytu stref DNS przerywał cały test domeny (Kosz AD, polityka haseł, dSHeuristics, zaufania). Test stref DNS ma teraz własną obsługę błędu (ERR-DNS-ZONES) i oznacza jako „Błąd testu” tylko D-DNS-CREATECHILD.
- Strefy DNS wyszukiwane od korzenia partycji (DomainDnsZones, ForestDnsZones, CN=System), a GPO domeny i DC jednym wyszukiwaniem w CN=Policies. Obiekt, którego konto nie może czytać, nie przerywa już odczytu błędem 0x8007200A, tylko jest pomijany i raportowany.
- INFO-GPO-READ: wyjaśnienie skutku (GPO bez prawa odczytu dla Authenticated Users / Domain Computers może nie być stosowane na komputerach, MS16-072) i polecenia do sprawdzenia uprawnień.

## 0.24 – 2026-11-07

- Testy konfiguracji DC (DC-GPO, CIS, Microsoft Security Baseline) nie przerywają się, gdy konto przeglądu nie może odczytać jednego z GPO podpiętych do domeny lub OU Domain Controllers (np. przez filtrowanie zabezpieczeń). Takie GPO są pomijane i wymienione w nowym znalezisku INFO-GPO-READ z kodem błędu.
- D-DNS-CREATECHILD: błąd odczytu stref DNS daje status „Błąd testu” zamiast fałszywego zaliczenia (pomijany jest tylko brak partycji/kontenera).
- DC-NETSESSION pominięty przy koncie uprzywilejowanym ma status „Pominięty”, także gdy inne testy DC zgłosiły błąd.

## 0.23 – 2026-11-07

- **D-GPP-PASSWORD** (Critical/High): hasła w preferencjach GPO w SYSVOL – `cpassword` (Groups, Services, ScheduledTasks, DataSources, Drives, Printers) i hasło autologowania `DefaultPassword` w Registry.xml; wszystkie GPO, także niepodlinkowane. Raport pokazuje GPO, plik, element i konto, nigdy samo hasło.
- **P-DnsAdmins** (Medium): niepusta grupa DnsAdmins; jej członkowie są traktowani jak konta uprzywilejowane we wszystkich testach (grupa wyszukiwana po nazwie, bo nie ma stałego SID).
- **P-GPCO** (Low): konta spoza administratorów w Group Policy Creator Owners.
- Znaleziska ACL (D-DCSYNC, D-ACL-DOMAIN, D-ACL-ADMINSDHOLDER, D-ACL-GPO): kolumna Czlonkowie – aktywne konta, które efektywnie (rekursywnie) mają prawo nadane grupie.
- Konto LDAP: skrypt pyta serwer, jakim kontem się uwierzytelnił (LDAP Who am I). Przy `runas /netonly` nagłówek raportu pokazuje osobno konto procesu i konto LDAP; ocena „konto uprzywilejowane” dotyczy konta LDAP.
- Zakres oceny pod wynikiem: liczba ocenionych reguł i nieocenionych (wymaga -UseWinRM, pominięte, błąd testu).
- INFO-REFDATA: ostrzeżenie w raporcie i konsoli, gdy wzorzec poprawek DC ma ponad 45 dni lub daty cyklu życia ponad 120 dni.
- Poprawki: P-STALE nie zgłasza kont utworzonych w ostatnich `-StaleDays` dniach; DC-UNKNOWN odróżnia testy pominięte celowo od nierozstrzygniętych; raport HTML5 bez pustej tabeli na końcu; neutralne sformułowania w zaleceniach (bez wewnętrznych procesów i nazw narzędzi).

## 0.22 – 2026-11-07

- Postęp w konsoli: połączenie z domeną, dane bazowe (liczba DC i kont uprzywilejowanych), każdy test z wynikiem (OK / liczba znalezisk i najwyższa waga / błąd) i czasem, zapis raportu, łączny czas przeglądu.
- `-Silent`: bez komunikatów w konsoli; skrypt zwraca obiekt (Klient, Domena, Wynik, Dojrzalosc, Critical, High, Raport, Json, Csv, CzasSek) do użycia w skryptach.
- Jednolita nazwa narzędzia **ADCheck**: plik `ADCheck.ps1` (wcześniej `PEPIX-ADCheck.ps1`), repozytorium `pepix-pm/ADCheck`, nagłówek w konsoli i stopka raportu; domyślny katalog wyników przy uruchomieniu z GitHuba: `%USERPROFILE%\ADCheck\raporty`.
- Licencja **PolyForm Shield 1.0.0** (`LICENSE.md`, nota w pomocy skryptu `.NOTES`).
- Metodyka w raporcie: neutralne sformułowanie o wprowadzaniu poleceń naprawczych (test skutków, zasady zarządzania zmianami organizacji).

## 0.21 – 2026-11-07

- Porównanie konfiguracji DC także z **Microsoft Security Baseline** dla Windows Server 2025 (profil Domain Controller; wartości wg Microsoft Learn, stan 2026-01): kolumny Microsoft i ZgodneMS w tabelach CIS, 7 dodatkowych ustawień spoza wybranych kontroli CIS (m.in. AllowCustomSSPsAPs, UseMachineId, AutoDisconnect).
- **DC-MSBASE** – tylko luki wg Microsoft, których nie zgłosił CIS ani inny test (bez podwójnego liczenia punktów).
- DC-CIS-SUMMARY: w tytule odsetek zgodności wg CIS i wg Microsoft.
- Przy znaleziskach odniesienie do odpowiadającej rekomendacji **Microsoft Defender for Identity** (ocena stanu zabezpieczeń tożsamości) z linkiem do Microsoft Learn; pole MDI w CSV/JSON.

## 0.20 – 2026-11-07

Nowe testy uprawnień (ACL), zwykłe konto, tylko odczyt:
- **D-DCSYNC** – prawo DS-Replication-Get-Changes-All (lub wszystkie prawa rozszerzone) na obiekcie domeny dla podmiotów spoza DC i administratorów; konto synchronizacji Entra ID oznaczane w kolumnie Uwagi.
- **D-ACL-DOMAIN** – GenericAll, WriteDacl, WriteOwner, zapis wszystkich atrybutów lub gPLink na obiekcie domeny (np. Exchange Windows Permissions).
- **D-ACL-ADMINSDHOLDER** – niestandardowe prawa zapisu / resetu hasła na AdminSDHolder.
- **D-ACL-GPO** – GPO podpięte do domeny i OU Domain Controllers modyfikowalne przez nie-adminów (obiekt w AD i katalog w SYSVOL).

## 0.19 – 2026-11-07

Poprawki po pierwszym przebiegu 0.18 w środowisku produkcyjnym:
- **Błąd:** sonda anonimowego LDAP przerywała testy DC wyjątkiem „retrieving member Dispose” (adapter PowerShell dla DirectoryEntry). Skutek: DC-LDAPSIGN, DC-LDAPCBT i DC-NTLMV1 oznaczone jako błąd testu. Metody DirectoryEntry wywoływane teraz przez `.psbase`, sondy są po głównych testach DC i każda ma własną obsługę błędów.
- Windows 11 build 26300 = 26H2 (daty końca wsparcia szacunkowe, do potwierdzenia po GA).
- DC-REGISTRATION: rozróżnia pozostałość po zdegradowanym DC (konto serwera bez flagi DC w OU Domain Controllers, pozostały obiekt serwera w lokacjach) od zwykłego komputera w tej OU.
- DC-SUBNET: osobny tytuł, gdy w AD nie ma żadnej podsieci; opis uwzględnia liczbę lokacji.
- C-OWNER: obiekty, których właściciela nie udało się odczytać, zgłaszane jako Info (C-OWNER-UNKNOWN) zamiast pomijane po cichu.
- Poprawiona odmiana w opisie C-LAPS-MISSING.
- DC-NTLMV1: dla nieustawionego LmCompatibilityLevel podana wartość domyślna (3) i jej skutek. DC-CIS-SUMMARY: w tytule liczba ustawień nieocenionych.
- DC-NETSESSION pomijany (z adnotacją w „Testy DC nierozstrzygnięte”), gdy przegląd uruchomiono kontem uprzywilejowanym – administrator zawsze widzi sesje, więc wynik byłby fałszywie dodatni. Na liście reguł ma status „Pominięty (konto uprzywilejowane)”, a nagłówek raportu informuje o uruchomieniu kontem uprzywilejowanym.

## 0.18 – 2026-11-06

Nowe testy (zwykłe konto, tylko odczyt):
- **DC-ANONLDAP** – sonda: czy DC zwraca konta na anonimowe zapytanie LDAP.
- **DC-NETSESSION** – sonda NetSessionEnum: czy zwykłe konto widzi sesje SMB na DC (brak NetCease).
- **D-DSHEURISTICS** – anonimowe operacje LDAP (7. znak) i wyłączone poprawki CVE-2021-42291 (28./29. znak).
- **D-DNS-CREATECHILD** – strefy DNS w AD z CreateChild dla szerokich grup i bez rekordu wildcard (ADIDNS spoofing).
- **D-GPO-LLMNR**, **D-GPO-HARDPATH**, **D-GPO-PSLOG** – ustawienia z wszystkich podlinkowanych GPO (domena, OU, lokacje; Registry.pol i preferencje rejestru), nie tylko z GPO kontrolerów domeny.
- **P-ADMINMAIL** – konta uprzywilejowane z adresem e-mail.
- Funkcje `Get-LinkedGpoRegistry` i `Get-DsHeuristicsChar`.

## 0.17 – 2026-11-06

Nowe testy (LDAP, zwykłe konto):
- **DC-REGISTRATION** – konto wyglądające na DC bez obiektu serwera lub NTDS Settings w CN=Sites, z niespójną grupą podstawową i flagą DC albo zwykły komputer w OU Domain Controllers.
- **DC-SUBNET** – adres DC poza podsieciami AD lub w podsieci innej lokacji.
- **D-FFL** – poziom funkcjonalny lasu < 2016.
- **P-ADMLOGIN** – wbudowany Administrator używany w ostatnich 35 dniach.
- **P-PROTECTED** – konta uprzywilejowane spoza Protected Users (bez kont z SPN i RID 500); brak grupy Protected Users.
- **C-OWNER** – komputery, których właścicielem obiektu jest konto spoza administratorów (ryzyko RBCD, odczytu LAPS).
- **D-PREWIN2000** – Everyone / Anonymous Logon / Authenticated Users w Pre-Windows 2000 Compatible Access.
- Funkcja `Test-IpInSubnet` z testami Pester.

## 0.16 – 2026-11-06

- Klasyfikacja systemów serwerowych także po numerze build, gdy nazwa nie zawiera roku: „Windows Server® 2008”, „Hyper-V Server” (2016/2019), Small Business Server 2011. Wcześniej takie systemy z buildem < 20348 trafiały błędnie do „SAC”; jako SAC oznaczane są teraz tylko buildy 16299–19042.
- Hyper-V Server rozpoznawany jako serwer (wcześniej pomijany, bo nazwa nie zawiera „Windows”).
- Windows 11 z buildem nowszym niż tabela (np. 26300, Insider) opisany jako „nowsza niż tabela / Insider” – bez oceny.
- C-LAPS-MISSING ocenia tylko komputery z Windows; konta bez systemu Windows (Linux, NAS, klastry, brak `operatingSystem`) są pomijane i liczone w opisie.
- Testy Pester dla `Get-OsLifecycle`; poprawka nazwy bloku `Describe` dla Pester 6.

## 0.15 – 2026-11-06

- **Bez RSAT:** odczyt AD przez LDAP (`System.DirectoryServices`) zamiast modułu ActiveDirectory. Skrypt działa na każdym Windows bez instalacji i bez uprawnień administratora na stacji. Replikacja i kopia AD z atrybutów konstruowanych `msDS-NCReplInboundNeighbors` / `msDS-ReplAttributeMetaData`; członkostwo rekursywne przez LDAP_MATCHING_RULE_IN_CHAIN.
- Wymagania: zamiast modułu AD sprawdzane połączenie LDAP z domeną (TCP 389).

## 0.14 – 2026-11-06

- Przycisk „Kopiuj” przy blokach z poleceniami naprawczymi w raporcie HTML (ukryty na wydruku).

## 0.13 – 2026-11-06

- Wygląd raportu w identyfikacji PEPIX: logo z papieru firmowego (osadzone w HTML), kolory marki (#F59F00, #4299E1), spójna paleta wag i ocen, stopka, poprawiony wydruk (kolory zachowane).

## 0.12 – 2026-11-06

- Plan naprawczy: trzy etapy (do 30 dni / 30–90 dni / do 12 miesięcy), szacunek pracochłonności w godzinach, uwagi i zależności; sekcja w HTML, `Plan` w JSON, plik `_plan.csv`.

## 0.11 – 2026-11-06

- Odniesienie do NIS2 art. 21 ust. 2 / UKSC i ISO/IEC 27001:2022 (załącznik A): pola NIS2 i ISO27001 w znaleziskach (HTML, JSON, CSV) i sekcja zestawienia w raporcie.

## 0.10 – 2026-11-06

- Raport w układzie zbliżonym do PingCastle: wynik 0–100 w czterech obszarach ryzyka (obiekty nieaktualne, konta uprzywilejowane, zaufania, anomalie), wynik ogólny = najgorszy obszar, poziom dojrzałości 1–5, macierz ryzyka, lista sprawdzonych reguł ze statusem, linki MITRE ATT&CK.
- Katalog reguł `$ruleCatalog`; znaleziska mają pola Obszar, Model, Poziom (JSON, CSV).
- **Zmiana znaczenia `Meta.Wynik`:** wcześniej suma punktów bez limitu, teraz 0–100 (najgorszy obszar). Porównanie `-Previous` z raportem sprzed 0.10 pokazuje różnicę w innych jednostkach.

## 0.9 – 2026-11-06

- Kerberos i szyfrowanie: DES w konfiguracji kont/komputerów/zaufań/KDC (D-KRB-DES), konta bez kluczy AES (D-KRB-NOAES), zaufania bez AES (D-KRB-TRUST); z `-UseWinRM` faktyczne bilety DES/RC4 z dziennika Security DC (DC-KRB-DES-USED, DC-KRB-RC4-USED).
- P-SPN i U-SPN: kolumna Szyfrowanie (RC4 / AES).

## 0.8 – 2026-11-06

- Aktualizacje DC: poziom poprawek (UBR) przez zdalny rejestr na zwykłym koncie, porównanie z ostatnim Patch Tuesday (DC-PATCH-OLD) i między DC (DC-PATCH-DIFF); z `-UseWinRM` ostatnia poprawka, restart, oczekujący restart, WSUS (DC-REBOOT). Tabela w załączniku A.

## 0.7 – 2026-11-06

- Konfiguracja DC wg CIS L1: opcje zabezpieczeń i szablony administracyjne (DC-CIS-REG), zasady audytu (DC-CIS-AUDIT), przypisanie praw (DC-CIS-RIGHTS), podsumowanie zgodności (DC-CIS-SUMMARY). Zwykłe konto: GPO z SYSVOL; `-UseWinRM`: rejestr i auditpol każdego DC.
- Parser `Registry.pol` (`Read-RegistryPol`) i zbiorczy odczyt GPO DC (`Get-DcGpoPolicy`).
- Testy jednostkowe Pester 5 w `tests/`.

## 0.6 – 2026-11-06

- Nowa kategoria „Kondycja domeny i replikacja”: błędy i opóźnienia replikacji (z tombstone lifetime), kopia zapasowa AD (dSASignature), SYSVOL na FRS, osierocone role FSMO, jeden DC, hasło konta komputera DC, porty usług AD, udziały SYSVOL/NETLOGON, czas DC względem PDC, spójność GPO AD–SYSVOL, rekordy SRV w DNS.
- LAPS: rozpoznanie legacy / Windows LAPS, pokrycie w opisie; nowe testy C-LAPS-EXPIRED (hasło przestało się zmieniać), C-LAPS-LEGACY, C-LAPS-READ-BROAD i C-LAPS-READERS (kto może czytać hasła – ACL na OU), C-LAPS-READABLE (konto przeglądu widzi hasła; bez pobierania wartości).
- Poprawka: test COMPUTERS kończył się błędem, gdy w schemacie nie ma atrybutów LAPS (null w `-Properties`) – w takiej domenie nie raportowano żadnego znaleziska o komputerach ani braku LAPS.

## 0.5 – 2026-11-06

- Systemy operacyjne oceniane według dat Microsoft Lifecycle (wersja z `operatingSystemVersion`) zamiast samej nazwy: rozpoznawane wersje Windows 11, LTSB/LTSC, Server SAC; kolumny Wersja i KoniecWsparcia.
- Nowe testy: C-OS-FEATURE (Windows 11 w wersji bez wsparcia), C-OS-SOON (serwery/LTSC z końcem wsparcia w ciągu 12 miesięcy).
- C-OS-W10 nie obejmuje już Windows 10 LTSC (oceniane osobno według dat). DC-OS-EOL według dat zamiast nazwy.
- Załącznik A: rozkład systemów operacyjnych (liczba komputerów, aktywne, koniec wsparcia).

## 0.4 – 2026-11-06

- Sprawdzanie wymagań na starcie zamiast wymuszania wersji PowerShella: Windows, moduł ActiveDirectory (z podpowiedzią instalacji dla serwera/stacji), ustalona domena, plik `-Previous`, połączenie z AD (ADWS TCP 9389). Wszystkie braki zgłaszane naraz.
- Pliki wynikowe zawsze w UTF-8 z BOM, także w PowerShell 7 (wcześniej polskie znaki w CSV/HTML mogły się psuć).

## 0.3 – 2026-11-06

- Uruchamianie bez kopiowania pliku: skrypt działa jako scriptblock pobrany z prywatnego repo GitHub (instrukcja w README).
- Usunięto `#Requires` (nieobsługiwane w scriptblocku); wersja PowerShell i moduł ActiveDirectory sprawdzane ręcznie z czytelnym komunikatem.
- Domyślny `-OutDir` bez `$PSScriptRoot`: przy uruchomieniu z GitHuba `%USERPROFILE%\PEPIX-ADCheck\raporty`.
- Poprawka: ustawienia DC z GPO nie trafiały do testów przy uruchomieniu jako scriptblock (`$script:gpoSettings`).
- Poprawka: funkcja `H` przesłaniana przez wbudowany alias `h` (`Get-History`) – zmieniona na `HtmlEnc`; generowanie HTML kończyło się błędem.

## 0.2

- Wersja wyjściowa.

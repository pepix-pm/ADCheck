# ADCheck

Skrypt PowerShell do przeglądu bezpieczeństwa Active Directory. Działa na **zwykłym koncie domenowym**, bez instalacji agentów i bez narzędzi firm trzecich. Wynikiem jest szczegółowy raport HTML dla właściciela domeny i administratorów oraz dane JSON/CSV do porównań między przeglądami.

Tworzy i rozwija [PEPIX](https://pepix.pl) – przeglądy bezpieczeństwa Active Directory, wdrożenia poprawek z raportu i stała opieka nad infrastrukturą Microsoft.

## Dlaczego ADCheck?

- **Wystarczy zwykłe konto domenowe.** Większość testów, także kontrolerów domeny, działa bez uprawnień administracyjnych: odczyt LDAP i SYSVOL oraz nieinwazyjne sondy sieciowe. Tryb `-UseWinRM` uzupełnia wynik o rzeczywisty stan DC.
- **Nic nie instaluje i niczego nie zmienia.** Jeden plik PowerShell, bez RSAT, agentów i dodatkowych modułów; wyłącznie odczyt.
- **Raport, z którym można pracować.** Każde znalezisko ma opis ryzyka zrozumiały dla właściciela domeny, zalecenie i przykładowe polecenia naprawcze. Plan naprawczy dzieli zadania na trzy etapy z szacunkiem pracochłonności.
- **Odniesienia do wymagań.** Znaleziska są przypisane do środków z art. 21 NIS2 / UKSC, zabezpieczeń ISO/IEC 27001:2022 (załącznik A) i technik MITRE ATT&CK; konfiguracja DC jest porównana z CIS Benchmark i Microsoft Security Baseline.
- **Porównania w czasie.** `-Previous` pokazuje, co naprawiono i co doszło, `-History` – trend wyniku; JSON i CSV nadają się do własnych zestawień.
- **Jawne granice oceny.** Raport podaje, ile reguł faktycznie ocenił i które wyniki opierają się na źródle pośrednim (np. GPO zamiast rejestru DC), zamiast traktować brak danych jako zaliczenie.
- **Po polsku.** Raport i komunikaty są w języku polskim; grupy uprzywilejowane są rozpoznawane po SID, więc spolszczone nazwy grup nie przeszkadzają.

## Czego ADCheck nie sprawdza

- Nie zastępuje testów penetracyjnych i nie próbuje wykorzystać podatności.
- Nie analizuje stacji końcowych ani serwerów członkowskich – ocenia konfigurację zapisaną w AD, GPO i kontrolery domeny.
- Uprawnienia (ACL) sprawdza na obiekcie domeny (w tym DCSync), AdminSDHolder, GPO podpiętych do domeny i OU Domain Controllers oraz na obiektach Tier 0 (konta i grupy uprzywilejowane, konta DC, OU Domain Controllers) – nie na pozostałych kontach, OU i serwerach.
- Z usług certyfikatów (AD CS) ocenia konfigurację zapisaną w AD (ESC1–5, 9, 13), ustawienia i uprawnienia CA przez jego interfejs administracyjny (ESC6, 7, 11 – wymaga łączności RPC z serwerem CA) i sondą HTTP rejestrację przez WWW (ESC8); rejestr DC (ESC10) ocenia tylko z `-UseWinRM`; nie ocenia HTTPS z EPA. Gdy serwer CA jest nieosiągalny, reguły mają status „Nierozstrzygnięty”, a przyczyna trafia do znaleziska INFO-ADCS-UNVERIFIED.
- Ocena GPO kontrolerów domeny uwzględnia łącza wymuszone, blokowanie dziedziczenia i filtrowanie zabezpieczeń (od v0.31); nie ocenia treści filtrów WMI (takie GPO są oznaczane jako niepewne), GPO podlinkowanych do lokacji ani tego, które GPO faktycznie obejmują dany komputer poza DC.
- Przypisania praw użytkowników na DC odczytuje z GPO (konfiguracja zamierzona), także przy `-UseWinRM`.
- Nieaktywność kont opiera się na `lastLogonTimestamp` (dokładność ok. 14 dni).
- Polecenia naprawcze w raporcie są przykładowe: przed wykonaniem sprawdź ich skutki w środowisku testowym i wprowadzaj je zgodnie z zasadami zarządzania zmianami w organizacji.

## Wymagania

- Windows 10/11 lub Windows Server z PowerShellem (Windows PowerShell 5.1 lub PowerShell 7)
- **Bez RSAT i bez instalowania czegokolwiek** – AD jest odczytywane przez LDAP (`System.DirectoryServices`, wbudowane w Windows)
- Stacja w domenie (lub `-Server`) z dostępem do kontrolerów domeny: LDAP (TCP 389), SMB/SYSVOL (TCP 445), DNS domeny
- Konto użytkownika domeny bez uprawnień administracyjnych (wystarczy członkostwo w Domain Users). Tryb `-UseWinRM` wymaga konta z grupy Administrators domeny (np. członka Domain Admins) i dostępu WinRM (TCP 5985) do każdego DC

Skrypt sprawdza wymagania na starcie i wypisuje wszystkie braki naraz.

**Nie uruchamiaj skryptu w zdalnej sesji PowerShell** (`Enter-PSSession`, `Invoke-Command`) na komputerze innym niż kontroler domeny. Taka sesja nie przekazuje poświadczeń dalej do DC (podwójny przeskok Kerberos), więc zapytania LDAP kończą się błędem „An operations error occurred”. Uruchom skrypt w sesji RDP lub na konsoli komputera w domenie, ewentualnie w zdalnej sesji bezpośrednio na kontrolerze domeny.

Pojęcia używane w README i raporcie:

- **konto bez uprawnień administracyjnych** (także „zwykłe konto”) – konto użytkownika domeny bez członkostwa w grupach administracyjnych, zwykle tylko w Domain Users;
- **administratorzy** – członkowie grup Domain Admins, Enterprise Admins i Administrators domeny;
- **podmiot** – konto użytkownika, komputera lub usługi albo grupa, której nadano prawo.

## Użycie

```powershell
clear
.\ADCheck.ps1 -Client KLIENT
.\ADCheck.ps1 -Client KLIENT -Server firma.local -UseWinRM
.\ADCheck.ps1 -Client KLIENT -Previous .\raporty\AD_KLIENT_firma.local_20260101-1200.json -History
```

| Parametr | Opis |
|---|---|
| `-Client` | Nazwa organizacji w raporcie i w nazwie pliku (wymagany). Do v0.29 tylko `-Klient` – ta nazwa nadal działa |
| `-Server` | Domena lub DC do odpytania (domyślnie domena bieżącego użytkownika) |
| `-OutDir` | Katalog wyników (domyślnie `.\raporty` obok skryptu; przy uruchomieniu z GitHuba `%USERPROFILE%\ADCheck\raporty`) |
| `-StaleDays` | Próg nieaktywności kont w dniach (domyślnie 90) |
| `-Previous` | JSON z poprzedniego przeglądu do porównania: nowe i usunięte znaleziska oraz – dla znalezisk obecnych w obu przeglądach – obiekty, które doszły i zniknęły (konta i komputery po SID, od v0.31) |
| `-History` | Sekcja „Historia przeglądów”: wykres wyników i zgodności DC z raportów JSON tego klienta i domeny w katalogu `-OutDir` – najnowsze, do limitu `-MaxHistoryPoints` (od v0.30) |
| `-UseWinRM` | Testy DC na podstawie rzeczywistej konfiguracji (rejestr, `auditpol`, dziennik Security) odczytanej przez WinRM; wymaga członkostwa w grupie Administrators domeny |
| `-SkipDCChecks` | Pomija testy kontrolerów domeny |
| `-MaxHistoryPoints` | Największa liczba przeglądów w sekcji „Historia przeglądów” – najnowsze, razem z bieżącym (domyślnie 24; od v0.31) |
| `-IncludeCheck`, `-ExcludeCheck` | Tylko wskazane testy albo wszystkie poza wskazanymi – np. szybki ponowny test po naprawie. Nazwa testu (`ADCS`, `PRIV`, `DC-PROBE`, …; pełna lista: `-ListChecks`) lub Id reguły (`D-ADCS-ESC1` uruchamia cały test `ADCS`); przy uruchomieniu z pliku (`.\ADCheck.ps1`) nazwy podpowiada klawisz TAB. Przegląd częściowy jest oznaczony w raporcie, nie trafia do historii, a jego wyniku nie należy porównywać z pełnym (od v0.31) |
| `-ListChecks` | Wypisuje testy i reguły (kolumny Test, Regula, Wymaga, Opis) i kończy – bez połączenia z domeną i bez `-Client`; kolumna Test to nazwa do `-IncludeCheck` / `-ExcludeCheck` (od v0.31) |
| `-MaxRows` | Maksymalna liczba obiektów na znalezisko w HTML (domyślnie 500; pełna lista w CSV) |
| `-Silent` | Bez komunikatów postępu w konsoli; skrypt zwraca obiekt z wynikiem i ścieżkami plików (do automatyzacji) |

## Stacja robocza Windows 10/11

Skrypt nie wymaga RSAT ani uprawnień administratora lokalnego na stacji; działa w PowerShellu uruchomionym bez podniesienia uprawnień.

**Stacja w badanej domenie** – zaloguj się kontem domenowym i uruchom bez `-Server`.

**Stacja spoza badanej domeny** (np. komputer audytora podłączony do sieci organizacji lub przez VPN):

1. DNS stacji musi rozwiązywać badaną domenę (serwery DNS = kontrolery tej domeny), bo przez nazwę domeny odczytywany jest m.in. SYSVOL.
2. Uruchom PowerShell z poświadczeniami badanej domeny – bez dołączania stacji do domeny:
   ```powershell
   runas /netonly /user:FIRMA\uzytkownik powershell.exe
   ```
3. W nowym oknie podaj domenę jawnie: `& $adcheck -Client KLIENT -Server firma.local`.

Raport pokazuje wtedy osobno konto procesu („Uruchomił”) i konto, którym skrypt uwierzytelnił się do LDAP („Konto LDAP”, ustalane zapytaniem LDAP *Who am I*). Ocena, czy przegląd wykonano kontem uprzywilejowanym, dotyczy konta LDAP.

## Uruchomienie z GitHuba (bez kopiowania pliku)

Repozytorium jest publiczne – token nie jest potrzebny. W środowisku produkcyjnym uruchamiaj **wyłącznie wydanie z tagiem i ze sprawdzeniem SHA256**. Wklej w PowerShellu na stacji w badanej domenie:

```powershell
$v='v0.28'; $h='76B48ABB9F078F2B4563D8F14397EC648B19EA4584D9D25EB8FE94411D0400BC'; [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; $b=(New-Object Net.WebClient).DownloadData("https://raw.githubusercontent.com/pepix-pm/ADCheck/$v/ADCheck.ps1"); if (([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($b)) -replace '-') -ne $h) { throw "SHA256 pobranego pliku nie zgadza się z wydaniem $v - skrypt NIE został uruchomiony" }; & ([scriptblock]::Create([Text.Encoding]::UTF8.GetString($b).TrimStart([char]0xFEFF))) -Klient KLIENT
```

- `$v` i `$h` to tag i SHA256 wydania (lista wydań: zakładka *Releases*). Wydania do v0.19 włącznie mają plik `PEPIX-ADCheck.ps1` – przy uruchamianiu starszego wydania zmień nazwę pliku w adresie. Skrypt uruchamia się tylko wtedy, gdy pobrany plik ma dokładnie ten hash – podmiana pliku lub tagu w repozytorium go zatrzyma.
- **Hash przechowuj poza GitHubem** (np. we własnej dokumentacji lub menedżerze haseł) i stamtąd kopiuj polecenie. Hash pobrany z tego samego repozytorium nie chroni przed przejęciem konta GitHub, bo atakujący zmieniłby oba.
- Pierwsza część włącza TLS 1.2 – bez niej Windows Server 2012 R2/2016 nie połączy się z GitHubem („Nie można utworzyć bezpiecznego kanału SSL/TLS”). Na Windows 10/11 nie przeszkadza.
- Uruchamianie kodu pobranego z sieci bez zapisu na dysk może wywołać alert EDR (zachowanie podobne do technik „fileless”). W organizacjach z EDR, AppLocker lub WDAC pobierz plik z wydania, sprawdź hash (`Get-FileHash .\ADCheck.ps1`) i uruchom go z dysku; przed przeglądem uprzedź zespół monitorujący bezpieczeństwo (SOC).

Gałąź `main` służy wyłącznie do rozwoju i testów w laboratorium. Wersja nieoznaczona tagiem (np. do testu przed wydaniem):

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; & ([scriptblock]::Create((irm https://raw.githubusercontent.com/pepix-pm/ADCheck/main/ADCheck.ps1).TrimStart([char]0xFEFF))) -Client KLIENT
```

Sprawdzenie składni bez uruchamiania (np. po zmianach w repo):

```powershell
$e=$null; [void][System.Management.Automation.Language.Parser]::ParseInput((irm https://raw.githubusercontent.com/pepix-pm/ADCheck/main/ADCheck.ps1).TrimStart([char]0xFEFF), [ref]$null, [ref]$e); $e | Format-List Message, @{n='Linia';e={$_.Extent.StartLineNumber}}, @{n='Kod';e={$_.Extent.Text}}
```

Uwagi:
- Dlaczego nie `iex (irm ...)`: `iex` nie przyjmuje parametrów (`-Client`, `-UseWinRM`…), a do tego wykonuje skrypt w bieżącej sesji – zostawia w niej zmienne skryptu i `$ErrorActionPreference = 'Stop'`. Scriptblock przyjmuje parametry i działa we własnym zakresie. Oba sposoby omijają ExecutionPolicy i nie zapisują skryptu na dysku.
- `.TrimStart([char]0xFEFF)` usuwa znacznik BOM (plik musi go mieć, żeby PowerShell 5.1 z pliku poprawnie czytał polskie znaki). GitHub wysyła `charset=utf-8`, więc `irm` dekoduje polskie znaki poprawnie.
- Wydanie (tag) powstaje dopiero po przetestowaniu wersji w środowisku testowym i w co najmniej jednym środowisku produkcyjnym. Tagi i gałąź `main` są chronione przed nadpisaniem i usunięciem.
- Raporty powstają w `%USERPROFILE%\ADCheck\raporty`. Jeśli przekazujesz je dalej, rób to szyfrowanym kanałem, a potem usuń je ze stacji.
- Zgłaszając błąd lub propozycję zmiany, nie wklejaj fragmentów raportu: nazwy domen, kont, serwerów i wyniki to dane wrażliwe badanej organizacji.

## Wyniki

W katalogu `raporty` powstają pliki `AD_<klient>_<domena>_<data>`:

- `.html` – raport: podsumowanie, karty znalezisk (ryzyko, zalecenie, przykładowa naprawa, obiekty), inwentaryzacja domeny, metodyka
- `.json` – pełne dane do porównań (`-Previous`); pole `SchemaVersion` określa wersję struktury (zmiana główna = niezgodna zmiana pól, drugorzędna = nowe pola)
- `.csv` – lista znalezisk
- `_obiekty.csv` – wszystkie obiekty dla wszystkich znalezisk
- `_plan.csv` – plan naprawczy (etap, zadanie, waga, szacunek godzin, uwagi)

### Punktacja i struktura raportu

- Każde znalezisko: Critical = 25, High = 10, Medium = 3, Low = 1 pkt.
- Znaleziska należą do jednego z **czterech obszarów ryzyka**: obiekty nieaktualne, konta uprzywilejowane, zaufania, anomalie. Wynik obszaru = suma punktów, maks. 100. **Wynik ogólny = najgorszy obszar** (0–100, im mniej, tym lepiej). Gdy suma przekracza 100, raport podaje też pełną sumę (np. 4 i 10 znalezisk Critical dają ten sam wynik 100, ale inną sumę); porównanie z `-Previous` pokazuje wtedy zmianę sumy. Karta zmiany podaje też zmianę klasy ekspozycji i liczbę nowych znalezisk Critical (wynik może spaść mimo nowego Critical, jeśli najgorszy jest inny obszar), a sekcja porównania ostrzega, gdy poprzedni przegląd wykonano w innym trybie (testy DC, konto przeglądu, uprawnienia konta).
- **Klasa ekspozycji A–E** wynika z najpoważniejszego znaleziska (Critical = E, High = D, Medium = C, Low = B, brak = A). Opisuje stan techniczny AD w zakresie testów, a nie dojrzałość procesów bezpieczeństwa organizacji.
- **Pewność wyniku** (Wysoka / Średnia / Niska) – znalezisko oparte na źródle pośrednim ma w karcie dopisek z uzasadnieniem: np. ustawienia DC odczytane z GPO zamiast z rejestru (Średnia) albo z GPO o niepewnym zakresie lub niepełnym odczycie (Niska). Pole `Pewnosc` jest też w JSON i CSV. Karta każdego obszaru podaje, ile jego reguł faktycznie oceniono (`Meta.PokrycieObszarow`) – przy niepełnym pokryciu wynik obszaru może być zaniżony.
- **Macierz ryzyka** pokazuje punkty w podziale obszar × rodzaj ryzyka (np. „Łamanie haseł”, „Pass-the-hash”, „Replikacja i kondycja”).
- **Historia przeglądów** (`-History`) – wykres wyniku ogólnego i obszarów oraz zgodności DC z CIS L1 i Microsoft Security Baseline w kolejnych przeglądach, z tabelą (data, wersja, tryb, wynik, klasa, liczba znalezisk wg wagi). Źródłem są pliki JSON z katalogu wyników, wyłącznie z tą samą nazwą klienta i domeną; pliki z niezgodną główną wersją `SchemaVersion` są pomijane. Przeglądy w innym trybie niż bieżący (inne źródło testów DC lub inne konto) mają pusty znacznik – zmiana może wynikać z trybu, a nie ze zmian w AD. Wykres jest wpisany w raport (SVG), bez zewnętrznych bibliotek.
- Nazwy kont i grup w tabelach mogą być w różnych językach. Grupy wbudowane i domenowe (np. „BUILTIN\Administratorzy”, „FIRMA\Administratorzy domeny”) mają nazwy zapisane w AD przy tworzeniu domeny – zostają w tym języku także po wymianie DC na system w innym języku. Identyfikatory dobrze znane (np. „Everyone”, „NT AUTHORITY\Authenticated Users”) tłumaczy system stacji, z której uruchomiono przegląd. Ocena opiera się na SID, więc wynik nie zależy od języka.
- **Sprawdzone reguły** – status każdego testu: znalezisko, zaliczony, zaliczony warunkowo (np. ustawienie tylko w GPO podlinkowanym do OU – zakres do potwierdzenia), nie dotyczy, pominięty, wymaga `-UseWinRM`, błąd testu, nierozstrzygnięty.

- **Plan naprawczy** – znaleziska w trzech etapach (do 30 dni / 30–90 dni / do 12 miesięcy) z szacunkiem pracochłonności i uwagami (zależności, kolejność). Znaleziska krytyczne zawsze w etapie 1. Szacunki są w tabeli `$planMeta` w skrypcie – warto je dostosować do własnych doświadczeń z wdrożeń.
- **Odniesienie do NIS2 / UKSC i ISO/IEC 27001:2022** – każde znalezisko jest przypisane (przez rodzaj ryzyka, `$complianceMap`) do środków z art. 21 ust. 2 NIS2 (wdrożonych w UKSC, Dz. U. 2026 poz. 252) i zabezpieczeń z załącznika A ISO 27001. Raport pokazuje dla każdego środka liczbę testów AD, znaleziska i punkty. To wskazanie, których wymagań dotyczą problemy techniczne – nie ocena zgodności.

Obszar, rodzaj ryzyka i test źródłowy każdej reguły są w katalogu `$ruleCatalog` w skrypcie. Układ raportu jest wzorowany na przeglądach typu PingCastle; teksty, identyfikatory i punktacja są własne.

> **Raporty zawierają informacje o podatnościach badanej organizacji.** Przechowuj je i przekazuj jak dane poufne (szyfrowany kanał, ograniczony dostęp).

## Jak sprawdzane są kontrolery domeny bez uprawnień administracyjnych

| Test | Metoda domyślna | Metoda `-UseWinRM` |
|---|---|---|
| Print Spooler | połączenie z potokiem `\\DC\pipe\spoolss` | stan usługi |
| SMBv1 | sonda negocjacji tylko dialektu SMB1 na TCP 445 | `Get-SmbServerConfiguration` |
| Podpisywanie LDAP | `GptTmpl.inf` z GPO domeny i OU Domain Controllers | rejestr DC |
| LDAP channel binding | `GptTmpl.inf` z GPO domeny i OU Domain Controllers | rejestr DC |
| Poziom NTLM (LmCompatibilityLevel) | `GptTmpl.inf` z GPO domeny i OU Domain Controllers | rejestr DC |

Odczyt z GPO pokazuje konfigurację zamierzoną; ustawienia lokalne na DC mogą się różnić. Testy, których nie da się rozstrzygnąć, trafiają do sekcji „Testy DC nierozstrzygnięte” i nie są traktowane jako zaliczone.

## Lista testów

| ID | Waga | Test | MITRE ATT&CK |
|---|---|---|---|
| D-DCSYNC | Critical / High / Medium | Prawa replikacji haseł (DCSync) dla podmiotów spoza DC i administratorów. Zestaw praw liczony dla podmiotu łącznie z jego grupami: pełny (Get-Changes + Get-Changes-All) – Critical, High, gdy tylko konto synchronizacji Entra ID; niepełny – Medium; kolumna Uwagi podaje prawa nadane przez grupy | T1003.006 |
| D-ACL-DOMAIN | Critical | GenericAll / WriteDacl / WriteOwner / zapis atrybutów obiektu domeny poza administratorami | T1222.001 |
| D-ACL-ADMINSDHOLDER | Critical | Niestandardowe prawa zapisu lub resetu hasła na AdminSDHolder | T1098 |
| D-ACL-GPO | High | GPO podlinkowane do domeny lub OU Domain Controllers, które mogą modyfikować konta i grupy spoza administratorów (obiekt AD i katalog SYSVOL) | T1484.001 |
| P-ACL-TIER0 | Critical / High | Konta i grupy spoza administratorów z prawami do kont i grup uprzywilejowanych, kont DC lub OU Domain Controllers: pełna kontrola, WriteDacl, WriteOwner, zapis atrybutów, członkostwo, reset hasła, Shadow Credentials, RBCD, zapis SPN, nietypowy właściciel (High, gdy dotyczy tylko konta synchronizacji Entra ID). Jeden wiersz na podmiot z liczbą obiektów i priorytetem; pełna lista w `_obiekty.csv` | T1222.001 |
| DC-RBCD | Critical | RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity) ustawione na koncie kontrolera domeny | T1558 |
| D-KCD-DC | Critical / High | Delegacja ograniczona do usług DC (Critical przy przejściu protokołu na aktywnym koncie) | T1558 |
| P-GMSA-READ | Critical / High | Hasło gMSA może pobrać szeroka grupa (Domain Users, Domain Computers…) albo gMSA jest w grupie uprzywilejowanej, a hasło pobierają serwery spoza Tier 0 (Critical przy obu warunkach naraz) | T1552 |
| D-ADCS-ESC1 | Critical / High / Low | Opublikowany szablon: nazwa podmiotu z żądania + EKU do logowania, bez zatwierdzania, z prawem Enroll dla kont i grup spoza administratorów (Critical dla szerokich grup; Low, gdy szablon jest opublikowany tylko na wycofanym CA – tak samo ESC2, 3, 4 i 9) | T1649 |
| D-ADCS-ESC3 | Critical / High | Szablon agenta rejestracji (Certificate Request Agent) dostępny dla kont i grup spoza administratorów | T1649 |
| D-ADCS-ESC4 | Critical / High | Konta i grupy spoza administratorów mogą zmieniać opublikowany szablon (pełna kontrola, WriteDacl, WriteOwner, zapis, właściciel) | T1649 |
| D-ADCS-ESC5 | Critical / High / Low | Prawa zapisu kont i grup spoza administratorów do kontenerów i obiektów PKI (NTAuthCertificates, obiekt CA, szablony, OID) lub do konta komputera serwera CA; Low, gdy dotyczą tylko podmiotów usuniętych z AD lub obiektów wycofanego CA | T1649 |
| D-ADCS-ESC13 | Critical / High | Szablon z zasadą wystawiania powiązaną z grupą (msDS-OIDToGroupLink) dostępny dla kont i grup spoza administratorów (Critical dla grupy uprzywilejowanej) | T1649 |
| D-ADCS-ORPHAN | High / Medium | CA wycofane (brak, wyłączone lub nieużywane konto serwera), ale nadal zarejestrowane w AD; High, gdy certyfikat CA jest w NTAuthCertificates | T1649 |
| D-ADCS-ESC2 | High / Medium | Szablon z EKU Any Purpose lub bez EKU dostępny dla kont i grup spoza administratorów | T1649 |
| D-ADCS-ESC7 | Critical / High | Rola zarządzania CA (ManageCA, Critical) lub zarządzania certyfikatami (ManageCertificates) dla kont i grup spoza administratorów – odczyt uprawnień CA przez interfejs administracyjny CA | T1649 |
| D-ADCS-ESC6 | High | CA z flagą EDITF_ATTRIBUTESUBJECTALTNAME2 (nazwa alternatywna z żądania) | T1649 |
| D-ADCS-ESC11 | High | CA bez wymogu szyfrowania żądań RPC (brak IF_ENFORCEENCRYPTICERTREQUEST) – NTLM relay do CA | T1557 |
| D-ADCS-ESC8 | High | Rejestracja przez WWW (`http://<CA>/certsrv/`) przyjmuje NTLM po HTTP – NTLM relay do CA (sonda HTTP bez poświadczeń; przy braku łączności status „Nierozstrzygnięty”) | T1557 |
| D-ADCS-ESC9 | Medium / Low | Szablon z flagą CT_FLAG_NO_SECURITY_EXTENSION i EKU do logowania | T1649 |
| D-ADCS-ESC10 | High / Medium | Tylko `-UseWinRM`: rejestr DC dopuszcza słabe wiązanie certyfikatu z kontem – mapowanie po UPN w Schannel (`CertificateMappingMethods` z bitem 0x4, High) lub `StrongCertificateBindingEnforcement` 0/1 (Medium). Przy pełnym wymuszaniu na wszystkich DC waga D-ADCS-ESC9 spada do Low | T1649 |
| C-RBCD | Critical / Medium / Low | RBCD na kontach poza DC: Critical na kontach z grup uprzywilejowanych, Medium gdy podmiotem jest konto komputera utworzone przez zwykłe konto (MachineAccountQuota), w pozostałych przypadkach Low (do weryfikacji) | T1558 |
| P-KRBTGT | High / Critical | Wiek hasła krbtgt (> 180 / > 365 dni) | T1558.001 |
| P-PNE | High | Konta uprzywilejowane z hasłem bez wygasania | T1078.002 |
| P-SPN | High | Konta uprzywilejowane z SPN | T1558.003 |
| P-DA-COUNT | Medium | Więcej niż 5 członków Domain Admins | T1078.002 |
| P-SchemaAdmins, P-AccountOperators, P-ServerOperators, P-PrintOperators, P-BackupOperators | Medium | Niepuste grupy wysokiego ryzyka | T1078.002 |
| P-DnsAdmins | Medium | Niepusta grupa DnsAdmins (wykonanie kodu na DC przez usługę DNS); członkowie traktowani jak konta uprzywilejowane | T1078.002 |
| P-KeyAdmins, P-EnterpriseKeyAdmins | Medium | Niepuste grupy Key Admins / Enterprise Key Admins (zapis msDS-KeyCredentialLink na kontach, Shadow Credentials); członkowie traktowani jak konta uprzywilejowane, a domyślne prawa tych grup nie są zgłaszane w ACL | T1078.002 |
| P-GPCO | Low | Konta spoza administratorów w Group Policy Creator Owners | T1484.001 |
| P-DELEG | Medium | Konta uprzywilejowane bez ochrony przed delegacją | T1558 |
| P-STALE | Medium | Nieużywane aktywne konta uprzywilejowane | T1078.002 |
| P-ADM500 | Medium / Low | Wiek hasła wbudowanego Administratora (Low, gdy konto jest wyłączone) | T1078.002 |
| P-ADMLOGIN | Medium | Wbudowane konto Administrator używane w ostatnich 35 dniach | T1078.002 |
| P-PROTECTED | Low | Konta uprzywilejowane spoza Protected Users (bez kont z SPN i RID 500) | T1550.002 |
| P-ADMINMAIL | Low | Konta uprzywilejowane z adresem e-mail | T1566 |
| U-UNCONSTR | Critical | Użytkownicy z delegacją nieograniczoną | T1558 |
| U-ASREP | High | Brak preautentykacji Kerberos | T1558.004 |
| U-PWDNOTREQ | High | Flaga PASSWD_NOTREQD | T1078.002 |
| U-REVERSIBLE | High | Hasło przechowywane odwracalnie | T1003.003 |
| U-DES | High | Wymuszony DES | T1558 |
| D-KRB-DES | High | DES dopuszczony w konfiguracji kont, komputerów, gMSA, zaufań lub KDC (`msDS-SupportedEncryptionTypes`, USE_DES_KEY_ONLY; KDC tylko z `-UseWinRM`) | T1558 |
| D-KRB-NOAES | High / Medium | Konta bez kluczy AES – hasło sprzed pierwszego DC 2008+ (High, gdy konto uprzywilejowane lub krbtgt) | T1558 |
| D-KRB-TRUST | Medium | Relacje zaufania bez włączonego AES | T1558 |
| DC-KRB-DES-USED | High | Faktycznie wydane bilety DES w ostatnich 7 dniach (zdarzenia 4768/4769, tylko `-UseWinRM`) | T1558 |
| DC-KRB-RC4-USED | Medium | Faktycznie wydane bilety RC4 w ostatnich 7 dniach (tylko `-UseWinRM`) | T1558.003 |
| U-GUEST | High | Włączone konto Gość | T1078.001 |
| U-SPN | Medium | Konta użytkowników z SPN | T1558.003 |
| U-SPN-WEAK | High | Konta z SPN z hasłem starszym niż 3 lata i bez AES – najbardziej narażone na Kerberoasting | T1558.003 |
| U-SIDHIST | Medium | Konta z SIDHistory | T1134.005 |
| U-PNE | Low | Konta spoza grup uprzywilejowanych z hasłem bez wygasania | T1078.002 |
| U-STALE | Low | Nieużywane aktywne konta | T1078.002 |
| U-ADMINCOUNT | Low | Osierocone adminCount=1 | T1098 |
| C-UNCONSTR | Critical | Komputery (nie-DC) z delegacją nieograniczoną | T1558 |
| C-OS-EOL | High | Systemy bez wsparcia (Windows 7/8.1, Server ≤ 2012 R2, wycofane LTSC/SAC) | T1210 |
| C-LAPS-READ-BROAD | Critical | Hasła LAPS czytelne dla szerokich grup (Domain Users, Authenticated Users…) | T1555 |
| C-LAPS-NONE | High | Brak LAPS w schemacie albo schemat bez żadnego komputera z hasłem LAPS | T1550.002 |
| C-LAPS-READABLE | High | Konto użyte do przeglądu (nieuprzywilejowane) widzi hasła LAPS | T1555 |
| C-OS-W10 | Medium | Windows 10 (poza LTSC) | T1210 |
| C-OS-FEATURE | Medium | Windows 11 w wersji bez wsparcia (np. 23H2 Pro) | T1210 |
| C-OS-SOON | Medium | Serwery/LTSC z końcem wsparcia w ciągu 12 miesięcy | T1210 |
| C-LAPS-MISSING | Medium | Komputery bez hasła LAPS | T1550.002 |
| C-LAPS-EXPIRED | Medium | Hasło LAPS przestało się zmieniać (wygasło, a komputer był w sieci) | T1550.002 |
| C-LAPS-LEGACY | Low | Komputery na wycofanym Microsoft LAPS (legacy) | T1550.002 |
| C-LAPS-READERS | Low | Podmioty spoza Domain Admins i Enterprise Admins z prawem odczytu haseł LAPS (ACL na OU) – do weryfikacji | T1555 |
| C-OWNER | Medium | Aktywne komputery (poza DC), których właścicielem jest konto spoza administratorów (ryzyko RBCD / odczytu LAPS) | T1134 |
| D-OWNER-OU | High | OU, kontenery i obiekt domeny z właścicielem spoza administratorów (właściciel może nadać sobie pełną kontrolę nad zawartością) | T1222.001 |
| D-OWNER-GPO | High / Medium | Wszystkie GPO z właścicielem spoza administratorów (Medium, gdy żadne nie ma aktywnego łącza) | T1484.001 |
| P-OWNER-GROUP | High / Medium | Grupy spoza Tier 0 z właścicielem spoza administratorów (High przy adminCount=1) | T1098 |
| U-OWNER-USER | High / Medium | Konta użytkowników spoza Tier 0, także wyłączone, z właścicielem spoza administratorów (High przy adminCount=1) | T1098 |
| C-MAQ | Medium | MachineAccountQuota > 0 | T1136.002 |
| C-STALE | Low | Nieużywane konta komputerów | T1078.002 |
| D-RECYCLE | Medium | Kosz AD wyłączony | – |
| D-PWDLEN | Medium | Minimalna długość hasła < 12 | T1110 |
| D-PWDCPLX | Medium | Złożoność haseł wyłączona | T1110 |
| D-LOCKOUT | Medium | Brak blokady konta | T1110.003 |
| D-FGPP-WEAK | High / Medium | Szczegółowe zasady haseł (PSO) słabsze od polityki domeny; High, gdy obejmują konta uprzywilejowane. Zwykłe konto zwykle nie widzi PSO – reguła ma wtedy status „Pominięty” | T1110 |
| D-TRUST-SIDF | Medium | Zaufania zewnętrzne bez filtrowania SID | T1134.005 |
| D-TRUST-STALE | Medium | Relacje zaufania bez zmiany hasła od ponad 90 dni (martwe lub uszkodzone) | T1199 |
| D-TRUST-SELAUTH | Low | Relacje zaufania z inną domeną lub lasem bez uwierzytelniania selektywnego | T1199 |
| D-DFL | Low | Poziom funkcjonalny domeny < 2016 | – |
| D-FFL | Low | Poziom funkcjonalny lasu < 2016 | – |
| D-PREWIN2000 | High / Low | Everyone, Anonymous Logon (High) lub Authenticated Users (Low) w Pre-Windows 2000 Compatible Access | T1087.002 |
| D-DSHEURISTICS | High / Medium | dSHeuristics: anonimowe operacje LDAP (7. znak) lub wyłączone poprawki CVE-2021-42291 (28./29. znak) | T1087.002 |
| D-DNS-CREATECHILD | Low | Strefy DNS z CreateChild dla Authenticated Users bez rekordu wildcard (ADIDNS spoofing) | T1557 |
| D-GPO-LLMNR | Medium | Żadne podlinkowane GPO nie wyłącza LLMNR (ustawienie tylko w GPO na OU/lokacji: „Zaliczony warunkowo”) | T1557.001 |
| D-GPO-HARDPATH | Medium / Low | GPO osłabia Hardened UNC Paths dla SYSVOL/NETLOGON lub ich brak przy starszych systemach | T1557 |
| D-GPO-PSLOG | Low | Żadne podlinkowane GPO nie włącza Script Block Logging (ustawienie tylko w GPO na OU/lokacji: „Zaliczony warunkowo”) | T1059.001 |
| D-GPO-UNLINKED | Low | GPO bez aktywnych łączy do domeny, OU lub lokacji | – |
| D-GPO-DEADLINK | Low | Łącza (gPLink) domeny, OU lub lokacji do GPO, które już nie istnieje | – |
| D-SPN-DUP | Low | Ta sama nazwa SPN na kilku kontach w domenie | T1558.003 |
| D-UPN-DUP | Low | Ta sama nazwa UPN na kilku kontach w domenie | – |
| D-GPP-PASSWORD | Critical / High | Hasła w preferencjach GPO w SYSVOL: `cpassword` (Critical, odszyfrowywalne przez każdego) lub hasło autologowania jawnym tekstem (High); wszystkie GPO, także niepodlinkowane; raport nie zawiera haseł | T1552.006 |
| D-GPO-LOCALADMIN | Critical / High / Low | Konta i grupy domenowe spoza administratorów dodawane do lokalnej grupy Administrators przez GPO z aktywnym łączem („Grupy z ograniczeniami” w GptTmpl.inf, preferencje Groups.xml): szeroka grupa, np. Domain Users (Critical), GPO podlinkowane do domeny lub OU Domain Controllers (High), pozostałe (Low). Konta lokalne są pomijane | T1078.002 |
| DC-OS-EOL | High | DC z systemem bez wsparcia | T1210 |
| DC-SPOOLER | High | Print Spooler na DC | T1187 |
| DC-SMB1 | High | SMBv1 na DC | T1210 |
| DC-ANONLDAP | High | DC zwraca konta na anonimowe zapytanie LDAP (sonda bez uwierzytelnienia) | T1087.002 |
| DC-NETSESSION | Low | Zwykłe konto może wyliczać sesje SMB na DC (NetSessionEnum, brak NetCease) | T1049 |
| DC-LDAPSIGN | Medium | Podpisywanie LDAP niewymagane | T1557 |
| DC-LDAPCBT | Medium | LDAP channel binding niewymuszony | T1557 |
| DC-NTLMV1 | Medium | DC akceptuje NTLMv1/LM | T1557.001 |
| DC-PATCH-OLD | High | DC bez aktualnych poprawek (UBR niższy niż ostatni Patch Tuesday; z WinRM także ostatnia poprawka > 60 dni) | T1210 |
| DC-PATCH-DIFF | Medium | DC z tym samym systemem na różnym poziomie poprawek | T1210 |
| DC-REBOOT | Medium | DC oczekujący na restart lub bez restartu > 60 dni (tylko `-UseWinRM`) | T1210 |
| DC-CIS-REG | wg najgorszego ustawienia | Opcje zabezpieczeń i szablony administracyjne DC niezgodne z CIS L1 (42 ustawienia) | – |
| DC-CIS-AUDIT | wg najgorszego ustawienia | Zaawansowane zasady audytu DC niezgodne z CIS L1 (24 podkategorie) | T1562.002 |
| DC-CIS-RIGHTS | wg najgorszego ustawienia | Przypisanie praw użytkowników na DC niezgodne z CIS L1 (16 praw) | T1078.002 |
| DC-MSBASE | wg najgorszego ustawienia | Ustawienia DC niezgodne z Microsoft Security Baseline (Windows Server 2025, profil DC), których nie zgłosił już CIS ani inny test | – |
| DC-CIS-SUMMARY | Info | Procent zgodności i pełna lista sprawdzonych ustawień | – |
| DC-REPL-TSL | Critical | Replikacja nieudana dłużej niż tombstone lifetime | – |
| D-FSMO | Critical | Role FSMO przypisane do nieistniejącego DC | – |
| DC-REPL-FAIL | High | Błędy replikacji AD (z opisem kodu błędu) | – |
| DC-REPL-STALE | High | Replikacja nieudana od ponad 24 h | – |
| D-BACKUP | High | Brak kopii zapasowej AD w ciągu 7 dni (atrybut dSASignature) | T1490 |
| D-SYSVOL-FRS | High | SYSVOL replikowany przez FRS | – |
| DC-SYSVOL-SHARE | High | DC bez udziału SYSVOL/NETLOGON | – |
| DC-TIME | High / Medium | Czas DC różni się od PDC o > 5 min / > 1 min | – |
| DC-TIME-SOURCE | High / Medium / Low | Źródło czasu PDC Emulatora z odpowiedzi NTP (UDP 123), z `-UseWinRM` także z `w32tm /query /source`: brak synchronizacji (High), zegar lokalny bez zewnętrznego źródła (Medium), czas z hosta wirtualizacji – dostawca czasu Hyper-V (Low) | – |
| D-SINGLEDC | Medium | Tylko jeden kontroler domeny | – |
| DC-MACHINEPWD | Medium | Hasło konta komputera DC starsze niż 45 dni | – |
| DC-PORTS | Medium | Niedostępne porty usług AD na DC (53, 88, 135, 389, 445, 9389, 3268) | – |
| D-GPO-SYNC | Medium / High | Wersja GPO w AD różna od GPT.INI w SYSVOL na DC; High, gdy podlinkowane GPO nie ma folderu w SYSVOL (ustawienia nie są stosowane) | – |
| DC-DNS-SRV | Medium | DC bez rekordu SRV `_ldap._tcp.dc._msdcs` | – |
| DC-REGISTRATION | Medium | Konto DC bez obiektu serwera / NTDS Settings w lesie, niespójne flagi lub zwykły komputer w OU Domain Controllers | T1003.006 |
| DC-SUBNET | Low | Adres DC poza podsieciami AD lub w podsieci innej lokacji | – |

## Aktualizacje kontrolerów domeny

Poziom poprawek to numer UBR (część wersji po kropce, np. `20348.5761`). Zwykłe konto odczytuje go przez zdalny rejestr – klucz `SOFTWARE\Microsoft\Windows NT\CurrentVersion` jest domyślnie dostępny zdalnie dla użytkowników domeny (wymaga działającej usługi Remote Registry na DC). Z `-UseWinRM` dochodzą: data i numer ostatniej poprawki, ostatni restart, oczekujący restart i źródło aktualizacji (WSUS).

Wzorzec to UBR ostatniej comiesięcznej aktualizacji zabezpieczeń (`$patchRef`, `$patchRefDate` w skrypcie) – **aktualizować co miesiąc po Patch Tuesday**. Gdy wzorzec ma ponad 40 dni, raport o tym ostrzega. Niezależnie od wzorca porównywane są DC z tym samym systemem między sobą.

## Konfiguracja DC wg CIS

Wybrane kontrole CIS Microsoft Windows Server Benchmark (profil L1, kontroler domeny) – nie pełna ocena zgodności z CIS. Treści zaleceń CIS nie są kopiowane (licencja CIS); raport podaje nazwę ustawienia, wartość oczekiwaną i aktualną.

| Obszar | Konto bez uprawnień administracyjnych (domyślnie) | `-UseWinRM` (grupa Administrators domeny) |
|---|---|---|
| Opcje zabezpieczeń, szablony administracyjne | GPO domeny i OU Domain Controllers: `GptTmpl.inf`, `Registry.pol` | rzeczywisty rejestr każdego DC |
| Zasady audytu | `audit.csv` w GPO | `auditpol /get /category:*` na każdym DC |
| Przypisanie praw użytkowników | `GptTmpl.inf` w GPO | `GptTmpl.inf` w GPO – także przy `-UseWinRM` (odczyt rzeczywistych przypisań wymagałby zapisu pliku na DC, a skrypt działa tylko w trybie odczytu) |

Ustawienie nieobecne w GPO oceniane jest według wartości domyślnej systemu; jeśli domyślna jest niezgodna z CIS – jako niezgodne. Pierwszeństwo GPO jak w pozostałych testach DC (od v0.31): łącza zwykłe od domeny do OU Domain Controllers wg kolejności łączy, potem łącza wymuszone (Enforced – wyższy poziom wygrywa); blokowanie dziedziczenia na OU pomija niewymuszone GPO domeny; GPO, którego filtrowanie zabezpieczeń nie obejmuje żadnego DC, jest pomijane, a GPO obejmujące tylko część DC – oceniane osobno dla tych DC (kolumna DC wymienia wtedy kontrolery). GPO z filtrem WMI albo z filtrowaniem, którego nie da się ustalić, jest stosowane z dopiskiem „niepewne” w kolumnie Źródło i uwagą w opisie znaleziska – filtru WMI nie da się ocenić bez DC. GPO podlinkowane do lokacji (site) nie są uwzględniane. Listy kontroli są w skrypcie (`$cisReg`, `$cisAudit`, `$cisRights`).

## LAPS

Skrypt rozpoznaje LAPS legacy (`ms-Mcs-AdmPwd`) i Windows LAPS (`msLAPS-*`). Sprawdza pokrycie, rotację haseł (data wygaśnięcia vs ostatnie logowanie komputera) oraz **kto może odczytać hasła** – z ACL kontenerów, w których są komputery (prawo rozszerzone do atrybutu hasła, wszystkie prawa rozszerzone, pełna kontrola). Sprawdza też, czy konto użyte do przeglądu widzi hasła: filtr LDAP zwraca tylko komputery z czytelnym hasłem – **wartości haseł nie są pobierane ani zapisywane**. Nie są analizowane uprawnienia nadane bezpośrednio na pojedynczych obiektach komputerów ani właściciel obiektu.

## Kondycja domeny i replikacja

Testy działają na zwykłym koncie: metadane replikacji przez LDAP z każdego DC (`msDS-NCReplInboundNeighbors`), udziały i `GPT.INI` przez SMB, czas przez NTP (`w32tm /stripchart`, UDP 123), rekordy SRV przez DNS stacji. Testy sieciowe (porty, udziały, czas, GPO, DNS) pomija `-SkipDCChecks`. Różnica czasu liczona jest względem PDC Emulatora, więc zegar stacji nie wpływa na wynik. Wynik testów sieciowych zależy od zapór między stacją a DC.

## Wersje systemów

Wersja i data końca wsparcia ustalane są z atrybutów `operatingSystem` i `operatingSystemVersion` kont komputerów w AD – bez łączenia się z komputerami. Tabela dat (`$win11Builds`, `$win10Ltsc`, `$serverEol`, `$legacyClient`, `$osLifecycleAsOf`) jest w skrypcie i **wymaga aktualizacji przy nowych wersjach Windows**; nieznane wersje nie są oceniane. Pełny rozkład systemów jest w załączniku A raportu.

## Testy jednostkowe

```powershell
Invoke-Pester .\tests
```

Testy (Pester 5) ładują z pliku skryptu definicje funkcji niezależnych od AD, bez uruchamiania skryptu. Warstwa raportu (HTML, JSON, CSV) jest sprawdzana na fikcyjnych danych z `tests/fixtures/znaleziska.json`. Reguły o najwyższej wadze mają testy regresyjne: niebezpieczne prawa w ACL, DCSync, szablony certyfikatów (ESC1–3, 9) i hasła w preferencjach GPO (pliki przykładowe `tests/fixtures/gpp-*.xml`). Przy każdym pushu i pull requeście GitHub Actions (`.github/workflows/ci.yml`, Windows) uruchamia PSScriptAnalyzer (Warning, Error; wyłączone reguły z uzasadnieniem w `PSScriptAnalyzerSettings.psd1`), testy Pester oraz sprawdza kodowanie UTF-8 z BOM plików `*.ps1`.

## Zgoda na badanie i ślad w środowisku

Narzędzie wolno uruchamiać **wyłącznie w środowisku, na którego badanie jest pisemna zgoda jego właściciela** (np. umowa lub zlecenie przeglądu z określonym zakresem i terminem). Administrator badający własną domenę również powinien mieć zgodę przełożonych lub osoby odpowiedzialnej za bezpieczeństwo.

„Tylko odczyt” znaczy, że skrypt niczego nie zmienia – nie znaczy, że jest niewidoczny. Wykonuje:

- zapytania LDAP o wszystkie konta, grupy, komputery, GPO, ACL i konfigurację lasu,
- odczyt SYSVOL po SMB (GPO, Registry.pol, GptTmpl.inf),
- sondy kontrolerów domeny: dostępność portów usług AD, zapytania NTP (UDP 123), potok `\\DC\pipe\spoolss`, wyliczanie sesji SMB (NetSessionEnum), **próbę anonimowego zapytania LDAP**,
- zapytanie HTTP bez poświadczeń do `http://<serwer CA>/certsrv/` i odczyt konfiguracji CA przez RPC/DCOM (interfejs administracyjny CA, tylko odczyt) – jeśli w lesie jest AD CS,
- odczyt dziennika zdarzeń DC (bilety Kerberos z DES/RC4), jeśli konto ma do niego dostęp,
- w trybie `-UseWinRM`: zdalne sesje PowerShell na każdym DC (odczyt rejestru, stanu usług, zasad audytu i dziennika Security).

Te operacje mogą trafić do logów DC i SIEM oraz wywołać alerty (np. Microsoft Defender for Identity: rozpoznanie przez LDAP, wyliczanie sesji SMB) lub zostać zablokowane przez zaporę. Uzgodnij termin przeglądu z właścicielem środowiska i uprzedź zespół monitorujący bezpieczeństwo (SOC).

`-UseWinRM` nie przyjmuje haseł: używa tożsamości Kerberos bieżącej sesji (np. po `runas /netonly`). Poświadczenia nie trafiają do raportu, plików wynikowych ani konsoli; na DC zostaje zwykły ślad logowania sieciowego (zdarzenie 4624, typ 3) i – jeśli włączone – rejestrowanie poleceń PowerShell.

## Udział w rozwoju

Zgłoszenia błędów i propozycje testów są mile widziane – zasady (w tym warunki licencyjne dla przesyłanych zmian) są w [CONTRIBUTING.md](CONTRIBUTING.md). Na początek dobre są zgłoszenia z etykietą [good first issue](https://github.com/pepix-pm/ADCheck/labels/good%20first%20issue).

## Licencja

[PolyForm Shield 1.0.0](LICENSE.md) – Required Notice: Copyright PEPIX Piotr Misztal.

W skrócie (wiążący jest tekst licencji):

- możesz bezpłatnie używać ADCheck do dowolnego celu, także komercyjnie, np. do badania domeny własnej firmy lub organizacji, którą administrujesz,
- możesz kopiować i modyfikować skrypt; przekazując go dalej, dołącz tekst licencji (lub jej adres) i linię `Required Notice`,
- **nie możesz** oferować produktu ani usługi konkurencyjnej wobec ADCheck lub wobec usług, które licencjodawca świadczy z jego użyciem – np. sprzedawać przeglądów bezpieczeństwa AD wykonywanych tym narzędziem ani rozpowszechniać go w ramach własnego produktu,
- oprogramowanie jest dostarczane bez gwarancji; autor nie odpowiada za skutki jego użycia.

W sprawie innej licencji (np. do świadczenia usług) skontaktuj się z autorem przez [pepix.pl](https://pepix.pl).

---
[PEPIX](https://pepix.pl) · Kielce

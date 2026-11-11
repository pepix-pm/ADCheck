# Laboratorium testowe ADCheck

Instrukcja dla osoby, która sprawdza ADCheck na domenie testowej przed wydaniem wersji. Czas: około 6 godzin, w tym około 1 godziny na przygotowanie VM.

> **Tylko domena testowa.** Skrypt `Lab-Scenariusze.ps1` celowo psuje konfigurację AD: nadaje prawa replikacji, zmienia grupę podstawową konta, usuwa foldery GPO z SYSVOL, ustawia delegację (także RBCD na koncie DC), dodaje wpis na AdminSDHolder, zapisuje fikcyjne hasła GPP i włącza konto Gość. Nigdy nie uruchamiaj go w domenie, z której ktoś korzysta. Sam ADCheck niczego nie zmienia.

## 1. Przygotowanie domeny testowej

1. W Hyper-V lub VirtualBox utwórz VM: Windows Server 2022 lub 2025 w wersji ewaluacyjnej (180 dni), 4 GB RAM, dysk 60 GB, karta sieciowa z dostępem do internetu.
2. Po instalacji nadaj stały adres IP, a jako DNS ustaw 127.0.0.1.
3. Zainstaluj AD i utwórz nową domenę (PowerShell jako administrator):

   ```powershell
   Rename-Computer -NewName DC01 -Restart
   Install-WindowsFeature AD-Domain-Services, GPMC -IncludeManagementTools
   Install-ADDSForest -DomainName lab.local -DomainNetbiosName LAB -InstallDns
   ```

4. Opcjonalnie, do przebiegu B: druga VM z Windows 11 (wersja ewaluacyjna), DNS wskazujący na DC, dołączona do domeny `lab.local`. W VirtualBox obie VM muszą być w tej samej sieci (np. „Sieć NAT” albo druga karta „Sieć wewnętrzna” ze stałymi adresami).
5. Utwórz katalog roboczy `C:\Lab` na DC i skopiuj do niego `Lab-Scenariusze.ps1` (z katalogu `tests/lab` repozytorium).

Polecenie uruchamiające ADCheck (wydanie v0.29, z katalogu `C:\Lab`; wszystkie przebiegi wykonuj tą samą wersją):

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; & ([scriptblock]::Create((irm https://raw.githubusercontent.com/pepix-pm/ADCheck/v0.29/ADCheck.ps1).TrimStart([char]0xFEFF))) -Klient LAB
```

Do kolejnych przebiegów dopisuj parametry na końcu (np. `-Previous <plik.json>`). Przy uruchomieniu z GitHuba raporty trafiają do `%USERPROFILE%\ADCheck\raporty` (np. `C:\Users\Administrator\ADCheck\raporty`).

## 2. Przebiegi

| Przebieg | Kiedy | Konto | Parametry |
|---|---|---|---|
| 0 | Czysta domena, przed skryptem | LAB\Administrator na DC | `-Klient LAB` |
| A | Po `Lab-Scenariusze.ps1` | LAB\Administrator na DC | `-Klient LAB -Previous <JSON z przebiegu 0>` |
| B | Po przebiegu A | LAB\lab-zwykly na stacji Windows 11 | `-Klient LAB` |
| C | Po przebiegu B | LAB\Administrator na DC | `-Klient LAB -UseWinRM` |
| D | Po `-Usun` | LAB\Administrator na DC | `-Klient LAB -Previous <JSON z przebiegu A>` |
| E | Po przebiegu D | LAB\Administrator na DC | `-Klient LAB -Previous <JSON z przebiegu C>` |
| F | Po przebiegu E, **wersja 0.30 z gałęzi `main`** | LAB\Administrator na DC | `-Client LAB -History` |
| G | Po przebiegu F, wersja 0.30 z gałęzi `main` | LAB\Administrator na DC | `-Client LAB -UseWinRM` |

Kolejność kroków:

1. Przebieg 0. Zachowaj raport HTML i JSON. Zanotuj wynik ogólny i liczbę znalezisk.
2. Utwórz przypadki testowe (zapyta o potwierdzenie i o hasło dla konta `lab-zwykly`):

   ```powershell
   cd C:\Lab
   .\Lab-Scenariusze.ps1 -Domena lab.local
   ```

3. Odczekaj 2 minuty (skrypt uruchamia przebieg SDProp – przypadek 23), potem przebiegi A, B i C.
4. Usuń przypadki testowe: `.\Lab-Scenariusze.ps1 -Domena lab.local -Usun` i odczekaj 2 minuty przed przebiegiem D. `-Usun` wyłącza też konto Gość.
5. Przebiegi D i E.
6. Przebieg F – przygotowanie i polecenie w sekcji „Przebieg F” poniżej.
7. Przebieg G – przed `-Usun` z punktu F10; polecenie i sprawdzenia w sekcji „Przebieg G”.
8. Przebieg H – pierwszeństwo GPO (wersja 0.31); kroki w sekcji „Przebieg H”.

Bez stacji Windows 11 przebieg B można wykonać z dowolnego komputera z Windows w tej samej sieci:
`runas /netonly /user:LAB\lab-zwykly powershell`, a w nowym oknie dopisać do polecenia `-Server lab.local`.

## 3. Oczekiwane wyniki

W tabeli „Sprawdzone reguły” na końcu raportu każda reguła ma status. Szczegóły znalezisk otwierasz kliknięciem pola w macierzy ryzyka.

### Przebieg A (konto Administrator, po skrypcie)

| Nr | Przypadek | Gdzie patrzeć | Oczekiwany wynik |
|---|---|---|---|
| 1 | `lab-dcsync-niepelny` ma tylko DS-Replication-Get-Changes-All | Znalezisko D-DCSYNC, kolumna Zestaw | wiersz z zestawem „niepełny (brak DS-Replication-Get-Changes)” |
| 2 | `lab-dcsync-pelny` ma Get-Changes-All bezpośrednio, a Get-Changes przez grupę `lab-repl-grupa` | D-DCSYNC | wiersz z zestawem „pełny (DCSync)”, w kolumnie Uwagi „Get-Changes przez LAB\lab-repl-grupa”; całe znalezisko **Critical**. Grupa `lab-repl-grupa` nie ma własnego wiersza (sam Get-Changes nie pozwala na DCSync) |
| 2a | jw. | Reguła D-ACL-DOMAIN | żadne z kont `lab-*` **nie** występuje w D-ACL-DOMAIN |
| 3 | `lab-pgid512` ma grupę podstawową Domain Admins (nie jest w liście członków) | Załącznik A, „Członkowie grup uprzywilejowanych” | `lab-pgid512` przy Domain Admins |
| 3a | jw., hasło bez wygasania | Znalezisko P-PNE | `lab-pgid512` na liście, P-PNE ma wagę High |
| 4 | LLMNR wyłączony tylko w GPO podlinkowanym do OU `ADCheck-Lab` | Sprawdzone reguły, D-GPO-LLMNR | status „Zaliczony warunkowo (…OU=ADCheck-Lab…)”; brak znaleziska D-GPO-LLMNR |
| 4a | W OU `ADCheck-Lab` jest łącze do usuniętego GPO | jw. | status D-GPO-LLMNR **nie** jest „Nierozstrzygnięty” |
| 4b | jw. | Znalezisko D-GPO-DEADLINK | waga Low, jeden wiersz: GUID usuniętego GPO, w kolumnie Podlinkowane DN OU `ADCheck-Lab`; tego GPO **nie** ma w INFO-GPO-READ |
| 5 | GPO „ADCheck-Lab Bez folderu” podlinkowane do OU, bez folderu w SYSVOL | Znalezisko D-GPO-SYNC | waga **High**, tytuł „Podlinkowane GPO bez folderu w SYSVOL…”, kolumna Podlinkowane z DN OU |
| 6 | GPO „ADCheck-Lab DC bez folderu” podlinkowane do OU Domain Controllers, bez folderu | Opis DC-CIS-REG, DC-CIS-AUDIT, DC-CIS-RIGHTS | zdanie „Uwaga: GPO 'ADCheck-Lab DC bez folderu' (podlinkowane do OU Domain Controllers) nie ma folderu w SYSVOL…” |
| 7 | Przegląd uruchomiony kontem Administrator | Znalezisko P-ADMLOGIN | opis kończy się zdaniem, że data logowania może pochodzić z samego przeglądu |
| 8 | Brak LAPS w domenie | C-LAPS-NONE | waga High; zanotuj wariant tytułu („brak atrybutów LAPS w schemacie” albo „schemat rozszerzony, żaden komputer nie ma hasła LAPS”) |
| 9 | Porównanie z przebiegiem 0 | Sekcja „Porównanie z poprzednim przeglądem” | nowe znaleziska: m.in. D-DCSYNC, D-GPO-SYNC, D-GPO-DEADLINK; wiersz „Nowe znaleziska Critical: D-DCSYNC”; brak ostrzeżenia o innym trybie; brak błędu wczytania pliku. Jeśli zniknęło znalezisko, którego skrypt nie dotyczy (np. D-BACKUP), zanotuj, co zmieniłeś w domenie między przebiegami |
| 9a | jw. | Karta „Zmiana od …” obok wyniku | dopisek „klasa ekspozycji D → E” (lub inna zmiana klasy) i „nowe Critical: N”, gdzie N ≥ 4 (m.in. D-DCSYNC, D-GPP-PASSWORD, DC-RBCD, D-ACL-ADMINSDHOLDER – lista w sekcji porównania); karta z czerwonym paskiem |
| 11 | `lab-asrep` bez preautentykacji Kerberos | U-ASREP | `lab-asrep` na liście |
| 12 | `lab-svc` z SPN i nowym hasłem | U-SPN; U-SPN-WEAK | `lab-svc` w U-SPN; **nie** występuje w U-SPN-WEAK (hasło nowe) |
| 12a | `lab-pgid512` (administrator domeny) z SPN | P-SPN; P-DELEG | `lab-pgid512` w obu znaleziskach; P-SPN ma wagę High |
| 13 | `lab-flagi`: hasło niewymagane, odwracalne szyfrowanie, tylko DES | U-PWDNOTREQ, U-REVERSIBLE, U-DES, D-KRB-DES | `lab-flagi` w każdym z czterech znalezisk. W U-PWDNOTREQ może być też konto Guest (przypadek 21) |
| 14 | `lab-deleg` z delegacją nieograniczoną | U-UNCONSTR | `lab-deleg` na liście |
| 15 | `lab-admincount` z adminCount=1 poza grupami uprzywilejowanymi | U-ADMINCOUNT | `lab-admincount` na liście; **nie ma** tam `lab-backup` ani `lab-pgid512` (są uprzywilejowani) |
| 16 | Komputer `LAB-SRV2008` (Windows Server 2008 R2, delegacja nieograniczona) | C-OS-EOL; C-UNCONSTR | `LAB-SRV2008` w obu znaleziskach |
| 17 | Komputer `LAB-W10` (Windows 10 Pro 22H2) z RBCD dla `LAB-SRV2008` | C-OS-W10; C-RBCD | `LAB-W10` w C-OS-W10; w C-RBCD wiersz Cel `LAB-W10$`, Podmiot `LAB\LAB-SRV2008$`, waga Low |
| 18 | RBCD na koncie DC dla `LAB-SRV2008` | DC-RBCD | waga **Critical**, wiersz z nazwą DC i podmiotem `LAB\LAB-SRV2008$`. Jeśli skrypt wypisał „Przypadek 18 pominięty”, zanotuj to i pomiń ten punkt |
| 19 | `lab-backup` w Backup Operators przez grupę `lab-operatorzy` | P-BackupOperators; Załącznik A | `lab-backup` w znalezisku (członkostwo rekursywne) i w Załączniku A przy Backup Operators |
| 20 | Hasła GPP w GPO „ADCheck-Lab GPP” (wartości fikcyjne) | D-GPP-PASSWORD; D-GPO-UNLINKED | D-GPP-PASSWORD **Critical**, dwa wiersze: cpassword (konto `lab-lokalny`) i DefaultPassword; raport **nie** zawiera wartości haseł. „ADCheck-Lab GPP” jest też w D-GPO-UNLINKED |
| 21 | Konto Gość włączone | U-GUEST | znalezisko występuje |
| 22 | `lab-zwykly` z prawem edycji GPO „ADCheck-Lab DC edycja” podlinkowanego do OU Domain Controllers | D-ACL-GPO | wiersze z `LAB\lab-zwykly` dla obiektu w AD i katalogu SYSVOL tego GPO; waga High |
| 23 | `lab-zwykly` z prawem zapisu na AdminSDHolder | D-ACL-ADMINSDHOLDER; P-ACL-TIER0 | D-ACL-ADMINSDHOLDER **Critical** z `LAB\lab-zwykly`. Po przebiegu SDProp `lab-zwykly` jest też w P-ACL-TIER0 (prawa do kont uprzywilejowanych) – jeśli nie ma, zanotuj, ile minut minęło od uruchomienia skryptu |
| 24 | PSO „ADCheck-Lab PSO” (długość 4, bez złożoności) dla `lab-operatorzy` | D-FGPP-WEAK | waga **High**; kolumna Slabsze z długością 4 i wyłączoną złożonością; w kolumnie Uprzywilejowani `lab-operatorzy` |
| 25 | `lab-zwykly` jest właścicielem OU „ADCheck-Lab Wlasciciel”, GPO „ADCheck-Lab LLMNR”, grupy `lab-wlasc-grupa`, konta `lab-wlasc-konto` i komputera `LAB-WLASC-PC` (**wymaga wersji 0.30 – sprawdzić w przebiegu F**) | D-OWNER-OU, D-OWNER-GPO, P-OWNER-GROUP, U-OWNER-USER, C-OWNER | w każdym znalezisku wiersz z właścicielem `LAB\lab-zwykly` i odpowiednim obiektem w kolumnie Przyklady; D-OWNER-OU i D-OWNER-GPO – waga **High**. Jeśli skrypt wypisał „Przypadek 25: nie ustawiono właściciela…”, zanotuj komunikat |
| 26 | GPO „ADCheck-Lab DC prawa” podlinkowane do OU Domain Controllers; prawo „Access Credential Manager as a trusted caller” zapisane nazwami `Administrators,Administratorzy` zamiast SID (**wymaga wersji 0.30 – sprawdzić w przebiegu F**, punkt K1) | DC-CIS-RIGHTS | patrz K1 |
| 10 | Nawigacja w raporcie | Macierz ryzyka | kliknięcie pola ze znaleziskami rozwija listę linków; link prowadzi do szczegółów; „↑ Macierz ryzyka” wraca na górę |

### Przebieg B (zwykłe konto)

| Nr | Oczekiwany wynik |
|---|---|
| B1 | Nagłówek raportu: „Konto: LAB\lab-zwykly”, a przy `runas /netonly` – „Uruchomił: <konto lokalne> … Konto LDAP: LAB\lab-zwykly”; w obu wariantach bez dopisku „(konto uprzywilejowane)” |
| B2 | DC-NETSESSION ma status inny niż „Pominięty (konto uprzywilejowane)” |
| B3 | Wyniki 1–6 i 11–23 takie same jak w przebiegu A (D-DCSYNC, `lab-pgid512`, D-GPO-LLMNR, D-GPO-SYNC, notka DC-CIS, flagi kont, delegacje, RBCD, GPP, ACL). Wynik 24 (PSO) – patrz B5 |
| B4 | Brak dopisku o przeglądzie kontem Administrator w P-ADMLOGIN (o ile znalezisko występuje) |
| B5 | Brak reguł ze statusem „Błąd testu”. Oczekiwane: D-FGPP-WEAK „Pominięty (kontener PSO niewidoczny dla konta przeglądu)” i trzy reguły „Wymaga -UseWinRM”. Zanotuj każdy inny status „Pominięty”, „Błąd testu” lub „Nierozstrzygnięty” wraz z przyczyną |
| B6 | Nazwy grup w DC-CIS-RIGHTS mogą być w języku systemu stacji (np. „BUILTIN\Administratorzy”) – to nie błąd; zanotuj język stacji |

### Przebieg C (`-UseWinRM`)

| Nr | Oczekiwany wynik |
|---|---|
| C1 | Reguły „Wymaga -UseWinRM” z przebiegu A mają teraz inny status |
| C2 | Opisy DC-CIS-REG i DC-CIS-AUDIT mówią o odczycie z rejestru i auditpol (bez zdania o GPO bez folderu) |
| C3 | Opis DC-CIS-RIGHTS mówi o odczycie z GPO „także przy -UseWinRM” i zawiera zdanie „Uwaga: GPO 'ADCheck-Lab DC bez folderu' …”; wiersze mają „wszystkie DC (GPO)” |

### Przebieg D (po `-Usun`)

| Nr | Oczekiwany wynik |
|---|---|
| D1 | „Porównanie z poprzednim przeglądem”: na liście usuniętych (naprawionych) m.in. D-DCSYNC, D-GPO-SYNC, D-GPO-DEADLINK, U-ASREP, U-DES, DC-RBCD, C-RBCD, D-GPP-PASSWORD, U-GUEST, D-ACL-GPO, D-ACL-ADMINSDHOLDER, D-FGPP-WEAK |
| D2 | Konta `lab-*`, grupy `lab-*` i komputery `LAB-SRV2008`, `LAB-W10` nie występują w raporcie; `lab-zwykly` nie występuje w P-ACL-TIER0 |
| D3 | Brak ostrzeżenia o innym trybie (przebiegi A i D wykonano w tym samym trybie) |

### Przebieg E (porównanie z przebiegiem w innym trybie)

| Nr | Oczekiwany wynik |
|---|---|
| E1 | „Porównanie z poprzednim przeglądem” zaczyna się od ostrzeżenia „poprzedni przegląd wykonano w innym trybie (testy DC: …)”; to samo ostrzeżenie na konsoli (żółte) |

### Przebieg F (wersja 0.30: `-History`, `-Client`)

Przebieg F sprawdza wersję rozwojową 0.30 (gałąź `main`, bez weryfikacji SHA256). Przygotowanie na DC:

1. W katalogu `%USERPROFILE%\ADCheck\raporty` muszą być raporty JSON z przebiegów 0, A, C, D i E. Skopiuj tam też JSON z przebiegu B (powstał na stacji, z której go uruchomiłeś).
2. Dodaj dwa pliki kontrolne – raport „innego klienta” i plik uszkodzony:

   ```powershell
   cd $env:USERPROFILE\ADCheck\raporty
   $src = Get-ChildItem AD_LAB_lab.local_*.json | Sort-Object Name | Select-Object -First 1
   (Get-Content $src.FullName -Raw -Encoding UTF8) -replace '"Klient":\s*"LAB"', '"Klient": "INNY"' | Set-Content AD_INNY_lab.local_20000101-0000.json -Encoding UTF8
   Set-Content AD_LAB_lab.local_20000101-0001.json 'to nie jest JSON'
   ```

3. Uruchom (z dowolnego katalogu):

   ```powershell
   [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; & ([scriptblock]::Create((irm https://raw.githubusercontent.com/pepix-pm/ADCheck/main/ADCheck.ps1).TrimStart([char]0xFEFF))) -Client LAB -History
   ```

4. Po przebiegu usuń oba pliki kontrolne (`AD_INNY_*` i `AD_LAB_lab.local_20000101-0001.json`).

| Nr | Oczekiwany wynik |
|---|---|
| F1 | Parametr `-Client` przyjęty (brak błędu o brakującym `-Klient`); nagłówek raportu: ADCheck 0.30, klient LAB |
| F2 | Konsola: żółty komunikat „-History: przeglądy w historii: 7, pominięte pliki (niezgodne lub uszkodzone): 1” (6 wcześniejszych przebiegów + bieżący; więcej, jeśli w katalogu są dodatkowe raporty LAB – zanotuj liczbę) |
| F3 | Sekcja „Historia przeglądów” (pod „Porównaniem…” lub pod zakresem oceny): wykres wyniku z liniami czterech obszarów i szarym pasmem wyniku ogólnego, legenda nad wykresem |
| F4 | Przebiegi B (konto `lab-zwykly`) i C (`-UseWinRM`) mają na wykresie pusty (biały) znacznik, a w tabeli dopisek „(inny tryb)”; pozostałe – pełny znacznik |
| F5 | Wykres „Zgodność konfiguracji DC” ma punkty dla wszystkich przebiegów; wartość w przebiegu C wyraźnie różni się od sąsiednich (inne źródło danych) |
| F6 | Tabela pod wykresami: najnowszy przegląd na górze z dopiskiem „(bieżący)”; wynik, klasa i liczby Critical/High/Medium/Low w każdym wierszu zgadzają się z kartami w raportach poszczególnych przebiegów |
| F7 | W historii **nie ma** przeglądu klienta INNY ani pliku uszkodzonego; pod tabelą notka „Pominięte pliki JSON (uszkodzone lub z niezgodną wersją schematu): 1.” |
| F8 | Najechanie kursorem na punkt wykresu pokazuje nazwę serii, wartość i datę |
| F9 | Wydruk do PDF (Ctrl+P): wykresy widoczne i nieucięte |
| F10 | Punkt 25 (właściciele obiektów) – przebieg F wykonuje się po `-Usun`, więc przed nim utwórz przypadki ponownie (`.\Lab-Scenariusze.ps1 -Domena lab.local`), uruchom przebiegi F i G, a na końcu znowu `-Usun`. W F10 sprawdź wynik 25 |

### Przebieg F – poprawność kontroli CIS i Microsoft Security Baseline (prawa użytkowników)

Kontrole porównują prawa po SID, nie po nazwie. Grupa Administrators (`S-1-5-32-544`) jest zgodna z CIS niezależnie od tego, czy raport pokazuje ją jako „BUILTIN\Administrators”, czy „BUILTIN\Administratorzy”. Te punkty to potwierdzają. Przed sprawdzeniem zanotuj język systemu DC i stacji: `Get-WinSystemLocale; (Get-UICulture).Name`.

| Nr | Gdzie patrzeć | Oczekiwany wynik |
|---|---|---|
| K1 | DC-CIS-RIGHTS, wiersz „Access Credential Manager as a trusted caller” (przypadek 26) | Zgodne: **Nie**; Źródło: „GPO: ADCheck-Lab DC prawa”. W kolumnie Aktualne jedna nazwa zamieniona na grupę (np. „BUILTIN\Administrators” na angielskim DC), a druga z dopiskiem „(nazwa zamiast SID, nierozpoznana na stacji przeglądu)”. Która jest która, zależy od języka systemu – zanotuj |
| K2 | DC-CIS-RIGHTS, wszystkie wiersze ze statusem Nie | Po „niedozwolone:” **nigdy** nie ma Administrators/Administratorzy, Domain Admins ani Enterprise Admins (w dowolnym języku). Wyjątek: K1, gdzie CIS wymaga, by prawo nie miało nikt |
| K3 | DC-CIS-RIGHTS a GPMC | Dla „Back up files and directories”, „Load and unload device drivers” i „Add workstations to domain” porównaj kolumnę Aktualne z ustawieniami Default Domain Controllers Policy w GPMC (zakładka Settings). Lista grup ta sama (nazwy w języku systemu). Zgodne = Tak tylko wtedy, gdy prawo ma wyłącznie Administrators (lub Domain Admins / Enterprise Admins) |
| K4 | DC-CIS-RIGHTS a stan na DC | Na DC: `secedit /export /areas USER_RIGHTS /cfg C:\Lab\prawa.inf` i `Select-String 'SeBackupPrivilege\|SeLoadDriverPrivilege\|SeMachineAccountPrivilege' C:\Lab\prawa.inf`. SID-y z pliku (`*S-1-5-32-544` = Administrators, `*S-1-5-32-551` = Backup Operators, `*S-1-5-32-549` = Server Operators, `*S-1-5-32-550` = Print Operators, `*S-1-5-11` = Authenticated Users) odpowiadają grupom w kolumnie Aktualne |
| K5 | Kolumna „Microsoft” w DC-CIS-REG | wartości liczbowe i ścieżki rejestru – bez nazw grup, więc niezależne od języka; tylko zanotuj, czy któryś wiersz wygląda podejrzanie |

Jeśli masz dostęp do polskiej wersji Windows Server, powtórz przypadek 26 i punkty K1–K4 na domenie zbudowanej na tej wersji. Nazwy grup wbudowanych powstają przy tworzeniu domeny w języku systemu i tylko taka domena sprawdza je naprawdę po polsku.

### Przebieg G (wersja 0.30, `-UseWinRM`: zasady audytu z `auditpol`)

Wersja 0.30 czyta wynik `auditpol` po pozycji kolumn, a nie po angielskich nagłówkach – na DC z polskim systemem nagłówki mogą być przetłumaczone.

1. Na DC zapisz nagłówek i dwa wiersze: `auditpol /get /category:* /r | Select-Object -First 3 | Set-Content C:\Lab\auditpol.txt`.
2. Uruchom (przypadki testowe muszą jeszcze istnieć – przebieg G wykonaj przed `-Usun` z punktu F10):

   ```powershell
   [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; & ([scriptblock]::Create((irm https://raw.githubusercontent.com/pepix-pm/ADCheck/main/ADCheck.ps1).TrimStart([char]0xFEFF))) -Client LAB -UseWinRM
   ```

| Nr | Oczekiwany wynik |
|---|---|
| G1 | Plik `C:\Lab\auditpol.txt` – przekaż go w całości (pokazuje język nagłówków i wartości) |
| G2 | DC-CIS-AUDIT: kolumna Źródło „auditpol (WinRM)” we wszystkich wierszach; **żaden** wiersz nie ma „nie odczytano podkategorii” |
| G3 | Wiersze „Account Logon: Credential Validation”, „Logon/Logoff: Logon” i „Account Management: Security Group Management” zgadzają się z wynikiem na DC: `auditpol /get /subcategory:{0CCE923F-69AE-11D9-BED3-505054503030},{0CCE9215-69AE-11D9-BED3-505054503030},{0CCE9237-69AE-11D9-BED3-505054503030}` (GUID-y działają w każdym języku systemu) |
| G4 | Wiersze z „nieustawione” w kolumnie Aktualne odpowiadają podkategoriom z „No Auditing” / „Brak inspekcji” w `auditpol /get /category:*` |
| G5 | DC-CIS-RIGHTS: wynik K1 taki sam jak w przebiegu F (prawa nadal z GPO także przy `-UseWinRM`) |

### Przebieg H (wersja 0.31: pierwszeństwo GPO kontrolerów domeny)

Wersja 0.31 uwzględnia łącza wymuszone (Enforced), blokowanie dziedziczenia, filtrowanie zabezpieczeń i filtry WMI. Każdy krok: zmiana w GPMC, potem przebieg zwykłym kontem bez `-UseWinRM` (`-Client LAB`), potem cofnięcie zmiany. Sprawdzany wiersz: DC-CIS-SUMMARY, ustawienie „Network security: LAN Manager authentication level” (kolumny Aktualne i Źródło).

Przygotowanie: GPO `Lab-H-Domena` podlinkowane do domeny z LmCompatibilityLevel = 3 („Send NTLMv2 response only”) oraz GPO `Lab-H-DC` podlinkowane do OU Domain Controllers z wartością 5 („…Refuse LM & NTLM”), z kolejnością łącza 1.

| Nr | Zmiana | Oczekiwany wynik |
|---|---|---|
| H1 | bez zmian | Aktualne 5, Źródło „GPO: Lab-H-DC” |
| H2 | łącze `Lab-H-Domena` do domeny: Enforced | Aktualne 3, Źródło „GPO: Lab-H-Domena (wymuszone)”; na DC `gpresult /r /scope computer` potwierdza to samo |
| H3 | H2 cofnięte; na OU Domain Controllers: Block Inheritance | Aktualne 5; opis DC-CIS-REG zawiera „OU Domain Controllers blokuje dziedziczenie”; ustawienia z Default Domain Policy (np. z GPO domeny) nie są źródłem żadnego wiersza |
| H4 | H3 cofnięte; `Lab-H-DC`: z Security Filtering usunięte Authenticated Users, dodana grupa bez DC (Authenticated Users zostaje z samym odczytem na karcie Delegation) | Aktualne 3, Źródło „GPO: Lab-H-Domena”; opis zawiera „GPO 'Lab-H-DC' … pominięto - filtrowanie zabezpieczeń nie obejmuje kontrolerów domeny” |
| H5 | H4 cofnięte; do `Lab-H-DC` przypisany dowolny filtr WMI | Aktualne 5, Źródło „GPO: Lab-H-DC (niepewne: filtr WMI)”; opis wymienia to GPO |
| H6 | GPO z wyłączeniem LLMNR podlinkowane do domeny + filtr WMI na tym GPO | Sprawdzone reguły: D-GPO-LLMNR „Zaliczony warunkowo (GPO domeny z ustawieniem ma ograniczony zakres…)” |
| H7 | H6 bez filtra WMI; OU z aktywnym komputerem ma Block Inheritance | D-GPO-LLMNR „Zaliczony warunkowo (OU z komputerami blokujące dziedziczenie…)”; po ustawieniu Enforced na łączu – „Zaliczony” |
| H8 | `-History -MaxHistoryPoints 3` przy co najmniej 4 raportach LAB w katalogu | Wykres i tabela mają 3 przeglądy (2 najnowsze + bieżący) i notkę o pominiętych starszych |

## 4. Co przekazać

1. Tabelę z kolumnami: Nr, Oczekiwany wynik, Faktyczny wynik, OK / NOK. Przy NOK dołącz zrzut ekranu fragmentu raportu.
2. Raporty HTML i JSON ze wszystkich przebiegów (dane laboratorium nie są poufne).
3. Pełny tekst każdego czerwonego lub żółtego komunikatu z konsoli i czas trwania każdego przebiegu.
4. Uwagi o czytelności raportu: co było niejasne, czego szukałeś dłużej niż minutę.

Jeżeli skrypt `Lab-Scenariusze.ps1` przerwie się błędem, zapisz komunikat, uruchom `-Usun` i zacznij od kroku 2. Nie poprawiaj skryptów samodzielnie.

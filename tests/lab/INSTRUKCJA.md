# Laboratorium testowe ADCheck

Instrukcja dla osoby, która sprawdza ADCheck na domenie testowej przed wydaniem wersji. Czas: około 4 godzin, w tym około 1 godziny na przygotowanie VM.

> **Tylko domena testowa.** Skrypt `Lab-Scenariusze.ps1` celowo psuje konfigurację AD: nadaje prawa replikacji, zmienia grupę podstawową konta i usuwa foldery GPO z SYSVOL. Nigdy nie uruchamiaj go w domenie, z której ktoś korzysta. Sam ADCheck niczego nie zmienia.

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

Kolejność kroków:

1. Przebieg 0. Zachowaj raport HTML i JSON. Zanotuj wynik ogólny i liczbę znalezisk.
2. Utwórz przypadki testowe (zapyta o potwierdzenie i o hasło dla konta `lab-zwykly`):

   ```powershell
   cd C:\Lab
   .\Lab-Scenariusze.ps1 -Domena lab.local
   ```

3. Przebiegi A, B i C.
4. Usuń przypadki testowe: `.\Lab-Scenariusze.ps1 -Domena lab.local -Usun`
5. Przebiegi D i E.

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
| 9a | jw. | Karta „Zmiana od …” obok wyniku | dopisek „klasa ekspozycji D → E” (lub inna zmiana klasy) i „nowe Critical: 1”; karta z czerwonym paskiem |
| 10 | Nawigacja w raporcie | Macierz ryzyka | kliknięcie pola ze znaleziskami rozwija listę linków; link prowadzi do szczegółów; „↑ Macierz ryzyka” wraca na górę |

### Przebieg B (zwykłe konto)

| Nr | Oczekiwany wynik |
|---|---|
| B1 | Nagłówek raportu: „Konto: LAB\lab-zwykly”, a przy `runas /netonly` – „Uruchomił: <konto lokalne> … Konto LDAP: LAB\lab-zwykly”; w obu wariantach bez dopisku „(konto uprzywilejowane)” |
| B2 | DC-NETSESSION ma status inny niż „Pominięty (konto uprzywilejowane)” |
| B3 | Wyniki 1–6 takie same jak w przebiegu A (D-DCSYNC, `lab-pgid512`, D-GPO-LLMNR, D-GPO-SYNC, notka DC-CIS) |
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
| D1 | „Porównanie z poprzednim przeglądem”: D-DCSYNC, D-GPO-SYNC i D-GPO-DEADLINK na liście usuniętych (naprawionych) |
| D2 | `lab-pgid512` i pozostałe konta `lab-*` nie występują w raporcie |
| D3 | Brak ostrzeżenia o innym trybie (przebiegi A i D wykonano w tym samym trybie) |

### Przebieg E (porównanie z przebiegiem w innym trybie)

| Nr | Oczekiwany wynik |
|---|---|
| E1 | „Porównanie z poprzednim przeglądem” zaczyna się od ostrzeżenia „poprzedni przegląd wykonano w innym trybie (testy DC: …)”; to samo ostrzeżenie na konsoli (żółte) |

## 4. Co przekazać

1. Tabelę z kolumnami: Nr, Oczekiwany wynik, Faktyczny wynik, OK / NOK. Przy NOK dołącz zrzut ekranu fragmentu raportu.
2. Raporty HTML i JSON ze wszystkich przebiegów (dane laboratorium nie są poufne).
3. Pełny tekst każdego czerwonego lub żółtego komunikatu z konsoli i czas trwania każdego przebiegu.
4. Uwagi o czytelności raportu: co było niejasne, czego szukałeś dłużej niż minutę.

Jeżeli skrypt `Lab-Scenariusze.ps1` przerwie się błędem, zapisz komunikat, uruchom `-Usun` i zacznij od kroku 2. Nie poprawiaj skryptów samodzielnie.

# Laboratorium testowe ADCheck

Instrukcja dla osoby, która sprawdza ADCheck na domenie testowej przed wydaniem wersji. Czas: około 4 godzin, w tym około 1 godziny na przygotowanie VM.

> **Tylko domena testowa.** Skrypt `Lab-Scenariusze.ps1` celowo psuje konfigurację AD: nadaje prawa replikacji, zmienia grupę podstawową konta i usuwa foldery GPO z SYSVOL. Nigdy nie uruchamiaj go w domenie, z której ktoś korzysta. Sam ADCheck niczego nie zmienia.

## 1. Przygotowanie domeny testowej

1. Na Hyper-V utwórz VM: Windows Server 2022 lub 2025 w wersji ewaluacyjnej (180 dni), 4 GB RAM, dysk 60 GB, karta sieciowa z dostępem do internetu.
2. Po instalacji nadaj stały adres IP, a jako DNS ustaw 127.0.0.1.
3. Zainstaluj AD i utwórz nową domenę (PowerShell jako administrator):

   ```powershell
   Rename-Computer -NewName DC01 -Restart
   Install-WindowsFeature AD-Domain-Services, GPMC -IncludeManagementTools
   Install-ADDSForest -DomainName lab.local -DomainNetbiosName LAB -InstallDns
   ```

4. Opcjonalnie, do przebiegu B: druga VM z Windows 11 (wersja ewaluacyjna), DNS wskazujący na DC, dołączona do domeny `lab.local`.
5. Utwórz katalog roboczy `C:\Lab` na DC i skopiuj do niego `Lab-Scenariusze.ps1` (z katalogu `tests/lab` repozytorium).

Polecenie uruchamiające ADCheck (wersja z gałęzi `main`, z katalogu `C:\Lab`):

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; & ([scriptblock]::Create((irm https://raw.githubusercontent.com/pepix-pm/ADCheck/main/ADCheck.ps1).TrimStart([char]0xFEFF))) -Klient LAB
```

Do kolejnych przebiegów dopisuj parametry na końcu (np. `-Previous <plik.json>`). Raporty trafiają do katalogu `raporty` w bieżącym katalogu.

## 2. Przebiegi

| Przebieg | Kiedy | Konto | Parametry |
|---|---|---|---|
| 0 | Czysta domena, przed skryptem | LAB\Administrator na DC | `-Klient LAB` |
| A | Po `Lab-Scenariusze.ps1` | LAB\Administrator na DC | `-Klient LAB -Previous <JSON z przebiegu 0>` |
| B | Po przebiegu A | LAB\lab-zwykly na stacji Windows 11 | `-Klient LAB` |
| C | Po przebiegu B | LAB\Administrator na DC | `-Klient LAB -UseWinRM` |
| D | Po `-Usun` | LAB\Administrator na DC | `-Klient LAB -Previous <JSON z przebiegu A>` |

Kolejność kroków:

1. Przebieg 0. Zachowaj raport HTML i JSON. Zanotuj wynik ogólny i liczbę znalezisk.
2. Utwórz przypadki testowe (zapyta o potwierdzenie i o hasło dla konta `lab-zwykly`):

   ```powershell
   cd C:\Lab
   .\Lab-Scenariusze.ps1 -Domena lab.local
   ```

3. Przebiegi A, B i C.
4. Usuń przypadki testowe: `.\Lab-Scenariusze.ps1 -Domena lab.local -Usun`
5. Przebieg D.

Bez stacji Windows 11 przebieg B można wykonać z dowolnego komputera z Windows w tej samej sieci:
`runas /netonly /user:LAB\lab-zwykly powershell`, a w nowym oknie dopisać do polecenia `-Server lab.local`.

## 3. Oczekiwane wyniki

W tabeli „Sprawdzone reguły” na końcu raportu każda reguła ma status. Szczegóły znalezisk otwierasz kliknięciem pola w macierzy ryzyka.

### Przebieg A (konto Administrator, po skrypcie)

| Nr | Przypadek | Gdzie patrzeć | Oczekiwany wynik |
|---|---|---|---|
| 1 | `lab-dcsync-niepelny` ma tylko DS-Replication-Get-Changes-All | Znalezisko D-DCSYNC, kolumna Zestaw | wiersz z zestawem „niepełny (brak DS-Replication-Get-Changes)” |
| 2 | `lab-dcsync-pelny` ma Get-Changes-All bezpośrednio, a Get-Changes przez grupę `lab-repl-grupa` | D-DCSYNC | wiersz z zestawem „pełny (DCSync)”; całe znalezisko **Critical**. Zanotuj, jak wygląda wiersz grupy `lab-repl-grupa` |
| 2a | jw. | Reguła D-ACL-DOMAIN | żadne z kont `lab-*` **nie** występuje w D-ACL-DOMAIN |
| 3 | `lab-pgid512` ma grupę podstawową Domain Admins (nie jest w liście członków) | Załącznik A, „Członkowie grup uprzywilejowanych” | `lab-pgid512` przy Domain Admins |
| 3a | jw., hasło bez wygasania | Znalezisko P-PNE | `lab-pgid512` na liście, P-PNE ma wagę High |
| 4 | LLMNR wyłączony tylko w GPO podlinkowanym do OU `ADCheck-Lab` | Sprawdzone reguły, D-GPO-LLMNR | status „Zaliczony warunkowo (…OU=ADCheck-Lab…)”; brak znaleziska D-GPO-LLMNR |
| 4a | W OU `ADCheck-Lab` jest łącze do usuniętego GPO | jw. | status D-GPO-LLMNR **nie** jest „Nierozstrzygnięty” |
| 5 | GPO „ADCheck-Lab Bez folderu” podlinkowane do OU, bez folderu w SYSVOL | Znalezisko D-GPO-SYNC | waga **High**, tytuł „Podlinkowane GPO bez folderu w SYSVOL…”, kolumna Podlinkowane z DN OU |
| 6 | GPO „ADCheck-Lab DC bez folderu” podlinkowane do OU Domain Controllers, bez folderu | Opis DC-CIS-REG, DC-CIS-AUDIT, DC-CIS-RIGHTS | zdanie „Uwaga: GPO 'ADCheck-Lab DC bez folderu' (podlinkowane do OU Domain Controllers) nie ma folderu w SYSVOL…” |
| 7 | Przegląd uruchomiony kontem Administrator | Znalezisko P-ADMLOGIN | opis kończy się zdaniem, że data logowania może pochodzić z samego przeglądu |
| 8 | Brak LAPS w domenie | C-LAPS-NONE | waga High; zanotuj wariant tytułu („brak atrybutów LAPS w schemacie” albo „schemat rozszerzony, żaden komputer nie ma hasła LAPS”) |
| 9 | Porównanie z przebiegiem 0 | Sekcja „Porównanie z poprzednim przeglądem” | nowe znaleziska: m.in. D-DCSYNC, D-GPO-SYNC; brak błędu wczytania pliku |
| 10 | Nawigacja w raporcie | Macierz ryzyka | kliknięcie pola ze znaleziskami rozwija listę linków; link prowadzi do szczegółów; „↑ Macierz ryzyka” wraca na górę |

### Przebieg B (zwykłe konto)

| Nr | Oczekiwany wynik |
|---|---|
| B1 | Nagłówek raportu: „Konto: LAB\lab-zwykly” bez dopisku „(konto uprzywilejowane)” |
| B2 | DC-NETSESSION ma status inny niż „Pominięty (konto uprzywilejowane)” |
| B3 | Wyniki 1–6 takie same jak w przebiegu A (D-DCSYNC, `lab-pgid512`, D-GPO-LLMNR, D-GPO-SYNC, notka DC-CIS) |
| B4 | Brak dopisku o przeglądzie kontem Administrator w P-ADMLOGIN (o ile znalezisko występuje) |
| B5 | Zanotuj każdą regułę ze statusem „Błąd testu” lub „Nierozstrzygnięty” wraz z przyczyną z raportu |

### Przebieg C (`-UseWinRM`)

| Nr | Oczekiwany wynik |
|---|---|
| C1 | Reguły „Wymaga -UseWinRM” z przebiegu A mają teraz inny status |
| C2 | Opisy DC-CIS-* mówią o odczycie z rejestru i auditpol (bez zdania o GPO bez folderu) |

### Przebieg D (po `-Usun`)

| Nr | Oczekiwany wynik |
|---|---|
| D1 | „Porównanie z poprzednim przeglądem”: D-DCSYNC i D-GPO-SYNC na liście usuniętych (naprawionych) |
| D2 | `lab-pgid512` i pozostałe konta `lab-*` nie występują w raporcie |

## 4. Co przekazać

1. Tabelę z kolumnami: Nr, Oczekiwany wynik, Faktyczny wynik, OK / NOK. Przy NOK dołącz zrzut ekranu fragmentu raportu.
2. Raporty HTML i JSON ze wszystkich przebiegów (dane laboratorium nie są poufne).
3. Pełny tekst każdego czerwonego lub żółtego komunikatu z konsoli i czas trwania każdego przebiegu.
4. Uwagi o czytelności raportu: co było niejasne, czego szukałeś dłużej niż minutę.

Jeżeli skrypt `Lab-Scenariusze.ps1` przerwie się błędem, zapisz komunikat, uruchom `-Usun` i zacznij od kroku 2. Nie poprawiaj skryptów samodzielnie.

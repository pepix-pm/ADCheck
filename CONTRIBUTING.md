# Udział w rozwoju ADCheck

Dziękujemy za zainteresowanie. Zgłoszenia błędów, propozycje nowych testów i poprawki są mile widziane. Zanim wyślesz zmianę, przeczytaj zasady poniżej – część z nich wynika z tego, że ADCheck jest uruchamiany w środowiskach produkcyjnych, a repozytorium jest publiczne.

## Zgłoszenia

- **Błąd:** opisz wersję ADCheck (`$Version` lub stopka raportu), wersję PowerShella, tryb uruchomienia (zwykłe konto / `-UseWinRM`) i komunikat błędu. Jeśli błąd dotyczy wyniku testu, podaj Id reguły (np. `DC-CIS-AUDIT`) i opis, czego się spodziewałeś.
- **Fałszywe znalezisko lub pominięty problem:** opisz konfigurację, która je wywołuje, na fikcyjnych danych.
- **Podatność w samym ADCheck:** nie zakładaj publicznego zgłoszenia – napisz do autora przez [pepix.pl](https://pepix.pl).

**Nie publikuj danych ze swojego środowiska.** Raporty, pliki JSON/CSV, zrzuty ekranu, nazwy domen, kont, serwerów i grup oraz SID-y mogą ujawnić podatności Twojej organizacji. W przykładach używaj nazw `KLIENT`, `firma.local`, `SRV01` i fikcyjnych SID-ów.

## Zasady dla zmian w kodzie

1. **Tylko odczyt.** Skrypt nigdy niczego nie zmienia w AD, GPO ani na kontrolerach domeny. Polecenia naprawcze trafiają wyłącznie do raportu (pole `Fix`).
2. **Domyślnie zwykłe konto domenowe.** Nowy test nie może wymagać uprawnień administracyjnych, chyba że działa wyłącznie w trybie `-UseWinRM` i jest w katalogu reguł oznaczony wymaganiem `W = 'WinRM'`.
3. **Bez dodatkowych zależności.** Bez RSAT i modułów spoza Windows; AD jest odczytywane przez LDAP (`System.DirectoryServices`). Nowe wymaganie (port, usługa, uprawnienie) musi być sprawdzane na starcie, z podpowiedzią, jak je spełnić.
4. **Grupy uprzywilejowane po SID, nie po nazwie** – nazwy bywają przetłumaczone.
5. **Kodowanie `*.ps1`: UTF-8 z BOM.** Bez BOM Windows PowerShell 5.1 psuje polskie znaki. CI to sprawdza.
6. **Język:** raport, komunikaty i komentarze w kodzie są po polsku.
7. **Nie zmieniaj istniejących Id reguł** – służą do porównań między przeglądami (`-Previous`).
8. **Nie kopiuj treści, identyfikatorów ani wyglądu raportów innych narzędzi.** Wzorować się można na zakresie testów, nie na tekstach.

## Jak dodać nowy test

1. Umieść kod w odpowiednim regionie skryptu i opakuj go w `Invoke-Check '<NAZWA>' { ... }` – błąd testu ma trafić do raportu jako informacja, a nie przerwać przeglądu.
2. Znalezisko dodaj przez `Add-IfAny @{ ... }` (lista obiektów) lub `Add-Finding @{ ... }` (pojedynczy fakt). Wymagane pola: `Id` (prefiks `P-`, `U-`, `C-`, `D-` lub `DC-`), `Category`, `Severity` (Critical/High/Medium/Low/Info), `Title`, `Description` (ryzyko zrozumiałe dla właściciela domeny), `Recommendation`, `Fix` (przez funkcję `Fx`), `Mitre` (jeśli ma sens).
3. Obiekty mapuj przez `ConvertTo-UserRow` / `ConvertTo-ComputerRow`; dodatkowe kolumny przez `Add-Member -NotePropertyName ... -PassThru`.
4. Dopisz regułę do `$ruleCatalog` (obszar, rodzaj ryzyka, nazwa testu, wymaganie, krótki opis), nowy rodzaj ryzyka do `$complianceMap`, a szacunek pracochłonności i etap do `$planMeta`.
5. Dopisz test do tabeli w `README.md` i opisz zmianę w `CHANGELOG.md`.
6. Funkcje niezależne od AD (parsowanie, ocena wartości) wydziel i pokryj testami Pester w `tests/ADCheck.Tests.ps1`. Dane przykładowe (`tests/fixtures/`) muszą być fikcyjne.

## Jakość

Przed wysłaniem zmiany uruchom:

```powershell
Invoke-ScriptAnalyzer -Path .\ADCheck.ps1 -Settings .\PSScriptAnalyzerSettings.psd1 -Severity Warning,Error
Invoke-Pester .\tests
```

CI (GitHub Actions, Windows PowerShell 5.1 i PowerShell 7) uruchamia to samo przy każdym pull requeście. Zmiany w wynikach testów sprawdź w środowisku testowym (instrukcja: `tests/lab/INSTRUKCJA.md`) – nigdy w cudzej domenie bez zgody jej właściciela.

## Licencja przesyłanych zmian

ADCheck jest udostępniany na licencji [PolyForm Shield 1.0.0](LICENSE.md), która nie jest licencją open source. Dlatego przesłanie zmiany wymaga zgody na poniższe warunki.

Wysyłając zmianę (pull request, poprawkę lub fragment kodu w zgłoszeniu), oświadczasz, że:

1. jesteś jej autorem albo masz prawo ją przekazać na poniższych warunkach, a zmiana nie zawiera cudzego kodu na licencji, która by to wykluczała;
2. udzielasz licencjodawcy (PEPIX Piotr Misztal) nieodpłatnej, niewyłącznej, nieodwołalnej, bezterminowej i nieograniczonej terytorialnie licencji na korzystanie ze zmiany, jej modyfikowanie, rozpowszechnianie i dalsze licencjonowanie, także na warunkach innych niż PolyForm Shield;
3. zmiana nie zawiera danych żadnego rzeczywistego środowiska.

Autorstwo zmiany pozostaje widoczne w historii repozytorium.

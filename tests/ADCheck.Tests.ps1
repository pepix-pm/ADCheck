# Testy jednostkowe funkcji niezależnych od AD (Pester 5). Uruchomienie: Invoke-Pester .\tests
BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot '..\ADCheck.ps1'
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
    $script:parseErrors = $errors
    $names = 'Read-RegistryPol', 'Test-CisValue', 'ConvertFrom-AuditText', 'ConvertFrom-AuditpolCsv', 'Format-RightHolder', 'Get-TopSeverity', 'Show-Val', 'Get-ParentOU', 'Format-Date', 'Format-EncTypes', 'Get-ScoreClass', 'Get-ExposureClass', 'Get-DcSyncSet', 'Get-DcSyncSource', 'Get-ReplicationRights', 'ConvertFrom-LdapResult', 'ConvertTo-LdapFilterValue', 'ConvertFrom-DnToDns', 'ConvertFrom-LdapTime', 'Get-OsLifecycle', 'Test-IpInSubnet', 'Get-DsHeuristicsChar', 'Test-MsSpec', 'Format-MsSpec', 'Format-Count', 'ConvertTo-HistoryPoint', 'Get-DcMethodNormalized', 'Format-SvgNum', 'ConvertTo-TrendSvg', 'ConvertFrom-GpLink', 'Get-GpoApplyOrder', 'Get-GpoApplySids', 'Test-GpoSecurityFilter', 'Get-CheckKey', 'Resolve-CheckList', 'Compare-FindingObject', 'Get-CertBindingState', 'ConvertFrom-NtpResponse', 'Get-NtpSourceIssue', 'Get-GptLocalAdmin', 'Get-GppLocalAdmin', 'Get-AceDanger', 'Get-TemplateEnrollSid', 'Get-TemplateEscFlag', 'Get-GppPasswordEntry', 'Get-NtpSourceSeverity'
    $defs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
    foreach ($d in $defs) { if ($d.Name -in $names) { . ([scriptblock]::Create($d.Extent.Text)) } }
    # Tabele cyklu życia Windows (zmienne skryptu) potrzebne Get-OsLifecycle
    $vars = 'dcMethodWinRM', 'dcMethodGpo', 'aclGuid', 'gpoApplyGuid', 'win11Builds', 'win10Ltsc', 'serverEol', 'serverBuilds', 'sacBuilds', 'legacyClient'
    $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                   $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] }, $false) |
        Where-Object { $_.Left.VariablePath.UserPath -in $vars } | ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }

    $ldapMulti = @('serviceprincipalname', 'memberof', 'sidhistory', 'objectclass', 'member', 'serverreferencebl', 'msds-ncreplinboundneighbors', 'msds-replattributemetadata', 'msds-enabledfeaturebl')

    function New-PolBytes([object[]]$Entries) {
        $u = [System.Text.Encoding]::Unicode
        $b = [System.Collections.Generic.List[byte]]::new()
        $b.AddRange([System.Text.Encoding]::ASCII.GetBytes('PReg')); $b.AddRange([BitConverter]::GetBytes([uint32]1))
        foreach ($e in $Entries) {
            $b.AddRange($u.GetBytes('[')); $b.AddRange($u.GetBytes("$($e.Key)`0;")); $b.AddRange($u.GetBytes("$($e.Name)`0;"))
            $b.AddRange([BitConverter]::GetBytes([uint32]4)); $b.AddRange($u.GetBytes(';'))
            $b.AddRange([BitConverter]::GetBytes([uint32]4)); $b.AddRange($u.GetBytes(';'))
            $b.AddRange([BitConverter]::GetBytes([uint32]$e.Data)); $b.AddRange($u.GetBytes(']'))
        }
        , $b.ToArray()
    }
}

Describe 'Skrypt' {
    It 'parsuje się bez błędów' { $script:parseErrors | Should -BeNullOrEmpty }
}

Describe 'Read-RegistryPol' {
    It 'odczytuje wpisy DWORD' {
        $bytes = New-PolBytes @(
            @{ Key = 'Software\Policies\Microsoft\Windows NT\DNSClient'; Name = 'EnableMulticast'; Data = 0 }
            @{ Key = 'Software\Policies\Microsoft\Windows\EventLog\Security'; Name = 'MaxSize'; Data = 196608 }
        )
        $r = @(Read-RegistryPol $bytes)
        $r.Count | Should -Be 2
        $r[0].Key | Should -Be 'Software\Policies\Microsoft\Windows NT\DNSClient'
        $r[0].Name | Should -Be 'EnableMulticast'
        $r[0].Data | Should -Be 0
        $r[1].Data | Should -Be 196608
    }
    It 'oznacza **del. jako usunięcie' {
        $r = @(Read-RegistryPol (New-PolBytes @(@{ Key = 'Software\X'; Name = '**del.Val'; Data = 0 })))
        $r[0].Name | Should -Be 'Val'
        $r[0].Deleted | Should -BeTrue
    }
    It 'zwraca pusty wynik dla złego nagłówka' {
        @(Read-RegistryPol ([byte[]](1, 2, 3, 4, 5, 6, 7, 8))).Count | Should -Be 0
    }
}

Describe 'Test-CisValue' {
    It 'eq: zgodne i niezgodne' {
        Test-CisValue 1 @{ Op = 'eq'; E = 1; D = $null } | Should -BeTrue
        Test-CisValue 0 @{ Op = 'eq'; E = 1; D = $null } | Should -BeFalse
    }
    It 'nieustawione: wartość domyślna albo niezgodne' {
        Test-CisValue $null @{ Op = 'eq'; E = 1; D = 1 } | Should -BeTrue
        Test-CisValue $null @{ Op = 'eq'; E = 1; D = $null } | Should -BeFalse
    }
    It 'le-nz: 0 jest niezgodne' {
        Test-CisValue 900 @{ Op = 'le-nz'; E = 900; D = $null } | Should -BeTrue
        Test-CisValue 0 @{ Op = 'le-nz'; E = 900; D = $null } | Should -BeFalse
    }
    It 'aes: bez RC4 i DES' {
        Test-CisValue 2147483640 @{ Op = 'aes'; E = 0; D = $null } | Should -BeTrue
        Test-CisValue 28 @{ Op = 'aes'; E = 0; D = $null } | Should -BeFalse   # RC4 + AES
    }
}

Describe 'ConvertFrom-AuditText' {
    It 'rozpoznaje ustawienia' {
        ConvertFrom-AuditText 'Success and Failure' | Should -Be 3
        ConvertFrom-AuditText 'Success' | Should -Be 1
        ConvertFrom-AuditText 'Failure' | Should -Be 2
        ConvertFrom-AuditText 'No Auditing' | Should -Be 0
    }
    It 'rozpoznaje ustawienia po polsku' {
        ConvertFrom-AuditText 'Sukces i niepowodzenie' | Should -Be 3
        ConvertFrom-AuditText 'Sukces' | Should -Be 1
        ConvertFrom-AuditText 'Niepowodzenie' | Should -Be 2
        ConvertFrom-AuditText 'Brak inspekcji' | Should -Be 0
    }
}

Describe 'ConvertFrom-AuditpolCsv' {
    It 'czyta kolumny po pozycji niezależnie od języka nagłówków' {
        # Nagłówek przykładowy - kolumny po pozycji, więc jego treść nie ma znaczenia
        $lines = @(
            'Nazwa komputera,Cel zasad,Podsystem,Podkategoria,Identyfikator GUID podkategorii,Ustawienie dołączenia,Ustawienie wykluczenia'
            ''
            'DC01,System,,Weryfikacja poświadczeń,{0CCE923F-69AE-11D9-BED3-505054503030},Sukces i niepowodzenie,'
            'DC01,System,,Logowanie,{0CCE9215-69AE-11D9-BED3-505054503030},Sukces,'
        )
        $r = @(ConvertFrom-AuditpolCsv $lines)
        $r.Count | Should -Be 2
        $r[0].G | Should -Be '0cce923f-69ae-11d9-bed3-505054503030'
        $r[0].S | Should -Be 'Sukces i niepowodzenie'
        ConvertFrom-AuditText $r[1].S | Should -Be 1
    }
    It 'czyta układ 6 kolumn (bez kolumny Subsystem) i wartości w cudzysłowach' {
        $lines = @(
            'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting'
            'DC01,System,Credential Validation,{0CCE923F-69AE-11D9-BED3-505054503030},Success and Failure,'
            '"DC01","System","Logon","{0CCE9215-69AE-11D9-BED3-505054503030}","No Auditing",""'
        )
        $r = @(ConvertFrom-AuditpolCsv $lines)
        $r.Count | Should -Be 2
        $r[0].G | Should -Be '0cce923f-69ae-11d9-bed3-505054503030'
        ConvertFrom-AuditText $r[0].S | Should -Be 3
        $r[1].S | Should -Be 'No Auditing'
        ConvertFrom-AuditText $r[1].S | Should -Be 0
    }
    It 'pomija wiersze bez GUID i pusty wynik' {
        @(ConvertFrom-AuditpolCsv @('Machine Name,Policy Target,Subsystem,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting', 'DC01,System,,X,,Success,')).Count | Should -Be 0
        @(ConvertFrom-AuditpolCsv @()).Count | Should -Be 0
    }
}

Describe 'Format-RightHolder' {
    It 'oznacza nazwę, której nie zamieniono na SID' {
        Format-RightHolder 'Administratorzy' | Should -Be 'Administratorzy (nazwa zamiast SID, nierozpoznana na stacji przeglądu)'
    }
}

Describe 'Format-EncTypes, ConvertFrom-Ldap*, ConvertFrom-DnToDns' {
    It 'opisuje bity szyfrowania' {
        Format-EncTypes 24 | Should -Be '24 (AES128, AES256)'
        Format-EncTypes 7 | Should -Be '7 (DES-CRC, DES-MD5, RC4)'
        Format-EncTypes $null | Should -Match 'nieustawione'
    }
}

Describe 'Get-ScoreClass' {
    It 'progi kolorów' {
        Get-ScoreClass 0 | Should -Be 'r0'
        Get-ScoreClass 9 | Should -Be 'r1'
        Get-ScoreClass 10 | Should -Be 'r2'
        Get-ScoreClass 30 | Should -Be 'r3'
    }
}

Describe 'Get-ExposureClass' {
    It 'Critical = E ... brak znalezisk = A' {
        1..5 | ForEach-Object { Get-ExposureClass $_ } | Should -Be @('E', 'D', 'C', 'B', 'A')
    }
    It 'zwraca napis (klucz tabeli opisów), nie znak' {
        Get-ExposureClass 1 | Should -BeOfType [string]
    }
    It 'poziom spoza zakresu' {
        Get-ExposureClass 0 | Should -Be '?'
        Get-ExposureClass 6 | Should -Be '?'
    }
}

Describe 'Warstwa LDAP' {
    It 'ConvertFrom-LdapResult mapuje atrybuty jak moduł AD' {
        $sid = [System.Security.Principal.SecurityIdentifier]'S-1-5-32-544'
        $b = New-Object byte[] $sid.BinaryLength; $sid.GetBinaryForm($b, 0)
        $o = ConvertFrom-LdapResult @{
            'userAccountControl' = @(66050); 'pwdLastSet' = @([int64]0); 'objectSid' = @(, $b)
            'servicePrincipalName' = @('HTTP/a', 'HTTP/b'); 'objectClass' = @('top', 'person', 'user'); 'sAMAccountName' = @('jan')
        }
        $o.Enabled | Should -BeFalse
        $o.PasswordNeverExpires | Should -BeTrue
        $o.PasswordLastSet | Should -BeNullOrEmpty
        $o.SID.Value | Should -Be 'S-1-5-32-544'
        @($o.ServicePrincipalName).Count | Should -Be 2
        $o.ObjectClass | Should -Be 'user'
        $o.SamAccountName | Should -Be 'jan'
    }
    It 'ConvertTo-LdapFilterValue escapuje znaki specjalne' {
        ConvertTo-LdapFilterValue 'CN=Kowalski\, Jan (IT)*' | Should -Be 'CN=Kowalski\5c, Jan \28IT\29\2a'
    }
    It 'ConvertFrom-DnToDns' {
        ConvertFrom-DnToDns 'OU=Biuro,DC=firma,DC=local' | Should -Be 'firma.local'
    }
    It 'ConvertFrom-LdapTime: zerowa data to brak' {
        ConvertFrom-LdapTime '1601-01-01T00:00:00Z' | Should -BeNullOrEmpty
        ConvertFrom-LdapTime '2026-01-02T03:04:05Z' | Should -Not -BeNullOrEmpty
    }
}

Describe 'Funkcje pomocnicze' {
    It 'Get-ParentOU obsługuje przecinek w nazwie' {
        Get-ParentOU 'CN=Kowalski\, Jan,OU=Biuro,DC=firma,DC=local' | Should -Be 'OU=Biuro,DC=firma,DC=local'
    }
    It 'Show-Val dla braku wartości' {
        Show-Val $null @{ 1 = 'x' } | Should -Be 'nieustawione'
    }
    It 'Format-Date dla braku daty' {
        Format-Date $null | Should -Be '—'
    }
    It 'Get-TopSeverity wybiera najwyższą wagę' {
        Get-TopSeverity @([pscustomobject]@{ Waga = 'Low' }, [pscustomobject]@{ Waga = 'High' }) | Should -Be 'High'
    }
}

Describe 'Get-OsLifecycle' {
    It '<Os> <Ver> -> <Typ> <Wersja>' -ForEach @(
        @{ Os = 'Windows Server® 2008 Standard';    Ver = '6.0 (6003)';   Typ = 'Serwer'; Wersja = '2008' }
        @{ Os = 'Windows Server 2008 R2 Enterprise'; Ver = '6.1 (7601)';  Typ = 'Serwer'; Wersja = '2008 R2' }
        @{ Os = 'Windows Server 2016 Standard';     Ver = '10.0 (14393)'; Typ = 'Serwer'; Wersja = '2016' }
        @{ Os = 'Hyper-V Server';                   Ver = '10.0 (17763)'; Typ = 'Serwer'; Wersja = 'Hyper-V 2019' }
        @{ Os = 'Hyper-V Server 2012 R2';           Ver = '6.3 (9600)';   Typ = 'Serwer'; Wersja = 'Hyper-V 2012 R2' }
        @{ Os = 'Windows Small Business Server 2011 Standard'; Ver = '6.1 (7601)'; Typ = 'Serwer'; Wersja = '2008 R2' }
        @{ Os = 'Windows Server Datacenter';        Ver = '10.0 (19042)'; Typ = 'Serwer'; Wersja = 'SAC (build 19042)' }
        @{ Os = 'Windows Server Datacenter';        Ver = '10.0 (20348)'; Typ = 'Serwer'; Wersja = '2022' }
        @{ Os = 'Windows 2000 Server';              Ver = '5.0 (2195)';   Typ = 'Legacy'; Wersja = 'Windows 2000' }
        @{ Os = 'Windows XP Professional x64 Edition'; Ver = '5.2 (3790)'; Typ = 'Legacy'; Wersja = 'Windows XP' }
        @{ Os = 'Windows 10 IoT Enterprise LTSC';   Ver = '10.0 (19044)'; Typ = 'LTSC';   Wersja = 'LTSC 2021' }
        @{ Os = 'Windows 11 Pro';                   Ver = '10.0 (26200)'; Typ = 'W11';    Wersja = '25H2' }
        @{ Os = 'Windows 11 Pro';                   Ver = '10.0 (26300)'; Typ = 'W11';    Wersja = '26H2' }
        @{ Os = 'Windows 11 Pro';                   Ver = '10.0 (28000)'; Typ = 'W11';    Wersja = 'build 28000 (nowsza niż tabela / Insider)' }
        @{ Os = '';                                 Ver = '';             Typ = 'Inne';   Wersja = '' }
        @{ Os = 'Linux';                            Ver = '';             Typ = 'Inne';   Wersja = '' }
    ) {
        $r = Get-OsLifecycle $Os $Ver
        $r.Typ | Should -Be $Typ
        $r.Wersja | Should -Be $Wersja
    }
    It 'Server 2008 bez roku w nazwie nie jest klasyfikowany jako SAC' {
        (Get-OsLifecycle 'Windows Server® 2008 Standard' '6.0 (6002)').Koniec | Should -Be ([datetime]'2020-01-14')
    }
    It 'Hyper-V Server 2016 ma datę końca wsparcia Server 2016' {
        (Get-OsLifecycle 'Hyper-V Server' '10.0 (14393)').Koniec | Should -Be ([datetime]'2027-01-12')
    }
}

Describe 'Test-IpInSubnet' {
    It '<Ip> w <Cidr> = <Wynik>' -ForEach @(
        @{ Ip = '10.1.2.3';     Cidr = '10.1.2.0/24';    Wynik = $true }
        @{ Ip = '10.1.3.3';     Cidr = '10.1.2.0/24';    Wynik = $false }
        @{ Ip = '192.168.5.10'; Cidr = '192.168.0.0/16'; Wynik = $true }
        @{ Ip = '172.16.0.1';   Cidr = '172.16.0.1/32';  Wynik = $true }
        @{ Ip = '8.8.8.8';      Cidr = '0.0.0.0/0';      Wynik = $true }
        @{ Ip = '10.0.0.129';   Cidr = '10.0.0.128/25';  Wynik = $true }
        @{ Ip = '10.0.0.127';   Cidr = '10.0.0.128/25';  Wynik = $false }
        @{ Ip = '10.0.0.1';     Cidr = '10.0.0.0';       Wynik = $false }
        @{ Ip = 'fe80::1';      Cidr = '10.0.0.0/8';     Wynik = $false }
        @{ Ip = '10.0.0.1';     Cidr = 'fe80::/64';      Wynik = $false }
    ) {
        Test-IpInSubnet $Ip $Cidr | Should -Be $Wynik
    }
}

Describe 'Get-DsHeuristicsChar' {
    It 'brak wartości to 0' { Get-DsHeuristicsChar '' 7 | Should -Be '0' }
    It 'krótsza wartość to 0' { Get-DsHeuristicsChar '00000002' 28 | Should -Be '0' }
    It 'siódmy znak' { Get-DsHeuristicsChar '0000002' 7 | Should -Be '2' }
    It 'znak 28 i 29' {
        $v = '0000000001000000000200000000' + '1' + '1'
        Get-DsHeuristicsChar $v 28 | Should -Be '0'
        Get-DsHeuristicsChar $v 29 | Should -Be '1'
        Get-DsHeuristicsChar $v 30 | Should -Be '1'
    }
}

Describe 'Test-MsSpec' {
    It '<Spec> dla <Value> (domyślnie <Default>) = <Wynik>' -ForEach @(
        @{ Value = 1;    Default = $null; Spec = 'eq:1';        Wynik = $true }
        @{ Value = $null; Default = 1;    Spec = 'eq:1';        Wynik = $true }
        @{ Value = $null; Default = $null; Spec = 'eq:1';       Wynik = $false }
        @{ Value = $null; Default = $null; Spec = 'eqn:0';      Wynik = $true }
        @{ Value = 1;    Default = $null; Spec = 'eqn:0';       Wynik = $false }
        @{ Value = 200000; Default = $null; Spec = 'ge:196608'; Wynik = $true }
        @{ Value = 1000; Default = $null; Spec = 'range:1-900'; Wynik = $false }
        @{ Value = 0;    Default = $null; Spec = 'range:1-900'; Wynik = $false }
        @{ Value = 2147483640; Default = $null; Spec = 'in:2147483624,2147483632,2147483640'; Wynik = $true }
        @{ Value = 28;   Default = $null; Spec = 'in:2147483624,2147483632,2147483640'; Wynik = $false }
    ) {
        Test-MsSpec $Value $Default $Spec | Should -Be $Wynik
    }
    It 'Format-MsSpec' {
        Format-MsSpec 'ge:196608' | Should -Be '≥ 196608'
        Format-MsSpec '' | Should -Be '— (brak w baseline)'
    }
}

Describe 'Format-Count' {
    It '<N> -> <Tekst>' -ForEach @(
        @{ N = 1; Tekst = '1 znalezisko' }; @{ N = 2; Tekst = '2 znaleziska' }; @{ N = 5; Tekst = '5 znalezisk' }
        @{ N = 12; Tekst = '12 znalezisk' }; @{ N = 22; Tekst = '22 znaleziska' }; @{ N = 25; Tekst = '25 znalezisk' }
    ) { Format-Count $N | Should -Be $Tekst }
}

Describe 'Get-DcSyncSet' {
    BeforeAll {
        $rights = @{
            'S-1-5-21-1-1-1-1001' = @{ GetChanges = $false; GetChangesAll = $true;  Filtered = $false }   # konto: sam -All
            'S-1-5-21-1-1-1-1002' = @{ GetChanges = $true;  GetChangesAll = $false; Filtered = $false }   # grupa: sam Get-Changes
            'S-1-5-21-1-1-1-1003' = @{ GetChanges = $true;  GetChangesAll = $true;  Filtered = $false }   # pełny w jednym podmiocie
            'S-1-5-21-1-1-1-1004' = @{ GetChanges = $false; GetChangesAll = $false; Filtered = $true }    # sam In-Filtered-Set
        }
    }
    It 'pełny zestaw w jednym podmiocie' { Get-DcSyncSet $rights @('S-1-5-21-1-1-1-1003') | Should -BeLike 'pełny*' }
    It 'pełny zestaw złożony z podmiotu i jego grupy' { Get-DcSyncSet $rights @('S-1-5-21-1-1-1-1001', 'S-1-5-21-1-1-1-1002') | Should -BeLike 'pełny*' }
    It 'sam Get-Changes-All - niepełny' { Get-DcSyncSet $rights @('S-1-5-21-1-1-1-1001', 'S-1-1-0') | Should -BeLike 'niepełny (brak DS-Replication-Get-Changes)' }
    It 'sam In-Filtered-Set - niepełny' { Get-DcSyncSet $rights @('S-1-5-21-1-1-1-1004') | Should -BeLike 'niepełny (sam In-Filtered-Set)' }
    It 'Get-Changes + In-Filtered-Set - zestaw filtrowany' { Get-DcSyncSet $rights @('S-1-5-21-1-1-1-1002', 'S-1-5-21-1-1-1-1004') | Should -BeLike 'zestaw filtrowany*' }
    It 'brak praw - pusty' { Get-DcSyncSet $rights @('S-1-5-21-1-1-1-9999') | Should -Be '' }
}

Describe 'Get-DcSyncSource' {
    BeforeAll {
        function Resolve-SidName([string]$Sid) { "FIRMA\$Sid" }
        $rights = @{
            'S-1-5-21-1-1-1-1001' = @{ GetChanges = $false; GetChangesAll = $true;  Filtered = $false }
            'S-1-5-21-1-1-1-1002' = @{ GetChanges = $true;  GetChangesAll = $false; Filtered = $false }
            'S-1-5-21-1-1-1-1003' = @{ GetChanges = $true;  GetChangesAll = $true;  Filtered = $false }
        }
    }
    It 'prawo tylko przez grupę' { Get-DcSyncSource $rights 'S-1-5-21-1-1-1-1001' @('S-1-5-21-1-1-1-1001', 'S-1-5-21-1-1-1-1002') | Should -Be 'Get-Changes przez FIRMA\S-1-5-21-1-1-1-1002' }
    It 'prawa nadane bezpośrednio - pusto' { Get-DcSyncSource $rights 'S-1-5-21-1-1-1-1003' @('S-1-5-21-1-1-1-1003', 'S-1-5-21-1-1-1-1002') | Should -Be '' }
    It 'kilka praw przez grupy' { Get-DcSyncSource $rights 'S-1-5-21-1-1-1-9999' @('S-1-5-21-1-1-1-9999', 'S-1-5-21-1-1-1-1001', 'S-1-5-21-1-1-1-1002') | Should -Be 'Get-Changes przez FIRMA\S-1-5-21-1-1-1-1002; Get-Changes-All przez FIRMA\S-1-5-21-1-1-1-1001' }
}

Describe 'Get-ReplicationRights' {
    BeforeAll {
        function New-Sd([object[]]$Aces) {
            $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
            foreach ($a in $Aces) {
                $sid = [System.Security.Principal.SecurityIdentifier]$a.Sid
                $rule = if ($a.Guid) { New-Object System.DirectoryServices.ActiveDirectoryAccessRule $sid, $a.Rights, $a.Type, ([guid]$a.Guid) }
                        else { New-Object System.DirectoryServices.ActiveDirectoryAccessRule $sid, $a.Rights, $a.Type }
                $sd.AddAccessRule($rule)
            }
            $sd
        }
        $er = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
        $allow = [System.Security.AccessControl.AccessControlType]::Allow
    }
    It 'Get-Changes i Get-Changes-All z osobnych wpisów' {
        $sd = New-Sd @(@{ Sid = 'S-1-5-21-1-1-1-1001'; Rights = $er; Type = $allow; Guid = $aclGuid.GetChanges }
                       @{ Sid = 'S-1-5-21-1-1-1-1001'; Rights = $er; Type = $allow; Guid = $aclGuid.GetChangesAll })
        $r = Get-ReplicationRights $sd
        $r['S-1-5-21-1-1-1-1001'].GetChanges | Should -BeTrue
        $r['S-1-5-21-1-1-1-1001'].GetChangesAll | Should -BeTrue
        $r['S-1-5-21-1-1-1-1001'].Filtered | Should -BeFalse
    }
    It 'wszystkie prawa rozszerzone i GenericAll obejmują każde prawo replikacji' {
        $sd = New-Sd @(@{ Sid = 'S-1-5-21-1-1-1-1002'; Rights = $er; Type = $allow }
                       @{ Sid = 'S-1-5-21-1-1-1-1003'; Rights = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll; Type = $allow })
        $r = Get-ReplicationRights $sd
        foreach ($s in 'S-1-5-21-1-1-1-1002', 'S-1-5-21-1-1-1-1003') {
            $r[$s].GetChanges | Should -BeTrue
            $r[$s].GetChangesAll | Should -BeTrue
            $r[$s].Filtered | Should -BeTrue
        }
    }
    It 'pomija Deny i prawa niezwiązane z replikacją' {
        $sd = New-Sd @(@{ Sid = 'S-1-5-21-1-1-1-1004'; Rights = $er; Type = [System.Security.AccessControl.AccessControlType]::Deny; Guid = $aclGuid.GetChangesAll }
                       @{ Sid = 'S-1-5-21-1-1-1-1005'; Rights = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty; Type = $allow })
        (Get-ReplicationRights $sd).Count | Should -Be 0
    }
    It 'zwraca pustą tabelę dla braku deskryptora' { (Get-ReplicationRights $null).Count | Should -Be 0 }
}

Describe 'Get-OsLifecycle - daty szacunkowe' {
    It '26H2 ma datę oznaczoną jako szacunek' { (Get-OsLifecycle 'Windows 11 Pro' '10.0 (26300)').Szacunek | Should -BeTrue }
    It '25H2 ma datę potwierdzoną' { (Get-OsLifecycle 'Windows 11 Pro' '10.0 (26200)').Szacunek | Should -BeFalse }
}

Describe 'Historia przeglądów' {
    It 'punkt z raportu sprzed 0.30: zgodność DC z tytułu DC-CIS-SUMMARY, liczba znalezisk wg wagi' {
        $j = '{"Meta":{"Data":"2026-01-10T10:00:00","Wynik":60,"Obszary":{"Anomalie":20,"Konta uprzywilejowane":60},"KlasaEkspozycji":"D","Wersja":"0.28"},"Znaleziska":[{"Id":"P-PNE","Severity":"High"},{"Id":"U-STALE","Severity":"Medium"},{"Id":"DC-CIS-SUMMARY","Severity":"Info","Title":"Zgodność DC: CIS L1 40 z 60 (66%), Microsoft Security Baseline 0 z 0 (0%)"}]}' | ConvertFrom-Json
        $p = ConvertTo-HistoryPoint $j
        $p.Wynik | Should -Be 60
        $p.Obszary['Anomalie'] | Should -Be 20
        $p.High | Should -Be 1
        $p.Medium | Should -Be 1
        $p.CIS | Should -Be 66
        $p.MS | Should -BeNullOrEmpty   # 0 ocenionych ustawień - brak wartości, nie 0%
        $p.KontoUprzywilejowane | Should -BeNullOrEmpty
    }
    It 'raport 0.27: dawna nazwa trybu bez -UseWinRM jak bieżąca, klasa z najpoważniejszego znaleziska' {
        $j = '{"Meta":{"Data":"2026-01-05T10:00:00","Wynik":70,"Obszary":{"Anomalie":70},"Wersja":"0.27","TestyDC":"sondy sieciowe + GPO z SYSVOL (zwykłe konto)"},"Znaleziska":[{"Id":"D-DCSYNC","Severity":"Critical"},{"Id":"P-PNE","Severity":"High"}]}' | ConvertFrom-Json
        $p = ConvertTo-HistoryPoint $j
        $p.TestyDC | Should -Be 'sondy sieciowe + GPO z SYSVOL (bez -UseWinRM)'
        $p.Klasa | Should -Be 'E'
        Get-DcMethodNormalized 'rejestr DC przez WinRM (konto admina)' | Should -BeLike 'rejestr i auditpol DC przez WinRM*'
    }
    It 'punkt z bieżącego przebiegu (słowniki uporządkowane)' {
        $meta = [ordered]@{ Data = '2026-02-01T09:30:00'; Wynik = 25; Obszary = [ordered]@{ Anomalie = 25 }; KlasaEkspozycji = 'E'; KontoUprzywilejowane = $false; ZgodnoscDC = [ordered]@{ CIS = 81; MS = 70 } }
        $p = ConvertTo-HistoryPoint ([pscustomobject]@{ Meta = $meta; Znaleziska = @([pscustomobject]@{ Id = 'D-DCSYNC'; Severity = 'Critical' }) })
        $p.Data | Should -Be ([datetime]'2026-02-01T09:30:00')
        $p.Critical | Should -Be 1
        $p.CIS | Should -Be 81
        $p.KontoUprzywilejowane | Should -BeFalse
    }
    It 'liczby w SVG z kropką dziesiętną niezależnie od kultury' {
        $c = [System.Threading.Thread]::CurrentThread.CurrentCulture
        try {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = 'pl-PL'
            Format-SvgNum 157.5 | Should -Be '157.5'
            $svg = ConvertTo-TrendSvg @('a', 'b', 'c') @(@{ Name = 'X'; Color = '#000'; Values = @(10, $null, 33) }) @($false, $true, $false)
            $svg | Should -Not -Match 'points="[^"]*\d,\d+ \d'
        } finally { [System.Threading.Thread]::CurrentThread.CurrentCulture = $c }
    }
    It 'brak wartości przerywa linię; pusty znacznik dla innego trybu' {
        $svg = ConvertTo-TrendSvg @('a', 'b', 'c') @(@{ Name = 'X'; Color = '#000'; Values = @(10, 20, $null) }) @($false, $true, $false)
        ([regex]::Matches($svg, '<polyline')).Count | Should -Be 1
        ([regex]::Matches($svg, '<circle')).Count | Should -Be 2
        $svg | Should -Match 'fill="#fff"'
    }
}

Describe 'Pierwszeństwo GPO' {
    BeforeAll {
        $a = 'cn={A},cn=policies,cn=system,DC=firma,DC=local'
        $b = 'cn={B},cn=policies,cn=system,DC=firma,DC=local'
        $c = 'cn={C},cn=policies,cn=system,DC=firma,DC=local'
        $dom = 'DC=firma,DC=local'; $ou = 'OU=Domain Controllers,DC=firma,DC=local'
    }
    It 'ConvertFrom-GpLink: opcje łącza (wyłączone, wymuszone)' {
        $r = @(ConvertFrom-GpLink "[LDAP://$a;0][LDAP://$b;1][LDAP://$c;2]")
        $r.Count | Should -Be 3
        $r[0].Dn | Should -Be $a
        $r[0].Disabled | Should -BeFalse; $r[0].Enforced | Should -BeFalse
        $r[1].Disabled | Should -BeTrue
        $r[2].Enforced | Should -BeTrue; $r[2].Disabled | Should -BeFalse
        @(ConvertFrom-GpLink '').Count | Should -Be 0
    }
    It 'bez flag: domena, potem OU; łącza wyłączone pominięte' {
        $r = @(Get-GpoApplyOrder @(@{ Dn = $dom; GpLink = "[LDAP://$a;0][LDAP://$c;1]"; Block = $false }, @{ Dn = $ou; GpLink = "[LDAP://$b;0]"; Block = $false }))
        ($r.Dn -join '|') | Should -Be "$a|$b"
    }
    It 'wymuszone łącze domeny wygrywa z GPO na OU' {
        $r = @(Get-GpoApplyOrder @(@{ Dn = $dom; GpLink = "[LDAP://$a;2]"; Block = $false }, @{ Dn = $ou; GpLink = "[LDAP://$b;0]"; Block = $false }))
        ($r.Dn -join '|') | Should -Be "$b|$a"
        $r[1].Enforced | Should -BeTrue
    }
    It 'wymuszone na domenie wygrywa z wymuszonym na OU' {
        $r = @(Get-GpoApplyOrder @(@{ Dn = $dom; GpLink = "[LDAP://$a;2]"; Block = $false }, @{ Dn = $ou; GpLink = "[LDAP://$b;2]"; Block = $false }))
        ($r.Dn -join '|') | Should -Be "$b|$a"
    }
    It 'blokowanie dziedziczenia pomija niewymuszone GPO domeny, wymuszone zostaje' {
        $r = @(Get-GpoApplyOrder @(@{ Dn = $dom; GpLink = "[LDAP://$a;0][LDAP://$c;2]"; Block = $false }, @{ Dn = $ou; GpLink = "[LDAP://$b;0]"; Block = $true }))
        ($r.Dn -join '|') | Should -Be "$b|$c"
    }
    It 'Test-GpoSecurityFilter: wszystkie, żadne, część, nieustalone' {
        $dc1 = [string[]]@('S-1-5-21-1-1001', 'S-1-5-21-1-516', 'S-1-5-11')
        $dc2 = [string[]]@('S-1-5-21-1-1002', 'S-1-5-21-1-516', 'S-1-5-11', 'S-1-5-21-1-2000')
        Test-GpoSecurityFilter @('S-1-5-11') @() @($dc1, $dc2) | Should -Be 'Tak'
        Test-GpoSecurityFilter @('S-1-5-21-1-515') @() @($dc1, $dc2) | Should -Be 'Nie'
        Test-GpoSecurityFilter @('S-1-5-21-1-2000') @() @($dc1, $dc2) | Should -Be 'Czesc'
        Test-GpoSecurityFilter @('S-1-5-11') @('S-1-5-21-1-516') @($dc1, $dc2) | Should -Be 'Nie'
        Test-GpoSecurityFilter @('S-1-5-11') @() @($dc1, $null) | Should -Be '?'
        Test-GpoSecurityFilter @('S-1-5-11') @() @() | Should -Be '?'
        Test-GpoSecurityFilter @('S-1-5-11') @() @(, $dc1) | Should -Be 'Tak'
    }
    It 'Get-GpoApplySids: Apply Group Policy z ACE zezwolenia i odmowy' {
        $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $R = [System.DirectoryServices.ActiveDirectoryRights]
        $au = [System.Security.Principal.SecurityIdentifier]'S-1-5-11'
        $g  = [System.Security.Principal.SecurityIdentifier]'S-1-5-21-1-2-3-1105'
        $T = [System.Security.AccessControl.AccessControlType]
        $sd.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $au, $R::ExtendedRight, $T::Allow, $gpoApplyGuid))
        $sd.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $au, $R::GenericRead, $T::Allow))
        $sd.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule $g, $R::ExtendedRight, $T::Deny, $gpoApplyGuid))
        $f = Get-GpoApplySids $sd
        $f.Allow | Should -Be @('S-1-5-11')
        $f.Deny | Should -Be @('S-1-5-21-1-2-3-1105')
    }
}

Describe 'Wybór testów (-IncludeCheck / -ExcludeCheck)' {
    BeforeAll {
        $known = [string[]]@('ADCS', 'DC-NET', 'DC-OS', 'DC-PROBE', 'DOMAIN', 'PRIV')
        $cat = @(@{ Id = 'D-ADCS-ESC1'; C = 'ADCS' }, @{ Id = 'D-DNS-CREATECHILD'; C = 'DNS-ZONES' }, @{ Id = 'DC-SMB1'; C = 'DC-PROBE' })
    }
    It 'Get-CheckKey: sondy DC i DC-GPO jako DC-PROBE, strefy DNS w teście DOMAIN' {
        Get-CheckKey 'adcs' $known | Should -Be 'ADCS'
        Get-CheckKey 'DC-OS' $known | Should -Be 'DC-OS'
        Get-CheckKey 'DC-GPO' $known | Should -Be 'DC-PROBE'
        Get-CheckKey 'DC-SRV01' $known | Should -Be 'DC-PROBE'
        Get-CheckKey 'DNS-ZONES' $known | Should -Be 'DOMAIN'
    }
    It 'Resolve-CheckList: Id reguły, lista z przecinkami, nieznane nazwy' {
        $unk = [System.Collections.Generic.List[string]]::new()
        $r = @(Resolve-CheckList @('D-ADCS-ESC1', 'priv, D-DNS-CREATECHILD', 'DC-SMB1', 'NIEMA') $cat $known $unk)
        ($r -join '|') | Should -Be 'ADCS|PRIV|DOMAIN|DC-PROBE'
        ($unk -join '|') | Should -Be 'NIEMA'
        @(Resolve-CheckList $null $cat $known $unk).Count | Should -Be 0
    }
}

Describe 'Compare-FindingObject' {
    It 'po SID: zmiana nazwy konta nie jest nowym obiektem' {
        $prev = @([pscustomobject]@{ Konto = 'j.kowalski'; _Id = 'S-1-5-21-1-2-3-1105' }, [pscustomobject]@{ Konto = 'a.nowak'; _Id = 'S-1-5-21-1-2-3-1106' })
        $curr = @([pscustomobject]@{ Konto = 'j.kowalski-nowy'; _Id = 'S-1-5-21-1-2-3-1105' }, [pscustomobject]@{ Konto = 'p.wisniewski'; _Id = 'S-1-5-21-1-2-3-1107' })
        $c = Compare-FindingObject $prev $curr
        $c.Klucz | Should -Be 'SID'
        $c.Bylo | Should -Be 2; $c.Jest | Should -Be 2
        $c.Nowe | Should -Be 1; $c.NowePrzyklady | Should -Be 'p.wisniewski'
        $c.Usuniete | Should -Be 1; $c.UsunietePrzyklady | Should -Be 'a.nowak'
    }
    It 'bez identyfikatora po jednej stronie: po pierwszej kolumnie, bez rozróżniania wielkości liter' {
        $prev = @([pscustomobject]@{ Konto = 'J.Kowalski' }, [pscustomobject]@{ Konto = 'a.nowak' })
        $curr = @([pscustomobject]@{ Konto = 'j.kowalski'; _Id = 'S-1-5-21-1-2-3-1105' })
        $c = Compare-FindingObject $prev $curr
        $c.Klucz | Should -Be 'nazwa'
        $c.Nowe | Should -Be 0
        $c.Usuniete | Should -Be 1
    }
    It 'puste listy i skrót przykładów' {
        $c = Compare-FindingObject @() @()
        $c.Nowe | Should -Be 0; $c.Usuniete | Should -Be 0
        $curr = 1..7 | ForEach-Object { [pscustomobject]@{ Obiekt = "o$_" } }
        (Compare-FindingObject @() $curr).NowePrzyklady | Should -Be 'o1; o2; o3; o4; o5 (+2)'
    }
}

Describe 'Get-CertBindingState (ESC10)' {
    It 'brak wartości i 2: pełne wymuszanie' {
        (Get-CertBindingState $null $null).KdcFull | Should -BeTrue
        (Get-CertBindingState 2 0x18).KdcFull | Should -BeTrue
        (Get-CertBindingState 2 0x18).UpnMap | Should -BeFalse
        (Get-CertBindingState $null $null).Uwagi | Should -BeNullOrEmpty
    }
    It 'tryb zgodności, wyłączone, mapowanie po UPN' {
        $s = Get-CertBindingState 1 0x1F
        $s.KdcFull | Should -BeFalse
        $s.UpnMap | Should -BeTrue
        $s.Map | Should -Be '0x1F'
        (Get-CertBindingState 0 $null).Kdc | Should -Be '0 (wyłączone)'
        (Get-CertBindingState 0 $null).KdcFull | Should -BeFalse
    }
}

Describe 'Źródło czasu (NTP)' {
    BeforeAll {
        function New-Ntp([int]$First, [int]$Stratum, [byte[]]$Ref) {
            $b = New-Object byte[] 48
            $b[0] = [byte]$First; $b[1] = [byte]$Stratum
            for ($i = 0; $i -lt 4; $i++) { $b[12 + $i] = $Ref[$i] }
            , $b
        }
    }
    It 'źródło IP na stratum 2: bez zastrzeżeń' {
        $n = ConvertFrom-NtpResponse (New-Ntp 0x1C 2 ([byte[]](192, 168, 1, 10)))
        $n.Leap | Should -Be 0
        $n.Stratum | Should -Be 2
        $n.RefId | Should -Be '192.168.1.10'
        Get-NtpSourceIssue $n | Should -BeNullOrEmpty
    }
    It 'dostawca czasu Hyper-V (VMTP) i zegar lokalny (LOCL)' {
        $vm = ConvertFrom-NtpResponse (New-Ntp 0x1C 2 ([System.Text.Encoding]::ASCII.GetBytes('VMTP')))
        $vm.RefId | Should -Be 'VMTP'
        Get-NtpSourceIssue $vm | Should -Match 'hosta wirtualizacji'
        $lo = ConvertFrom-NtpResponse (New-Ntp 0x1C 1 ([System.Text.Encoding]::ASCII.GetBytes('LOCL')))
        Get-NtpSourceIssue $lo | Should -Match 'zegar lokalny'
    }
    It 'zegar niezsynchronizowany (Leap Indicator 3) i za krótka odpowiedź' {
        $n = ConvertFrom-NtpResponse (New-Ntp 0xDC 0 ([byte[]](0, 0, 0, 0)))
        $n.Leap | Should -Be 3
        Get-NtpSourceIssue $n | Should -Match 'niezsynchronizowany'
        ConvertFrom-NtpResponse ([byte[]](1, 2, 3)) | Should -BeNullOrEmpty
    }
}

Describe 'Lokalni administratorzy z GPO' {
    It 'Get-GptLocalAdmin: Members grupy Administrators i Memberof' {
        $inf = @(
            '[Unicode]', 'Unicode=yes',
            '[Group Membership]',
            '*S-1-5-32-544__Memberof =',
            '*S-1-5-32-544__Members = *S-1-5-21-1-2-3-1105,FIRMA\helpdesk',
            '*S-1-5-21-1-2-3-1200__Memberof = *S-1-5-32-544',
            '*S-1-5-21-1-2-3-1300__Memberof = *S-1-5-32-555',
            '*S-1-5-32-555__Members = *S-1-5-21-1-2-3-1400',
            '[Privilege Rights]',
            'SeBackupPrivilege = *S-1-5-32-544'
        )
        $r = @(Get-GptLocalAdmin $inf)
        ($r -join '|') | Should -Be 'S-1-5-21-1-2-3-1105|FIRMA\helpdesk|S-1-5-21-1-2-3-1200'
    }
    It 'Get-GppLocalAdmin: tylko akcja ADD w grupie Administrators' {
        $x = [xml]@'
<Groups>
  <Group name="Administrators (built-in)"><Properties action="U" groupSid="S-1-5-32-544" groupName="Administrators (built-in)">
    <Members>
      <Member name="FIRMA\helpdesk" action="ADD" sid="S-1-5-21-1-2-3-1105"/>
      <Member name="FIRMA\stary" action="REMOVE" sid="S-1-5-21-1-2-3-1106"/>
      <Member name="FIRMA\bezsid" action="ADD" sid=""/>
    </Members></Properties></Group>
  <Group name="Remote Desktop Users (built-in)"><Properties action="U" groupSid="S-1-5-32-555" groupName="Remote Desktop Users (built-in)">
    <Members><Member name="FIRMA\rdp" action="ADD" sid="S-1-5-21-1-2-3-1107"/></Members></Properties></Group>
</Groups>
'@
        $r = @(Get-GppLocalAdmin $x)
        ($r -join '|') | Should -Be 'S-1-5-21-1-2-3-1105|FIRMA\bezsid'
    }
}

# Testy regresyjne reguł o najwyższej wadze: przejęcie obiektów przez ACL (P-ACL-TIER0, D-ACL-*), szablony certyfikatów (ESC1-3, 9)
# i hasła w preferencjach GPO (D-GPP-PASSWORD). Pliki przykładowe w tests\fixtures zawierają wyłącznie dane fikcyjne.
Describe 'Regresja: niebezpieczne prawa w ACL (Get-AceDanger)' {
    BeforeAll {
        $R = [System.DirectoryServices.ActiveDirectoryRights]
        $allow = [System.Security.AccessControl.AccessControlType]::Allow
        $sid = [System.Security.Principal.SecurityIdentifier]'S-1-5-21-1-2-3-1105'
        function New-Ace($Rights, $Guid) {
            if ($Guid) { New-Object System.DirectoryServices.ActiveDirectoryAccessRule $sid, $Rights, $allow, ([guid]$Guid) }
            else { New-Object System.DirectoryServices.ActiveDirectoryAccessRule $sid, $Rights, $allow }
        }
    }
    It 'pełna kontrola, zmiana uprawnień i przejęcie własności' {
        # nazwa inna niż $r: zmienne nie rozróżniają wielkości liter, a $R to typ praw
        $full = @(Get-AceDanger (New-Ace $R::GenericAll $null))
        $full.Count | Should -Be 1
        $full[0] | Should -Match 'GenericAll'
        (@(Get-AceDanger (New-Ace $R::WriteDacl $null)) -join ';') | Should -Match 'WriteDacl'
        (@(Get-AceDanger (New-Ace $R::WriteOwner $null)) -join ';') | Should -Match 'WriteOwner'
    }
    It 'zapis atrybutów: member, gPLink, Shadow Credentials, RBCD, SPN, wszystkie atrybuty' {
        (@(Get-AceDanger (New-Ace $R::WriteProperty $aclGuid.Member)) -join ';') | Should -Match 'member'
        (@(Get-AceDanger (New-Ace $R::WriteProperty $aclGuid.GpLink)) -join ';') | Should -Match 'gPLink'
        (@(Get-AceDanger (New-Ace $R::WriteProperty $aclGuid.KeyCredLink)) -join ';') | Should -Match 'Shadow Credentials'
        (@(Get-AceDanger (New-Ace $R::WriteProperty $aclGuid.Rbcd)) -join ';') | Should -Match 'RBCD'
        (@(Get-AceDanger (New-Ace $R::WriteProperty $aclGuid.Spn)) -join ';') | Should -Match 'SPN'
        @(Get-AceDanger (New-Ace $R::WriteProperty $null)).Count | Should -Be 1
    }
    It 'prawa rozszerzone: reset hasła, replikacja haseł, wszystkie prawa' {
        @(Get-AceDanger (New-Ace $R::ExtendedRight $aclGuid.ForceChangePwd)).Count | Should -Be 1
        (@(Get-AceDanger (New-Ace $R::ExtendedRight $aclGuid.GetChangesAll)) -join ';') | Should -Match 'DCSync'
        (@(Get-AceDanger (New-Ace $R::ExtendedRight $null)) -join ';') | Should -Match 'DCSync'
    }
    It 'prawa nieszkodliwe nie są zgłaszane' {
        @(Get-AceDanger (New-Ace $R::GenericRead $null)).Count | Should -Be 0
        @(Get-AceDanger (New-Ace $R::ReadProperty $null)).Count | Should -Be 0
        # zapis pojedynczego, nieistotnego atrybutu (description) i samo Get-Changes
        @(Get-AceDanger (New-Ace $R::WriteProperty 'bf967950-0de6-11d0-a285-00aa003049e2')).Count | Should -Be 0
        @(Get-AceDanger (New-Ace $R::ExtendedRight $aclGuid.GetChanges)).Count | Should -Be 0
    }
}

Describe 'Regresja: szablony certyfikatów (ESC1, ESC2, ESC3, ESC9)' {
    BeforeAll {
        $clientAuth = '1.3.6.1.5.5.7.3.2'; $serverAuth = '1.3.6.1.5.5.7.3.1'; $agent = '1.3.6.1.4.1.311.20.2.1'; $anyPurpose = '2.5.29.37.0'
    }
    It 'ESC1: podmiot z żądania + logowanie, bez zatwierdzania' {
        $f = Get-TemplateEscFlag 1 0 0 @($clientAuth)
        $f.Open | Should -BeTrue
        $f.Esc1 | Should -BeTrue
        $f.Esc2 | Should -BeFalse
        $f.Esc3 | Should -BeFalse
        $f.Esc9 | Should -BeFalse
    }
    It 'zatwierdzanie przez menedżera CA lub podpis agenta zamyka szablon' {
        (Get-TemplateEscFlag 1 2 0 @($clientAuth)).Open | Should -BeFalse
        (Get-TemplateEscFlag 1 0 1 @($clientAuth)).Open | Should -BeFalse
    }
    It 'podmiot z żądania bez EKU do logowania nie jest ESC1' {
        $f = Get-TemplateEscFlag 1 0 0 @($serverAuth)
        $f.Esc1 | Should -BeFalse
        $f.Auth | Should -BeFalse
    }
    It 'ESC2: brak EKU lub Any Purpose (nadaje się też do logowania)' {
        $f = Get-TemplateEscFlag 0 0 0 @()
        $f.Esc2 | Should -BeTrue
        $f.Auth | Should -BeTrue
        $f.Esc1 | Should -BeFalse
        (Get-TemplateEscFlag 0 0 0 @($anyPurpose)).Esc2 | Should -BeTrue
        (Get-TemplateEscFlag 1 0 0 @($anyPurpose)).Esc1 | Should -BeTrue
    }
    It 'ESC3: certyfikat agenta rejestracji' {
        $f = Get-TemplateEscFlag 0 0 0 @($agent)
        $f.Esc3 | Should -BeTrue
        $f.Esc2 | Should -BeFalse
    }
    It 'ESC9: bez rozszerzenia SID + logowanie' {
        (Get-TemplateEscFlag 0 0x80000 0 @($clientAuth)).Esc9 | Should -BeTrue
        (Get-TemplateEscFlag 0 0x80000 0 @($serverAuth)).Esc9 | Should -BeFalse
        (Get-TemplateEscFlag 0 0 0 @($clientAuth)).Esc9 | Should -BeFalse
    }
    It 'Get-TemplateEnrollSid: Enroll, AutoEnroll, wszystkie prawa rozszerzone i pełna kontrola; bez odmów i innych praw' {
        $R = [System.DirectoryServices.ActiveDirectoryRights]
        $T = [System.Security.AccessControl.AccessControlType]
        $mk = { param($Rid, $Rights, $Type, $Guid)
            $s = [System.Security.Principal.SecurityIdentifier]"S-1-5-21-1-2-3-$Rid"
            if ($Guid) { New-Object System.DirectoryServices.ActiveDirectoryAccessRule $s, $Rights, $Type, ([guid]$Guid) }
            else { New-Object System.DirectoryServices.ActiveDirectoryAccessRule $s, $Rights, $Type } }
        $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $sd.AddAccessRule((& $mk 513  $R::ExtendedRight $T::Allow '0e10c968-78fb-11d2-90d4-00c04f79dc55'))   # Enroll
        $sd.AddAccessRule((& $mk 1106 $R::ExtendedRight $T::Allow 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'))   # AutoEnroll
        $sd.AddAccessRule((& $mk 1107 $R::GenericAll    $T::Allow $null))
        $sd.AddAccessRule((& $mk 1111 $R::ExtendedRight $T::Allow $null))                                    # wszystkie prawa rozszerzone
        $sd.AddAccessRule((& $mk 1108 $R::ExtendedRight $T::Deny  '0e10c968-78fb-11d2-90d4-00c04f79dc55'))   # odmowa
        $sd.AddAccessRule((& $mk 1109 $R::GenericRead   $T::Allow $null))
        $sd.AddAccessRule((& $mk 1110 $R::ExtendedRight $T::Allow $aclGuid.ForceChangePwd))                  # inne prawo rozszerzone
        $got = @(Get-TemplateEnrollSid $sd | Sort-Object)
        $exp = @('S-1-5-21-1-2-3-513', 'S-1-5-21-1-2-3-1106', 'S-1-5-21-1-2-3-1107', 'S-1-5-21-1-2-3-1111' | Sort-Object)
        ($got -join '|') | Should -Be ($exp -join '|')
        @(Get-TemplateEnrollSid $null).Count | Should -Be 0
    }
}

Describe 'Regresja: hasła w preferencjach GPO (D-GPP-PASSWORD)' {
    BeforeAll {
        function Read-Fixture([string]$Name) { [xml](Get-Content -LiteralPath (Join-Path $PSScriptRoot "fixtures\$Name") -Raw -Encoding UTF8) }
    }
    It 'Groups.xml: cpassword konta lokalnego; pusty cpassword pominięty' {
        $r = @(Get-GppPasswordEntry (Read-Fixture 'gpp-groups.xml') 'Groups.xml')
        $r.Count | Should -Be 1
        $r[0].Element | Should -Be 'lokalny-admin'
        $r[0].Konto | Should -Be 'lokalny-admin'
        $r[0].Typ | Should -Match '^cpassword'
    }
    It 'ScheduledTasks.xml: konto z atrybutu runAs' {
        $r = @(Get-GppPasswordEntry (Read-Fixture 'gpp-scheduledtasks.xml') 'ScheduledTasks.xml')
        $r.Count | Should -Be 1
        $r[0].Element | Should -Be 'Kopia'
        $r[0].Konto | Should -Be 'FIRMA\svc-kopia'
    }
    It 'Registry.xml: hasło autologowania, bez wartości hasła w wyniku' {
        $r = @(Get-GppPasswordEntry (Read-Fixture 'gpp-registry.xml') 'Registry.xml')
        $r.Count | Should -Be 1
        $r[0].Element | Should -Be 'DefaultPassword'
        $r[0].Typ | Should -Match 'DefaultPassword'
        (($r | ForEach-Object { $_.PSObject.Properties.Value }) -join ' ') | Should -Not -Match 'PrzykladoweHaslo'
    }
    It 'plik preferencji rejestru nie jest czytany jak plik z cpassword i odwrotnie' {
        @(Get-GppPasswordEntry (Read-Fixture 'gpp-registry.xml') 'Groups.xml').Count | Should -Be 0
        @(Get-GppPasswordEntry (Read-Fixture 'gpp-groups.xml') 'Registry.xml').Count | Should -Be 0
        @(Get-GppPasswordEntry $null 'Groups.xml').Count | Should -Be 0
    }
}

Describe 'Waga DC-TIME-SOURCE' {
    It 'zależy od problemu' {
        Get-NtpSourceSeverity 'zegar niezsynchronizowany (usługa czasu nie ma działającego źródła)' | Should -Be 'High'
        Get-NtpSourceSeverity 'zegar lokalny serwera (Local CMOS Clock) - brak zewnętrznego źródła czasu' | Should -Be 'Medium'
        Get-NtpSourceSeverity 'czas z hosta wirtualizacji (VM IC Time Synchronization Provider)' | Should -Be 'Low'
    }
}

# Warstwa raportu bez AD: funkcje i tabele ze skryptu, znaleziska z pliku przykładowego, a potem kod regionów
# "wynik: dane" i "wynik: pliki" wykonany tak jak w skrypcie.
Describe 'Raport z danych przykładowych (HTML, JSON, CSV)' {
    BeforeAll {
        foreach ($d in $defs) { . ([scriptblock]::Create($d.Extent.Text)) }
        $tables = 'Version', 'jsonSchemaVersion', 'weights', 'areaNames', 'ruleCatalog', 'nis2Names', 'isoNames', 'complianceMap', 'planMeta', 'planStages',
                  'sevLevel', 'mdiBase', 'mdiPages', 'mdiMap', 'checkLabels'
        $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                       $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] }, $false) |
            Where-Object { $_.Left.VariablePath.UserPath -in $tables } | ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }
        $ruleMeta = @{}
        foreach ($r in $ruleCatalog) { $ruleMeta[$r.Id] = $r }

        # Parametry i dane, które w skrypcie pochodzą z AD
        $Klient = 'KLIENT'; $Silent = $true; $History = $false; $Previous = $null; $prev = $null; $UseWinRM = $false; $SkipDCChecks = $false
        $MaxRows = 500; $MaxHistoryPoints = 24; $StaleDays = 90
        $OutDir = Join-Path $TestDrive 'raporty'
        $encOut = if ($PSVersionTable.PSVersion.Major -ge 6) { 'utf8BOM' } else { 'UTF8' }
        $now = [datetime]'2026-01-15T10:00:00'
        $runTimer = [System.Diagnostics.Stopwatch]::StartNew()
        $osLifecycleAsOf = '2026-11'; $patchRefDate = [datetime]'2026-10-13'
        $domain = [pscustomobject]@{ DNSRoot = 'firma.local'; NetBIOSName = 'FIRMA'; DomainMode = 'Windows2012R2Domain'; DistinguishedName = 'DC=firma,DC=local'
                                     PDCEmulator = 'dc1.firma.local'; RIDMaster = 'dc1.firma.local'; InfrastructureMaster = 'dc1.firma.local' }
        $forest = [pscustomobject]@{ Name = 'firma.local'; RootDomain = 'firma.local'; ForestMode = 'Windows2012R2Forest'; SchemaMaster = 'dc1.firma.local'; DomainNamingMaster = 'dc1.firma.local' }
        $pp = [pscustomobject]@{ MinPasswordLength = 8; ComplexityEnabled = $true; MaxPasswordAge = [timespan]::FromDays(90); PasswordHistoryCount = 24; LockoutThreshold = 5 }
        $dcs = @([pscustomobject]@{ Name = 'DC1'; HostName = 'dc1.firma.local'; OperatingSystem = 'Windows Server 2022 Standard'; Site = 'Default-First-Site-Name'
                                    IPv4Address = '10.0.0.10'; IsGlobalCatalog = $true; IsReadOnly = $false })
        $trusts = @(); $invPriv = @()
        $invOs = [System.Collections.Generic.List[object]]::new(); $invPatch = [System.Collections.Generic.List[object]]::new()
        $dcCompliance = [ordered]@{}; $dcMethod = 'pominięte'
        $ldapIdentity = 'FIRMA\audytor'; $runAsPriv = $false; $tokenFiltered = $false
        $ruleNote = @{}
        $checkKnown = [string[]]@(@($checkLabels.Keys | Where-Object { $_ -ne 'DC-GPO' }) + 'DC-PROBE')
        $checkInclude = [string[]]@(); $checkExclude = [string[]]@(); $partialRun = $false

        $findings = [System.Collections.Generic.List[object]]::new()
        $fx = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures\znaleziska.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($f in $fx.Znaleziska) {
            Add-Finding @{ Id = $f.Id; Category = $f.Category; Severity = $f.Severity; Title = $f.Title; Description = $f.Description
                           Recommendation = $f.Recommendation; Fix = $f.Fix; Mitre = $f.Mitre; Objects = @($f.Objects) }
        }

        $src = Get-Content -LiteralPath $scriptPath -Raw -Encoding UTF8
        $code = $src.Substring($src.IndexOf('#region ---------- wynik: dane'))
        $out = @(. ([scriptblock]::Create($code)))
        $res = $out | Where-Object { $_ -and $_.PSObject.Properties['Raport'] } | Select-Object -Last 1
        $html = if ($res) { Get-Content -LiteralPath $res.Raport -Raw -Encoding UTF8 } else { '' }
        $json = if ($res) { Get-Content -LiteralPath $res.Json -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
    }
    It 'każda reguła katalogu należy do testu z etykietą (-ListChecks, -IncludeCheck)' {
        $bad = @($ruleCatalog | Where-Object { $checkKnown -notcontains (Get-CheckKey $_.C $checkKnown) } | ForEach-Object { "$($_.Id) -> $($_.C)" })
        $bad | Should -BeNullOrEmpty
        @($ruleCatalog | Group-Object { $_.Id } | Where-Object Count -gt 1).Count | Should -Be 0
    }
    It 'tworzy pliki raportu i zwraca wynik (-Silent)' {
        $res | Should -Not -BeNullOrEmpty
        Test-Path -LiteralPath $res.Raport | Should -BeTrue
        Test-Path -LiteralPath $res.Json | Should -BeTrue
        Test-Path -LiteralPath $res.Csv | Should -BeTrue
        $res.Klient | Should -Be 'KLIENT'
        $res.KlasaEkspozycji | Should -Be 'E'
        $res.Critical | Should -Be 1
    }
    It 'HTML: znaleziska, kodowanie znaków specjalnych, bez ukrytych kolumn' {
        $html | Should -Match '<!DOCTYPE html>'
        $html.Contains('id="D-GPP-PASSWORD"') | Should -BeTrue
        $html.Contains('id="U-SIDHIST"') | Should -BeTrue
        $html.Contains('&lt;script&gt;alert(1)&lt;/script&gt;') | Should -BeTrue
        $html.Contains('<script>alert(1)') | Should -BeFalse
        $html.Contains('&lt;b&gt;pogrubienie&lt;/b&gt;') | Should -BeTrue
        $html.Contains('<th>_Id</th>') | Should -BeFalse
        $html.Contains('S-1-5-21-1111111111') | Should -BeFalse
        $html.Contains('j.kowalski') | Should -BeTrue
        $html.Contains('ocenione reguły:') | Should -BeTrue
    }
    It 'pewność wyniku: wartość domyślna i przekazana w znalezisku' {
        $before = $findings.Count
        Add-Finding @{ Id = 'DC-LDAPSIGN'; Category = 'Kontrolery domeny'; Severity = 'Medium'; Title = 'test'; Confidence = 'Niska'; ConfidenceNote = 'uwaga testowa' }
        $findings[$before].Pewnosc | Should -Be 'Niska'
        $findings[$before].PewnoscUwagi | Should -Be 'uwaga testowa'
        Add-Finding @{ Id = 'DC-LDAPCBT'; Category = 'Kontrolery domeny'; Severity = 'Medium'; Title = 'test' }
        $findings[$before + 1].Pewnosc | Should -Be 'Wysoka'
    }
    It 'JSON: wersja schematu, wynik, identyfikatory obiektów, statusy reguł' {
        $json.SchemaVersion | Should -Be $jsonSchemaVersion
        $json.Meta.Klient | Should -Be 'KLIENT'
        $json.Meta.Wynik | Should -Be 25
        $json.Meta.Czesciowy | Should -BeFalse
        $json.Meta.PokrycieObszarow.Anomalie.Razem | Should -BeGreaterThan 0
        @($json.Znaleziska | Where-Object Id -eq 'U-SIDHIST')[0].Pewnosc | Should -Be 'Wysoka'
        @($json.Znaleziska).Count | Should -Be 4
        @($json.Znaleziska | Where-Object Id -eq 'U-SIDHIST')[0].Objects[0]._Id | Should -Be 'S-1-5-21-1111111111-2222222222-3333333333-1105'
        @($json.Reguly | Where-Object Id -eq 'D-GPP-PASSWORD')[0].Status | Should -Be 'Znalezisko'
        @($json.Reguly).Count | Should -Be $ruleCatalog.Count
    }
    It 'CSV obiektów bez ukrytych kolumn' {
        $csv = Get-Content -LiteralPath ($res.Json -replace '\.json$', '_obiekty.csv') -Raw -Encoding UTF8
        $csv.Contains('j.kowalski') | Should -BeTrue
        $csv.Contains('_Id=') | Should -BeFalse
    }
}

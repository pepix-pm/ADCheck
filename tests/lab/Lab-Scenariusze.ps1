<#
.SYNOPSIS
    Tworzy (lub usuwa) przypadki testowe ADCheck w domenie LABORATORYJNEJ.

.DESCRIPTION
    TYLKO DLA DOMENY TESTOWEJ. Skrypt ZMIENIA Active Directory, GPO i SYSVOL - nie uruchamiać w domenie produkcyjnej.
    Zabezpieczenia: wymaga podania nazwy domeny (-Domena) zgodnej z bieżącą domeną, odmawia działania,
    gdy domena ma więcej niż 50 kont użytkowników, i prosi o przepisanie nazwy domeny przed zmianą.

    Uruchamiać na kontrolerze domeny laboratorium kontem administratora domeny (moduły ActiveDirectory i GroupPolicy).
    Oczekiwane wyniki ADCheck dla każdego przypadku: tests/lab/INSTRUKCJA.md.

.PARAMETER Domena
    Nazwa DNS domeny laboratoryjnej, np. lab.local.

.PARAMETER Usun
    Usuwa wszystko, co skrypt utworzył (konta, grupę, OU, GPO, wpisy ACL, łącza).

.PARAMETER BezSysvol
    Pomija przypadki 5 i 6 (usuwanie folderów GPO z SYSVOL).

.NOTES
    -Usun wyłącza też konto Gość (przypadek 21), niezależnie od jego stanu sprzed skryptu.

.EXAMPLE
    .\Lab-Scenariusze.ps1 -Domena lab.local
    .\Lab-Scenariusze.ps1 -Domena lab.local -Usun
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Domena,
    [switch]$Usun,
    [switch]$BezSysvol
)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory, GroupPolicy

$dom = Get-ADDomain
if ($dom.DNSRoot -ne $Domena) { throw "Bieżąca domena to $($dom.DNSRoot), a podano $Domena - przerwano." }
$users = @(Get-ADUser -Filter * -ResultSetSize 51).Count
if ($users -gt 50) { throw "Domena ma ponad 50 kont użytkowników - to nie wygląda na laboratorium. Przerwano." }
$potw = Read-Host "Skrypt ZMIENI domenę $Domena (laboratorium). Przepisz nazwę domeny, aby kontynuować"
if ($potw -ne $Domena) { throw 'Nazwa się nie zgadza - przerwano.' }

$ouName  = 'ADCheck-Lab'
$ouDn    = "OU=$ouName,$($dom.DistinguishedName)"
$rootAd  = "AD:\$($dom.DistinguishedName)"
$sidDom  = $dom.DomainSID.Value
$guidAll = [guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'   # DS-Replication-Get-Changes-All
$guidGet = [guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'   # DS-Replication-Get-Changes
$gpoNames = 'ADCheck-Lab LLMNR', 'ADCheck-Lab Stare lacze', 'ADCheck-Lab Bez folderu', 'ADCheck-Lab DC bez folderu', 'ADCheck-Lab GPP', 'ADCheck-Lab DC edycja'
$ashAd   = "AD:\CN=AdminSDHolder,CN=System,$($dom.DistinguishedName)"
$psoName = 'ADCheck-Lab PSO'
$dcComp  = Get-ADComputer $dom.PDCEmulator.Split('.')[0] -Properties PrincipalsAllowedToDelegateToAccount

# Natychmiastowy przebieg SDProp (kopiuje ACL z AdminSDHolder na konta uprzywilejowane; domyślnie co 60 min)
function Invoke-SdProp {
    $r = [ADSI]"LDAP://$($dom.PDCEmulator)/RootDSE"
    $r.Put('runProtectAdminGroupsTask', 1); $r.SetInfo()
}
function Add-LabSpn($Account, [string]$Spn) {
    if (@((Get-ADUser $Account -Properties servicePrincipalName).servicePrincipalName) -notcontains $Spn) { Set-ADUser $Account -ServicePrincipalNames @{ Add = $Spn } }
}

function Remove-LabAce([string]$Name, [string]$Path = $rootAd) {
    $obj = Get-ADObject -Filter "sAMAccountName -eq '$Name'" -Properties objectSid
    if (-not $obj) { return }
    $acl = Get-Acl $Path
    foreach ($r in @($acl.Access)) {
        $sid = try { $r.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $null }
        if ($sid -eq $obj.objectSid.Value) { [void]$acl.RemoveAccessRule($r) }
    }
    Set-Acl $Path $acl
}

if ($Usun) {
    foreach ($n in 'lab-dcsync-niepelny', 'lab-dcsync-pelny', 'lab-repl-grupa') { Remove-LabAce $n }
    # Przypadek 23: wpis na AdminSDHolder (SDProp usunie kopie z kont uprzywilejowanych w ciągu ok. 60 min)
    Remove-LabAce 'lab-zwykly' $ashAd
    Invoke-SdProp
    # Przypadek 18: RBCD na DC - czyszczone tylko, gdy wskazuje wyłącznie konto laboratorium
    $srv = Get-ADComputer -Filter "sAMAccountName -eq 'LAB-SRV2008$'"
    if ($srv -and @($dcComp.PrincipalsAllowedToDelegateToAccount).Count -eq 1 -and $dcComp.PrincipalsAllowedToDelegateToAccount[0] -eq $srv.DistinguishedName) {
        Set-ADComputer $dcComp -PrincipalsAllowedToDelegateToAccount $null
    }
    # Przypadek 24: PSO
    if (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$psoName'") {
        Set-ADFineGrainedPasswordPolicy $psoName -ProtectedFromAccidentalDeletion $false
        Remove-ADFineGrainedPasswordPolicy $psoName -Confirm:$false
    }
    # Przypadek 21: konto Gość z powrotem wyłączone
    Disable-ADAccount -Identity "$sidDom-501"
    foreach ($g in $gpoNames) {
        $gpo = Get-GPO -Name $g -ErrorAction SilentlyContinue
        if (-not $gpo) { continue }
        foreach ($t in $ouDn, $dom.DomainControllersContainer) { Remove-GPLink -Guid $gpo.Id -Target $t -ErrorAction SilentlyContinue | Out-Null }
        # GPO bez folderu w SYSVOL (przypadki 5 i 6) - Remove-GPO może zgłosić błąd, wtedy usuwamy sam obiekt w AD
        try { Remove-GPO -Guid $gpo.Id -ErrorAction Stop }
        catch { Remove-ADObject "CN={$($gpo.Id)},CN=Policies,CN=System,$($dom.DistinguishedName)" -Recursive -Confirm:$false }
    }
    $pg = Get-ADUser -Filter "sAMAccountName -eq 'lab-pgid512'"
    if ($pg) {
        Add-ADGroupMember -Identity "$sidDom-513" -Members $pg -ErrorAction SilentlyContinue
        Set-ADUser $pg -Replace @{ primaryGroupID = 513 }
    }
    if (Get-ADOrganizationalUnit -Filter "distinguishedName -eq '$ouDn'") {
        Set-ADOrganizationalUnit $ouDn -ProtectedFromAccidentalDeletion $false
        Remove-ADOrganizationalUnit $ouDn -Recursive -Confirm:$false
    }
    Write-Host 'Usunięto przypadki testowe ADCheck-Lab.' -ForegroundColor Green
    return
}

function Get-LabGpo([string]$Name) {
    $g = Get-GPO -Name $Name -ErrorAction SilentlyContinue
    if ($g) { $g } else { New-GPO -Name $Name }
}

# --- OU, konta i grupa ---
if (-not (Get-ADOrganizationalUnit -Filter "distinguishedName -eq '$ouDn'")) {
    New-ADOrganizationalUnit -Name $ouName -Path $dom.DistinguishedName -ProtectedFromAccidentalDeletion $false
}
function New-LabUser([string]$Name) {
    if (-not (Get-ADUser -Filter "sAMAccountName -eq '$Name'")) {
        $pw = ConvertTo-SecureString ([guid]::NewGuid().ToString() + 'Aa1!') -AsPlainText -Force
        New-ADUser -Name $Name -SamAccountName $Name -Path $ouDn -AccountPassword $pw -Enabled $true
    }
    Get-ADUser $Name
}
$uNiepelny = New-LabUser 'lab-dcsync-niepelny'
$uPelny    = New-LabUser 'lab-dcsync-pelny'
$uPg       = New-LabUser 'lab-pgid512'
if (-not (Get-ADGroup -Filter "sAMAccountName -eq 'lab-repl-grupa'")) {
    New-ADGroup -Name 'lab-repl-grupa' -SamAccountName 'lab-repl-grupa' -GroupScope Global -Path $ouDn
}
$gRepl = Get-ADGroup 'lab-repl-grupa'
Add-ADGroupMember $gRepl -Members $uPelny

# Konto do przeglądu zwykłym kontem (przebieg B) - hasło podaje osoba testująca
if (-not (Get-ADUser -Filter "sAMAccountName -eq 'lab-zwykly'")) {
    $pw = Read-Host 'Hasło dla konta lab-zwykly (zwykłe konto do przebiegu B)' -AsSecureString
    New-ADUser -Name 'lab-zwykly' -SamAccountName 'lab-zwykly' -Path $ouDn -AccountPassword $pw -Enabled $true
}

# --- Przypadek 1 i 2: prawa replikacji na obiekcie domeny ---
$acl = Get-Acl $rootAd
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule($uNiepelny.SID, 'ExtendedRight', 'Allow', $guidAll)))
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule($gRepl.SID, 'ExtendedRight', 'Allow', $guidGet)))
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule($uPelny.SID, 'ExtendedRight', 'Allow', $guidAll)))
Set-Acl $rootAd $acl

# --- Przypadek 3: grupa podstawowa Domain Admins (primaryGroupID=512) ---
Add-ADGroupMember -Identity "$sidDom-512" -Members $uPg
Set-ADUser $uPg -Replace @{ primaryGroupID = 512 } -PasswordNeverExpires $true

# --- Przypadek 4: LLMNR wyłączony tylko w GPO podlinkowanym do OU ---
$gL = Get-LabGpo 'ADCheck-Lab LLMNR'
Set-GPRegistryValue -Guid $gL.Id -Key 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient' -ValueName EnableMulticast -Type DWord -Value 0 | Out-Null
New-GPLink -Guid $gL.Id -Target $ouDn -ErrorAction SilentlyContinue | Out-Null

# Nieaktualne łącze: GPO usunięte, łącze w gPLink zostaje
$gS = New-GPO -Name 'ADCheck-Lab Stare lacze'
New-GPLink -Guid $gS.Id -Target $ouDn | Out-Null
Remove-GPO -Guid $gS.Id -KeepLinks

if (-not $BezSysvol) {
    $sysvol = "\\$($dom.PDCEmulator)\SYSVOL\$($dom.DNSRoot)\Policies"
    # --- Przypadek 5: podlinkowane GPO bez folderu w SYSVOL (OU testowe) ---
    $gB = Get-LabGpo 'ADCheck-Lab Bez folderu'
    New-GPLink -Guid $gB.Id -Target $ouDn -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -LiteralPath "$sysvol\{$($gB.Id)}" -Recurse -Force -ErrorAction SilentlyContinue
    # --- Przypadek 6: GPO podlinkowane do OU Domain Controllers bez folderu w SYSVOL ---
    $gD = Get-LabGpo 'ADCheck-Lab DC bez folderu'
    New-GPLink -Guid $gD.Id -Target $dom.DomainControllersContainer -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -LiteralPath "$sysvol\{$($gD.Id)}" -Recurse -Force -ErrorAction SilentlyContinue
}

# --- Przypadek 11: konto bez preautentykacji Kerberos (AS-REP roasting) ---
$u = New-LabUser 'lab-asrep'
Set-ADAccountControl $u -DoesNotRequirePreAuth $true

# --- Przypadek 12 i 12a: konto usługi z SPN (nowe hasło - nie powinno trafić do U-SPN-WEAK) i SPN na koncie administratora ---
$u = New-LabUser 'lab-svc'
Add-LabSpn $u "HTTP/lab-svc.$($dom.DNSRoot)"
Add-LabSpn $uPg "HTTP/lab-pgid512.$($dom.DNSRoot)"

# --- Przypadek 13: flagi kont: hasło niewymagane, odwracalne szyfrowanie, tylko DES ---
$u = New-LabUser 'lab-flagi'
Set-ADAccountControl $u -PasswordNotRequired $true -AllowReversiblePasswordEncryption $true -UseDESKeyOnly $true

# --- Przypadek 14 i 15: użytkownik z delegacją nieograniczoną; konto z adminCount=1 poza grupami uprzywilejowanymi ---
$u = New-LabUser 'lab-deleg'
Set-ADAccountControl $u -TrustedForDelegation $true
$u = New-LabUser 'lab-admincount'
Set-ADUser $u -Replace @{ adminCount = 1 }

# --- Przypadek 16 i 17: komputery z systemem bez wsparcia, delegacją nieograniczoną i RBCD ---
function New-LabComputer([string]$Name, [string]$Os, [string]$OsVer) {
    if (-not (Get-ADComputer -Filter "sAMAccountName -eq '$Name$'")) {
        New-ADComputer -Name $Name -SamAccountName "$Name$" -Path $ouDn -OperatingSystem $Os -OperatingSystemVersion $OsVer -Enabled $true
    }
    Get-ADComputer $Name
}
$cSrv = New-LabComputer 'LAB-SRV2008' 'Windows Server 2008 R2 Standard' '6.1 (7601)'
Set-ADAccountControl $cSrv -TrustedForDelegation $true
$cW10 = New-LabComputer 'LAB-W10' 'Windows 10 Pro' '10.0 (19045)'
Set-ADComputer $cW10 -PrincipalsAllowedToDelegateToAccount $cSrv

# --- Przypadek 18: RBCD na koncie DC (tylko gdy atrybut jest pusty - nie nadpisujemy istniejącej konfiguracji) ---
if (-not @($dcComp.PrincipalsAllowedToDelegateToAccount).Count) {
    Set-ADComputer $dcComp -PrincipalsAllowedToDelegateToAccount $cSrv
} else {
    Write-Host 'Przypadek 18 pominięty: konto DC ma już ustawione RBCD.' -ForegroundColor Yellow
}

# --- Przypadek 19: członkostwo w Backup Operators przez zagnieżdżoną grupę ---
if (-not (Get-ADGroup -Filter "sAMAccountName -eq 'lab-operatorzy'")) {
    New-ADGroup -Name 'lab-operatorzy' -SamAccountName 'lab-operatorzy' -GroupScope Global -Path $ouDn
}
$gOps = Get-ADGroup 'lab-operatorzy'
$uBak = New-LabUser 'lab-backup'
Add-ADGroupMember $gOps -Members $uBak
Add-ADGroupMember -Identity 'S-1-5-32-551' -Members $gOps   # Backup Operators (po SID - nazwa bywa spolszczona)

# --- Przypadek 20: hasła w preferencjach GPO (SYSVOL); wartości fikcyjne, nie są prawdziwymi hasłami ---
$gG = Get-LabGpo 'ADCheck-Lab GPP'
$gppRoot = "\\$($dom.PDCEmulator)\SYSVOL\$($dom.DNSRoot)\Policies\{$($gG.Id)}\Machine\Preferences"
New-Item -ItemType Directory -Force -Path "$gppRoot\Groups", "$gppRoot\Registry" | Out-Null
Set-Content -LiteralPath "$gppRoot\Groups\Groups.xml" -Encoding UTF8 -Value @'
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="lab-lokalny" image="2" changed="2026-11-10 10:00:00" uid="{8D2D2B6E-4C1B-4C59-9E3E-0A1F2B3C4D5E}"><Properties action="U" newName="" fullName="" description="ADCheck-Lab" cpassword="QURDaGVjay1MYWItZmlrY3lqbmU=" changeLogon="0" noChange="0" neverExpires="1" acctDisabled="0" userName="lab-lokalny"/></User></Groups>
'@
Set-Content -LiteralPath "$gppRoot\Registry\Registry.xml" -Encoding UTF8 -Value @'
<?xml version="1.0" encoding="utf-8"?>
<RegistrySettings clsid="{A3CCFC41-DFDB-43a5-8D26-0FE8B954DA51}"><Registry clsid="{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}" name="DefaultPassword" status="DefaultPassword" image="7" changed="2026-11-10 10:00:00" uid="{1A2B3C4D-5E6F-4A1B-9C2D-3E4F5A6B7C8D}"><Properties action="U" displayDecimal="0" default="0" hive="HKEY_LOCAL_MACHINE" key="SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" name="DefaultPassword" type="REG_SZ" value="ADCheck-Lab-fikcyjne"/></Registry></RegistrySettings>
'@

# --- Przypadek 21: włączone konto Gość ---
Enable-ADAccount -Identity "$sidDom-501"

# --- Przypadek 22 i 23: GPO podlinkowane do OU Domain Controllers z prawem edycji dla zwykłego konta; wpis zwykłego konta na AdminSDHolder ---
$gE = Get-LabGpo 'ADCheck-Lab DC edycja'
New-GPLink -Guid $gE.Id -Target $dom.DomainControllersContainer -ErrorAction SilentlyContinue | Out-Null
Set-GPPermission -Guid $gE.Id -TargetName 'lab-zwykly' -TargetType User -PermissionLevel GpoEdit | Out-Null
$uZw = Get-ADUser 'lab-zwykly'
$acl = Get-Acl $ashAd
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule($uZw.SID, 'GenericWrite', 'Allow')))
Set-Acl $ashAd $acl
Invoke-SdProp

# --- Przypadek 24: PSO słabsze od polityki domeny, obejmujące grupę uprzywilejowaną (przez Backup Operators) ---
if (-not (Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$psoName'")) {
    New-ADFineGrainedPasswordPolicy -Name $psoName -Precedence 10 -MinPasswordLength 4 -ComplexityEnabled $false -LockoutThreshold 0 `
        -MaxPasswordAge '42.00:00:00' -MinPasswordAge '1.00:00:00' -PasswordHistoryCount 0 -ReversibleEncryptionEnabled $false -ProtectedFromAccidentalDeletion $false
}
Add-ADFineGrainedPasswordPolicySubject $psoName -Subjects $gOps

# --- Przypadek 25: zwykłe konto jako właściciel OU, GPO, grupy, konta i komputera (obiekty zakładane zwykłym kontem) ---
$ouOwn = "OU=ADCheck-Lab Wlasciciel,$ouDn"
if (-not (Get-ADOrganizationalUnit -Filter "distinguishedName -eq '$ouOwn'")) {
    New-ADOrganizationalUnit -Name 'ADCheck-Lab Wlasciciel' -Path $ouDn -ProtectedFromAccidentalDeletion $false
}
if (-not (Get-ADGroup -Filter "sAMAccountName -eq 'lab-wlasc-grupa'")) {
    New-ADGroup -Name 'lab-wlasc-grupa' -SamAccountName 'lab-wlasc-grupa' -GroupScope Global -Path $ouOwn
}
$uOwnTarget = New-LabUser 'lab-wlasc-konto'
$cOwnTarget = New-LabComputer 'LAB-WLASC-PC' 'Windows 11 Pro' '10.0 (26100)'
foreach ($dn in $ouOwn, (Get-ADGroup 'lab-wlasc-grupa').DistinguishedName, $uOwnTarget.DistinguishedName, $cOwnTarget.DistinguishedName,
                "CN={$($gL.Id)},CN=Policies,CN=System,$($dom.DistinguishedName)") {
    try {
        $a = Get-Acl "AD:\$dn"
        $a.SetOwner($uZw.SID)
        Set-Acl "AD:\$dn" $a
    } catch { Write-Host "Przypadek 25: nie ustawiono właściciela $dn - $($_.Exception.Message)" -ForegroundColor Yellow }
}

Write-Host 'Utworzono przypadki testowe. Oczekiwane wyniki: tests/lab/INSTRUKCJA.md.' -ForegroundColor Green
Write-Host "Po testach: .\Lab-Scenariusze.ps1 -Domena $Domena -Usun" -ForegroundColor Yellow

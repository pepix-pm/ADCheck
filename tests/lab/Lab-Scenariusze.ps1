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
$gpoNames = 'ADCheck-Lab LLMNR', 'ADCheck-Lab Stare lacze', 'ADCheck-Lab Bez folderu', 'ADCheck-Lab DC bez folderu'

function Remove-LabAce([string]$Name) {
    $obj = Get-ADObject -Filter "sAMAccountName -eq '$Name'" -Properties objectSid
    if (-not $obj) { return }
    $acl = Get-Acl $rootAd
    foreach ($r in @($acl.Access)) {
        $sid = try { $r.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $null }
        if ($sid -eq $obj.objectSid.Value) { [void]$acl.RemoveAccessRule($r) }
    }
    Set-Acl $rootAd $acl
}

if ($Usun) {
    foreach ($n in 'lab-dcsync-niepelny', 'lab-dcsync-pelny', 'lab-repl-grupa') { Remove-LabAce $n }
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

Write-Host 'Utworzono przypadki testowe. Oczekiwane wyniki: tests/lab/INSTRUKCJA.md.' -ForegroundColor Green
Write-Host "Po testach: .\Lab-Scenariusze.ps1 -Domena $Domena -Usun" -ForegroundColor Yellow

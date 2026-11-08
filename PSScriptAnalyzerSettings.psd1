# Ustawienia PSScriptAnalyzer dla ADCheck (CI i VS Code).
# Uruchomienie: Invoke-ScriptAnalyzer -Path .\ADCheck.ps1 -Settings .\PSScriptAnalyzerSettings.psd1 -Severity Warning,Error
@{
    ExcludeRules = @(
        # Nazwy funkcji wewnętrznych skryptu (np. Get-DangerousAces) - nie są eksportowane jako cmdlety
        'PSUseSingularNouns'
        # Write-Host celowo: kolorowe komunikaty postępu w konsoli, wyłączane przez -Silent (Write-Step)
        'PSAvoidUsingWriteHost'
        # Fałszywe alarmy: Invoke-Command -ArgumentList z param() w scriptblocku (zmienne nie pochodzą z zakresu zewnętrznego)
        'PSUseUsingScopeModifierInNewRunspaces'
    )
}

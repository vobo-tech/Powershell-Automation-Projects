Set-StrictMode -Version Latest

# --- Load the implementation into module scope ---
# Dot-sourcing defines helpers and commands in this module, where they can share script-scoped state.
$privateFiles = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -File | Sort-Object Name)
$publicFiles = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -File | Sort-Object Name)

foreach ($file in @($privateFiles) + @($publicFiles)) {
    . $file.FullName
}

# --- Publish only the workflow commands ---
Export-ModuleMember -Function @(
    'Import-ADIdentityConfig'
    'Get-ADIdentitySnapshot'
    'New-ADOffboardingPlan'
    'Test-ADOffboardingPlan'
    'Invoke-ADOffboardingPlan'
    'Test-ADOffboardingResult'
    'Export-ADIdentityReport'
)

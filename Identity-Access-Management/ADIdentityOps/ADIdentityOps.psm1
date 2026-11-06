Set-StrictMode -Version Latest

$privateFiles = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -File | Sort-Object Name)
$publicFiles = @(Get-ChildItem -Path (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -File | Sort-Object Name)

foreach ($file in @($privateFiles) + @($publicFiles)) {
    . $file.FullName
}

Export-ModuleMember -Function @(
    'Import-ADIdentityConfig'
    'Get-ADIdentitySnapshot'
    'New-ADOffboardingPlan'
    'Test-ADOffboardingPlan'
    'Invoke-ADOffboardingPlan'
    'Test-ADOffboardingResult'
    'Export-ADIdentityReport'
)

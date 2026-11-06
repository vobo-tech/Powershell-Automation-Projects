@{
    RootModule            = 'ADIdentityOps.psm1'
    ModuleVersion         = '0.1.0'
    GUID                  = '5d0f6f0e-3c4b-4d7e-9a57-6f1f2b7d9a31'
    Author                = 'Powershell-Automation-Projects contributors'
    Description           = 'AD Identity Operations Toolkit (pre-release): read-only identity snapshots, reviewable offboarding plans, controlled execution, verification, and evidence reports.'
    PowerShellVersion     = '5.1'
    CompatiblePSEditions  = @('Desktop', 'Core')
    FunctionsToExport     = @(
        'Import-ADIdentityConfig'
        'Get-ADIdentitySnapshot'
        'New-ADOffboardingPlan'
        'Test-ADOffboardingPlan'
        'Invoke-ADOffboardingPlan'
        'Test-ADOffboardingResult'
        'Export-ADIdentityReport'
    )
    CmdletsToExport       = @()
    VariablesToExport     = @()
    AliasesToExport       = @()
    PrivateData           = @{ PSData = @{ Tags = @('ActiveDirectory', 'Offboarding', 'IdentityGovernance'); ProjectUri = 'https://github.com/buffnerd/Powershell-Automation-Projects' } }
}

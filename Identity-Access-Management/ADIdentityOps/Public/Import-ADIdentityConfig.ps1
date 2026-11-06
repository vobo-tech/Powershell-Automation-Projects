function Import-ADIdentityConfig {
    <#
    .SYNOPSIS
        Reads and validates an AD identity toolkit configuration file.

    .DESCRIPTION
        Throws a terminating error listing every validation problem. Returns a normalized configuration
        object including a Fingerprint over the security-relevant settings (not the output paths).
        See Config\ADIdentityOps.example.json. Use only synthetic values in examples; keep real
        configuration out of source control.

    .PARAMETER Path
        Path to the JSON configuration file.

    .OUTPUTS
        A validated configuration object with a recomputed security-settings fingerprint.

    .EXAMPLE
        $cfg = Import-ADIdentityConfig -Path .\ADIdentityOps.json
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Path)
    Resolve-ADIdentityConfig -Config $Path
}

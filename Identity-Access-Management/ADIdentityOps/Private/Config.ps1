function Test-ADIdentityConfigObject {
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)]$Config)

    $errors = New-Object System.Collections.Generic.List[string]
    $allowed = 'SchemaVersion', 'DomainController', 'AllowedSourceOUs', 'QuarantineOU', 'ProtectedAccounts', 'ProtectedGroups', 'GroupRemovalExclusions', 'PlanLifetimeHours', 'Output', 'Fingerprint'
    $names = @($Config.PSObject.Properties | ForEach-Object { $_.Name })

    foreach ($n in $names) { if ($allowed -notcontains $n -and $n -notlike '_*') { $errors.Add("Unknown configuration key '$n'.") } }
    foreach ($n in 'SchemaVersion', 'DomainController', 'AllowedSourceOUs', 'QuarantineOU', 'ProtectedAccounts', 'ProtectedGroups', 'GroupRemovalExclusions', 'Output') {
        if ($names -notcontains $n) { $errors.Add("Missing required key '$n'.") }
    }
    if ($errors.Count -gt 0) { return $errors.ToArray() }

    if ([string]$Config.SchemaVersion -ne '1.0') { $errors.Add("Unsupported SchemaVersion '$($Config.SchemaVersion)'. Expected '1.0'.") }

    $dc = [string]$Config.DomainController
    if ($dc -notmatch '^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$') { $errors.Add('DomainController must be an explicit host name (no wildcards, no URL, no empty value).') }

    $ous = @($Config.AllowedSourceOUs)
    if ($ous.Count -eq 0) { $errors.Add('AllowedSourceOUs must contain at least one OU distinguished name.') }
    foreach ($o in $ous) {
        if ((Get-IdentifierKind -Value ([string]$o)) -ne 'dn' -or ([string]$o) -notmatch '^(?i)OU=') { $errors.Add("AllowedSourceOUs entry '$o' must be an OU distinguished name.") }
    }

    $q = [string]$Config.QuarantineOU
    if ((Get-IdentifierKind -Value $q) -ne 'dn' -or $q -notmatch '^(?i)OU=') {
        $errors.Add('QuarantineOU must be an OU distinguished name.')
    }
    else {
        foreach ($o in $ous) {
            if ((Get-IdentifierKind -Value ([string]$o)) -eq 'dn' -and (Test-DnUnderOu -Dn $q -OuDn ([string]$o))) {
                $errors.Add("QuarantineOU must not be inside an allowed source OU ('$o'); moved accounts would remain in scope.")
            }
        }
    }

    foreach ($key in 'ProtectedAccounts', 'ProtectedGroups', 'GroupRemovalExclusions') {
        foreach ($v in @($Config.$key)) {
            $kind = Get-IdentifierKind -Value ([string]$v)
            if ($kind -notin 'guid', 'sid', 'dn') { $errors.Add("$key entry '$v' must be an ObjectGUID, SID, or distinguished name (names are ambiguous).") }
        }
    }
    if (@($Config.ProtectedAccounts).Count + @($Config.ProtectedGroups).Count -eq 0) {
        $errors.Add('Configure at least one protected account or protected group (for example privileged group SIDs).')
    }

    if ($names -contains 'PlanLifetimeHours') {
        $h = 0
        if (-not [int]::TryParse([string]$Config.PlanLifetimeHours, [ref]$h) -or $h -lt 1 -or $h -gt 72) { $errors.Add('PlanLifetimeHours must be an integer from 1 to 72.') }
    }

    $out = $Config.Output
    foreach ($n in 'PlanDirectory', 'ResultDirectory', 'ReportDirectory') {
        if ($null -eq $out -or @($out.PSObject.Properties.Name) -notcontains $n -or [string]::IsNullOrWhiteSpace([string]$out.$n)) { $errors.Add("Output.$n is required.") }
    }
    $errors.ToArray()
}

function Get-ADIdentityConfigFingerprint {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)]$Config)
    $norm = {
        param($list)
        $items = @(@($list) | ForEach-Object { ConvertTo-NormalizedIdentifier -Value ([string]$_) } | Sort-Object -Unique)
        , $items
    }
    $material = [ordered]@{
        SchemaVersion          = [string]$Config.SchemaVersion
        DomainController       = ([string]$Config.DomainController).ToLowerInvariant()
        AllowedSourceOUs       = (& $norm $Config.AllowedSourceOUs)
        QuarantineOU           = ConvertTo-NormalizedIdentifier -Value ([string]$Config.QuarantineOU)
        ProtectedAccounts      = (& $norm $Config.ProtectedAccounts)
        ProtectedGroups        = (& $norm $Config.ProtectedGroups)
        GroupRemovalExclusions = (& $norm $Config.GroupRemovalExclusions)
    }
    Get-Sha256Hex -Text (ConvertTo-CanonicalJson -InputObject $material)
}

function Resolve-ADIdentityConfig {
    <#
    .SYNOPSIS
        Accepts a config path or object, validates it, and returns a normalized config with a recomputed fingerprint.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)]$Config)

    $raw = $Config
    if ($Config -is [string]) { $raw = Read-JsonFile -Path $Config }
    elseif ($null -eq $Config -or $Config -isnot [psobject]) { throw 'Config must be a path or a configuration object.' }

    $problems = @(Test-ADIdentityConfigObject -Config $raw)
    if ($problems.Count -gt 0) { throw ("Invalid AD identity configuration:`n - " + ($problems -join "`n - ")) }

    $lifetime = 24
    if (@($raw.PSObject.Properties.Name) -contains 'PlanLifetimeHours') { $lifetime = [int]$raw.PlanLifetimeHours }

    [pscustomobject][ordered]@{
        SchemaVersion          = [string]$raw.SchemaVersion
        DomainController       = [string]$raw.DomainController
        AllowedSourceOUs       = @(@($raw.AllowedSourceOUs) | ForEach-Object { [string]$_ })
        QuarantineOU           = [string]$raw.QuarantineOU
        ProtectedAccounts      = @(@($raw.ProtectedAccounts) | ForEach-Object { [string]$_ })
        ProtectedGroups        = @(@($raw.ProtectedGroups) | ForEach-Object { [string]$_ })
        GroupRemovalExclusions = @(@($raw.GroupRemovalExclusions) | ForEach-Object { [string]$_ })
        PlanLifetimeHours      = $lifetime
        Output                 = [pscustomobject][ordered]@{
            PlanDirectory   = [string]$raw.Output.PlanDirectory
            ResultDirectory = [string]$raw.Output.ResultDirectory
            ReportDirectory = [string]$raw.Output.ReportDirectory
        }
        Fingerprint            = Get-ADIdentityConfigFingerprint -Config $raw
    }
}

function Get-ADIdentitySnapshot {
    <#
    .SYNOPSIS
        Collects a read-only identity snapshot for one user account.

    .DESCRIPTION
        Resolves the account once and records stable identifiers (ObjectGUID, SID), state, direct
        group memberships, and nested (inherited) membership paths. Matches are evaluated against the
        configured protected accounts/groups and allowed source OUs.

        This command performs only read operations. Collection failures are recorded in
        Collection.Errors and set Collection.IsComplete to $false; callers (planning, execution)
        treat an incomplete snapshot as unsafe.

        Group membership is not proof of effective access, and no logon timestamps are collected:
        lastLogonTimestamp is replicated approximately and is not evidence of inactivity.

    .PARAMETER Identity
        ObjectGUID, SID, distinguished name, or sAMAccountName. Use the ObjectGUID for repeat lookups.

    .PARAMETER Config
        Path to a configuration file, or a configuration object (see Import-ADIdentityConfig).

    .PARAMETER MaxNestingDepth
        Maximum group nesting depth to follow. Exceeding it marks the snapshot incomplete.

    .EXAMPLE
        $snap = Get-ADIdentitySnapshot -Identity 'a1b2c3d4-0000-0000-0000-000000000001' -Config .\ADIdentityOps.json
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][ValidateNotNullOrEmpty()][string]$Identity,
        [Parameter(Mandatory)]$Config,
        [ValidateRange(1, 20)][int]$MaxNestingDepth = 10
    )
    process {
        Assert-ADCommand
        $cfg = Resolve-ADIdentityConfig -Config $Config
        $server = $cfg.DomainController
        $errors = New-Object System.Collections.Generic.List[string]

        $props = 'ObjectGUID', 'SID', 'DistinguishedName', 'SamAccountName', 'UserPrincipalName', 'Enabled', 'Department', 'Manager', 'MemberOf', 'AdminCount', 'PrimaryGroupID', 'ObjectClass'
        try { $u = Get-ADUser -Identity $Identity -Server $server -Properties $props -ErrorAction Stop }
        catch { throw "Unable to resolve identity on '$server': $(Get-SanitizedText -Text $_.Exception.Message)" }
        if ($null -eq $u) { throw "Identity did not resolve to a user on '$server'." }
        if ([string](Get-ObjectProperty $u 'ObjectClass') -ne 'user') { throw "Identity resolved to object class '$(Get-ObjectProperty $u 'ObjectClass')', not 'user'." }

        $userDn = ConvertTo-IdString (Get-ObjectProperty $u 'DistinguishedName')
        $enabled = Get-ObjectProperty $u 'Enabled'
        if ($null -eq $enabled) { $errors.Add('Enabled state could not be read.') }

        $cache = @{}
        $getGroup = {
            param([string]$dn)
            $k = ConvertTo-NormalizedIdentifier -Value $dn
            if (-not $cache.ContainsKey($k)) {
                $info = Get-ADGroupInfo -Identity $dn -Server $server
                if (-not $info.Resolved) { $errors.Add("Group '$dn' could not be resolved: $($info.Error)") }
                $cache[$k] = $info
            }
            $cache[$k]
        }
        $toEntry = {
            param($info, [string]$membership, [string[]]$path)
            [pscustomobject][ordered]@{
                ObjectGuid        = $info.ObjectGuid
                Sid               = $info.Sid
                DistinguishedName = $info.DistinguishedName
                Name              = $info.Name
                Membership        = $membership
                Path              = @($path)
                Depth             = ($path.Count - 2)
                Resolved          = $info.Resolved
            }
        }

        $direct = New-Object System.Collections.Generic.List[object]
        $nested = New-Object System.Collections.Generic.List[object]
        $queue = New-Object System.Collections.Queue

        foreach ($gdn in @(@(Get-ObjectProperty $u 'MemberOf') | Where-Object { $_ })) {
            $info = & $getGroup ([string]$gdn)
            $path = @($userDn, [string]$gdn)
            $direct.Add((& $toEntry $info 'Direct' $path))
            $queue.Enqueue([pscustomobject]@{ Info = $info; Path = $path })
        }

        $maxPaths = 2000
        $stop = $false
        while ($queue.Count -gt 0 -and -not $stop) {
            $item = $queue.Dequeue()
            foreach ($parentDn in @($item.Info.MemberOf)) {
                $pk = ConvertTo-NormalizedIdentifier -Value $parentDn
                $inPath = @($item.Path | Where-Object { (ConvertTo-NormalizedIdentifier -Value $_) -eq $pk }).Count -gt 0
                if ($inPath) { continue }
                if (($item.Path.Count - 1) -ge $MaxNestingDepth) {
                    $errors.Add("Nesting depth limit ($MaxNestingDepth) reached below '$($item.Info.Name)'; inherited memberships may be incomplete.")
                    continue
                }
                if ($nested.Count -ge $maxPaths) {
                    $errors.Add("Nested membership path limit ($maxPaths) reached; inherited memberships are incomplete.")
                    $stop = $true
                    break
                }
                $pInfo = & $getGroup $parentDn
                $newPath = @($item.Path) + @($parentDn)
                $nested.Add((& $toEntry $pInfo 'Inherited' $newPath))
                $queue.Enqueue([pscustomobject]@{ Info = $pInfo; Path = $newPath })
            }
        }

        $target = [pscustomobject][ordered]@{
            ObjectGuid        = ConvertTo-IdString (Get-ObjectProperty $u 'ObjectGUID')
            Sid               = ConvertTo-IdString (Get-ObjectProperty $u 'SID')
            DistinguishedName = $userDn
            SamAccountName    = ConvertTo-IdString (Get-ObjectProperty $u 'SamAccountName')
            UserPrincipalName = ConvertTo-IdString (Get-ObjectProperty $u 'UserPrincipalName')
            Enabled           = $enabled
            OrganizationalUnit = Get-ParentDN -DistinguishedName $userDn
            Department        = ConvertTo-IdString (Get-ObjectProperty $u 'Department')
            Manager           = ConvertTo-IdString (Get-ObjectProperty $u 'Manager')
            AdminCount        = Get-ObjectProperty $u 'AdminCount'
            PrimaryGroupId    = Get-ObjectProperty $u 'PrimaryGroupID'
        }
        if (-not $target.ObjectGuid -or -not $target.Sid) { $errors.Add('ObjectGUID or SID could not be read.') }

        $directArr = $direct.ToArray()
        $nestedArr = $nested.ToArray()
        $protection = Get-ADProtectionMatch -Target $target -DirectGroups $directArr -NestedGroups $nestedArr -Config $cfg
        $inScope = $false
        foreach ($ou in $cfg.AllowedSourceOUs) { if ($userDn -and (Test-DnUnderOu -Dn $userDn -OuDn $ou)) { $inScope = $true } }

        [pscustomobject][ordered]@{
            SchemaVersion     = '1.0'
            SnapshotId        = [guid]::NewGuid().ToString()
            CollectedUtc      = Get-UtcTimestamp
            DomainController  = $server
            ConfigFingerprint = $cfg.Fingerprint
            Target            = $target
            DirectGroups      = $directArr
            NestedGroups      = $nestedArr
            Protection        = $protection
            Scope             = [pscustomobject][ordered]@{ InAllowedSourceOU = $inScope; AllowedSourceOUs = @($cfg.AllowedSourceOUs) }
            Collection        = [pscustomobject][ordered]@{ IsComplete = ($errors.Count -eq 0); Errors = $errors.ToArray() }
            Notes             = @($script:ToolkitLimitations[1], $script:ToolkitLimitations[3])
        }
    }
}

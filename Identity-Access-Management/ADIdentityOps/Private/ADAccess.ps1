# --- Directory access helpers ---
# Public workflow commands use these wrappers to tolerate unset AD attributes and surface read failures.
function Get-ObjectProperty {
    <#
    .SYNOPSIS
        Strict-mode-safe property read (AD objects omit attributes that are not set).
    #>
    [CmdletBinding()]
    param([AllowNull()]$InputObject, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $InputObject) { return $null }
    $p = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    $p.Value
}

function Assert-ADCommand {
    <#
    .SYNOPSIS
        Confirms the ActiveDirectory cmdlets used by the toolkit are available; imports the module if needed.
    #>
    [CmdletBinding()]
    param()
    $required = 'Get-ADUser', 'Get-ADGroup', 'Get-ADOrganizationalUnit', 'Disable-ADAccount', 'Remove-ADGroupMember', 'Move-ADObject'
    $missing = @($required | Where-Object { -not (Get-Command -Name $_ -ErrorAction Ignore) })
    if ($missing.Count -gt 0 -and (Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction Ignore)) {
        Import-Module ActiveDirectory -ErrorAction Stop
        $missing = @($required | Where-Object { -not (Get-Command -Name $_ -ErrorAction Ignore) })
    }
    if ($missing.Count -gt 0) {
        throw "Required ActiveDirectory commands are unavailable: $($missing -join ', '). Install RSAT (ActiveDirectory module) on a supported Windows host."
    }
}

function Get-ADGroupInfo {
    <#
    .SYNOPSIS
        Resolves a group and its parent memberships, or returns an unresolved record with a sanitized error.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string]$Identity, [Parameter(Mandatory)][string]$Server)
    try {
        $g = Get-ADGroup -Identity $Identity -Server $Server -Properties MemberOf -ErrorAction Stop
        [pscustomobject][ordered]@{
            Resolved          = $true
            ObjectGuid        = (ConvertTo-IdString (Get-ObjectProperty $g 'ObjectGUID'))
            Sid               = (ConvertTo-IdString (Get-ObjectProperty $g 'SID'))
            DistinguishedName = (ConvertTo-IdString (Get-ObjectProperty $g 'DistinguishedName'))
            Name              = (ConvertTo-IdString (Get-ObjectProperty $g 'Name'))
            MemberOf          = @(@(Get-ObjectProperty $g 'MemberOf') | Where-Object { $_ } | ForEach-Object { [string]$_ })
            Error             = $null
        }
    }
    catch {
        # Preserve the failed lookup as evidence; an unresolved group makes snapshot collection incomplete.
        [pscustomobject][ordered]@{
            Resolved          = $false
            ObjectGuid        = $null
            Sid               = $null
            DistinguishedName = $(if ((Get-IdentifierKind -Value $Identity) -eq 'dn') { $Identity } else { $null })
            Name              = $Identity
            MemberOf          = @()
            Error             = (Get-SanitizedText -Text $_.Exception.Message)
        }
    }
}

function Get-ADProtectionMatch {
    <#
    .SYNOPSIS
        Evaluates the target and its direct and inherited groups against configured protection rules.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)]$Target, [AllowEmptyCollection()][object[]]$DirectGroups, [AllowEmptyCollection()][object[]]$NestedGroups, [Parameter(Mandatory)]$Config)

    $found = New-Object System.Collections.Generic.List[object]
    if (Test-IdentifierInList -Candidate @($Target.ObjectGuid, $Target.Sid, $Target.DistinguishedName) -List $Config.ProtectedAccounts) {
        $found.Add([pscustomobject][ordered]@{ Kind = 'ProtectedAccount'; Detail = 'Target matches a configured protected account identifier.'; Membership = $null; Path = @() })
    }
    # adminCount can persist after privileged membership ends; treat that uncertainty conservatively.
    if ($null -ne $Target.AdminCount -and [int]$Target.AdminCount -eq 1) {
        $found.Add([pscustomobject][ordered]@{ Kind = 'AdminCount'; Detail = 'adminCount=1 (current or former protected-group member); treated as protected.'; Membership = $null; Path = @() })
    }
    foreach ($g in @(@($DirectGroups) + @($NestedGroups))) {
        if ($null -eq $g) { continue }
        if (Test-IdentifierInList -Candidate @($g.ObjectGuid, $g.Sid, $g.DistinguishedName) -List $Config.ProtectedGroups) {
            $found.Add([pscustomobject][ordered]@{ Kind = 'ProtectedGroup'; Detail = "Member of protected group '$($g.Name)'."; Membership = $g.Membership; Path = @($g.Path) })
        }
    }
    $arr = $found.ToArray()
    [pscustomobject][ordered]@{ IsProtected = ($arr.Count -gt 0); Matches = $arr }
}

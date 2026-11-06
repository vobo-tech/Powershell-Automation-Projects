function Get-ADOffboardingPlanHash {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)]$Plan)
    $table = @{}
    foreach ($p in $Plan.PSObject.Properties) { if ($p.Name -ne 'Integrity') { $table[$p.Name] = $p.Value } }
    Get-Sha256Hex -Text (ConvertTo-CanonicalJson -InputObject $table)
}

function New-ADOffboardingPlan {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Creates an in-memory object (and optionally a plan file); it never changes AD.')]
    <#
    .SYNOPSIS
        Creates a reviewable, serializable offboarding plan from a snapshot. Read-only: changes nothing in AD.

    .DESCRIPTION
        Supported actions: disable the account; remove explicitly selected DIRECT group memberships;
        move the account to the configured quarantine OU. Group removals are never implied; every
        direct group that is not selected is listed as retained. Inherited (nested) memberships are
        listed as exclusions and can never be planned for removal.

        The plan embeds a SHA-256 integrity hash. The hash detects modification of the plan content
        only. It does not prove who created or approved it. Execution authorization comes from AD
        permissions and your change process. RequestedBy/Reason/TicketReference are free-text
        metadata, not access control.

        Ineligible targets (protected, out of scope, incomplete snapshot) still produce a plan so the
        reason can be reviewed, but Eligibility.IsEligible is $false and execution is blocked.

        Not supported in this release: deletion, password reset, mailbox actions, Entra session
        revocation, home-folder deletion.

    .PARAMETER Snapshot
        Output of Get-ADIdentitySnapshot.

    .PARAMETER RemoveGroup
        Direct groups to remove, as ObjectGUID, SID, or DN. Must match a direct membership.

    .PARAMETER MoveToQuarantine
        Include a move to the configured quarantine OU.

    .PARAMETER Path
        Optional JSON file to write the plan to.

    .EXAMPLE
        New-ADOffboardingPlan -Snapshot $snap -Config $cfgPath -TicketReference CHG-1001 -RequestedBy 'helpdesk-lead' `
            -RemoveGroup 'S-1-5-21-1-2-3-1201' -MoveToQuarantine -Path .\plan.json
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]$Snapshot,
        [Parameter(Mandatory)]$Config,
        [Parameter(Mandatory)][ValidatePattern('^[A-Za-z][A-Za-z0-9._/#-]{0,63}$')][string]$TicketReference,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][ValidateLength(1, 128)][string]$RequestedBy,
        [ValidateLength(0, 500)][string]$Reason = '',
        [string[]]$RemoveGroup = @(),
        [switch]$MoveToQuarantine,
        [ValidateRange(1, 72)][int]$ExpiresInHours,
        [string]$Path
    )

    $cfg = Resolve-ADIdentityConfig -Config $Config
    foreach ($req in 'SchemaVersion', 'SnapshotId', 'Target', 'DirectGroups', 'NestedGroups', 'Collection', 'DomainController') {
        if (-not $Snapshot.PSObject.Properties[$req]) { throw "Snapshot is missing '$req'. Provide the output of Get-ADIdentitySnapshot." }
    }
    if ([string]$Snapshot.SchemaVersion -ne '1.0') { throw "Unsupported snapshot schema '$($Snapshot.SchemaVersion)'." }
    if ([string]$Snapshot.DomainController -ne $cfg.DomainController) { throw 'Snapshot was collected from a different domain controller than the configuration specifies.' }
    Assert-NoIsoDateLikeText -Name 'RequestedBy' -Value $RequestedBy
    Assert-NoIsoDateLikeText -Name 'Reason' -Value $Reason

    $t = $Snapshot.Target
    $direct = @($Snapshot.DirectGroups)
    $nested = @($Snapshot.NestedGroups)

    # Re-evaluate eligibility with the current configuration rather than trusting the snapshot's own verdict.
    $blocks = New-Object System.Collections.Generic.List[string]
    if (-not $Snapshot.Collection.IsComplete) { $blocks.Add('Snapshot collection was incomplete: ' + (@($Snapshot.Collection.Errors) -join ' | ')) }
    $prot = Get-ADProtectionMatch -Target $t -DirectGroups $direct -NestedGroups $nested -Config $cfg
    if ($prot.IsProtected) { $blocks.Add('Target matches protection rules: ' + (@($prot.Matches | ForEach-Object { $_.Detail }) -join ' ')) }
    $inScope = $false
    foreach ($ou in $cfg.AllowedSourceOUs) { if (Test-DnUnderOu -Dn ([string]$t.DistinguishedName) -OuDn $ou) { $inScope = $true } }
    if (-not $inScope) { $blocks.Add('Target is not inside an allowed source OU.') }
    if ($null -eq $t.Enabled) { $blocks.Add('Enabled state is unknown.') }

    # Resolve explicit group selections against DIRECT memberships only.
    $selected = @{}
    foreach ($id in @($RemoveGroup)) {
        $norm = ConvertTo-NormalizedIdentifier -Value $id
        if (-not $norm -or $norm -like 'name:*') { throw "RemoveGroup '$id' must be an ObjectGUID, SID, or distinguished name." }
        $hit = @($direct | Where-Object { (@($_.ObjectGuid, $_.Sid, $_.DistinguishedName) | ForEach-Object { ConvertTo-NormalizedIdentifier -Value $_ }) -contains $norm })
        if ($hit.Count -eq 0) {
            $viaNested = @($nested | Where-Object { (@($_.ObjectGuid, $_.Sid, $_.DistinguishedName) | ForEach-Object { ConvertTo-NormalizedIdentifier -Value $_ }) -contains $norm })
            if ($viaNested.Count -gt 0) { throw "RemoveGroup '$id' is an inherited (nested) membership, not a direct one. It cannot be removed from this account." }
            throw "RemoveGroup '$id' is not a direct membership of the target."
        }
        if (-not $hit[0].Resolved -or -not $hit[0].ObjectGuid) { throw "RemoveGroup '$id' could not be resolved to a stable identifier; plan cannot be created safely." }
        $selected[(ConvertTo-NormalizedIdentifier -Value $hit[0].ObjectGuid)] = $hit[0]
    }

    $actions = New-Object System.Collections.Generic.List[object]
    $exclusions = New-Object System.Collections.Generic.List[object]
    $warnings = New-Object System.Collections.Generic.List[string]
    $n = 1
    $actions.Add([pscustomobject][ordered]@{
            ActionId = "A$n"; Order = $n; Type = 'DisableAccount'; DependsOn = @()
            Description = 'Disable the account (AD userAccountControl). Does not end existing sessions or cloud access.'
            Intended = [pscustomobject][ordered]@{ Enabled = $false }
            Group = $null
        })
    $disableId = "A$n"

    foreach ($g in $direct) {
        $gk = if ($g.ObjectGuid) { ConvertTo-NormalizedIdentifier -Value $g.ObjectGuid } else { $null }
        $isExcluded = Test-IdentifierInList -Candidate @($g.ObjectGuid, $g.Sid, $g.DistinguishedName) -List $cfg.GroupRemovalExclusions
        $wasSelected = $gk -and $selected.ContainsKey($gk)
        $groupRef = [pscustomobject][ordered]@{ ObjectGuid = $g.ObjectGuid; Sid = $g.Sid; DistinguishedName = $g.DistinguishedName; Name = $g.Name }
        if ($isExcluded) {
            $why = 'ConfigExclusion: group is listed in GroupRemovalExclusions and is always retained.'
            if ($wasSelected) { $why += ' It was explicitly selected for removal, but the configuration exclusion takes precedence.'; $warnings.Add("Selected group '$($g.Name)' is excluded by configuration and was not planned for removal.") }
            $exclusions.Add([pscustomobject][ordered]@{ Type = 'DirectGroupMembership'; Group = $groupRef; Reason = $why })
        }
        elseif ($wasSelected) {
            $n++
            $actions.Add([pscustomobject][ordered]@{
                    ActionId = "A$n"; Order = $n; Type = 'RemoveGroupMembership'; DependsOn = @($disableId)
                    Description = "Remove direct membership in '$($g.Name)'."
                    Intended = [pscustomobject][ordered]@{ DirectMember = $false }
                    Group = $groupRef
                })
            $stillInherited = @($nested | Where-Object { $_.ObjectGuid -and (ConvertTo-NormalizedIdentifier -Value $_.ObjectGuid) -eq $gk })
            if ($stillInherited.Count -gt 0) { $warnings.Add("Group '$($g.Name)' is also reachable through nested membership; that inherited path will remain after the direct removal.") }
        }
        else {
            $exclusions.Add([pscustomobject][ordered]@{ Type = 'DirectGroupMembership'; Group = $groupRef; Reason = 'NotSelected: retained; removal requires explicit selection.' })
        }
    }

    $seen = @{}
    foreach ($ng in $nested) {
        $k = if ($ng.ObjectGuid) { $ng.ObjectGuid } else { $ng.DistinguishedName }
        if ($seen.ContainsKey($k)) { $seen[$k].Paths += , @($ng.Path); continue }
        $entry = [pscustomobject][ordered]@{
            Type   = 'InheritedGroupMembership'
            Group  = [pscustomobject][ordered]@{ ObjectGuid = $ng.ObjectGuid; Sid = $ng.Sid; DistinguishedName = $ng.DistinguishedName; Name = $ng.Name }
            Reason = 'Inherited through nested groups; cannot be removed as a direct membership.'
            Paths  = @(, @($ng.Path))
        }
        $seen[$k] = $entry
        $exclusions.Add($entry)
    }

    if ($MoveToQuarantine) {
        $n++
        $actions.Add([pscustomobject][ordered]@{
                ActionId = "A$n"; Order = $n; Type = 'MoveToQuarantine'; DependsOn = @($disableId)
                Description = 'Move the account to the configured quarantine OU. Original OU is preserved as recovery evidence.'
                Intended = [pscustomobject][ordered]@{ ParentDn = $cfg.QuarantineOU }
                Group = $null
            })
    }

    $hours = if ($PSBoundParameters.ContainsKey('ExpiresInHours')) { $ExpiresInHours } else { $cfg.PlanLifetimeHours }
    $now = Get-UtcNow
    $groupSnapshot = @($direct | ForEach-Object { [pscustomobject][ordered]@{ ObjectGuid = $_.ObjectGuid; Sid = $_.Sid; DistinguishedName = $_.DistinguishedName; Name = $_.Name } })

    $plan = [pscustomobject][ordered]@{
        SchemaVersion     = '1.0'
        PlanId            = [guid]::NewGuid().ToString()
        CreatedUtc        = Get-UtcTimestamp -DateTime $now
        ExpiresUtc        = Get-UtcTimestamp -DateTime $now.AddHours($hours)
        Request           = [pscustomobject][ordered]@{
            TicketReference = $TicketReference
            RequestedBy     = (Get-SanitizedText -Text $RequestedBy -MaxLength 128)
            Reason          = (Get-SanitizedText -Text $Reason)
            Note            = 'Free-text metadata only. It is not approval and is not used for authorization.'
        }
        Target            = [pscustomobject][ordered]@{
            ObjectGuid = $t.ObjectGuid; Sid = $t.Sid; DistinguishedName = $t.DistinguishedName; SamAccountName = $t.SamAccountName
        }
        DomainController  = $cfg.DomainController
        ConfigFingerprint = $cfg.Fingerprint
        ObservedState     = [pscustomobject][ordered]@{
            SnapshotId = $Snapshot.SnapshotId; CollectedUtc = $Snapshot.CollectedUtc
            Enabled = $t.Enabled; ParentDn = $t.OrganizationalUnit; DirectGroups = $groupSnapshot
        }
        Preconditions     = @(
            'Target ObjectGUID and SID match the live account.'
            'Target is not protected and is inside an allowed source OU.'
            'Enabled state, parent OU, and direct group set match ObservedState (excluding changes made by the same plan run).'
            'No selected group is excluded by configuration; QuarantineOU exists when a move is planned.'
        )
        Eligibility       = [pscustomobject][ordered]@{ IsEligible = ($blocks.Count -eq 0); BlockReasons = $blocks.ToArray() }
        Actions           = $actions.ToArray()
        Exclusions        = $exclusions.ToArray()
        Warnings          = $warnings.ToArray()
        Limitations       = @($script:ToolkitLimitations)
    }
    $plan | Add-Member -NotePropertyName Integrity -NotePropertyValue ([pscustomobject][ordered]@{
            Algorithm = 'SHA256'
            Hash      = (Get-ADOffboardingPlanHash -Plan $plan)
            Note      = 'Detects modification only; does not establish approval or authenticity.'
        })

    if ($Path) { [void](Write-Utf8File -Path $Path -Content (ConvertTo-Json -InputObject $plan -Depth 12)) }
    $plan
}

function Resolve-ADOffboardingPlanInput {
    [CmdletBinding()]
    param($Plan, [string]$PlanPath)
    if ($PlanPath) { return (Read-JsonFile -Path $PlanPath) }
    $Plan
}

function Get-ADOffboardingCarryover {
    <#
    .SYNOPSIS
        Derives which state changes were made by an earlier run of the SAME plan, so a resume does not
        mistake the toolkit's own changes for drift. Only actions recorded as Succeeded earn credit.
    #>
    [CmdletBinding()]
    param($Plan, $PreviousResult)
    $credit = [ordered]@{ Disable = $false; Move = $false; RemovedGroupGuids = @() }
    if ($null -eq $PreviousResult) { return [pscustomobject]$credit }
    $removed = @()
    foreach ($a in @($PreviousResult.Actions)) {
        if ([string]$a.Status -ne 'Succeeded') { continue }
        $def = @($Plan.Actions | Where-Object { $_.ActionId -eq $a.ActionId })
        if ($def.Count -ne 1 -or $def[0].Type -ne $a.Type) { continue }
        switch ($a.Type) {
            'DisableAccount' { $credit.Disable = $true }
            'MoveToQuarantine' { $credit.Move = $true }
            'RemoveGroupMembership' { $removed += (ConvertTo-NormalizedIdentifier -Value ([string]$def[0].Group.ObjectGuid)) }
        }
    }
    $credit.RemovedGroupGuids = @($removed)
    [pscustomobject]$credit
}

function Invoke-ADOffboardingPreflight {
    <#
    .SYNOPSIS
        Runs the validation checks shared by Test-ADOffboardingPlan and Invoke-ADOffboardingPlan.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)]$Plan, [Parameter(Mandatory)]$Config, [switch]$Live, $Carryover)

    $checks = New-Object System.Collections.Generic.List[object]
    $add = {
        param([string]$Name, $Passed, [string]$Detail)
        $checks.Add([pscustomobject][ordered]@{ Name = $Name; Passed = [bool]$Passed; Detail = $Detail })
    }
    $finish = {
        param($Snapshot)
        $arr = $checks.ToArray()
        [pscustomobject][ordered]@{ Passed = (@($arr | Where-Object { -not $_.Passed }).Count -eq 0); Checks = $arr; LiveSnapshot = $Snapshot }
    }
    if ($null -eq $Carryover) { $Carryover = [pscustomobject]@{ Disable = $false; Move = $false; RemovedGroupGuids = @() } }

    # --- Schema -------------------------------------------------------------------------------
    $missing = New-Object System.Collections.Generic.List[string]
    $has = { param($o, $n) ($null -ne $o) -and ($null -ne $o.PSObject.Properties[$n]) }
    foreach ($n in 'SchemaVersion', 'PlanId', 'CreatedUtc', 'ExpiresUtc', 'Request', 'Target', 'DomainController', 'ConfigFingerprint', 'ObservedState', 'Eligibility', 'Actions', 'Exclusions', 'Integrity') {
        if (-not (& $has $Plan $n)) { $missing.Add($n) }
    }
    if ($missing.Count -eq 0) {
        foreach ($n in 'ObjectGuid', 'Sid', 'DistinguishedName') { if (-not (& $has $Plan.Target $n)) { $missing.Add("Target.$n") } }
        foreach ($n in 'Enabled', 'ParentDn', 'DirectGroups') { if (-not (& $has $Plan.ObservedState $n)) { $missing.Add("ObservedState.$n") } }
        foreach ($n in 'IsEligible', 'BlockReasons') { if (-not (& $has $Plan.Eligibility $n)) { $missing.Add("Eligibility.$n") } }
        foreach ($n in 'Algorithm', 'Hash') { if (-not (& $has $Plan.Integrity $n)) { $missing.Add("Integrity.$n") } }
        if (-not (& $has $Plan.Request 'TicketReference')) { $missing.Add('Request.TicketReference') }
        foreach ($a in @($Plan.Actions)) {
            foreach ($n in 'ActionId', 'Type', 'Order', 'DependsOn', 'Intended') { if (-not (& $has $a $n)) { $missing.Add("Actions[].$n") } }
        }
    }
    $schemaOk = ($missing.Count -eq 0) -and ([string]$Plan.SchemaVersion -eq '1.0')
    $detail = 'Schema 1.0 with all required fields.'
    if ($missing.Count -gt 0) { $detail = 'Missing fields: ' + (($missing | Select-Object -Unique) -join ', ') }
    elseif (-not $schemaOk) { $detail = "Unsupported schema version '$($Plan.SchemaVersion)'." }
    & $add 'Schema' $schemaOk $detail
    if (-not $schemaOk) { return (& $finish $null) }

    $planGuid = [guid]::Empty
    & $add 'PlanId' ([guid]::TryParse([string]$Plan.PlanId, [ref]$planGuid)) 'PlanId must be a GUID.'

    # --- Integrity ----------------------------------------------------------------------------
    $computed = Get-ADOffboardingPlanHash -Plan $Plan
    $integrityOk = ([string]$Plan.Integrity.Algorithm -eq 'SHA256') -and ([string]$Plan.Integrity.Hash -ieq $computed)
    & $add 'Integrity' $integrityOk 'Plan content hash must match (detects modification only; not proof of approval or authenticity).'

    # --- Expiry -------------------------------------------------------------------------------
    try {
        $created = ConvertTo-UtcDateTime -Value $Plan.CreatedUtc
        $expires = ConvertTo-UtcDateTime -Value $Plan.ExpiresUtc
        $now = Get-UtcNow
        $fresh = ($expires -gt $now) -and ($expires -gt $created) -and ($created -le $now.AddMinutes(5))
        & $add 'NotExpired' $fresh "Plan valid from $(Get-UtcTimestamp -DateTime $created) until $(Get-UtcTimestamp -DateTime $expires). Regenerate the plan if expired."
    }
    catch { & $add 'NotExpired' $false 'CreatedUtc/ExpiresUtc could not be parsed.' }

    # --- Configuration ------------------------------------------------------------------------
    & $add 'ConfigFingerprint' ([string]$Plan.ConfigFingerprint -ieq $Config.Fingerprint) 'Plan must have been created under the current configuration; regenerate it if the configuration changed.'
    & $add 'DomainController' ([string]$Plan.DomainController -ieq $Config.DomainController) 'Plan must target the explicitly configured domain controller.'
    & $add 'PlanEligible' ([bool]$Plan.Eligibility.IsEligible) ('Plan eligibility: ' + $(if ($Plan.Eligibility.IsEligible) { 'eligible.' } else { 'BLOCKED - ' + (@($Plan.Eligibility.BlockReasons) -join ' ') }))

    # --- Target identifier format -------------------------------------------------------------
    $tg = [guid]::Empty
    $idOk = [guid]::TryParse([string]$Plan.Target.ObjectGuid, [ref]$tg) -and ([string]$Plan.Target.Sid -match '^S-1-\d+(-\d+)+$')
    & $add 'TargetIdentifiers' $idOk 'Target must have a valid ObjectGUID and SID.'

    # --- Action structure ---------------------------------------------------------------------
    $actions = @($Plan.Actions)
    $ids = @($actions | ForEach-Object { [string]$_.ActionId })
    $problems = New-Object System.Collections.Generic.List[string]
    $allowedTypes = 'DisableAccount', 'RemoveGroupMembership', 'MoveToQuarantine'
    foreach ($a in $actions) { if ($allowedTypes -notcontains [string]$a.Type) { $problems.Add("Unsupported action type '$($a.Type)'.") } }
    if (@($ids | Select-Object -Unique).Count -ne $ids.Count) { $problems.Add('Duplicate ActionId values.') }
    $disables = @($actions | Where-Object { $_.Type -eq 'DisableAccount' })
    if ($disables.Count -ne 1) { $problems.Add('Exactly one DisableAccount action is required.') }
    if (@($actions | Where-Object { $_.Type -eq 'MoveToQuarantine' }).Count -gt 1) { $problems.Add('At most one MoveToQuarantine action is allowed.') }
    foreach ($a in $actions) {
        foreach ($d in @($a.DependsOn)) { if ($ids -notcontains [string]$d) { $problems.Add("Action $($a.ActionId) depends on unknown action '$d'.") } }
        if ($a.Type -eq 'RemoveGroupMembership') {
            $gg = [guid]::Empty
            if (-not (& $has $a 'Group') -or $null -eq $a.Group -or -not [guid]::TryParse([string]$a.Group.ObjectGuid, [ref]$gg)) { $problems.Add("Action $($a.ActionId) lacks a group ObjectGUID.") }
            elseif (Test-IdentifierInList -Candidate @($a.Group.ObjectGuid, $a.Group.Sid, $a.Group.DistinguishedName) -List $Config.GroupRemovalExclusions) { $problems.Add("Action $($a.ActionId) targets a group excluded by configuration.") }
            elseif (-not (@($Plan.ObservedState.DirectGroups | Where-Object { (ConvertTo-NormalizedIdentifier -Value ([string]$_.ObjectGuid)) -eq (ConvertTo-NormalizedIdentifier -Value ([string]$a.Group.ObjectGuid)) }).Count)) { $problems.Add("Action $($a.ActionId) targets a group that was not a direct membership when observed.") }
        }
        if ($a.Type -eq 'MoveToQuarantine' -and (ConvertTo-NormalizedIdentifier -Value ([string]$a.Intended.ParentDn)) -ne (ConvertTo-NormalizedIdentifier -Value $Config.QuarantineOU)) {
            $problems.Add("Action $($a.ActionId) destination differs from the configured QuarantineOU.")
        }
    }
    & $add 'ActionStructure' ($problems.Count -eq 0) $(if ($problems.Count -eq 0) { 'Actions must be well-formed, supported, and consistent with configuration.' } else { $problems -join ' ' })

    if (-not $Live) { return (& $finish $null) }

    # --- Live state ---------------------------------------------------------------------------
    $snap = $null
    try { $snap = Get-ADIdentitySnapshot -Identity ([string]$Plan.Target.ObjectGuid) -Config $Config }
    catch { & $add 'LiveTargetResolved' $false ('Target could not be re-read from the configured domain controller: ' + (Get-SanitizedText -Text $_.Exception.Message)) }
    if ($null -eq $snap) { return (& $finish $null) }

    & $add 'LiveTargetResolved' $true 'Target re-read from the configured domain controller.'
    & $add 'LiveIdentityMatch' (($snap.Target.ObjectGuid -ieq [string]$Plan.Target.ObjectGuid) -and ($snap.Target.Sid -ieq [string]$Plan.Target.Sid)) 'Live ObjectGUID and SID must equal the plan target.'
    & $add 'LiveSnapshotComplete' ([bool]$snap.Collection.IsComplete) $(if ($snap.Collection.IsComplete) { 'Live collection must be complete.' } else { 'Live collection incomplete: ' + (@($snap.Collection.Errors) -join ' | ') })
    & $add 'LiveNotProtected' (-not $snap.Protection.IsProtected) $(if ($snap.Protection.IsProtected) { 'Target is protected: ' + (@($snap.Protection.Matches | ForEach-Object { $_.Detail }) -join ' ') } else { 'Target must match no protection rule.' })
    # A move already made by this plan's earlier run legitimately leaves the account in quarantine.
    $scopeOk = [bool]$snap.Scope.InAllowedSourceOU
    $scopeDetail = $(if ($scopeOk) { 'Target is inside an allowed source OU.' } else { 'Target must be inside an allowed source OU.' })
    if (-not $scopeOk -and $Carryover.Move -and ((ConvertTo-NormalizedIdentifier -Value ([string]$snap.Target.OrganizationalUnit)) -eq (ConvertTo-NormalizedIdentifier -Value $Config.QuarantineOU))) {
        $scopeOk = $true
        $scopeDetail = 'Target is in the quarantine OU as a result of this plan''s earlier run.'
    }
    & $add 'LiveInScope' $scopeOk $scopeDetail

    $expectedEnabled = [bool]$Plan.ObservedState.Enabled
    if ($Carryover.Disable) { $expectedEnabled = $false }
    $enabledNow = $snap.Target.Enabled
    & $add 'DriftEnabled' (($null -ne $enabledNow) -and ([bool]$enabledNow -eq $expectedEnabled)) "Expected Enabled=$expectedEnabled; observed $enabledNow."

    $expectedParent = [string]$Plan.ObservedState.ParentDn
    if ($Carryover.Move) { $expectedParent = $Config.QuarantineOU }
    $parentNow = [string]$snap.Target.OrganizationalUnit
    & $add 'DriftParentOu' ((ConvertTo-NormalizedIdentifier -Value $parentNow) -eq (ConvertTo-NormalizedIdentifier -Value $expectedParent)) "Expected parent OU '$expectedParent'; observed '$parentNow'."

    $expectedSet = @(@($Plan.ObservedState.DirectGroups | ForEach-Object { ConvertTo-NormalizedIdentifier -Value ([string]$_.ObjectGuid) }) | Where-Object { @($Carryover.RemovedGroupGuids) -notcontains $_ })
    $actualSet = @($snap.DirectGroups | ForEach-Object { ConvertTo-NormalizedIdentifier -Value ([string]$_.ObjectGuid) })
    $added = @($actualSet | Where-Object { $expectedSet -notcontains $_ })
    $gone = @($expectedSet | Where-Object { $actualSet -notcontains $_ })
    & $add 'DriftDirectGroups' (($added.Count + $gone.Count) -eq 0) $(if (($added.Count + $gone.Count) -eq 0) { 'Direct group set must match the plan (adjusted for changes made by this plan).' } else { "Direct group set changed since planning. Added: $($added -join ', '). Missing: $($gone -join ', '). Regenerate the plan." })

    if (@($actions | Where-Object { $_.Type -eq 'MoveToQuarantine' }).Count -gt 0) {
        $ouOk = $false
        try { $null = Get-ADOrganizationalUnit -Identity $Config.QuarantineOU -Server $Config.DomainController -ErrorAction Stop; $ouOk = $true } catch { $ouOk = $false }
        & $add 'QuarantineOuExists' $ouOk 'Configured quarantine OU must exist on the domain controller.'
    }

    foreach ($a in @($actions | Where-Object { $_.Type -eq 'RemoveGroupMembership' })) {
        $gi = Get-ADGroupInfo -Identity ([string]$a.Group.ObjectGuid) -Server $Config.DomainController
        $okG = $gi.Resolved -and ($gi.Sid -ieq [string]$a.Group.Sid) -and -not (Test-IdentifierInList -Candidate @($gi.ObjectGuid, $gi.Sid, $gi.DistinguishedName) -List $Config.GroupRemovalExclusions)
        & $add "LiveGroup:$($a.ActionId)" $okG "Group '$($a.Group.Name)' must resolve to the planned SID and must not be excluded."
    }

    & $finish $snap
}

function Test-ADOffboardingPlan {
    <#
    .SYNOPSIS
        Validates an offboarding plan. Read-only.

    .DESCRIPTION
        Offline checks: schema, integrity hash, expiry, configuration fingerprint, action structure,
        exclusions. With -CheckLiveState the target is also re-read from the configured domain
        controller to check identity, protection, scope, and state drift.

    .EXAMPLE
        Test-ADOffboardingPlan -PlanPath .\plan.json -Config .\ADIdentityOps.json -CheckLiveState
    #>
    [CmdletBinding(DefaultParameterSetName = 'Object')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Object', ValueFromPipeline)]$Plan,
        [Parameter(Mandatory, ParameterSetName = 'Path')][string]$PlanPath,
        [Parameter(Mandatory)]$Config,
        [switch]$CheckLiveState
    )
    process {
        $cfg = Resolve-ADIdentityConfig -Config $Config
        $p = Resolve-ADOffboardingPlanInput -Plan $Plan -PlanPath $PlanPath
        if ($CheckLiveState) { Assert-ADCommand }
        $r = Invoke-ADOffboardingPreflight -Plan $p -Config $cfg -Live:$CheckLiveState
        $planId = $null
        if ($null -ne $p -and $p.PSObject.Properties['PlanId']) { $planId = [string]$p.PlanId }
        [pscustomobject][ordered]@{
            PlanId           = $planId
            IsValid          = $r.Passed
            LiveStateChecked = [bool]$CheckLiveState
            EvaluatedUtc     = Get-UtcTimestamp
            Checks           = $r.Checks
            FailedChecks     = @($r.Checks | Where-Object { -not $_.Passed })
        }
    }
}

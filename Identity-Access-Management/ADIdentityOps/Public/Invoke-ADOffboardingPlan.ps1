function Invoke-ADOffboardingPlan {
    <#
    .SYNOPSIS
        Executes a deliberately selected offboarding plan with safeguards, or previews it with -WhatIf.

    .DESCRIPTION
        Before any write the plan is validated (schema, integrity, expiry, configuration fingerprint,
        action structure) and the target is re-read from the explicitly configured domain controller to
        confirm identity, protection, scope, and that material state has not drifted. Any failed check
        blocks execution and the plan must be regenerated. Nothing is written in that case.

        Actions run in order. Group removals and the OU move depend on the account-disable action
        having Succeeded or been AlreadyCompliant; otherwise they are Blocked. Every change is
        verified by re-reading AD; a failed verification is recorded as Failed, never Succeeded.

        -WhatIf performs only reads. Use -ResumeFrom with a previous result for the same plan to retry
        unfinished work: Succeeded/AlreadyCompliant actions are carried forward and are NOT repeated,
        and state changes made by that earlier run are expected rather than treated as drift. A plan
        that has expired must be regenerated even when resuming.

        Authorization is determined by the AD permissions of the account running this command and by
        your change process. Nothing in the plan (including 'RequestedBy') grants authority.

        ConfirmImpact is High: you are prompted per write unless you pass -Confirm:$false.
        There is no rollback. OriginalState in the result records the pre-change OU and direct
        memberships as recovery evidence only.

        Callers must check the returned Status; a blocked run returns a result object (Status
        'Blocked') rather than throwing.

    .PARAMETER ConfirmPlanId
        Must equal the plan's PlanId. Guards against executing the wrong plan file.

    .PARAMETER Plan
        In-memory plan object to execute or preview.

    .PARAMETER PlanPath
        Path to a plan JSON file instead of an in-memory object.

    .PARAMETER Config
        Configuration object or JSON path; its settings must match the plan fingerprint.

    .PARAMETER ResumeFrom
        A previous result object or path produced by this command for the same plan.

    .PARAMETER ResultPath
        Optional destination for execution evidence; WhatIf does not write a result file.

    .OUTPUTS
        A result object with preflight checks, per-action outcomes, attempt counts, and recovery evidence.

    .EXAMPLE
        Invoke-ADOffboardingPlan -PlanPath .\plan.json -Config .\ADIdentityOps.json -ConfirmPlanId $planId -WhatIf

    .EXAMPLE
        $r = Invoke-ADOffboardingPlan -PlanPath .\plan.json -Config .\ADIdentityOps.json -ConfirmPlanId $planId -Confirm:$false
        $r = Invoke-ADOffboardingPlan -PlanPath .\plan.json -Config .\ADIdentityOps.json -ConfirmPlanId $planId -ResumeFrom $r -Confirm:$false
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Object')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Object')]$Plan,
        [Parameter(Mandatory, ParameterSetName = 'Path')][string]$PlanPath,
        [Parameter(Mandatory)]$Config,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ConfirmPlanId,
        $ResumeFrom,
        [string]$ResultPath
    )

    # --- Validate configuration and target scope ---
    Assert-ADCommand
    $cfg = Resolve-ADIdentityConfig -Config $Config
    $p = Resolve-ADOffboardingPlanInput -Plan $Plan -PlanPath $PlanPath
    if ($null -eq $p -or -not $p.PSObject.Properties['PlanId']) { throw 'Plan is missing or malformed.' }
    if ([string]$p.PlanId -ne $ConfirmPlanId) { throw 'ConfirmPlanId does not match the plan PlanId; refusing to execute.' }

    $whatIfMode = [bool]$WhatIfPreference
    $runId = [guid]::NewGuid().ToString()
    $startedUtc = Get-UtcTimestamp

    # Resume record must belong to this exact plan.
    $previous = $null
    if ($null -ne $ResumeFrom) {
        $previous = if ($ResumeFrom -is [string]) { Read-JsonFile -Path $ResumeFrom } else { $ResumeFrom }
        $planHash = if ($p.PSObject.Properties['Integrity']) { [string]$p.Integrity.Hash } else { '' }
        if ([string]$previous.PlanId -ne [string]$p.PlanId -or [string]$previous.PlanHash -ne $planHash -or [string]$previous.Target.ObjectGuid -ne [string]$p.Target.ObjectGuid) {
            throw 'The resume record does not belong to this plan (PlanId, plan hash, or target differs).'
        }
    }

    # Live preflight permits only drift attributed to successful actions in the matching previous run.
    $carryover = if ($previous) { Get-ADOffboardingCarryover -Plan $p -PreviousResult $previous } else { $null }
    $pre = Invoke-ADOffboardingPreflight -Plan $p -Config $cfg -Live -Carryover $carryover

    $planActions = @()
    if ($p.PSObject.Properties['Actions']) { $planActions = @($p.Actions | Sort-Object { [int]$_.Order }) }
    $okStates = 'Succeeded', 'AlreadyCompliant'

    $records = New-Object System.Collections.Generic.List[object]
    foreach ($a in $planActions) {
        $prev = $null
        if ($previous) { $prev = @($previous.Actions | Where-Object { $_.ActionId -eq $a.ActionId -and $_.Type -eq $a.Type -and $okStates -contains [string]$_.Status }) | Select-Object -First 1 }
        $rec = [ordered]@{
            ActionId = $a.ActionId; Type = $a.Type; Order = $a.Order; DependsOn = @($a.DependsOn)
            Description = $a.Description; Intended = $a.Intended; Group = $a.Group
            Status = 'Planned'; Observed = $null; StartedUtc = $null; EndedUtc = $null; Attempts = 0; Error = $null; CarriedFromRunId = $null
        }
        # Retain counts even for failed or blocked actions; only successful/compliant actions are carried.
        if ($previous) {
            $anyPrev = @($previous.Actions | Where-Object { $_.ActionId -eq $a.ActionId -and $_.Type -eq $a.Type }) | Select-Object -First 1
            if ($anyPrev) { $rec.Attempts = [int]$anyPrev.Attempts }
        }
        if ($prev) {
            foreach ($f in 'Status', 'Observed', 'StartedUtc', 'EndedUtc', 'Attempts', 'Error') { $rec[$f] = $prev.$f }
            $rec.CarriedFromRunId = [string]$previous.RunId
        }
        $records.Add([pscustomobject]$rec)
    }

    # Original state is manual recovery evidence, not an automatic rollback mechanism.
    $original = $null
    if ($previous -and $previous.PSObject.Properties['OriginalState']) { $original = $previous.OriginalState }
    elseif ($pre.LiveSnapshot) {
        $s = $pre.LiveSnapshot
        $original = [pscustomobject][ordered]@{
            CapturedUtc = $s.CollectedUtc; Source = 'Live read immediately before first execution'
            Enabled = $s.Target.Enabled; DistinguishedName = $s.Target.DistinguishedName; ParentDn = $s.Target.OrganizationalUnit
            DirectGroups = @($s.DirectGroups | ForEach-Object { [pscustomobject][ordered]@{ ObjectGuid = $_.ObjectGuid; Sid = $_.Sid; DistinguishedName = $_.DistinguishedName; Name = $_.Name } })
        }
    }

    $result = [pscustomobject][ordered]@{
        SchemaVersion    = '1.0'
        RunId            = $runId
        ResumedFromRunId = $(if ($previous) { [string]$previous.RunId } else { $null })
        PlanId           = [string]$p.PlanId
        PlanHash         = $(if ($p.PSObject.Properties['Integrity']) { [string]$p.Integrity.Hash } else { $null })
        Target           = $(if ($p.PSObject.Properties['Target']) { $p.Target } else { $null })
        Mode             = $(if ($whatIfMode) { 'WhatIf' } else { 'Execute' })
        StartedUtc       = $startedUtc
        EndedUtc         = $null
        Status           = 'Planned'
        StatusReason     = $null
        Preflight        = [pscustomobject][ordered]@{ Passed = $pre.Passed; Checks = $pre.Checks }
        OriginalState    = $original
        Actions          = $records.ToArray()
        Summary          = $null
        ResultPath       = $null
        Verification     = $null
        Limitations      = @($script:ToolkitLimitations)
    }

    # --- Preserve execution evidence ---
    # Save after each action so a partial run has useful evidence; WhatIf does not write result files.
    $resultDestination = $ResultPath
    $save = {
        $result.Summary = Get-ADOffboardingResultSummary -Actions $result.Actions
        if (-not $whatIfMode) {
            $dest = $resultDestination
            if (-not $dest) { $dest = Join-Path $cfg.Output.ResultDirectory "result-$($result.PlanId)-$runId.json" }
            $result.ResultPath = Write-Utf8File -Path $dest -Content (ConvertTo-Json -InputObject $result -Depth 14)
        }
    }

    if (-not $pre.Passed) {
        $failed = @($pre.Checks | Where-Object { -not $_.Passed } | ForEach-Object { "$($_.Name): $($_.Detail)" })
        # --- Execute eligible actions ---
        # A failed prerequisite blocks dependent actions. WhatIf treats a planned prerequisite as previewable.
        foreach ($r in $result.Actions) {
            if ($okStates -notcontains $r.Status) { $r.Status = 'Blocked'; $r.Error = Get-SanitizedText -Text ('Preflight failed. ' + ($failed -join ' | ')) }
        }
        $result.Status = 'Blocked'
        $result.StatusReason = 'Preflight validation failed; no changes were made. Regenerate the plan after resolving: ' + ($failed -join ' | ')
        $result.EndedUtc = Get-UtcTimestamp
        Write-Warning $result.StatusReason
        & $save
        return $result
    }

    foreach ($r in $result.Actions) {
        if ($okStates -contains $r.Status -and $r.CarriedFromRunId) { continue }

        $blocker = $null
        foreach ($d in @($r.DependsOn)) {
            $dep = @($result.Actions | Where-Object { $_.ActionId -eq $d }) | Select-Object -First 1
            $depOk = $dep -and (($okStates -contains $dep.Status) -or ($whatIfMode -and $dep.Status -eq 'Planned'))
            if (-not $depOk) { $blocker = "Prerequisite $d is '$(if ($dep) { $dep.Status } else { 'missing' })'." }
        }
        if ($blocker) {
            $r.Status = 'Blocked'
            $r.Error = $blocker
            & $save
            continue
        }

        $r.StartedUtc = Get-UtcTimestamp
        $r.Attempts = [int]$r.Attempts + 1
        $planAction = @($planActions | Where-Object { $_.ActionId -eq $r.ActionId })[0]
        # Pass the public cmdlet context so each actual write uses its ShouldProcess/-WhatIf decision.
        $o = Invoke-ADOffboardingAction -Action $planAction -Plan $p -Config $cfg -Cmdlet $PSCmdlet -WhatIfMode $whatIfMode
        $r.Status = $o.Status
        $r.Observed = $o.Observed
        $r.Error = $o.Error
        $r.EndedUtc = Get-UtcTimestamp
        & $save
    }

    $statuses = @($result.Actions | ForEach-Object { $_.Status })
    $result.Summary = Get-ADOffboardingResultSummary -Actions $result.Actions
    if ($whatIfMode) { $result.Status = 'WhatIf'; $result.StatusReason = 'Preview only. No Active Directory changes were made.' }
    elseif (@($statuses | Where-Object { $okStates -notcontains $_ }).Count -eq 0) { $result.Status = 'Succeeded'; $result.StatusReason = 'All actions Succeeded or were AlreadyCompliant. Run Test-ADOffboardingResult for independent verification.' }
    elseif (@($statuses | Where-Object { $okStates -contains $_ }).Count -gt 0) { $result.Status = 'PartiallyCompleted'; $result.StatusReason = 'Some actions are incomplete: ' + ($result.Summary.IncompleteActionIds -join ', ') + '. Review errors; retry with -ResumeFrom.' }
    elseif ($statuses -contains 'Failed') { $result.Status = 'Failed'; $result.StatusReason = 'No action completed; see action errors.' }
    else { $result.Status = 'Blocked'; $result.StatusReason = 'No action completed.' }
    $result.EndedUtc = Get-UtcTimestamp
    & $save
    $result
}

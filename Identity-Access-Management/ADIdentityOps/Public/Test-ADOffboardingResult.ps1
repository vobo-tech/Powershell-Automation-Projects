function Test-ADOffboardingResult {
    <#
    .SYNOPSIS
        Independently verifies the live state of the target against a plan and its execution result. Read-only.

    .DESCRIPTION
        Re-reads the account from the configured domain controller and compares live state with each
        planned action's intended state, regardless of what the result claims. The verification only
        reports Passed when every planned action is satisfied live, retained groups are still
        direct memberships, identity/plan-hash checks hold, and no action is incomplete.
        A mismatch between a reported success and live state is listed under Discrepancies.

        Inherited (nested) memberships that remain are reported as informational residuals; they are
        outside the scope of direct-membership removal.

    .PARAMETER Plan
        A plan object or the path to a plan JSON file.

    .PARAMETER Result
        A result object from Invoke-ADOffboardingPlan or the path to its JSON file.

    .PARAMETER Config
        Configuration object or JSON path selecting the domain controller and quarantine OU.

    .OUTPUTS
        Verification checks, live comparisons, incomplete actions, and residual inherited membership paths.

    .EXAMPLE
        $v = Test-ADOffboardingResult -Plan .\plan.json -Result $r -Config .\ADIdentityOps.json
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]$Plan,
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)]$Config
    )
    Assert-ADCommand
    $cfg = Resolve-ADIdentityConfig -Config $Config
    $p = if ($Plan -is [string]) { Read-JsonFile -Path $Plan } else { $Plan }
    $r = if ($Result -is [string]) { Read-JsonFile -Path $Result } else { $Result }

    $checks = New-Object System.Collections.Generic.List[object]
    $items = New-Object System.Collections.Generic.List[object]
    $addCheck = {
        param([string]$Name, $Passed, [string]$Detail)
        $checks.Add([pscustomobject][ordered]@{ Name = $Name; Passed = [bool]$Passed; Detail = $Detail })
    }

    # --- Verify result identity and capture current state ---
    # The hash binds this result to plan content for comparison; it does not establish approval.
    $hashOk = $p.PSObject.Properties['Integrity'] -and ([string]$p.Integrity.Hash -ieq (Get-ADOffboardingPlanHash -Plan $p))
    & $addCheck 'PlanIntegrity' $hashOk 'Plan hash matches its content (modification check only).'
    & $addCheck 'ResultMatchesPlan' (([string]$r.PlanId -eq [string]$p.PlanId) -and ([string]$r.PlanHash -ieq [string]$p.Integrity.Hash)) 'Result PlanId and plan hash match the supplied plan.'

    $snap = $null
    $errorText = $null
    try { $snap = Get-ADIdentitySnapshot -Identity ([string]$p.Target.ObjectGuid) -Config $cfg }
    catch { $errorText = Get-SanitizedText -Text $_.Exception.Message }

    $incomplete = @($r.Actions | Where-Object { @('Succeeded', 'AlreadyCompliant') -notcontains [string]$_.Status } | ForEach-Object { [string]$_.ActionId })
    $discrepancies = New-Object System.Collections.Generic.List[string]
    $residual = @()
    $removedStillInherited = @()

    if ($null -eq $snap) {
        & $addCheck 'LiveStateRead' $false "Live state could not be read: $errorText"
    }
    else {
        & $addCheck 'LiveStateRead' $true 'Live state read from the configured domain controller.'
        & $addCheck 'LiveIdentityMatch' (($snap.Target.ObjectGuid -ieq [string]$p.Target.ObjectGuid) -and ($snap.Target.Sid -ieq [string]$p.Target.Sid)) 'Live ObjectGUID and SID equal the plan target.'
        & $addCheck 'LiveSnapshotComplete' ([bool]$snap.Collection.IsComplete) $(if ($snap.Collection.IsComplete) { 'Live collection complete.' } else { 'Incomplete: ' + (@($snap.Collection.Errors) -join ' | ') })

        # --- Compare intended changes with the live read ---
        # A reported success is insufficient if the directory no longer has the intended state.
        $liveDirect = @($snap.DirectGroups | ForEach-Object { ConvertTo-NormalizedIdentifier -Value ([string]$_.ObjectGuid) })
        foreach ($a in @($p.Actions | Sort-Object { [int]$_.Order })) {
            $reported = [string](@($r.Actions | Where-Object { $_.ActionId -eq $a.ActionId } | Select-Object -First 1 | ForEach-Object { $_.Status }))
            if (-not $reported) { $reported = 'NotRecorded' }
            $expected = $null; $observed = $null; $ok = $false
            switch ($a.Type) {
                'DisableAccount' { $expected = 'Enabled=False'; $observed = "Enabled=$($snap.Target.Enabled)"; $ok = ($snap.Target.Enabled -eq $false) }
                'MoveToQuarantine' {
                    $expected = "ParentDn=$($cfg.QuarantineOU)"; $observed = "ParentDn=$($snap.Target.OrganizationalUnit)"
                    $ok = (ConvertTo-NormalizedIdentifier -Value ([string]$snap.Target.OrganizationalUnit)) -eq (ConvertTo-NormalizedIdentifier -Value $cfg.QuarantineOU)
                }
                'RemoveGroupMembership' {
                    $gk = ConvertTo-NormalizedIdentifier -Value ([string]$a.Group.ObjectGuid)
                    $isMember = $liveDirect -contains $gk
                    $expected = "DirectMember[$($a.Group.Name)]=False"; $observed = "DirectMember[$($a.Group.Name)]=$isMember"; $ok = -not $isMember
                    $via = @($snap.NestedGroups | Where-Object { $_.ObjectGuid -and (ConvertTo-NormalizedIdentifier -Value ([string]$_.ObjectGuid)) -eq $gk })
                    if ($via.Count -gt 0) { $removedStillInherited += $a.Group.Name }
                }
                default { $expected = 'Unsupported'; $observed = 'Unsupported' }
            }
            if (@('Succeeded', 'AlreadyCompliant') -contains $reported -and -not $ok) { $discrepancies.Add("$($a.ActionId) reported $reported but live state does not match.") }
            $items.Add([pscustomobject][ordered]@{ ActionId = $a.ActionId; Category = 'PlannedChange'; Type = $a.Type; ReportedStatus = $reported; Expected = $expected; Observed = $observed; Verified = [bool]$ok })
        }

        foreach ($ex in @($p.Exclusions | Where-Object { $_.Type -eq 'DirectGroupMembership' })) {
            $gk = if ($ex.Group.ObjectGuid) { ConvertTo-NormalizedIdentifier -Value ([string]$ex.Group.ObjectGuid) } else { $null }
            $still = if ($gk) { $liveDirect -contains $gk } else { $false }
            $items.Add([pscustomobject][ordered]@{
                    ActionId = $null; Category = 'RetainedGroup'; Type = 'DirectGroupMembership'; ReportedStatus = 'Retained'
                    Expected = "DirectMember[$($ex.Group.Name)]=True"; Observed = "DirectMember[$($ex.Group.Name)]=$still"; Verified = [bool]$still
                })
        }
        # A removed direct membership can still be inherited through another path. This is not an
        # effective-access calculation and does not establish whether existing sessions have ended.
        $seen = @{}
        $residualUnique = foreach ($x in @($snap.NestedGroups)) { $k = [string]$x.ObjectGuid + '|' + (@($x.Path) -join '>'); if (-not $seen.ContainsKey($k)) { $seen[$k] = $true; $x } }
        $residual = @($residualUnique)
    }

    $itemArr = $items.ToArray()
    $checkArr = $checks.ToArray()
    $unverified = @($itemArr | Where-Object { -not $_.Verified })
    $checksOk = (@($checkArr | Where-Object { -not $_.Passed }).Count -eq 0)
    $passed = $checksOk -and ($itemArr.Count -gt 0) -and ($unverified.Count -eq 0) -and ($incomplete.Count -eq 0) -and ($discrepancies.Count -eq 0)

    [pscustomobject][ordered]@{
        SchemaVersion                = '1.0'
        PlanId                       = [string]$p.PlanId
        RunId                        = [string]$r.RunId
        VerifiedUtc                  = Get-UtcTimestamp
        Passed                       = $passed
        Checks                       = $checkArr
        Items                        = $itemArr
        UnverifiedItems              = @($unverified | ForEach-Object { if ($_.ActionId) { $_.ActionId } else { $_.Expected } })
        IncompleteActionIds          = $incomplete
        Discrepancies                = $discrepancies.ToArray()
        RemovedButStillInherited     = @($removedStillInherited | Select-Object -Unique)
        ResidualInheritedMemberships = @($residual | ForEach-Object { [pscustomobject][ordered]@{ Group = $_.Name; Path = @($_.Path) } })
        AfterState                   = $(if ($snap) { [pscustomobject][ordered]@{ Enabled = $snap.Target.Enabled; DistinguishedName = $snap.Target.DistinguishedName; ParentDn = $snap.Target.OrganizationalUnit; DirectGroups = @($snap.DirectGroups | ForEach-Object { $_.Name }) } } else { $null })
        Notes                        = @('Verification is a point-in-time read of AD attributes. It does not prove sessions ended, cloud access was revoked, or effective access changed.')
    }
}

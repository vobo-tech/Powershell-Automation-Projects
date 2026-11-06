<#
.SYNOPSIS
  Repeatable SYNTHETIC demonstration of the ADIdentityOps offboarding workflow. No domain is contacted.

.DESCRIPTION
  Dot-sources an in-memory fake of the ActiveDirectory cmdlets (Demo/FakeActiveDirectory.ps1) and runs the REAL
  ADIdentityOps module against it. Every user, group, SID, GUID, and domain name is fabricated.
  All AD "writes" are changes to an in-memory hashtable. Output is labelled SIMULATED.

  Walkthrough:
    1. Snapshot an ordinary employee (direct + nested memberships) and a protected privileged account.
    2. Plan for the protected account -> ineligible; execution is blocked and nothing is written.
    3. Plan for the employee, removing two selected direct groups; one direct group is retained by policy
       and one is simply not selected.
    4. -WhatIf run (zero writes), then a real run with an injected failure on one group removal.
    5. Verification of the partial run (cannot pass), resume of only the unfinished work, final verification
       showing inherited access paths that remain after direct membership removal.
    6. JSON, CSV, and HTML evidence reports.

.PARAMETER OutputDirectory
  Parent directory for this run's plans, results, and reports. A new run-specific child directory is created;
  existing contents are never removed. Default: ./out/demo (ignored by git).

.EXAMPLE
  pwsh -File ./Identity-Access-Management/ADIdentityOps/Demo/Invoke-SyntheticDemo.ps1
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '', Justification='The synthetic AD fake keeps its state in $global:FakeAD, which the demo inspects for before/after evidence.')]
[CmdletBinding()]
[OutputType([pscustomobject])]
param(
    [string]$OutputDirectory = (Join-Path (Get-Location).Path 'out/demo')
)

$ErrorActionPreference = 'Stop'
$moduleRoot = Split-Path -Path $PSScriptRoot -Parent

function Write-DemoLine {
    param([string]$Text)
    Write-Information -MessageData $Text -InformationAction Continue
}

function Write-DemoStep {
    param([string]$Title)
    Write-DemoLine ''
    Write-DemoLine "=== $Title ==="
}

function Assert-Demo {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "Demo self-check failed: $Message" }
    Write-DemoLine "  [check ok] $Message"
}

$outputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
$runName = 'run-{0}-{1}' -f (Get-Date).ToUniversalTime().ToString("yyyyMMdd'T'HHmmssfff'Z'"), ([guid]::NewGuid().ToString('N').Substring(0, 8))
$OutputDirectory = Join-Path $outputRoot $runName
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

. (Join-Path $moduleRoot 'Demo/FakeActiveDirectory.ps1')
Initialize-SyntheticDirectory
Import-Module (Join-Path $moduleRoot 'ADIdentityOps.psd1') -Force

try {
    $cfg = New-SyntheticConfig
    $cfg.Output = [pscustomobject]@{
        PlanDirectory   = (Join-Path $OutputDirectory 'plans')
        ResultDirectory = (Join-Path $OutputDirectory 'results')
        ReportDirectory = (Join-Path $OutputDirectory 'reports')
    }
    $shareGroup = 'aaaaaaaa-0000-0000-0000-000000001201'   # GG-Finance-Share (direct)
    $atlasGroup = 'aaaaaaaa-0000-0000-0000-000000001203'   # GG-Project-Atlas (direct; removal fails in run 1)

    Write-DemoLine '*** SIMULATED DEMO: synthetic in-memory directory; no domain, no real identities, no AD changes. ***'

    Write-DemoStep '1. Read-only snapshots'
    $snap = Get-ADIdentitySnapshot -Identity 'jdoe' -Config $cfg
    $adminSnap = Get-ADIdentitySnapshot -Identity 'adm-ops' -Config $cfg
    Write-DemoLine ("jdoe  Enabled={0}  OU={1}" -f $snap.Target.Enabled, $snap.Target.OrganizationalUnit)
    foreach ($g in $snap.DirectGroups) { Write-DemoLine ("  DIRECT    {0}" -f $g.Name) }
    foreach ($g in $snap.NestedGroups) { Write-DemoLine ("  INHERITED {0}  via {1}" -f $g.Name, (@($g.Path) -join ' > ')) }
    Write-DemoLine ("adm-ops protected match count: {0}" -f @($adminSnap.Protection.Matches).Count)
    Assert-Demo ($global:FakeAD.WriteLog.Count -eq 0) 'discovery performed zero AD writes'

    Write-DemoStep '2. Protected account: plan is ineligible and execution is blocked'
    $adminPlan = New-ADOffboardingPlan -Snapshot $adminSnap -Config $cfg -TicketReference 'CHG-DEMO-0' -RequestedBy 'demo-operator' -RemoveGroup @()
    Assert-Demo (-not $adminPlan.Eligibility.IsEligible) 'protected account plan is not eligible'
    $blocked = Invoke-ADOffboardingPlan -Plan $adminPlan -Config $cfg -ConfirmPlanId $adminPlan.PlanId -Confirm:$false -WarningAction SilentlyContinue
    Write-DemoLine ("Execution status: {0}" -f $blocked.Status)
    Assert-Demo ($blocked.Status -eq 'Blocked') 'execution for the protected account is Blocked'
    Assert-Demo ($global:FakeAD.WriteLog.Count -eq 0) 'blocked run performed zero AD writes'

    Write-DemoStep '3. Plan for the ordinary employee (explicit group selection)'
    $planPath = Join-Path $OutputDirectory 'plans/jdoe-plan.json'
    $plan = New-ADOffboardingPlan -Snapshot $snap -Config $cfg -TicketReference 'CHG-DEMO-1' -RequestedBy 'demo-operator' `
        -Reason 'SIMULATED offboarding' -RemoveGroup @($shareGroup, $atlasGroup) -MoveToQuarantine -Path $planPath
    foreach ($a in $plan.Actions) { Write-DemoLine ("  ACTION   {0} {1}" -f $a.ActionId, $a.Type) }
    foreach ($e in $plan.Exclusions) { Write-DemoLine ("  EXCLUDED {0}: {1}" -f $e.Type, $e.Reason) }
    $check = Test-ADOffboardingPlan -PlanPath $planPath -Config $cfg -CheckLiveState
    Assert-Demo $check.IsValid 'plan validates (schema, hash, expiry, fingerprint, live drift, scope)'

    Write-DemoStep '4a. -WhatIf (no writes)'
    $whatIf = Invoke-ADOffboardingPlan -PlanPath $planPath -Config $cfg -ConfirmPlanId $plan.PlanId -WhatIf
    Write-DemoLine ("WhatIf status: {0}; AD write calls: {1}" -f $whatIf.Status, $global:FakeAD.WriteLog.Count)
    Assert-Demo ($global:FakeAD.WriteLog.Count -eq 0) '-WhatIf performed zero AD writes'

    Write-DemoStep '4b. Execute with an injected (simulated) failure removing GG-Project-Atlas'
    $global:FakeAD.FailWrite['RemoveGroup:GG-Project-Atlas'] = 'Access is denied. (SIMULATED failure)'
    $run1 = Invoke-ADOffboardingPlan -PlanPath $planPath -Config $cfg -ConfirmPlanId $plan.PlanId -Confirm:$false -WarningAction SilentlyContinue
    Write-DemoLine ("Run 1 status: {0}" -f $run1.Status)
    foreach ($a in $run1.Actions) { Write-DemoLine ("  {0} {1,-22} {2}" -f $a.ActionId, $a.Type, $a.Status) }
    Assert-Demo ($run1.Status -eq 'PartiallyCompleted') 'run 1 reported as PartiallyCompleted, not success'
    $verify1 = Test-ADOffboardingResult -Plan $plan -Result $run1 -Config $cfg
    Assert-Demo (-not $verify1.Passed) 'verification of the partial run does NOT pass'

    Write-DemoStep '5. Resume (failure cleared) - only unfinished work is attempted'
    $global:FakeAD.FailWrite.Clear()
    $writesBefore = $global:FakeAD.WriteLog.Count
    $run2 = Invoke-ADOffboardingPlan -PlanPath $planPath -Config $cfg -ConfirmPlanId $plan.PlanId -Confirm:$false -ResumeFrom $run1
    Write-DemoLine ("Run 2 status: {0}" -f $run2.Status)
    foreach ($a in $run2.Actions) { Write-DemoLine ("  {0} {1,-22} {2} (attempts={3})" -f $a.ActionId, $a.Type, $a.Status, $a.Attempts) }
    $newWrites = @($global:FakeAD.WriteLog | Select-Object -Skip $writesBefore)
    foreach ($w in $newWrites) { Write-DemoLine ("  AD write on resume: {0}" -f $w) }
    Assert-Demo ($run2.Status -eq 'Succeeded') 'resume completed the plan'
    Assert-Demo (@($newWrites | Where-Object { $_ -like 'Disable-ADAccount*' }).Count -eq 0) 'resume did not repeat the already-successful disable'

    Write-DemoStep '6. Verification and before/after evidence'
    $verify2 = Test-ADOffboardingResult -Plan $plan -Result $run2 -Config $cfg
    Write-DemoLine ("Verification passed: {0}" -f $verify2.Passed)
    Write-DemoLine ("BEFORE: Enabled={0}  OU={1}  Direct={2}" -f $snap.Target.Enabled, $snap.Target.OrganizationalUnit, (@($snap.DirectGroups.Name) -join ', '))
    Write-DemoLine ("AFTER : Enabled={0}  OU={1}  Direct={2}" -f $verify2.AfterState.Enabled, $verify2.AfterState.ParentDn, (@($verify2.AfterState.DirectGroups) -join ', '))
    foreach ($g in $verify2.ResidualInheritedMemberships) { Write-DemoLine ("  STILL INHERITED: {0} via {1}" -f $g.Group, (@($g.Path) -join ' > ')) }
    Assert-Demo $verify2.Passed 'final verification passed for the planned changes'
    Assert-Demo (@($verify2.Items | Where-Object Category -eq 'RetainedGroup').Count -ge 1) 'retained group verified as still a direct member'
    Assert-Demo (@($verify2.ResidualInheritedMemberships).Count -ge 1) 'inherited access paths that remain are reported (not treated as removed)'

    Write-DemoStep '7. Evidence reports'
    $report = Export-ADIdentityReport -Plan $plan -Result $run2 -Verification $verify2 -Snapshot $snap `
        -OutputDirectory $cfg.Output.ReportDirectory -Label 'SIMULATED - synthetic data, in-memory directory'
    Write-DemoLine ("JSON: {0}" -f $report.JsonPath)
    Write-DemoLine ("CSV : {0}" -f $report.CsvPath)
    Write-DemoLine ("HTML: {0}" -f $report.HtmlPath)
    Write-DemoLine ''
    Write-DemoLine 'Demo complete. Results above are SIMULATED; they say nothing about behavior against a real domain.'

    [pscustomobject][ordered]@{
        Simulated     = $true
        OutputDirectory = $OutputDirectory
        PlanPath      = $planPath
        FirstRun      = $run1.Status
        ResumeRun     = $run2.Status
        Verified      = $verify2.Passed
        JsonPath      = $report.JsonPath
        CsvPath       = $report.CsvPath
        HtmlPath      = $report.HtmlPath
    }
}
finally {
    Remove-Module ADIdentityOps -ErrorAction Ignore
    Remove-FakeAD
}

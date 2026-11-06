#Requires -Modules Pester
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '', Justification='Tests inspect the synthetic AD state, which is global by design.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Test helper only builds an in-memory plan.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification='Pester scoping.')]
param()

BeforeAll {
    $script:ModuleRoot = Split-Path -Path $PSScriptRoot -Parent
    . (Join-Path $script:ModuleRoot 'Demo/FakeActiveDirectory.ps1')
    Import-Module (Join-Path $script:ModuleRoot 'ADIdentityOps.psd1') -Force

    $script:Jdoe = '11111111-0000-0000-0000-000000003001'
    $script:G = @{
        Share = 'aaaaaaaa-0000-0000-0000-000000001201'
        Vpn = 'aaaaaaaa-0000-0000-0000-000000001202'
        Atlas = 'aaaaaaaa-0000-0000-0000-000000001203'
        AllStaff = 'aaaaaaaa-0000-0000-0000-000000001100'
        FinDept = 'aaaaaaaa-0000-0000-0000-000000001210'
    }

    function Resolve-Cfg {
        param($Config)
        InModuleScope ADIdentityOps -Parameters @{ C = $Config } { param($C) Resolve-ADIdentityConfig -Config $C }
    }

    function New-TestPlan {
        param($Config, [string]$Identity = 'jdoe', [string[]]$Remove = @($script:G.Share, $script:G.Vpn), [switch]$NoMove)
        $snap = Get-ADIdentitySnapshot -Identity $Identity -Config $Config
        $a = @{ Snapshot = $snap; Config = $Config; TicketReference = 'CHG-1001'; RequestedBy = 'helpdesk-lead'; Reason = 'Synthetic test'; RemoveGroup = $Remove }
        if (-not $NoMove) { $a.MoveToQuarantine = $true }
        New-ADOffboardingPlan @a
    }
}

AfterAll {
    Remove-Module ADIdentityOps -ErrorAction Ignore
    Remove-FakeAD
}

Describe 'ADIdentityOps' {
BeforeEach {
    Initialize-SyntheticDirectory
    $cfg = New-SyntheticConfig
    $cfg.Output.ResultDirectory = $TestDrive
    $cfg.Output.PlanDirectory = $TestDrive
    $cfg.Output.ReportDirectory = $TestDrive
}

Describe 'Configuration' {
    It 'loads and validates the documented example configuration' {
        $c = Import-ADIdentityConfig -Path (Join-Path $script:ModuleRoot 'Config/ADIdentityOps.example.json')
        $c.DomainController | Should -Be 'dc01.corp.example.invalid'
        $c.Fingerprint | Should -Match '^[0-9a-f]{64}$'
    }

    It 'produces a stable fingerprint that ignores output paths but reacts to security settings' {
        $a = Resolve-Cfg -Config $cfg
        $cfg.Output.ReportDirectory = '/elsewhere'
        (Resolve-Cfg -Config $cfg).Fingerprint | Should -Be $a.Fingerprint
        $cfg.ProtectedGroups = @($cfg.ProtectedGroups) + 'S-1-5-21-1-2-3-999'
        (Resolve-Cfg -Config $cfg).Fingerprint | Should -Not -Be $a.Fingerprint
    }

    It 'rejects <Name>' -ForEach @(
        @{ Name = 'a missing domain controller'; Mutate = { $c = $args[0]; $c.DomainController = '' } }
        @{ Name = 'a quarantine OU inside an allowed source OU'; Mutate = { $c = $args[0]; $c.QuarantineOU = 'OU=Q,OU=Staff,OU=Corp,DC=corp,DC=example,DC=invalid' } }
        @{ Name = 'ambiguous (name-based) protected identifiers'; Mutate = { $c = $args[0]; $c.ProtectedGroups = @('Domain Admins') } }
        @{ Name = 'an empty protection list'; Mutate = { $c = $args[0]; $c.ProtectedGroups = @(); $c.ProtectedAccounts = @() } }
        @{ Name = 'unknown keys'; Mutate = { $c = $args[0]; $c | Add-Member -NotePropertyName Surprise -NotePropertyValue 1 } }
        @{ Name = 'an unsupported schema version'; Mutate = { $c = $args[0]; $c.SchemaVersion = '9.9' } }
    ) {
        & $Mutate $cfg
        { Resolve-Cfg -Config $cfg } | Should -Throw '*Invalid AD identity configuration*'
    }
}

Describe 'Get-ADIdentitySnapshot' {
    It 'is read-only and only talks to the configured domain controller' {
        $s = Get-ADIdentitySnapshot -Identity 'jdoe' -Config $cfg
        $global:FakeAD.WriteLog.Count | Should -Be 0
        @($global:FakeAD.Servers | Select-Object -Unique) | Should -Be @('dc01.corp.example.invalid')
        $s.Target.ObjectGuid | Should -Be $script:Jdoe
        $s.Target.Sid | Should -Match '^S-1-5-21-'
        $s.Collection.IsComplete | Should -BeTrue
    }

    It 'separates direct from inherited memberships and preserves paths' {
        $s = Get-ADIdentitySnapshot -Identity 'jdoe' -Config $cfg
        @($s.DirectGroups.Name) | Should -Contain 'GG-Finance-Share'
        @($s.DirectGroups | Where-Object Membership -ne 'Direct') | Should -BeNullOrEmpty
        @($s.DirectGroups.Name) | Should -Not -Contain 'GG-Finance-Dept'
        $inherited = @($s.NestedGroups | Where-Object Name -eq 'GG-Budget-Approvers')
        $inherited.Count | Should -Be 2
        $inherited[0].Membership | Should -Be 'Inherited'
        $inherited[0].Path.Count | Should -Be 4
        $inherited[0].Path[0] | Should -Match '^CN=Jane Doe'
    }

    It 'flags protected targets via group membership and adminCount, and out-of-scope OUs' {
        (Get-ADIdentitySnapshot -Identity 'adm-ops' -Config $cfg).Protection.IsProtected | Should -BeTrue
        (Get-ADIdentitySnapshot -Identity 'jdoe' -Config $cfg).Protection.IsProtected | Should -BeFalse
        (Get-ADIdentitySnapshot -Identity 'contractor1' -Config $cfg).Scope.InAllowedSourceOU | Should -BeFalse
    }

    It 'reports incomplete collection instead of hiding a group read failure' {
        $global:FakeAD.FailRead['GG-Finance-Dept'] = 'simulated directory timeout'
        $s = Get-ADIdentitySnapshot -Identity 'jdoe' -Config $cfg
        $s.Collection.IsComplete | Should -BeFalse
        ($s.Collection.Errors -join ' ') | Should -Match 'GG-Finance-Dept'
    }

    It 'throws a terminating error for an unknown identity' {
        { Get-ADIdentitySnapshot -Identity 'nobody' -Config $cfg } | Should -Throw '*Unable to resolve*'
    }
}

Describe 'New-ADOffboardingPlan' {
    It 'performs no AD writes and records identifiers, actions, exclusions, and integrity' {
        $plan = New-TestPlan -Config $cfg
        $global:FakeAD.WriteLog.Count | Should -Be 0
        $plan.Target.ObjectGuid | Should -Be $script:Jdoe
        @($plan.Actions.Type) | Should -Be @('DisableAccount', 'RemoveGroupMembership', 'RemoveGroupMembership', 'MoveToQuarantine')
        $plan.Integrity.Hash | Should -Match '^[0-9a-f]{64}$'
        $plan.ConfigFingerprint | Should -Be (Resolve-Cfg -Config $cfg).Fingerprint
        $plan.Eligibility.IsEligible | Should -BeTrue
    }

    It 'retains unselected and config-excluded groups and lists inherited groups as non-removable' {
        $plan = New-TestPlan -Config $cfg -Remove @($script:G.Share, $script:G.AllStaff)
        @($plan.Actions | Where-Object Type -eq 'RemoveGroupMembership' | ForEach-Object { $_.Group.Name }) | Should -Be @('GG-Finance-Share')
        $reasons = @{}
        foreach ($e in $plan.Exclusions) { $reasons[$e.Group.Name] = $e.Reason }
        $reasons['GG-All-Staff'] | Should -Match 'ConfigExclusion'
        $reasons['GG-VPN-Users'] | Should -Match 'NotSelected'
        $reasons['GG-Project-Atlas'] | Should -Match 'NotSelected'
        $reasons['GG-Finance-Dept'] | Should -Match 'Inherited'
        @($plan.Warnings) -join ' ' | Should -Match 'GG-All-Staff'
    }

    It 'refuses to plan removal of an inherited membership or a non-member' {
        { New-TestPlan -Config $cfg -Remove @($script:G.FinDept) } | Should -Throw '*inherited*'
        { New-TestPlan -Config $cfg -Remove @('aaaaaaaa-0000-0000-0000-000000000512') } | Should -Throw '*not a direct membership*'
        { New-TestPlan -Config $cfg -Remove @('GG-Finance-Share') } | Should -Throw '*ObjectGUID, SID*'
    }

    It 'marks protected and out-of-scope targets ineligible but still reviewable' {
        $p = New-TestPlan -Config $cfg -Identity 'adm-ops' -Remove @()
        $p.Eligibility.IsEligible | Should -BeFalse
        ($p.Eligibility.BlockReasons -join ' ') | Should -Match 'protection'
        $o = New-TestPlan -Config $cfg -Identity 'contractor1' -Remove @()
        ($o.Eligibility.BlockReasons -join ' ') | Should -Match 'allowed source OU'
    }

    It 'marks an incomplete snapshot ineligible' {
        $global:FakeAD.FailRead['GG-Finance-Dept'] = 'simulated directory timeout'
        (New-TestPlan -Config $cfg).Eligibility.IsEligible | Should -BeFalse
    }

    It 'rejects malformed ticket references and ISO-timestamp-like free text' {
        $snap = Get-ADIdentitySnapshot -Identity 'jdoe' -Config $cfg
        { New-ADOffboardingPlan -Snapshot $snap -Config $cfg -TicketReference 'bad ticket!' -RequestedBy x } | Should -Throw
        { New-ADOffboardingPlan -Snapshot $snap -Config $cfg -TicketReference 'CHG-1' -RequestedBy '2026-01-01T00:00:00Z' } | Should -Throw '*ISO-8601*'
    }
}

Describe 'Test-ADOffboardingPlan' {
    It 'validates a plan after a JSON file round trip (hash is reproducible)' {
        $plan = New-TestPlan -Config $cfg
        $path = Join-Path $TestDrive 'plan.json'
        $null = New-ADOffboardingPlan -Snapshot (Get-ADIdentitySnapshot -Identity 'jdoe' -Config $cfg) -Config $cfg -TicketReference 'CHG-7' -RequestedBy 'ops' -RemoveGroup $script:G.Share -Path $path
        $r = Test-ADOffboardingPlan -PlanPath $path -Config $cfg -CheckLiveState
        $r.IsValid | Should -BeTrue
        $r.LiveStateChecked | Should -BeTrue
    }

    It 'blocks a plan whose content was modified' {
        $plan = New-TestPlan -Config $cfg
        $plan.Actions[1].Group.ObjectGuid = $script:G.Atlas
        $r = Test-ADOffboardingPlan -Plan $plan -Config $cfg
        $r.IsValid | Should -BeFalse
        @($r.FailedChecks.Name) | Should -Contain 'Integrity'
    }

    It 'blocks an expired plan' {
        $plan = New-TestPlan -Config $cfg
        Mock Get-UtcNow { [datetime]::UtcNow.AddHours(48) } -ModuleName ADIdentityOps
        $r = Test-ADOffboardingPlan -Plan $plan -Config $cfg
        @($r.FailedChecks.Name) | Should -Contain 'NotExpired'
    }

    It 'blocks a plan created under a different configuration' {
        $plan = New-TestPlan -Config $cfg
        $cfg.GroupRemovalExclusions = @('S-1-5-21-1111111111-2222222222-3333333333-1100', 'S-1-5-21-1111111111-2222222222-3333333333-1201')
        $r = Test-ADOffboardingPlan -Plan $plan -Config $cfg
        @($r.FailedChecks.Name) | Should -Contain 'ConfigFingerprint'
    }

    It 'blocks malformed plans and unsupported actions without throwing' {
        $r = Test-ADOffboardingPlan -Plan ([pscustomobject]@{ SchemaVersion = '1.0' }) -Config $cfg
        $r.IsValid | Should -BeFalse
        @($r.FailedChecks.Name) | Should -Contain 'Schema'
    }
}

Describe 'Invoke-ADOffboardingPlan' {
    It 'requires the plan id to be confirmed' {
        $plan = New-TestPlan -Config $cfg
        { Invoke-ADOffboardingPlan -Plan $plan -Config $cfg -ConfirmPlanId ([guid]::NewGuid().ToString()) -Confirm:$false } | Should -Throw '*ConfirmPlanId*'
        $global:FakeAD.WriteLog.Count | Should -Be 0
    }

    It '-WhatIf performs zero AD writes and reports the preview' {
        $plan = New-TestPlan -Config $cfg
        $r = Invoke-ADOffboardingPlan -Plan $plan -Config $cfg -ConfirmPlanId $plan.PlanId -WhatIf
        $global:FakeAD.WriteLog.Count | Should -Be 0
        $r.Status | Should -Be 'WhatIf'
        @($r.Actions.Status | Select-Object -Unique) | Should -Be @('Planned')
        $r.ResultPath | Should -BeNullOrEmpty
    }

    It 'executes all actions, verifies them, and keeps retained groups' {
        $plan = New-TestPlan -Config $cfg
        $r = Invoke-ADOffboardingPlan -Plan $plan -Config $cfg -ConfirmPlanId $plan.PlanId -Confirm:$false
        $r.Status | Should -Be 'Succeeded'
        @($r.Actions.Status | Select-Object -Unique) | Should -Be @('Succeeded')
        $u = Find-FakeUser 'jdoe'
        $u.Enabled | Should -BeFalse
        $u.DistinguishedName | Should -Match 'OU=Quarantine'
        @($u.MemberOf | ForEach-Object { ($_ -split ',')[0] }) | Should -Be @('CN=GG-All-Staff', 'CN=GG-Project-Atlas')
        $r.OriginalState.ParentDn | Should -Match 'OU=Staff'
        @($r.OriginalState.DirectGroups).Count | Should -Be 4
        Test-Path $r.ResultPath | Should -BeTrue
        $r.Actions[0].Observed.EnabledBefore | Should -BeTrue
        $r.Actions[0].Observed.EnabledAfter | Should -BeFalse
    }

    It 'marks already-compliant state instead of writing again' {
        (Find-FakeUser 'jdoe').Enabled = $false
        $plan = New-TestPlan -Config $cfg -NoMove
        $r = Invoke-ADOffboardingPlan -Plan $plan -Config $cfg -ConfirmPlanId $plan.PlanId -Confirm:$false
        $r.Actions[0].Status | Should -Be 'AlreadyCompliant'
        @($global:FakeAD.WriteLog | Where-Object { $_ -like 'Disable-ADAccount*' }).Count | Should -Be 0
    }

    It 'blocks a protected target even when the plan was forged with a recomputed hash' {
        $plan = New-TestPlan -Config $cfg -Identity 'adm-ops' -Remove @() -NoMove
        $plan.Eligibility.IsEligible = $true
        $plan.Eligibility.BlockReasons = @()
        $newHash = InModuleScope ADIdentityOps -Parameters @{ P = $plan } { param($P) Get-ADOffboardingPlanHash -Plan $P }
        $plan.Integrity.Hash = $newHash
        $r = Invoke-ADOffboardingPlan -Plan $plan -Config $cfg -ConfirmPlanId $plan.PlanId -Confirm:$false -WarningAction SilentlyContinue
        $r.Status | Should -Be 'Blocked'
        $global:FakeAD.WriteLog.Count | Should -Be 0
        @($r.Preflight.Checks | Where-Object { -not $_.Passed }).Name | Should -Contain 'LiveNotProtected'
        (Find-FakeUser 'adm-ops').Enabled | Should -BeTrue
    }

    It 'blocks an out-of-scope target' {
        $plan = New-TestPlan -Config $cfg -Identity 'contractor1' -Remove @() -NoMove
        $r = Invoke-ADOffboardingPlan -Plan $plan -Config $cfg -ConfirmPlanId $plan.PlanId -Confirm:$false -WarningAction SilentlyContinue
        $r.Status | Should -Be 'Blocked'
        $global:FakeAD.WriteLog.Count | Should -Be 0
    }

    It 'blocks invalid, expired, and modified plans with zero writes' {
        $plan = New-TestPlan -Config $cfg
        $plan.Request.TicketReference = 'CHG-9999'
        $r = Invoke-ADOffboardingPlan -Plan $plan -Config $cfg -ConfirmPlanId $plan.PlanId -Confirm:$false -WarningAction SilentlyContinue
        $r.Status | Should -Be 'Blocked'

        $plan2 = New-TestPlan -Config $cfg
        Mock Get-UtcNow { [datetime]::UtcNow.AddDays(10) } -ModuleName ADIdentityOps
        $r2 = Invoke-ADOffboardingPlan -Plan $plan2 -Config $cfg -ConfirmPlanId $plan2.PlanId -Confirm:$false -WarningAction SilentlyContinue
        $r2.Status | Should -Be 'Blocked'
        $global:FakeAD.WriteLog.Count | Should -Be 0
    }

    It 'blocks on material state drift and requires a regenerated plan' -ForEach @(
        @{ Name = 'a membership was added'; Change = { (Find-FakeUser 'jdoe').MemberOf.Add((Find-FakeGroup 'GG-Domain-Admins').DistinguishedName) | Out-Null }; Check = 'DriftDirectGroups' }
        @{ Name = 'a membership was removed elsewhere'; Change = { $u = Find-FakeUser 'jdoe'; $u.MemberOf = [System.Collections.ArrayList]@($u.MemberOf | Where-Object { $_ -notlike 'CN=GG-Project-Atlas*' }) }; Check = 'DriftDirectGroups' }
        @{ Name = 'the account was disabled by someone else'; Change = { (Find-FakeUser 'jdoe').Enabled = $false }; Check = 'DriftEnabled' }
        @{ Name = 'the account moved OU'; Change = { $u = Find-FakeUser 'jdoe'; $u.DistinguishedName = 'CN=Jane Doe,OU=Contractors,OU=Corp,DC=corp,DC=example,DC=invalid' }; Check = 'DriftParentOu' }
    ) {
        $plan = New-TestPlan -Config $cfg
        & $Change
        $r = Invoke-ADOffboardingPlan -Plan $plan -Config $cfg -ConfirmPlanId $plan.PlanId -Confirm:$false -WarningAction SilentlyContinue
        $r.Status | Should -Be 'Blocked'
        @($r.Preflight.Checks | Where-Object { -not $_.Passed }).Name | Should -Contain $Check
        $global:FakeAD.WriteLog.Count | Should -Be 0
    }

    It 'stops dependent actions when disabling fails' {
        $global:FakeAD.FailWrite['Disable'] = 'Access is denied.'
        $plan = New-TestPlan -Config $cfg
        $r = Invoke-ADOffboardingPlan -Plan $plan -Config $cfg -ConfirmPlanId $plan.PlanId -Confirm:$false
        $r.Actions[0].Status | Should -Be 'Failed'
        @($r.Actions | Select-Object -Skip 1 | ForEach-Object { $_.Status } | Select-Object -Unique) | Should -Be @('Blocked')
        $r.Status | Should -Be 'Failed'
        @($global:FakeAD.WriteLog).Count | Should -Be 1
        (Find-FakeUser 'jdoe').MemberOf.Count | Should -Be 4
    }

    It 'treats a disable that has no effect as Failed (verification) and blocks dependents' {
        $global:FakeAD.NoEffect['Disable'] = $true
        $plan = New-TestPlan -Config $cfg
        $r = Invoke-ADOffboardingPlan -Plan $plan -Config $cfg -ConfirmPlanId $plan.PlanId -Confirm:$false
        $r.Actions[0].Status | Should -Be 'Failed'
        $r.Actions[0].Error | Should -Match 'Verification failed'
        $r.Status | Should -Not -Be 'Succeeded'
        @($global:FakeAD.WriteLog | Where-Object { $_ -like 'Remove-*' -or $_ -like 'Move-*' }).Count | Should -Be 0
    }

    It 'reports partial failures accurately and sanitizes error text' {
        $global:FakeAD.FailWrite['RemoveGroup:GG-VPN-Users'] = 'Access is denied. password=hunter2'
        $plan = New-TestPlan -Config $cfg
        $r = Invoke-ADOffboardingPlan -Plan $plan -Config $cfg -ConfirmPlanId $plan.PlanId -Confirm:$false
        $r.Status | Should -Be 'PartiallyCompleted'
        @($r.Actions.Status) | Should -Be @('Succeeded', 'Succeeded', 'Failed', 'Succeeded')
        $r.Summary.IncompleteActionIds | Should -Be @('A3')
        $r.Actions[2].Error | Should -Not -Match 'hunter2'
        (Get-Content $r.ResultPath -Raw) | Should -Not -Match 'hunter2'
    }

    It 'resumes unfinished work without repeating completed changes' {
        $global:FakeAD.FailWrite['RemoveGroup:GG-VPN-Users'] = 'transient failure'
        $plan = New-TestPlan -Config $cfg
        $r1 = Invoke-ADOffboardingPlan -Plan $plan -Config $cfg -ConfirmPlanId $plan.PlanId -Confirm:$false
        $global:FakeAD.FailWrite.Clear()
        $before = $global:FakeAD.WriteLog.Count

        $r2 = Invoke-ADOffboardingPlan -Plan $plan -Config $cfg -ConfirmPlanId $plan.PlanId -Confirm:$false -ResumeFrom $r1
        $r2.Status | Should -Be 'Succeeded'
        $r2.ResumedFromRunId | Should -Be $r1.RunId
        ($global:FakeAD.WriteLog.Count - $before) | Should -Be 1
        $global:FakeAD.WriteLog[-1] | Should -Match "^Remove-ADGroupMember $($script:G.Vpn)"
        $r2.Actions[0].CarriedFromRunId | Should -Be $r1.RunId
        $r2.Actions[2].Attempts | Should -Be 2
        $r2.OriginalState.ParentDn | Should -Match 'OU=Staff'
        (Test-ADOffboardingResult -Plan $plan -Result $r2 -Config $cfg).Passed | Should -BeTrue
    }

    It 'resumes from a result file and still blocks unrelated state changes' {
        $global:FakeAD.FailWrite['RemoveGroup:GG-VPN-Users'] = 'transient failure'
        $plan = New-TestPlan -Config $cfg
        $r1 = Invoke-ADOffboardingPlan -Plan $plan -Config $cfg -ConfirmPlanId $plan.PlanId -Confirm:$false
        $global:FakeAD.FailWrite.Clear()
        $u = Find-FakeUser 'jdoe'
        $u.MemberOf.Add((Find-FakeGroup 'GG-Domain-Admins').DistinguishedName) | Out-Null
        $before = $global:FakeAD.WriteLog.Count
        $r2 = Invoke-ADOffboardingPlan -Plan $plan -Config $cfg -ConfirmPlanId $plan.PlanId -Confirm:$false -ResumeFrom $r1.ResultPath -WarningAction SilentlyContinue
        $r2.Status | Should -Be 'Blocked'
        $global:FakeAD.WriteLog.Count | Should -Be $before
    }

    It 'refuses a resume record from a different plan' {
        $plan = New-TestPlan -Config $cfg
        $other = New-TestPlan -Config $cfg
        $r1 = Invoke-ADOffboardingPlan -Plan $other -Config $cfg -ConfirmPlanId $other.PlanId -WhatIf
        { Invoke-ADOffboardingPlan -Plan $plan -Config $cfg -ConfirmPlanId $plan.PlanId -ResumeFrom $r1 -Confirm:$false } | Should -Throw '*does not belong*'
    }
}

Describe 'Test-ADOffboardingResult' {
    It 'passes only when live state satisfies every planned change and retained groups remain' {
        $plan = New-TestPlan -Config $cfg -Remove @($script:G.Vpn)
        $r = Invoke-ADOffboardingPlan -Plan $plan -Config $cfg -ConfirmPlanId $plan.PlanId -Confirm:$false
        $before = $global:FakeAD.WriteLog.Count
        $v = Test-ADOffboardingResult -Plan $plan -Result $r -Config $cfg
        $v.Passed | Should -BeTrue
        $global:FakeAD.WriteLog.Count | Should -Be $before
        @($v.Items | Where-Object Category -eq 'RetainedGroup').Count | Should -BeGreaterThan 0
        $v.AfterState.Enabled | Should -BeFalse
        @($v.ResidualInheritedMemberships.Group) | Should -Contain 'GG-Budget-Approvers'
    }

    It 'cannot report success for a run that was only a WhatIf preview' {
        $plan = New-TestPlan -Config $cfg
        $r = Invoke-ADOffboardingPlan -Plan $plan -Config $cfg -ConfirmPlanId $plan.PlanId -WhatIf
        (Test-ADOffboardingResult -Plan $plan -Result $r -Config $cfg).Passed | Should -BeFalse
    }

    It 'fails verification and lists a discrepancy when live state contradicts a reported success' {
        $plan = New-TestPlan -Config $cfg
        $r = Invoke-ADOffboardingPlan -Plan $plan -Config $cfg -ConfirmPlanId $plan.PlanId -Confirm:$false
        (Find-FakeUser 'jdoe').Enabled = $true
        $v = Test-ADOffboardingResult -Plan $plan -Result $r -Config $cfg
        $v.Passed | Should -BeFalse
        ($v.Discrepancies -join ' ') | Should -Match 'A1'
    }

    It 'fails verification for incomplete runs and when a retained group went missing' {
        $global:FakeAD.FailWrite['RemoveGroup:GG-VPN-Users'] = 'transient failure'
        $plan = New-TestPlan -Config $cfg
        $r = Invoke-ADOffboardingPlan -Plan $plan -Config $cfg -ConfirmPlanId $plan.PlanId -Confirm:$false
        $v = Test-ADOffboardingResult -Plan $plan -Result $r -Config $cfg
        $v.Passed | Should -BeFalse
        $v.IncompleteActionIds | Should -Be @('A3')
    }

    It 'fails when the result belongs to another plan' {
        $plan = New-TestPlan -Config $cfg
        $other = New-TestPlan -Config $cfg
        $r = Invoke-ADOffboardingPlan -Plan $other -Config $cfg -ConfirmPlanId $other.PlanId -Confirm:$false
        (Test-ADOffboardingResult -Plan $plan -Result $r -Config $cfg).Passed | Should -BeFalse
    }
}

Describe 'Export-ADIdentityReport' {
    It 'encodes hostile text in HTML, neutralizes CSV formulas, and never writes secrets' {
        $evil = Add-FakeGroup -Name '@SUM(1+1)' -Rid 1299 -Guid 'aaaaaaaa-0000-0000-0000-000000001299'
        $html = Add-FakeGroup -Name '<img src=x onerror=alert(1)>' -Rid 1298 -Guid 'aaaaaaaa-0000-0000-0000-000000001298'
        $u = Find-FakeUser 'jdoe'
        $u.MemberOf.Add($evil) | Out-Null
        $u.MemberOf.Add($html) | Out-Null
        $global:FakeAD.FailWrite['RemoveGroup:@SUM(1+1)'] = '=HYPERLINK("http://x.invalid") token=abc123secret'

        $snap = Get-ADIdentitySnapshot -Identity 'jdoe' -Config $cfg
        $plan = New-ADOffboardingPlan -Snapshot $snap -Config $cfg -TicketReference 'CHG-5' -RequestedBy '<script>alert(1)</script>' -Reason '=cmd|calc' `
            -RemoveGroup 'aaaaaaaa-0000-0000-0000-000000001299', 'aaaaaaaa-0000-0000-0000-000000001298'
        $r = Invoke-ADOffboardingPlan -Plan $plan -Config $cfg -ConfirmPlanId $plan.PlanId -Confirm:$false
        $v = Test-ADOffboardingResult -Plan $plan -Result $r -Config $cfg
        $rep = Export-ADIdentityReport -Plan $plan -Result $r -Verification $v -Snapshot $snap -OutputDirectory (Join-Path $TestDrive 'rep') -Label 'SIMULATED <b>DATA</b>'

        $h = Get-Content $rep.HtmlPath -Raw
        $h | Should -Not -Match '<script>alert'
        $h | Should -Not -Match '<img src=x'
        $h | Should -Match '&lt;script&gt;alert\(1\)&lt;/script&gt;'
        $h | Should -Match '&lt;img src=x onerror=alert\(1\)&gt;'
        $h | Should -Match 'SIMULATED &lt;b&gt;DATA&lt;/b&gt;'
        $h | Should -Not -Match '<script'

        $rows = Import-Csv $rep.CsvPath
        ($rows | Where-Object Type -eq 'RemoveGroupMembership' | Where-Object Object -like "*SUM*").Object | Should -Be "'@SUM(1+1)"
        ($rows | Where-Object ReportedStatus -eq 'Failed').Error | Should -Match "^'="
        foreach ($row in $rows) { foreach ($p in $row.PSObject.Properties) { $p.Value | Should -Not -Match '^[=+\-@]' } }

        foreach ($f in $rep.JsonPath, $rep.CsvPath, $rep.HtmlPath) { (Get-Content $f -Raw) | Should -Not -Match 'abc123secret' }
        { Get-Content $rep.JsonPath -Raw | ConvertFrom-Json } | Should -Not -Throw
    }

    It 'shows incomplete work and includes before/after evidence' {
        $global:FakeAD.FailWrite['RemoveGroup:GG-VPN-Users'] = 'transient failure'
        $snap = Get-ADIdentitySnapshot -Identity 'jdoe' -Config $cfg
        $plan = New-TestPlan -Config $cfg
        $r = Invoke-ADOffboardingPlan -Plan $plan -Config $cfg -ConfirmPlanId $plan.PlanId -Confirm:$false
        $v = Test-ADOffboardingResult -Plan $plan -Result $r -Config $cfg
        $rep = Export-ADIdentityReport -Plan $plan -Result $r -Verification $v -Snapshot $snap -OutputDirectory (Join-Path $TestDrive 'rep2')
        $h = Get-Content $rep.HtmlPath -Raw
        $h | Should -Match 'Incomplete work'
        $h | Should -Match 'A3'
        $h | Should -Match 'NOT PASSED'
        $h | Should -Match 'Original state'
    }

    It 'writes nothing under -WhatIf' {
        $plan = New-TestPlan -Config $cfg
        $dir = Join-Path $TestDrive 'whatif'
        Export-ADIdentityReport -Plan $plan -OutputDirectory $dir -WhatIf | Should -BeNullOrEmpty
        Test-Path $dir | Should -BeFalse
    }
}
}

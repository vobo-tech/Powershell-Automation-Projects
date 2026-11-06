# ADIdentityOps – AD Identity Operations Toolkit (v0.1.0, pre-pilot)

A PowerShell module for a **controlled, reviewable, verifiable** on-prem Active Directory offboarding workflow:

1. **Discover** – read-only identity snapshot (direct vs. inherited memberships, protection matches).
2. **Plan** – a serializable offboarding plan that changes nothing.
3. **Review / test** – validate the plan (and optionally compare it to live state) without writing.
4. **Execute** – deliberately selected plan, `-WhatIf` supported, fail-closed safeguards.
5. **Verify** – re-read AD and compare to what was planned.
6. **Resume** – retry only unfinished work after revalidation.
7. **Report** – JSON, CSV, and a self-contained HTML evidence report.

> **Status: not production-ready.** It has only been run against a *synthetic in-memory AD fake* (see
> [Validation status](#validation-status)). It has never touched a real domain or the real `ActiveDirectory` module.

## Business problem

Offboarding is usually a mix of ad-hoc clicks and one-off scripts: nobody can answer *what exactly was changed, was it
verified, and what is still outstanding*. This toolkit makes the scope explicit (a reviewed plan), refuses risky targets
by default, stops dependent steps when a prerequisite fails, and leaves evidence.

Initial supported actions: **disable the account**, **remove explicitly selected *direct* group memberships**, and
**move the account to a configured quarantine OU**. Not in this release: deletion, password resets, mailbox actions,
Entra ID session/token revocation, home-folder deletion.

## Layout

| Path | Purpose |
|---|---|
| `ADIdentityOps.psd1 / .psm1` | Module manifest / loader (exports 7 functions) |
| `Public/`, `Private/` | Commands and internal helpers |
| `Config/ADIdentityOps.example.json` | Synthetic example configuration |
| `Demo/FakeActiveDirectory.ps1` | In-memory stand-ins for the AD cmdlets (tests + demo only) |
| `Demo/Invoke-SyntheticDemo.ps1` | Repeatable simulated walkthrough |
| `Tests/` | Pester tests (module + demo). Legacy-script regressions: `../Tests/ExistingScripts.Tests.ps1` |

No naming collisions were found with the commands in the Windows `ActiveDirectory` module (`*-AD*Identity*`,
`*-ADOffboarding*` do not exist there). This was checked by inspection, not on a machine with RSAT installed.

## Prerequisites

* **Supported target:** Windows PowerShell **5.1** or PowerShell **7.x on Windows**, with the RSAT **ActiveDirectory**
  module and network access to the configured domain controller. The code avoids PowerShell-7-only syntax, but only
  PowerShell 7.4 on Linux has actually been executed (against the fake) – see Validation status.
* An account holding only the delegated permissions listed below.
* No dependencies are installed by the module. Pester (tests) and PSScriptAnalyzer (lint) are optional dev tools.

```powershell
Import-Module .\Identity-Access-Management\ADIdentityOps\ADIdentityOps.psd1
```

## Configuration

Copy `Config/ADIdentityOps.example.json` to a path **outside source control** and replace every value.
It is validated on load (`Import-ADIdentityConfig`); invalid configuration fails closed.

| Key | Meaning |
|---|---|
| `SchemaVersion` | Must be `1.0` |
| `DomainController` | **Explicit** DC (FQDN). Every AD call passes `-Server` with this value |
| `AllowedSourceOUs` | Target must be inside one of these OUs (subtree) or it is out of scope |
| `QuarantineOU` | Destination OU; must **not** be inside an allowed source OU |
| `ProtectedAccounts`, `ProtectedGroups` | SIDs / GUIDs / DNs (name-only identifiers are rejected). Targets that match, or are members – direct or nested – of a protected group, or have `adminCount=1`, are blocked |
| `GroupRemovalExclusions` | Groups that can never be selected for removal |
| `PlanLifetimeHours` | Plan expiry |
| `Output.PlanDirectory / ResultDirectory / ReportDirectory` | Output locations (excluded from the configuration fingerprint) |

The configuration **fingerprint** (SHA-256 of the canonical security-relevant settings) is stored in each plan; a plan is
rejected if the configuration changed since it was generated.

## Workflow examples

```powershell
$cfg = Import-ADIdentityConfig -Path C:\secure\ADIdentityOps.json

# 1. Read-only snapshot. Direct and inherited memberships are kept apart; inherited entries carry their path.
$snap = Get-ADIdentitySnapshot -Identity 'S-1-5-21-...-3001' -Config $cfg   # prefer ObjectGUID/SID/DN over names
$snap.DirectGroups; $snap.NestedGroups; $snap.Protection; $snap.Collection   # Collection.IsComplete / Errors

# 2. Plan (no writes). Group removals must be selected explicitly by GUID/SID/DN and must be DIRECT memberships.
$plan = New-ADOffboardingPlan -Snapshot $snap -Config $cfg -TicketReference 'CHG-12345' `
          -RequestedBy 'a.requester' -Reason 'Leaver' -RemoveGroup '<group-guid>' -MoveToQuarantine `
          -Path C:\secure\plans\chg-12345.json
$plan.Actions; $plan.Exclusions; $plan.Eligibility

# 3. Test the plan, including a live comparison against the configured DC (still read-only)
Test-ADOffboardingPlan -PlanPath C:\secure\plans\chg-12345.json -Config $cfg -CheckLiveState

# 4. Preview – performs zero AD writes
Invoke-ADOffboardingPlan -PlanPath C:\secure\plans\chg-12345.json -Config $cfg -ConfirmPlanId $plan.PlanId -WhatIf

# 5. Execute (prompts; -ConfirmPlanId must equal the plan ID)
$run = Invoke-ADOffboardingPlan -PlanPath C:\secure\plans\chg-12345.json -Config $cfg -ConfirmPlanId $plan.PlanId
$run.Status      # Succeeded | PartiallyCompleted | Failed | Blocked | WhatIf
$run.Actions     # per action: Planned/Succeeded/AlreadyCompliant/Failed/Skipped/Blocked, intended vs observed, timestamps

# 6. Verify against live AD
$verify = Test-ADOffboardingResult -Plan $plan -Result $run -Config $cfg
$verify.Passed; $verify.IncompleteActionIds; $verify.ResidualInheritedMemberships

# 7. Resume unfinished work (revalidates plan and live state; completed actions are not repeated)
$run2 = Invoke-ADOffboardingPlan -PlanPath C:\secure\plans\chg-12345.json -Config $cfg `
          -ConfirmPlanId $plan.PlanId -ResumeFrom $run.ResultPath

# 8. Evidence
Export-ADIdentityReport -Plan $plan -Result $run2 -Verification $verify -Snapshot $snap -Config $cfg
```

Core functions return objects; none pipe to `Format-Table`. Format at the call site if you want a table.

## Required delegated permissions (least privilege)

Do **not** use Domain Admin by default. Delegate narrowly on the allowed source OUs / quarantine OU, e.g. with
*Delegation of Control*, to a dedicated operator group, and review with your AD owners:

| Operation | Needed on | Permission |
|---|---|---|
| Snapshot, plan, test, verify | User objects, group objects, source/quarantine OUs | **Read** (including `memberOf`, `objectSid`, `adminCount`, `userAccountControl`) on the DC |
| Disable account | Users in the allowed source OUs | Write `userAccountControl` (or *Disable/enable account* in the delegation wizard) |
| Remove direct group membership | **Each group** to be modified | Write `member` on that group (*Modify the membership of a group*) |
| Move to quarantine | Source OU and quarantine OU | *Delete* (or move-from) child objects on the source OU **and** *Create* user objects on the quarantine OU; `Move-ADObject` also needs write access to the object's name/parent |

Exact ACE requirements depend on your delegation model and must be confirmed in a test domain. Authorization to execute
comes **only** from AD permissions and your change-management process. The plan's `RequestedBy`, `Reason`, and ticket fields
are metadata – a free-text "approved" value is **not** access control.

## Safety model

* Discovery and planning are read-only; `-WhatIf` performs zero AD writes (tests prove no write cmdlet is called).
* Every execution (even `-WhatIf`) first validates: schema, **expiry**, **integrity hash**, target ObjectGUID+SID,
  configuration fingerprint, scope, protection, and then **re-reads live state** from the configured DC.
* **Material drift blocks execution** (enabled state, parent OU, direct group set differ from the plan) → regenerate the plan.
* **Fail closed:** protected targets, out-of-scope targets, unresolved exclusions, incomplete collection, or any failed
  safety check ⇒ `Blocked` with no writes.
* Order: **disable → verify** (re-read) before any group removal or move. A failed or unverified disable blocks dependents.
  Each write is verified by re-reading AD; a write cmdlet succeeding without a changed state is recorded as **Failed**.
* Nested memberships are reported with their path and are **never** removed as if direct. Removing a direct membership may
  leave access via another path – `Test-ADOffboardingResult` reports `ResidualInheritedMemberships`.
* The integrity hash detects modification only; it does **not** prove approval, authorship, or authenticity.
* Error text is sanitized (secret-looking tokens redacted, control characters stripped, length-capped). Reports never
  contain passwords or tokens. HTML output is encoded with a restrictive CSP; CSV cells beginning with `= + - @` (and
  tab/CR) are neutralized against spreadsheet formula injection.

### Partial failures, resume, and recovery limits

* A partial run returns `PartiallyCompleted`, saves a result file, and `Test-ADOffboardingResult` will **not** pass.
* `-ResumeFrom` accepts a result object or file **for the same plan** (plan ID, hash, and target must match). Only unfinished
  actions are attempted. State changed by that same run (e.g. the quarantine move) is credited; any *other* change still blocks.
* **No rollback.** Original OU and original direct memberships are stored in the plan/snapshot as recovery *evidence*.
  Restoring them is a manual, separately authorized action.
* If a disable actually applied but was recorded `Failed`, the plan must be regenerated (drift check).
* Limitations: disabling an AD account does **not** terminate existing sessions, Kerberos tickets, cached credentials, or
  Entra ID / cloud access. Group membership is not proof of effective access. `primaryGroupID` is not handled.
  AD `lastLogonTimestamp` is approximate and is never used as inactivity evidence here.

## Synthetic demo and tests

Everything below uses the in-memory fake; no domain is contacted. Results are **simulated**.

```powershell
# Demo (creates a new run folder under ./out/demo; it does not delete existing contents)
pwsh -NoProfile -File .\Identity-Access-Management\ADIdentityOps\Demo\Invoke-SyntheticDemo.ps1

# Full Identity-Access-Management suite (requires Pester 5+)
$testFiles = @(
  '.\Identity-Access-Management\ADIdentityOps\Tests\ADIdentityOps.Tests.ps1',
  '.\Identity-Access-Management\ADIdentityOps\Tests\SyntheticDemo.Tests.ps1',
  '.\Identity-Access-Management\Tests\ExistingScripts.Tests.ps1'
)
Invoke-Pester -Path $testFiles -Output Detailed

# Static analysis (requires PSScriptAnalyzer)
Invoke-ScriptAnalyzer -Path .\Identity-Access-Management -Recurse -Severity Warning,Error
```

The demo shows an ordinary employee and a protected privileged account (blocked), direct and inherited memberships, a
retained group, a `-WhatIf` run, an injected failed group removal, a resume that does not repeat completed actions,
verification (including inherited paths that remain), and JSON/CSV/HTML reports. Existing files in the selected output
directory are preserved; each demo run writes to a new `run-*` child directory.

Container equivalent (no local PowerShell needed; Pester and PSScriptAnalyzer must be provided separately):
`podman run --rm -v "$PWD:/repo:Z" -w /repo mcr.microsoft.com/powershell pwsh -NoProfile -File Identity-Access-Management/ADIdentityOps/Demo/Invoke-SyntheticDemo.ps1`

## Related fixes to existing scripts (intentional behavior changes)

| Script | Change |
|---|---|
| `PermissionAuditing/Shared/FileSystemRights.ps1` (new), `ReportNTFSPermissions.ps1`, `DetectOverPermissionedAccounts.ps1` | Composite `FileSystemRights` are labelled only when **all** mask bits are present (`($r -band $m) -eq $m`); previously a read-only ACE could be labelled `Modify`/`FullControl`. Rows state they are per-ACE findings, not effective access (`Caveat`, `DenyAcesOnPath`, `ExpansionStatus`); failed group expansion is an error, not "no members". `ExpandedGroupMembers` is the clearer field; legacy `EffectiveUsers` remains as a compatibility alias only. |
| Same + `InactiveAccountReport.ps1`, `PasswordReset.ps1` | Output **objects** instead of `Format-Table` text; previously hidden scan/remediation failures are now recorded and surfaced as errors; incomplete scans warn that their results are incomplete. |
| `BulkUserCreation.ps1` | An **existing** user is skipped *entirely* (no group changes, no home folder). Lookup filter is quote-escaped; a failed lookup is a failure. One result object per row (`Created`, `SkippedExisting`, `WhatIf`, `PartiallyCompleted`, `Failed`); dependent steps are not attempted after a failed create. |
| `InactiveAccountReport.ps1` | Labelled as approximate `LastLogonTimestamp`; move is blocked if the requested disable failed. A pre-existing parse defect (functions before `begin{}`) was fixed in this script and `PasswordReset.ps1`. |

Behavior changes to be aware of: console output of these scripts is now objects (default formatting applies), and some
previously swallowed conditions now emit non-terminating errors (use `-ErrorAction Stop` to make them terminating).

### Shared batch passwords – migration path

`BulkUserCreation.ps1 -DefaultPassword` gives every new account the same initial secret. Migrate to either (a) unique random
per-account passwords delivered through your approved credential-delivery process (never logged or exported), or (b) accounts
created disabled/without a usable password and activated through helpdesk or self-service enrollment, keeping
change-at-next-logon. `PasswordReset.ps1 -GenerateRandom` still returns generated passwords in its output/CSV; treat them
as secrets. Credential delivery is intentionally **not** implemented here.

## Validation status

| Item | Status |
|---|---|
| Pester tests against the synthetic fake / mocks | **Passed:** 77/77 on PowerShell 7.4.2 (Linux container), Pester 6.2.0: 49 module tests, 1 demo test, and 27 legacy-script regression tests. |
| PSScriptAnalyzer | **Run:** PSScriptAnalyzer 1.23.0 against the module, changed scripts, and tests; zero Warning/Error findings. |
| Windows PowerShell 5.1 | **Not run.** The manifest declares 5.1 and the code was statically inspected for newer-only syntax, but execution remains unverified. |
| Real `ActiveDirectory` module / a real DC | **Never run.** Parameter behavior (e.g. `Move-ADObject`, `Get-ADUser -Properties`) is assumed from documentation |
| Production readiness | **Not claimed** |

Exact compatibility and analyzer follow-up commands, to run once under `powershell.exe` 5.1 and again under `pwsh` 7.x on
a Windows test host (after Pester and PSScriptAnalyzer are available from an approved source):

```powershell
$PSVersionTable
Test-ModuleManifest .\Identity-Access-Management\ADIdentityOps\ADIdentityOps.psd1
$testFiles = @(
  '.\Identity-Access-Management\ADIdentityOps\Tests\ADIdentityOps.Tests.ps1',
  '.\Identity-Access-Management\ADIdentityOps\Tests\SyntheticDemo.Tests.ps1',
  '.\Identity-Access-Management\Tests\ExistingScripts.Tests.ps1'
)
Invoke-Pester -Path $testFiles -Output Detailed
Invoke-ScriptAnalyzer -Path .\Identity-Access-Management -Recurse -Severity Warning,Error
```

## Before a controlled real-domain pilot

* First run the synthetic demo and suite on Windows PowerShell 5.1 **and** 7.x; add integration tests against an isolated **lab** domain with fabricated/test accounts.
* Verify every AD cmdlet's real behavior (identity resolution by GUID/SID, `-Server` handling, `memberOf` and `adminCount`
  availability, referral/trust edge cases, `primaryGroupID`, group scope/size limits, replication delays between DCs).
* Define and test the delegation model above; confirm no broader rights are needed.
* Review protected-account/group lists with the directory owners; add organization-specific protections.
* Decide where plans/results/reports are stored (access control, retention, tamper evidence); consider signing plans if
  authenticity matters – the built-in hash does not provide it.
* Agree the change process (who approves, how approval is recorded) – it is outside the module.
* Pair with the separate steps this release excludes: session/token revocation, Entra ID/M365 handling, mailbox and home-folder policy.
* Pilot on a small set of non-critical, consenting test accounts first, with a documented manual recovery procedure.

The following is a read-only smoke-test sequence for a separately approved lab configuration. It still makes live
directory **queries**, so do not run it against production unless the directory owner has approved the scope:

```powershell
$modulePath = '.\Identity-Access-Management\ADIdentityOps\ADIdentityOps.psd1'
$configPath = 'C:\secure\ADIdentityOps-lab.json' # explicit lab DC and lab OUs only
Import-Module $modulePath -Force
$cfg = Import-ADIdentityConfig -Path $configPath
$snapshot = Get-ADIdentitySnapshot -Identity '<lab-user-object-guid>' -Config $cfg
$plan = New-ADOffboardingPlan -Snapshot $snapshot -Config $cfg -TicketReference 'CHG-LAB-0001' `
  -RequestedBy '<operator>' -Reason 'Controlled lab validation' -RemoveGroup @() -MoveToQuarantine `
  -Path 'C:\secure\plans\lab-user-plan.json'
$validation = Test-ADOffboardingPlan -Plan $plan -Config $cfg -CheckLiveState
if (-not $validation.IsValid) { throw 'Lab plan validation failed; do not execute.' }
Invoke-ADOffboardingPlan -Plan $plan -Config $cfg -ConfirmPlanId $plan.PlanId -WhatIf
```

The `-WhatIf` sequence makes no AD changes. Any subsequent actual execution is a separately approved lab change that
will disable and move the test account; it must use a reviewed plan, authorized delegated credentials, documented
recovery steps, and independent verification. No real-domain pilot or AD write has been performed for this release.

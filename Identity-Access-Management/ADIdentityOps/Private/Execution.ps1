# --- Re-read and execute individual actions ---
# The public executor owns ordering and preflight; these helpers perform and verify one action at a time.
# Read the current account state by GUID from the configured controller.
function Get-ADLiveAccountState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string]$Guid, [Parameter(Mandatory)][string]$Server)
    $u = Get-ADUser -Identity $Guid -Server $Server -Properties Enabled, MemberOf, DistinguishedName -ErrorAction Stop
    if ($null -eq $u) { throw 'Account not found.' }
    $dn = ConvertTo-IdString (Get-ObjectProperty $u 'DistinguishedName')
    [pscustomobject][ordered]@{
        Enabled           = Get-ObjectProperty $u 'Enabled'
        DistinguishedName = $dn
        ParentDn          = Get-ParentDN -DistinguishedName $dn
        MemberOf          = @(@(Get-ObjectProperty $u 'MemberOf') | Where-Object { $_ } | ForEach-Object { [string]$_ })
    }
}

# Resolve the group GUID to its current DN before checking the user's direct memberOf entries.
function Test-ADLiveDirectMember {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$AccountState, [Parameter(Mandatory)][string]$GroupGuid, [Parameter(Mandatory)][string]$Server)
    $g = Get-ADGroup -Identity $GroupGuid -Server $Server -ErrorAction Stop
    $gdn = ConvertTo-NormalizedIdentifier -Value (ConvertTo-IdString (Get-ObjectProperty $g 'DistinguishedName'))
    @($AccountState.MemberOf | Where-Object { (ConvertTo-NormalizedIdentifier -Value $_) -eq $gdn }).Count -gt 0
}

function Invoke-ADOffboardingAction {
    <#
    .SYNOPSIS
        Executes (or previews) one planned action and verifies the outcome by re-reading AD.
        All AD writes live here, each guarded by ShouldProcess.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '', Justification='ShouldProcess is delegated to the calling public cmdlet via the $Cmdlet parameter so -WhatIf/-Confirm apply to the caller.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]$Action,
        [Parameter(Mandatory)]$Plan,
        [Parameter(Mandatory)]$Config,
        [Parameter(Mandatory)]$Cmdlet,
        [bool]$WhatIfMode
    )
    $server = $Config.DomainController
    $guid = [string]$Plan.Target.ObjectGuid
    $label = "$($Plan.Target.SamAccountName) [$guid]"
    $out = [ordered]@{ Status = 'Failed'; Observed = $null; Error = $null }
    $declined = if ($WhatIfMode) { 'Planned' } else { 'Skipped' }

    # Read before each action, including previews. The caller's ShouldProcess gates every AD write;
    # direct cmdlet dispatch also lets the synthetic adapter replace AD commands during tests.
    try {
        $before = Get-ADLiveAccountState -Guid $guid -Server $server
        switch ($Action.Type) {
            'DisableAccount' {
                $obs = [ordered]@{ EnabledBefore = $before.Enabled; EnabledAfter = $before.Enabled }
                $out.Observed = [pscustomobject]$obs
                if ($before.Enabled -eq $false) { $out.Status = 'AlreadyCompliant' }
                elseif ($Cmdlet.ShouldProcess($label, 'Disable AD account')) {
                    Disable-ADAccount -Identity $guid -Server $server -ErrorAction Stop
                    $after = Get-ADLiveAccountState -Guid $guid -Server $server
                    $obs.EnabledAfter = $after.Enabled
                    $out.Observed = [pscustomobject]$obs
                    if ($after.Enabled -eq $false) { $out.Status = 'Succeeded' }
                    else { $out.Error = 'Verification failed: account is still enabled after Disable-ADAccount.' }
                }
                else { $out.Status = $declined }
            }
            'RemoveGroupMembership' {
                $groupGuid = [string]$Action.Group.ObjectGuid
                $isMember = Test-ADLiveDirectMember -AccountState $before -GroupGuid $groupGuid -Server $server
                $obs = [ordered]@{ DirectMemberBefore = $isMember; DirectMemberAfter = $isMember }
                $out.Observed = [pscustomobject]$obs
                if (-not $isMember) { $out.Status = 'AlreadyCompliant' }
                elseif ($Cmdlet.ShouldProcess($label, "Remove direct membership in '$($Action.Group.Name)'")) {
                    Remove-ADGroupMember -Identity $groupGuid -Members $before.DistinguishedName -Server $server -Confirm:$false -ErrorAction Stop
                    $after = Get-ADLiveAccountState -Guid $guid -Server $server
                    $still = Test-ADLiveDirectMember -AccountState $after -GroupGuid $groupGuid -Server $server
                    $obs.DirectMemberAfter = $still
                    $out.Observed = [pscustomobject]$obs
                    if (-not $still) { $out.Status = 'Succeeded' }
                    else { $out.Error = 'Verification failed: account is still a direct member after Remove-ADGroupMember.' }
                }
                else { $out.Status = $declined }
            }
            'MoveToQuarantine' {
                $target = $Config.QuarantineOU
                $obs = [ordered]@{ ParentDnBefore = $before.ParentDn; ParentDnAfter = $before.ParentDn }
                $out.Observed = [pscustomobject]$obs
                if ((ConvertTo-NormalizedIdentifier -Value $before.ParentDn) -eq (ConvertTo-NormalizedIdentifier -Value $target)) { $out.Status = 'AlreadyCompliant' }
                elseif ($Cmdlet.ShouldProcess($label, "Move to quarantine OU '$target'")) {
                    Move-ADObject -Identity $guid -TargetPath $target -Server $server -Confirm:$false -ErrorAction Stop
                    $after = Get-ADLiveAccountState -Guid $guid -Server $server
                    $obs.ParentDnAfter = $after.ParentDn
                    $out.Observed = [pscustomobject]$obs
                    if ((ConvertTo-NormalizedIdentifier -Value $after.ParentDn) -eq (ConvertTo-NormalizedIdentifier -Value $target)) { $out.Status = 'Succeeded' }
                    else { $out.Error = "Verification failed: account parent is '$($after.ParentDn)', expected quarantine OU." }
                }
                else { $out.Status = $declined }
            }
            default { $out.Error = "Unsupported action type '$($Action.Type)'." }
        }
    }
    catch {
        # Report a failed action instead of hiding a partial run or implying a successful write.
        $out.Status = 'Failed'
        $out.Error = Get-SanitizedText -Text $_.Exception.Message
    }
    [pscustomobject]$out
}

function Get-ADOffboardingResultSummary {
    <#
    .SYNOPSIS
        Counts action outcomes and identifies work that has not succeeded or become compliant.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Actions)
    $counts = [ordered]@{}
    foreach ($s in 'Planned', 'Succeeded', 'AlreadyCompliant', 'Failed', 'Skipped', 'Blocked') {
        $counts[$s] = @($Actions | Where-Object { $_.Status -eq $s }).Count
    }
    [pscustomobject][ordered]@{
        Counts               = [pscustomobject]$counts
        IncompleteActionIds  = @($Actions | Where-Object { $_.Status -notin 'Succeeded', 'AlreadyCompliant' } | ForEach-Object { $_.ActionId })
    }
}

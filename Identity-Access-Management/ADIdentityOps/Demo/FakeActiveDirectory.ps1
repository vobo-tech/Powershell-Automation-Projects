[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '', Justification='Synthetic AD test double; module code resolves the stand-in cmdlets from global scope.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification='State is read by other scripts.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification='Stand-ins accept the real cmdlets parameter surface without using every parameter.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '', Justification='Stand-ins deliberately record the call even under -WhatIf so tests can prove zero writes.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Justification='Mirrors the New-ADUser surface; no real password is ever supplied or stored.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '', Justification='Mirrors the New-ADUser surface.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Test double.')]
param()
# SYNTHETIC IN-MEMORY ACTIVE DIRECTORY. Used by the tests and the demo. It never contacts a domain.
# Dot-source this file; it defines global stand-ins for the ActiveDirectory cmdlets the toolkit calls.
# State lives in $global:FakeAD. Every write cmdlet logs its invocation (even under -WhatIf) so tests can prove zero writes.

$global:FakeDomainSid = 'S-1-5-21-1111111111-2222222222-3333333333'

function global:Reset-FakeAD {
    $global:FakeAD = @{
        Users        = @{}
        Groups       = @{}
        OUs          = New-Object System.Collections.ArrayList
        WriteLog     = New-Object System.Collections.ArrayList
        ReadLog      = New-Object System.Collections.ArrayList
        Servers      = New-Object System.Collections.ArrayList
        FailWrite    = @{}   # 'Disable' | 'RemoveGroup:<name>' | 'Move' -> error message (cmdlet throws)
        NoEffect     = @{}   # same keys -> cmdlet "succeeds" but changes nothing
        FailRead     = @{}   # group name -> error message for Get-ADGroup
    }
}

function global:Add-FakeOU { param([string]$Dn) [void]$global:FakeAD.OUs.Add($Dn) }

function global:Add-FakeGroup {
    param([string]$Name, [int]$Rid, [string]$Guid, [string[]]$MemberOf = @(), [string]$Ou = 'OU=Groups,DC=corp,DC=example,DC=invalid')
    $dn = "CN=$Name,$Ou"
    $global:FakeAD.Groups[$dn.ToLowerInvariant()] = [pscustomobject]@{
        ObjectGUID = [guid]$Guid; SID = "$($global:FakeDomainSid)-$Rid"; DistinguishedName = $dn; Name = $Name
        MemberOf = [System.Collections.ArrayList]@($MemberOf); ObjectClass = 'group'
    }
    $dn
}

function global:Add-FakeUser {
    param([string]$Sam, [int]$Rid, [string]$Guid, [string]$Ou, [string[]]$MemberOf = @(), [bool]$Enabled = $true, [string]$Department = 'Finance', $AdminCount = $null, [string]$Cn)
    if (-not $Cn) { $Cn = $Sam }
    $dn = "CN=$Cn,$Ou"
    $global:FakeAD.Users[$Guid.ToLowerInvariant()] = [pscustomobject]@{
        ObjectGUID = [guid]$Guid; SID = "$($global:FakeDomainSid)-$Rid"; DistinguishedName = $dn; SamAccountName = $Sam
        UserPrincipalName = "$Sam@corp.example.invalid"; Enabled = $Enabled; Department = $Department
        Manager = 'CN=manager1,OU=Staff,OU=Corp,DC=corp,DC=example,DC=invalid'; MemberOf = [System.Collections.ArrayList]@($MemberOf)
        AdminCount = $AdminCount; PrimaryGroupID = 513; ObjectClass = 'user'
    }
    $dn
}

function global:Find-FakeUser {
    param([string]$Identity)
    foreach ($u in $global:FakeAD.Users.Values) {
        if ($u.ObjectGUID.ToString() -ieq $Identity -or $u.SID -ieq $Identity -or $u.DistinguishedName -ieq $Identity -or $u.SamAccountName -ieq $Identity) { return $u }
    }
    $null
}

function global:Find-FakeGroup {
    param([string]$Identity)
    foreach ($g in $global:FakeAD.Groups.Values) {
        if ($g.ObjectGUID.ToString() -ieq $Identity -or $g.SID -ieq $Identity -or $g.DistinguishedName -ieq $Identity -or $g.Name -ieq $Identity) { return $g }
    }
    $null
}

function global:Assert-FakeServer {
    param([string]$Server)
    if ([string]::IsNullOrWhiteSpace($Server)) { throw 'FakeAD: -Server was not specified (the toolkit must always target the configured DC).' }
    [void]$global:FakeAD.Servers.Add($Server)
}

function global:Copy-FakeObject {
    param($Source)
    $c = $Source.PSObject.Copy()
    if ($c.PSObject.Properties['MemberOf']) { $c.MemberOf = @($Source.MemberOf) }
    $c
}

function global:Get-ADUser {
    [CmdletBinding()]
    param([string]$Identity, [string]$Filter, [string]$Server, [string[]]$Properties)
    Assert-FakeServer $Server
    [void]$global:FakeAD.ReadLog.Add("Get-ADUser $Identity$Filter")
    if ($Filter) {
        if ($Filter -notmatch "^SamAccountName\s+-eq\s+'((?:[^']|'')*)'$") { throw "FakeAD: unsupported filter '$Filter'." }
        $sam = $Matches[1] -replace "''", "'"
        $hit = @($global:FakeAD.Users.Values | Where-Object { $_.SamAccountName -ieq $sam })
        return $hit | ForEach-Object { Copy-FakeObject $_ }
    }
    $u = Find-FakeUser $Identity
    if (-not $u) { throw "Cannot find an object with identity: '$Identity'." }
    Copy-FakeObject $u
}

function global:Get-ADGroup {
    [CmdletBinding()]
    param([string]$Identity, [string]$Server, [string[]]$Properties)
    Assert-FakeServer $Server
    [void]$global:FakeAD.ReadLog.Add("Get-ADGroup $Identity")
    $g = Find-FakeGroup $Identity
    if (-not $g) { throw "Cannot find an object with identity: '$Identity'." }
    if ($global:FakeAD.FailRead.ContainsKey($g.Name)) { throw $global:FakeAD.FailRead[$g.Name] }
    Copy-FakeObject $g
}

function global:Get-ADOrganizationalUnit {
    [CmdletBinding()]
    param([string]$Identity, [string]$Server)
    Assert-FakeServer $Server
    if (@($global:FakeAD.OUs | Where-Object { $_ -ieq $Identity }).Count -eq 0) { throw "Cannot find OU '$Identity'." }
    [pscustomobject]@{ DistinguishedName = $Identity }
}

function global:Disable-ADAccount {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Identity, [string]$Server)
    Assert-FakeServer $Server
    [void]$global:FakeAD.WriteLog.Add("Disable-ADAccount $Identity")
    if ($global:FakeAD.FailWrite.ContainsKey('Disable')) { throw $global:FakeAD.FailWrite['Disable'] }
    if ($global:FakeAD.NoEffect.ContainsKey('Disable')) { return }
    $u = Find-FakeUser $Identity
    if (-not $u) { throw "Cannot find an object with identity: '$Identity'." }
    $u.Enabled = $false
}

function global:Remove-ADGroupMember {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Identity, [string[]]$Members, [string]$Server)
    Assert-FakeServer $Server
    [void]$global:FakeAD.WriteLog.Add("Remove-ADGroupMember $Identity $($Members -join ',')")
    $g = Find-FakeGroup $Identity
    if (-not $g) { throw "Cannot find an object with identity: '$Identity'." }
    if ($global:FakeAD.FailWrite.ContainsKey("RemoveGroup:$($g.Name)")) { throw $global:FakeAD.FailWrite["RemoveGroup:$($g.Name)"] }
    if ($global:FakeAD.NoEffect.ContainsKey("RemoveGroup:$($g.Name)")) { return }
    $u = Find-FakeUser $Members[0]
    if (-not $u) { throw "Cannot find member '$($Members[0])'." }
    $keep = @($u.MemberOf | Where-Object { $_ -ine $g.DistinguishedName })
    $u.MemberOf = [System.Collections.ArrayList]@($keep)
}

function global:Move-ADObject {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Identity, [string]$TargetPath, [string]$Server)
    Assert-FakeServer $Server
    [void]$global:FakeAD.WriteLog.Add("Move-ADObject $Identity -> $TargetPath")
    if ($global:FakeAD.FailWrite.ContainsKey('Move')) { throw $global:FakeAD.FailWrite['Move'] }
    if ($global:FakeAD.NoEffect.ContainsKey('Move')) { return }
    if (@($global:FakeAD.OUs | Where-Object { $_ -ieq $TargetPath }).Count -eq 0) { throw "Target OU '$TargetPath' not found." }
    $u = Find-FakeUser $Identity
    if (-not $u) { throw "Cannot find an object with identity: '$Identity'." }
    $rdn = [regex]::Match($u.DistinguishedName, '^((?:\\.|[^,\\])+),').Groups[1].Value
    $u.DistinguishedName = "$rdn,$TargetPath"
}

# --- Creation-path stand-ins used by BulkUserCreation regression tests --------------------------
function global:New-ADUser {
    [CmdletBinding(SupportsShouldProcess)]
    param($SamAccountName, $Name, $GivenName, $Surname, $DisplayName, $UserPrincipalName, $AccountPassword, $ChangePasswordAtLogon, $Enabled, $Path, $Department, $Title, $EmailAddress, $Manager)
    [void]$global:FakeAD.WriteLog.Add("New-ADUser $SamAccountName")
    $ou = if ($Path) { $Path } else { 'CN=Users,DC=corp,DC=example,DC=invalid' }
    [void](Add-FakeUser -Sam $SamAccountName -Rid (Get-Random -Minimum 5000 -Maximum 9000) -Guid ([guid]::NewGuid().ToString()) -Ou $ou -Enabled ([bool]$Enabled))
}

function global:Add-ADGroupMember {
    [CmdletBinding(SupportsShouldProcess)]
    param($Identity, $Members)
    [void]$global:FakeAD.WriteLog.Add("Add-ADGroupMember $Identity $($Members -join ',')")
}

function global:Set-ADUser {
    [CmdletBinding(SupportsShouldProcess)]
    param($Identity, $HomeDirectory, $HomeDrive)
    [void]$global:FakeAD.WriteLog.Add("Set-ADUser $Identity")
}

function global:Initialize-SyntheticDirectory {
    <#
    .SYNOPSIS
        Builds the synthetic domain used by tests and the demo. All names, SIDs, and GUIDs are fabricated.
    #>
    Reset-FakeAD
    $base = 'DC=corp,DC=example,DC=invalid'
    foreach ($ou in "OU=Staff,OU=Corp,$base", "OU=Contractors,OU=Corp,$base", "OU=Quarantine,OU=Disabled,$base") { Add-FakeOU $ou }

    $budget = Add-FakeGroup -Name 'GG-Budget-Approvers' -Rid 1211 -Guid 'aaaaaaaa-0000-0000-0000-000000001211'
    $fdept = Add-FakeGroup -Name 'GG-Finance-Dept' -Rid 1210 -Guid 'aaaaaaaa-0000-0000-0000-000000001210' -MemberOf @($budget)
    $null = Add-FakeGroup -Name 'GG-Domain-Admins' -Rid 512 -Guid 'aaaaaaaa-0000-0000-0000-000000000512'
    $null = Add-FakeGroup -Name 'GG-All-Staff' -Rid 1100 -Guid 'aaaaaaaa-0000-0000-0000-000000001100'
    $null = Add-FakeGroup -Name 'GG-Finance-Share' -Rid 1201 -Guid 'aaaaaaaa-0000-0000-0000-000000001201' -MemberOf @($fdept)
    $null = Add-FakeGroup -Name 'GG-VPN-Users' -Rid 1202 -Guid 'aaaaaaaa-0000-0000-0000-000000001202' -MemberOf @($fdept)
    $null = Add-FakeGroup -Name 'GG-Project-Atlas' -Rid 1203 -Guid 'aaaaaaaa-0000-0000-0000-000000001203'

    $g = { param($n) (Find-FakeGroup $n).DistinguishedName }
    $staff = "OU=Staff,OU=Corp,$base"
    $null = Add-FakeUser -Sam 'jdoe' -Rid 3001 -Guid '11111111-0000-0000-0000-000000003001' -Ou $staff -Cn 'Jane Doe' -MemberOf @((& $g 'GG-All-Staff'), (& $g 'GG-Finance-Share'), (& $g 'GG-VPN-Users'), (& $g 'GG-Project-Atlas'))
    $null = Add-FakeUser -Sam 'adm-ops' -Rid 3002 -Guid '11111111-0000-0000-0000-000000003002' -Ou $staff -Cn 'Ops Admin' -MemberOf @((& $g 'GG-All-Staff'), (& $g 'GG-Domain-Admins')) -AdminCount 1
    $null = Add-FakeUser -Sam 'contractor1' -Rid 3003 -Guid '11111111-0000-0000-0000-000000003003' -Ou "OU=Contractors,OU=Corp,$base" -Cn 'Contractor One' -MemberOf @((& $g 'GG-All-Staff'))
}

function global:New-SyntheticConfig {
    [pscustomobject]@{
        SchemaVersion          = '1.0'
        DomainController       = 'dc01.corp.example.invalid'
        AllowedSourceOUs       = @('OU=Staff,OU=Corp,DC=corp,DC=example,DC=invalid')
        QuarantineOU           = 'OU=Quarantine,OU=Disabled,DC=corp,DC=example,DC=invalid'
        ProtectedAccounts      = @("$($global:FakeDomainSid)-500")
        ProtectedGroups        = @("$($global:FakeDomainSid)-512")
        GroupRemovalExclusions = @("$($global:FakeDomainSid)-1100")
        PlanLifetimeHours      = 24
        Output                 = [pscustomobject]@{ PlanDirectory = './out/plans'; ResultDirectory = './out/results'; ReportDirectory = './out/reports' }
    }
}

function global:Remove-FakeAD {
    foreach ($f in 'Reset-FakeAD', 'Add-FakeOU', 'Add-FakeGroup', 'Add-FakeUser', 'Find-FakeUser', 'Find-FakeGroup', 'Assert-FakeServer', 'Copy-FakeObject', 'Get-ADUser', 'Get-ADGroup', 'Get-ADOrganizationalUnit', 'Disable-ADAccount', 'Remove-ADGroupMember', 'Move-ADObject', 'New-ADUser', 'Add-ADGroupMember', 'Set-ADUser', 'Initialize-SyntheticDirectory', 'New-SyntheticConfig') {
        Remove-Item -Path "function:global:$f" -ErrorAction Ignore
    }
    Remove-Variable -Name FakeAD -Scope Global -ErrorAction Ignore
}

#Requires -Modules Pester
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification='Pester scoping.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification='Stand-in command signatures.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '', Justification='Stand-in signature of New-ADUser.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Justification='Stand-in signatures; no password is used.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification='Stand-ins let Get-Acl/Set-Acl be mocked on platforms without Windows ACL support.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Test stand-ins and builders.')]
param()

# Regression tests for defects fixed in the pre-existing Identity-Access-Management scripts.
# All AD and ACL commands are stand-ins/mocks over synthetic data; nothing touches a domain or a real ACL.

BeforeAll {
    $script:IamRoot = Split-Path -Path $PSScriptRoot -Parent
    $script:NtfsScript = Join-Path $script:IamRoot 'PermissionAuditing/ReportNTFSPermissions/ReportNTFSPermissions.ps1'
    $script:OverPermScript = Join-Path $script:IamRoot 'PermissionAuditing/DetectOverPermissionedAccounts/DetectOverPermissionedAccounts.ps1'
    $script:BulkScript = Join-Path $script:IamRoot 'UserAccountManagement/BulkUserCreation/BulkUserCreation.ps1'
    $script:InactiveScript = Join-Path $script:IamRoot 'UserAccountManagement/InactiveAccountReport/InactiveAccountReport.ps1'
    $script:ResetScript = Join-Path $script:IamRoot 'UserAccountManagement/PasswordReset/PasswordReset.ps1'
    $script:SentinelScripts = @(
        (Join-Path (Split-Path -Path $script:IamRoot -Parent) 'Data-Protection-Recovery/LogCollectionAnalysis/Sentinel-Lab/Enhanced-Sentinel-Lab.ps1'),
        (Join-Path (Split-Path -Path $script:IamRoot -Parent) 'Data-Protection-Recovery/LogCollectionAnalysis/Sentinel-Lab/Sentinel-Lab.ps1')
    )
    . (Join-Path $script:IamRoot 'PermissionAuditing/Shared/FileSystemRights.ps1')

    # Stand-ins so commands can be mocked on machines without RSAT / Windows ACL support
    function Get-Acl { [CmdletBinding()] param($LiteralPath, $Path) }
    function Set-Acl { [CmdletBinding()] param($LiteralPath, $Path, $AclObject) }
    function Get-ADUser { [CmdletBinding()] param($Filter, $Identity, $Properties, $SearchBase) }
    function New-ADUser { [CmdletBinding()] param($SamAccountName, $Name, $GivenName, $Surname, $DisplayName, $UserPrincipalName, $AccountPassword, $ChangePasswordAtLogon, $Enabled, $Path, $Department, $Title, $EmailAddress, $Manager) }
    function Add-ADGroupMember { [CmdletBinding()] param($Identity, $Members) }
    function Set-ADUser { [CmdletBinding()] param($Identity, $HomeDirectory, $HomeDrive, $ChangePasswordAtLogon) }
    function Get-ADGroup { [CmdletBinding()] param($Identity, $Server) }
    function Get-ADGroupMember { [CmdletBinding()] param($Identity, [switch]$Recursive, $Server) }
    function Disable-ADAccount { [CmdletBinding()] param($Identity) }
    function Move-ADObject { [CmdletBinding()] param($Identity, $TargetPath) }
    function Unlock-ADAccount { [CmdletBinding()] param($Identity) }
    function Set-ADAccountPassword { [CmdletBinding()] param($Identity, $NewPassword, [switch]$Reset) }

    function New-TestAce {
        param([string]$Principal, [System.Security.AccessControl.FileSystemRights]$Rights, [string]$Type = 'Allow')
        [pscustomobject]@{
            IdentityReference = [pscustomobject]@{ Value = $Principal }
            FileSystemRights  = $Rights
            AccessControlType = $Type
            InheritanceFlags  = 'ContainerInherit, ObjectInherit'
            PropagationFlags  = 'None'
            IsInherited       = $false
        }
    }
    function New-TestAcl {
        param([object[]]$Ace)
        [pscustomobject]@{ Owner = 'CONTOSO\Owner'; AreAccessRulesProtected = $false; Access = $Ace }
    }
}

Describe 'FileSystemRights helper (composite bitmask regression)' {
    It 'labels <Rights> as <Expected>' -ForEach @(
        @{ Rights = 'FullControl'; Expected = 'FullControl' }
        @{ Rights = 'Modify'; Expected = 'Modify' }
        @{ Rights = 'Write'; Expected = 'Write' }
        @{ Rights = 'ReadAndExecute'; Expected = 'ReadExecute' }
        @{ Rights = 'Read'; Expected = 'Read' }
        @{ Rights = 'ReadData'; Expected = 'ReadData' }
        @{ Rights = 'Delete'; Expected = 'Delete' }
    ) {
        Convert-FileSystemRightsLabel -Rights ([System.Security.AccessControl.FileSystemRights]$Rights) | Should -Be $Expected
    }

    It 'documents the old defect: an any-bit test treats a read-only ACE as FullControl' {
        $fsr = [System.Security.AccessControl.FileSystemRights]
        [bool]($fsr::Read -band $fsr::FullControl) | Should -BeTrue
        Test-FileSystemRight -Rights $fsr::Read -Required $fsr::FullControl | Should -BeFalse
        Test-FileSystemRight -Rights $fsr::ReadAndExecute -Required $fsr::Modify | Should -BeFalse
    }

    It 'requires every bit of the mask' {
        $fsr = [System.Security.AccessControl.FileSystemRights]
        Test-FileSystemRight -Rights ($fsr::Modify -bor $fsr::TakeOwnership) -Required $fsr::Modify | Should -BeTrue
        Test-FileSystemRight -Rights ($fsr::Modify -band (-bnot $fsr::Delete)) -Required $fsr::Modify | Should -BeFalse
    }
}

Describe 'ReportNTFSPermissions.ps1' {
    BeforeEach {
        $script:Root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path (Join-Path $script:Root 'good') -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $script:Root 'bad') -Force | Out-Null
        Mock Get-Acl {
            if ($LiteralPath -like '*bad*') { throw 'Access to the path is denied (synthetic).' }
            New-TestAcl -Ace @(
                (New-TestAce -Principal 'Everyone' -Rights ReadAndExecute),
                (New-TestAce -Principal 'CONTOSO\Domain Users' -Rights Modify),
                (New-TestAce -Principal 'CONTOSO\Blocked' -Rights FullControl -Type Deny)
            )
        }
    }

    It 'does not flag a ReadAndExecute ACE for a broad principal as high rights, and emits objects' {
        $rows = @(& $script:NtfsScript -Path (Join-Path $script:Root 'good') -ErrorAction Continue)
        $rows.Count | Should -Be 3
        $rows[0] | Should -BeOfType [pscustomobject]
        $ev = $rows | Where-Object Principal -eq 'Everyone'
        $ev.Rights | Should -Be 'ReadExecute'
        $ev.Risk_BroadHigh | Should -BeFalse
        $ev.Caveat | Should -Match 'not an effective-access determination'
        ($rows | Where-Object Principal -eq 'CONTOSO\Domain Users').Risk_BroadHigh | Should -BeTrue
        ($rows | Where-Object Principal -eq 'CONTOSO\Blocked').Risk_Deny | Should -BeTrue
    }

    It 'reports a path whose ACL cannot be read as an error and a warning instead of hiding it' {
        $rows = @(& $script:NtfsScript -Path $script:Root -Recurse -ErrorVariable ev -WarningVariable wv -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)
        @($ev | Where-Object { $_.Exception.Message -like '*denied*' }).Count | Should -BeGreaterThan 0
        ($wv -join ' ') | Should -Match 'INCOMPLETE'
        @($rows | Where-Object Path -like '*good*').Count | Should -BeGreaterThan 0
    }

    It 'reports a missing root path as an error' {
        $null = & $script:NtfsScript -Path (Join-Path $script:Root 'nope') -ErrorVariable ev -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        ($ev | Out-String) | Should -Match 'Path not found'
    }
}

Describe 'DetectOverPermissionedAccounts.ps1' {
    BeforeEach {
        $script:Root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:Root -Force | Out-Null
        Mock Import-Module { }
        Mock Get-Acl {
            New-TestAcl -Ace @(
                (New-TestAce -Principal 'CONTOSO\Readers' -Rights ReadAndExecute),
                (New-TestAce -Principal 'CONTOSO\Editors' -Rights Modify),
                (New-TestAce -Principal 'CONTOSO\Denied' -Rights FullControl -Type Deny)
            )
        }
    }

    It 'does not flag read-only ACEs and flags Modify, as objects carrying a not-effective-access caveat' {
        $f = @(& $script:OverPermScript -Path $script:Root -MinRight Modify -ErrorAction Continue)
        $f.Count | Should -Be 1
        $f[0].Principal | Should -Be 'CONTOSO\Editors'
        $f[0].Rights | Should -Be 'Modify'
        $f[0].DenyAcesOnPath | Should -Be 1
        $f[0].Caveat | Should -Match 'Not an effective-access determination'
    }

    It 'reports a failed group expansion instead of presenting it as an empty membership' {
        Mock Get-ADGroup { throw 'The server is not operational (synthetic).' }
        $f = @(& $script:OverPermScript -Path $script:Root -ExpandADGroups -Domain 'dc1.corp.example.invalid' -ErrorVariable ev -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)
        $f[0].ExpansionStatus | Should -BeLike 'Failed*'
        $f[0].EffectiveUsers | Should -BeNullOrEmpty
        ($ev | Out-String) | Should -Match 'Group expansion failed'
    }

    It 'lists members of an expanded group with an Expanded status' {
        Mock Get-ADGroup { [pscustomobject]@{ Name = 'Editors' } }
        Mock Get-ADGroupMember { [pscustomobject]@{ objectClass = 'user'; SamAccountName = 'jdoe' } }
        $f = @(& $script:OverPermScript -Path $script:Root -ExpandADGroups -Domain 'dc1.corp.example.invalid')
        $f[0].ExpansionStatus | Should -Be 'Expanded'
        $f[0].ExpandedGroupMembers | Should -Be 'jdoe'
        # Compatibility field; it is a member list, not an effective-access assertion.
        $f[0].EffectiveUsers | Should -Be 'jdoe'
    }
}

Describe 'BulkUserCreation.ps1' {
    BeforeEach {
        $script:Csv = Join-Path $TestDrive ([guid]::NewGuid().ToString('N') + '.csv')
        $script:Pw = New-Object System.Security.SecureString
        Mock Import-Module { }
        Mock Get-ADUser { $null }
        Mock New-ADUser { }
        Mock Add-ADGroupMember { }
        Mock Set-ADUser { }
        Mock Get-Acl { New-TestAcl -Ace @() }
        Mock Set-Acl { }
        Mock New-Item { }
    }

    It 'skips an existing user entirely: no create, no group changes, no home folder work' {
        Set-Content -Path $script:Csv -Value "SamAccountName,GivenName,Surname,Groups`njdoe,Jane,Doe,GG_HR;GG_All"
        Mock Get-ADUser { [pscustomobject]@{ DistinguishedName = 'CN=Jane Doe,OU=Staff,DC=corp,DC=example,DC=invalid' } }
        $r = @(& $script:BulkScript -CsvPath $script:Csv -DefaultPassword $script:Pw -CreateHomeFolders -HomeRootPath '\\fs01.example.invalid\homes' -AddToGroups 'GG_Extra' -WarningAction SilentlyContinue)
        $r.Count | Should -Be 1
        $r[0].Status | Should -Be 'SkippedExisting'
        Should -Invoke New-ADUser -Times 0 -Exactly
        Should -Invoke Add-ADGroupMember -Times 0 -Exactly
        Should -Invoke Set-ADUser -Times 0 -Exactly
        Should -Invoke New-Item -Times 0 -Exactly
        Should -Invoke Set-Acl -Times 0 -Exactly
    }

    It 'creates a new user, adds groups, and reports Created' {
        Set-Content -Path $script:Csv -Value "SamAccountName,GivenName,Surname,Groups`nasmith,Alex,Smith,GG_HR"
        $r = @(& $script:BulkScript -CsvPath $script:Csv -DefaultPassword $script:Pw -AddToGroups 'GG_All')
        $r[0].Status | Should -Be 'Created'
        $r[0].GroupsAdded | Should -Be @('GG_HR', 'GG_All')
        Should -Invoke New-ADUser -Times 1 -Exactly
        Should -Invoke Add-ADGroupMember -Times 2 -Exactly
    }

    It 'reports a partial failure instead of hiding it behind a warning' {
        Set-Content -Path $script:Csv -Value "SamAccountName,GivenName,Surname,Groups`nasmith,Alex,Smith,GG_OK;GG_BAD"
        Mock Add-ADGroupMember { if ($Identity -eq 'GG_BAD') { throw 'Access denied (synthetic).' } }
        $r = @(& $script:BulkScript -CsvPath $script:Csv -DefaultPassword $script:Pw -ErrorVariable ev -ErrorAction SilentlyContinue)
        $r[0].Status | Should -Be 'PartiallyCompleted'
        $r[0].Created | Should -BeTrue
        $r[0].GroupsAdded | Should -Be @('GG_OK')
        $r[0].GroupsFailed | Should -Be @('GG_BAD')
        ($ev | Out-String) | Should -Match 'GG_BAD'
    }

    It 'does not attempt groups or home folders when creation fails' {
        Set-Content -Path $script:Csv -Value "SamAccountName,GivenName,Surname,Groups`nasmith,Alex,Smith,GG_HR"
        Mock New-ADUser { throw 'Constraint violation (synthetic).' }
        $r = @(& $script:BulkScript -CsvPath $script:Csv -DefaultPassword $script:Pw -CreateHomeFolders -HomeRootPath '\\fs01.example.invalid\homes' -ErrorAction SilentlyContinue)
        $r[0].Status | Should -Be 'Failed'
        Should -Invoke Add-ADGroupMember -Times 0 -Exactly
        Should -Invoke Set-ADUser -Times 0 -Exactly
    }

    It 'treats a failed existence lookup as a failure, not as "user does not exist"' {
        Set-Content -Path $script:Csv -Value "SamAccountName,GivenName,Surname`nasmith,Alex,Smith"
        Mock Get-ADUser { throw 'Server unavailable (synthetic).' }
        $r = @(& $script:BulkScript -CsvPath $script:Csv -DefaultPassword $script:Pw -ErrorAction SilentlyContinue)
        $r[0].Status | Should -Be 'Failed'
        Should -Invoke New-ADUser -Times 0 -Exactly
    }

    It 'escapes single quotes in the lookup filter' {
        Set-Content -Path $script:Csv -Value "SamAccountName,GivenName,Surname`no'brien,Oona,Brien"
        $null = & $script:BulkScript -CsvPath $script:Csv -DefaultPassword $script:Pw
        Should -Invoke Get-ADUser -Times 1 -Exactly -ParameterFilter { $Filter -eq "SamAccountName -eq 'o''brien'" }
    }

    It 'performs no writes under -WhatIf' {
        Set-Content -Path $script:Csv -Value "SamAccountName,GivenName,Surname,Groups`nasmith,Alex,Smith,GG_HR"
        $r = @(& $script:BulkScript -CsvPath $script:Csv -DefaultPassword $script:Pw -WhatIf)
        $r[0].Status | Should -Be 'WhatIf'
        Should -Invoke New-ADUser -Times 0 -Exactly
        Should -Invoke Add-ADGroupMember -Times 0 -Exactly
    }
}

Describe 'InactiveAccountReport.ps1' {
    BeforeEach {
        Mock Import-Module { }
        Mock Get-ADUser {
            [pscustomobject]@{
                SamAccountName = 'stale1'; DisplayName = 'Stale One'; Enabled = $true
                LastLogonTimeStamp = (Get-Date).AddDays(-200).ToFileTime()
                whenCreated = (Get-Date).AddDays(-900); DistinguishedName = 'CN=Stale One,OU=Staff,DC=corp,DC=example,DC=invalid'
            }
        }
        Mock Disable-ADAccount { }
        Mock Move-ADObject { }
    }

    It 'emits objects labelled with the approximate basis and does not change AD without switches' {
        $r = @(& $script:InactiveScript -DaysInactive 90)
        $r.Count | Should -Be 1
        $r[0].SamAccountName | Should -Be 'stale1'
        $r[0].InactivityBasis | Should -Match 'approximate'
        Should -Invoke Disable-ADAccount -Times 0 -Exactly
        Should -Invoke Move-ADObject -Times 0 -Exactly
    }

    It 'blocks the move when the disable failed and reports the failure' {
        Mock Disable-ADAccount { throw 'Access denied (synthetic).' }
        $r = @(& $script:InactiveScript -DaysInactive 90 -Disable -MoveToOU 'OU=Quarantine,DC=corp,DC=example,DC=invalid' -Confirm:$false -ErrorVariable ev -ErrorAction SilentlyContinue)
        $r[0].DisableStatus | Should -Be 'Failed'
        $r[0].MoveStatus | Should -Be 'Blocked'
        Should -Invoke Move-ADObject -Times 0 -Exactly
        ($ev | Out-String) | Should -Match 'Failed to disable'
    }

    It 'performs no writes under -WhatIf' {
        $r = @(& $script:InactiveScript -DaysInactive 90 -Disable -MoveToOU 'OU=Quarantine,DC=corp,DC=example,DC=invalid' -WhatIf)
        $r[0].DisableStatus | Should -Be 'Skipped'
        Should -Invoke Disable-ADAccount -Times 0 -Exactly
        Should -Invoke Move-ADObject -Times 0 -Exactly
    }
}

Describe 'PasswordReset.ps1' {
    BeforeEach {
        Mock Import-Module { }
        Mock Set-ADAccountPassword { }
        Mock Unlock-ADAccount { throw 'Unlock denied (synthetic).' }
        Mock Set-ADUser { }
    }

    It 'does not report an unlock as applied when it failed, and surfaces the error' {
        $r = @(& $script:ResetScript -Identity 'jdoe' -GenerateRandom -Unlock -ForceChangeAtLogon -Confirm:$false -ErrorVariable ev -ErrorAction SilentlyContinue)
        $r[0].Changed | Should -BeTrue
        $r[0].Unlocked | Should -BeFalse
        $r[0].ForcedCPW | Should -BeTrue
        ($ev | Out-String) | Should -Match 'unlock failed'
    }
}

Describe 'Sentinel geolocation API key configuration' {
    It 'uses runtime configuration and contains no hardcoded key in either script' {
        $literalAssignment = '(?im)^\s*\$(?:API_KEY|ApiKey)\s*=\s*["''][^"'']+'
        $literalQueryKey = '(?i)apiKey=[A-Za-z0-9._-]{16,}'
        foreach ($path in $script:SentinelScripts) {
            Test-Path -LiteralPath $path | Should -BeTrue
            $content = Get-Content -LiteralPath $path -Raw
            $content | Should -Match '\$env:IPGEOLOCATION_API_KEY'
            $content | Should -Not -Match $literalAssignment
            $content | Should -Not -Match $literalQueryKey
        }
    }
}

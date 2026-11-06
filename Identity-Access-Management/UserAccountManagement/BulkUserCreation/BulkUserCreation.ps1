# ██████╗░██╗░░░██╗███████╗███████╗  ███╗░░██╗███████╗██████╗░██████╗░
# ██╔══██╗██║░░░██║██╔════╝██╔════╝  ████╗░██║██╔════╝██╔══██╗██╔══██╗
# ██████╦╝██║░░░██║█████╗░░█████╗░░  ██╔██╗██║█████╗░░██████╔╝██║░░██║
# ██╔══██╗██║░░░██║██╔══╝░░██╔══╝░░  ██║╚████║██╔══╝░░██╔══██╗██║░░██║
# ██████╦╝╚██████╔╝██║░░░░░██║░░░░░  ██║░╚███║███████╗██║░░██║██████╔╝
# ╚═════╝░░╚═════╝░╚═╝░░░░░╚═╝░░░░░  ╚═╝░░╚══╝╚══════╝╚═╝░░╚═╝╚═════╝░
# -------Script by Aaron Voborny---https://github.com/buffnerd--------

<#
.SYNOPSIS
  Bulk creates Active Directory users from a CSV with safe defaults.

.DESCRIPTION
  - Reads a CSV and creates AD users with specified attributes.
  - Supports per-user OU and group assignments from CSV.
  - Optional home folder creation with NTFS permissions.
  - Forces password change at next logon by default.
  - Safe to test with -WhatIf and verbose with -Verbose.
  - Emits one result object per CSV row (Status: Created, SkippedExisting, WhatIf, Failed, PartiallyCompleted)
    so partial failures are visible to callers; failures are also written as non-terminating errors.
  - An account that already exists is skipped ENTIRELY: no group changes and no home folder work.

  SECURITY NOTE - shared password: -DefaultPassword gives every created account the same initial secret.
  Migration path: (1) generate a unique random password per account (never log or export it) and deliver it
  through the organization's approved credential-delivery process, or (2) create accounts disabled/with no
  usable password and let a helpdesk or self-service enrollment flow set it, keeping ChangePasswordAtLogon.
  This script does not implement credential delivery; the parameter is retained for compatibility.

.REQUIREMENTS
  - RSAT Active Directory module installed (PowerShell).
  - Run as a domain user with permissions to create users (and folders, if enabled).

.CSV SCHEMA (columns)
  Required:
    SamAccountName, GivenName, Surname
  Optional (highly recommended):
    DisplayName, UserPrincipalName, OU, Department, Title, Email, Manager, Groups
      - Groups: semicolon-separated list (e.g., "GG_HR;GG_AllStaff")

.EXAMPLES
  PS> .\BulkUserCreation.ps1 -CsvPath .\users.csv -TargetOU "OU=Staff,OU=Corp,DC=contoso,DC=com" `
       -DefaultUPNSuffix "@contoso.com" -DefaultPassword (Read-Host "Password" -AsSecureString) -EnableAccounts `
       -CreateHomeFolders -HomeRootPath "\\fs01\homes" -AddToGroups "GG_AllStaff" -Verbose -WhatIf

.NOTES (Adjustments for your environment)
  - Update -TargetOU to your default staging OU DN.
  - Set -DefaultUPNSuffix to your domain UPN suffix (e.g., @contoso.com).
  - If using home folders, set -HomeRootPath to your file server share and ensure the script runner can create folders.
  - Pre-create/securitize any default groups you pass in -AddToGroups.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(Mandatory)]
  [ValidateScript({ Test-Path $_ })]
  [string]$CsvPath,

  [Parameter(Mandatory)]
  [SecureString]$DefaultPassword,

  [Parameter()]
  [string]$TargetOU, # Default OU if row doesn't specify OU

  [Parameter()]
  [string]$DefaultUPNSuffix = "@contoso.com",

  [Parameter()]
  [switch]$EnableAccounts,  # If not specified, users are created disabled (safer)

  [Parameter()]
  [switch]$CreateHomeFolders,

  [Parameter()]
  [ValidateScript({ $_ -match '^[\\]{2}.+' })]
  [string]$HomeRootPath,    # e.g., \\fs01\homes

  [Parameter()]
  [string[]]$AddToGroups    # Default groups for all created users (optional)
)

begin {
  # --- Validate dependencies and input ---
  try {
    Import-Module ActiveDirectory -ErrorAction Stop
  } catch {
    throw "ActiveDirectory module not found. Install RSAT or run on a domain-joined admin host."
  }

  if ($CreateHomeFolders -and -not $HomeRootPath) {
    throw "When -CreateHomeFolders is used, you must supply -HomeRootPath (e.g., \\fs01\homes)."
  }

  $users = Import-Csv -Path $CsvPath
  if (-not $users) { throw "CSV '$CsvPath' is empty or unreadable." }

  Write-Verbose "Loaded $($users.Count) row(s) from CSV."
}

process {
  # --- Process each requested account ---
  # Each row produces its own outcome, so a downstream failure is not mistaken for full success.
  foreach ($row in $users) {
    # Required fields
    $sam   = $row.SamAccountName
    $given = $row.GivenName
    $sn    = $row.Surname

    if (-not $sam -or -not $given -or -not $sn) {
      Write-Warning "Skipping row missing required fields (SamAccountName/GivenName/Surname). Row: $($row | ConvertTo-Json -Compress)"
      [pscustomobject][ordered]@{
        SamAccountName = $sam; Status = 'Failed'; Created = $false; GroupsAdded = @(); GroupsFailed = @(); HomeFolder = 'NotRequested'
        Errors = @('Row is missing SamAccountName, GivenName, or Surname.')
      }
      continue
    }

    # Optional fields and sensible defaults
    $display = if ($row.DisplayName) { $row.DisplayName } else { "$given $sn" }
    $upn     = if ($row.UserPrincipalName) { $row.UserPrincipalName } else { "$sam$DefaultUPNSuffix" }
    $ou      = if ($row.OU) { $row.OU } elseif ($TargetOU) { $TargetOU } else { $null }
    $dept    = $row.Department
    $title   = $row.Title
    $email   = $row.Email
    $manager = $row.Manager
    $rowGroups = @()
    if ($row.Groups) { $rowGroups = $row.Groups -split ';' | Where-Object { $_ -and $_.Trim() } }

    $enable = [bool]$EnableAccounts

    # Build New-ADUser arguments
    $newUserParams = @{
      SamAccountName            = $sam
      Name                      = $display
      GivenName                 = $given
      Surname                   = $sn
      DisplayName               = $display
      UserPrincipalName         = $upn
      AccountPassword           = $DefaultPassword
      ChangePasswordAtLogon     = $true
      Enabled                   = $enable
      ErrorAction               = 'Stop'
    }
    if ($ou)      { $newUserParams['Path']       = $ou }
    if ($dept)    { $newUserParams['Department'] = $dept }
    if ($title)   { $newUserParams['Title']      = $title }
    if ($email)   { $newUserParams['EmailAddress'] = $email }
    if ($manager) { $newUserParams['Manager']    = $manager }
    $result = [pscustomobject][ordered]@{
      SamAccountName = $sam
      Status         = 'Pending'    # Created | SkippedExisting | WhatIf | Failed | PartiallyCompleted
      Created        = $false
      GroupsAdded    = @()
      GroupsFailed   = @()
      HomeFolder     = 'NotRequested'
      Errors         = @()
    }
    $errs = New-Object System.Collections.Generic.List[string]

    # Existence check is read-only and runs before any write. A failed lookup is a failure, not "not found".
    # Single quotes are doubled so the value cannot break out of the filter string.
    $safeSam = $sam -replace "'", "''"
    try {
      $existing = Get-ADUser -Filter "SamAccountName -eq '$safeSam'" -ErrorAction Stop
    } catch {
      $result.Status = 'Failed'
      $result.Errors = @("Lookup of '$sam' failed; no changes made: $($_.Exception.Message)")
      Write-Error $result.Errors[0]
      $result
      continue
    }

    if ($existing) {
      # An existing account was not created by this run, so its groups and home folder are NOT modified.
      Write-Warning "User '$sam' already exists (DN: $($existing.DistinguishedName)). Skipping creation, group membership, and home folder."
      $result.Status = 'SkippedExisting'
      $result
      continue
    }

    # No creation means no later group or home-folder changes for this row, including under WhatIf.
    if (-not $PSCmdlet.ShouldProcess("AD User '$sam'", "Create")) {
      $result.Status = 'WhatIf'
      $result
      continue
    }

    try {
      New-ADUser @newUserParams
      $result.Created = $true
      Write-Verbose "Created user '$sam'."
    } catch {
      $result.Status = 'Failed'
      $result.Errors = @("Error creating user '$sam'; groups and home folder not attempted: $($_.Exception.Message)")
      Write-Error $result.Errors[0]
      $result
      continue
    }

    # Group membership (row-specific first, then default groups)
    $allGroups = @()
    if ($rowGroups) { $allGroups += $rowGroups }
    if ($AddToGroups) { $allGroups += $AddToGroups }
    $allGroups = $allGroups | Select-Object -Unique

    $added = New-Object System.Collections.Generic.List[string]
    $failedGroups = New-Object System.Collections.Generic.List[string]
    foreach ($g in $allGroups) {
      if (-not $g) { continue }
      if ($PSCmdlet.ShouldProcess("User '$sam'", "Add to group '$g'")) {
        try {
          Add-ADGroupMember -Identity $g -Members $sam -ErrorAction Stop
          $added.Add($g)
          Write-Verbose "Added '$sam' to '$g'."
        } catch {
          $failedGroups.Add($g)
          $errs.Add("Failed to add '$sam' to '$g': $($_.Exception.Message)")
        }
      }
    }
    $result.GroupsAdded = $added.ToArray()
    $result.GroupsFailed = $failedGroups.ToArray()

    # Home folder provisioning (optional)
    if ($CreateHomeFolders) {
      $userHome = Join-Path $HomeRootPath $sam
      if ($PSCmdlet.ShouldProcess("FileSystem '$userHome'", "Create & set NTFS perms")) {
        $result.HomeFolder = 'Created'
        try {
          if (-not (Test-Path -LiteralPath $userHome)) {
            New-Item -Path $userHome -ItemType Directory -Force -ErrorAction Stop | Out-Null
          }
          # Grant user full control on their home folder (NTFS)
          $acl = Get-Acl -LiteralPath $userHome
          $id  = New-Object System.Security.Principal.NTAccount("$env:USERDOMAIN",$sam)
          $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($id,"FullControl","ContainerInherit,ObjectInherit","None","Allow")
          $acl.SetAccessRule($rule)
          Set-Acl -LiteralPath $userHome -AclObject $acl -ErrorAction Stop
          Write-Verbose "Set NTFS permissions on '$userHome'."
          # AD home directory attributes are set only after the folder and its ACL exist
          Set-ADUser -Identity $sam -HomeDirectory $userHome -HomeDrive "H:" -ErrorAction Stop
        } catch {
          $result.HomeFolder = 'Failed'
          $errs.Add("Home folder provisioning failed for '$sam' at '$userHome': $($_.Exception.Message)")
        }
      }
    }

    $result.Errors = $errs.ToArray()
    $result.Status = if ($errs.Count -gt 0) { 'PartiallyCompleted' } else { 'Created' }
    foreach ($e in $errs) { Write-Error $e }
    $result
  }
}

end {
  Write-Verbose "Bulk user creation process completed."
}

<#
.SYNOPSIS
  Detect over-permissioned accounts (users or groups) on NTFS paths.

.DESCRIPTION
  Walks ACLs on one or more roots and flags ACEs that grant high rights (Write/Modify/Full)
  to accounts not in an allow-list. Optionally expands AD groups recursively to show
  user membership of those groups. Findings are per-ACE and describe POTENTIAL exposure: they do not
  evaluate Deny precedence, share permissions, nested-group token effects, or any other condition required
  to establish a user's effective access. Errors (unreadable paths, failed group expansion) are emitted as
  non-terminating errors and a final warning rather than being hidden.

.PARAMETER Path
  One or more root paths (UNC or local).

.PARAMETER Recurse
  Recurse into subfolders. Use -MaxDepth to control scope.

.PARAMETER MaxDepth
  Maximum recursion depth when -Recurse is set (default: 5).

.PARAMETER IncludeFiles
  If set, evaluate files as well as folders.

.PARAMETER ResolveSIDs
  Resolve SID to NTAccount. Recommended when using -AllowedPrincipals/-DeniedPrincipals.

.PARAMETER MinRight
  Minimum right to flag: 'Write', 'Modify', or 'FullControl'. Default: 'Modify'.

.PARAMETER AllowedPrincipals
  Principals (domain\group or user) allowed to have >= MinRight without being flagged.

.PARAMETER ExcludePrincipals
  Principals to ignore entirely (e.g., 'BUILTIN\Administrators','NT AUTHORITY\SYSTEM').

.PARAMETER IncludePathLike
  Optional wildcard filter for paths to include (e.g., '*\Finance\*').

.PARAMETER ExcludePathLike
  Optional wildcard filter for paths to exclude.

.PARAMETER ExpandADGroups
  If set, expand AD group members recursively (requires RSAT ActiveDirectory). Emits additional rows per user.

.PARAMETER Domain
  Optional AD domain (DNS name) for queries when expanding groups.

.PARAMETER OutputCsv
  Optional CSV output for findings.

.EXAMPLES
  # Flag anything >= Modify that isn't explicitly allowed
  .\DetectOverPermissionedAccounts.ps1 -Path '\\fs01\Projects' -Recurse -MaxDepth 4 `
    -AllowedPrincipals 'CONTOSO\FileAdmins','CONTOSO\Project-Leads' -OutputCsv .\overperm.csv

  # Expand group membership to list members of flagged groups (not proof of effective access)
  .\DetectOverPermissionedAccounts.ps1 -Path 'D:\Data' -Recurse -ExpandADGroups -ResolveSIDs -MinRight Write -Verbose

.NOTES (Environment-specific adjustments & future GUI prompts)
  - Scope: -Path, -Recurse, -MaxDepth, -IncludeFiles
  - Threshold: -MinRight (Write/Modify/FullControl)
  - Policy: -AllowedPrincipals, -ExcludePrincipals
  - Filters: -IncludePathLike, -ExcludePathLike
  - SID resolution & AD expansion: -ResolveSIDs, -ExpandADGroups, -Domain
  - Exports: -OutputCsv
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
  [string[]]$Path,

  [Parameter()]
  [switch]$Recurse,

  [Parameter()]
  [ValidateRange(1,64)]
  [int]$MaxDepth = 5,

  [Parameter()]
  [switch]$IncludeFiles,

  [Parameter()]
  [switch]$ResolveSIDs,

  [Parameter()]
  [ValidateSet('Write','Modify','FullControl')]
  [string]$MinRight = 'Modify',

  [Parameter()]
  [string[]]$AllowedPrincipals = @('BUILTIN\Administrators','NT AUTHORITY\SYSTEM'),

  [Parameter()]
  [string[]]$ExcludePrincipals,

  [Parameter()]
  [string]$IncludePathLike,

  [Parameter()]
  [string]$ExcludePathLike,

  [Parameter()]
  [switch]$ExpandADGroups,

  [Parameter()]
  [string]$Domain,

  [Parameter()]
  [string]$OutputCsv
)

begin {
  # --- Prepare rights classification and error reporting ---
  . (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'Shared/FileSystemRights.ps1')
  $script:ErrorCount = 0

  function Write-ScanError {
    param([string]$Msg)
    $script:ErrorCount++
    Write-Error -Message $Msg
  }

  function Get-SimplifiedRight {
    param([System.Security.AccessControl.FileSystemRights]$r)
    # Exact-mask labelling; anything below Write is 'ReadOrLower'
    $label = Convert-FileSystemRightsLabel -Rights $r
    if ($label -in @('FullControl','Modify','Write')) { return $label }
    return 'ReadOrLower'
  }

  function Test-RightThreshold {
    param([string]$simple,[string]$min='Modify')
    switch ($min) {
      'FullControl' { return ($simple -eq 'FullControl') }
      'Modify'      { return ($simple -eq 'FullControl' -or $simple -eq 'Modify') }
      'Write'       { return ($simple -in @('FullControl','Modify','Write')) }
    }
  }

  function Resolve-AclPrincipalName {
    param($id,[switch]$DoResolve)
    try {
      if (-not $DoResolve) { return $id.Value }
      $sid = try { New-Object System.Security.Principal.SecurityIdentifier($id.Value) } catch { $null }
      if ($sid) { return ($sid.Translate([System.Security.Principal.NTAccount])).Value }
      return $id.Value
    } catch { return $id.Value }
  }

  function Get-ScanTarget {
    param([string]$root,[switch]$Recurse,[int]$MaxDepth,[switch]$Files)
    $targets = @($root)
    if ($Recurse) {
      $enumErrors = @()
      $dirs = @(Get-ChildItem -LiteralPath $root -Directory -Recurse -ErrorAction SilentlyContinue -ErrorVariable +enumErrors)
      $targets += $dirs.FullName
      if ($Files) {
        $targets += (@(Get-ChildItem -LiteralPath $root -File -Recurse -ErrorAction SilentlyContinue -ErrorVariable +enumErrors)).FullName
      }
      foreach ($e in $enumErrors) { Write-ScanError "Enumeration error under $root : $($e.Exception.Message)" }
      if ($MaxDepth -gt 0) {
        $base = ($root -split '[\\/]').Count
        $targets = $targets | Where-Object { (($_ -split '[\\/]').Count - $base) -le $MaxDepth }
      }
    }
    return $targets | Sort-Object -Unique
  }

  function Expand-AdGroupMember {
    param([string]$Principal,[string]$Domain)
    # Returns @{ Status; Users } for a group principal. Status is explicit so a failed lookup is never
    # reported as "no members": NotAGroup | Expanded | Failed:<reason>
    # Group expansion supplies possible membership context, not a complete Windows access token.
    try {
      Import-Module ActiveDirectory -ErrorAction Stop | Out-Null
      $dc = @{}
      if ($Domain) { $dc.Server = $Domain }
      $isGroup = $null
      try { $isGroup = Get-ADGroup -Identity $Principal @dc -ErrorAction Stop }
      catch {
        # Only a definite "not found" means the principal is not a group; any other error is a failure
        if ($_.Exception.GetType().Name -ne 'ADIdentityNotFoundException') { throw }
        $isGroup = $null
      }
      if (-not $isGroup) { return @{ Status = 'NotAGroup'; Users = @() } }
      $mem = Get-ADGroupMember -Identity $Principal -Recursive @dc -ErrorAction Stop |
             Where-Object { $_.objectClass -eq 'user' }
      return @{ Status = 'Expanded'; Users = @($mem | ForEach-Object { $_.SamAccountName }) }
    } catch {
      return @{ Status = "Failed: $($_.Exception.Message)"; Users = @() }
    }
  }

  $findings = New-Object System.Collections.Generic.List[Object]
}

process {
  # --- Inventory candidate ACEs ---
  # Filters and thresholds identify potential exposure; they do not evaluate effective access.
  foreach ($root in $Path) {
    if (-not (Test-Path -LiteralPath $root)) { Write-ScanError "Path not found: $root"; continue }

    $targets = Get-ScanTarget -root $root -Recurse:$Recurse.IsPresent -MaxDepth $MaxDepth -Files:$IncludeFiles.IsPresent

    foreach ($t in $targets) {
      if ($IncludePathLike -and ($t -notlike $IncludePathLike)) { continue }
      if ($ExcludePathLike -and ($t -like  $ExcludePathLike))   { continue }

      try {
        $acl = Get-Acl -LiteralPath $t
      } catch { Write-ScanError "ACL read failed for $t : $($_.Exception.Message)"; continue }

      $denyCount = @($acl.Access | Where-Object { $_.AccessControlType -eq 'Deny' }).Count

      foreach ($ace in $acl.Access) {
        $principal = Resolve-AclPrincipalName -id $ace.IdentityReference -DoResolve:$ResolveSIDs.IsPresent

        if ($ExcludePrincipals -and ($principal -in $ExcludePrincipals)) { continue }

        $right = Get-SimplifiedRight -r $ace.FileSystemRights
        $isHigh = Test-RightThreshold -simple $right -min $MinRight
        if (-not $isHigh) { continue }

        $isAllow = ($ace.AccessControlType -eq 'Allow')
        if (-not $isAllow) { continue } # focus on over-permissioned (Allow)

        $allowed = ($AllowedPrincipals -contains $principal)
        if ($allowed) { continue }

        # At this point: candidate finding
        $finding = [pscustomobject]@{
          Path            = $t
          Principal       = $principal
          Rights          = $right
          IsInherited     = $ace.IsInherited
          InheritanceOn   = -not $acl.AreAccessRulesProtected
          AccessType      = $ace.AccessControlType
          IncludeReason   = ">= $MinRight and not in AllowedPrincipals"
          DenyAcesOnPath  = $denyCount
          ExpansionStatus = 'NotRequested'
          ExpandedGroupMembers = $null
          # Retained for compatibility; this contains expanded group membership, not effective access.
          EffectiveUsers  = $null
          Caveat          = 'Single-ACE finding. Not an effective-access determination: Deny precedence, share permissions, other ACEs, and token/group state are not evaluated.'
        }

        if ($ExpandADGroups) {
          # Only attempt expansion for group-like principals
          $exp = Expand-AdGroupMember -Principal $principal -Domain $Domain
          $finding.ExpansionStatus = $exp.Status
          if ($exp.Status -like 'Failed*') { Write-ScanError "Group expansion failed for $principal : $($exp.Status)" }
          if ($exp.Users.Count -gt 0) {
            $finding.ExpandedGroupMembers = ($exp.Users -join '; ')
            $finding.EffectiveUsers = $finding.ExpandedGroupMembers
          }
        }

        $findings.Add($finding)
      }
    }
  }
}

end {
  $out = $findings | Sort-Object Path, Principal

  if ($OutputCsv) {
    try { $out | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8 -ErrorAction Stop } catch { Write-ScanError "CSV export failed: $($_.Exception.Message)" }
  }

  if ($script:ErrorCount -gt 0) {
    Write-Warning "$($script:ErrorCount) error(s) occurred. The findings are INCOMPLETE; see the error stream."
  }

  # Objects are emitted (no Format-Table) so callers can consume them programmatically.
  $out
}

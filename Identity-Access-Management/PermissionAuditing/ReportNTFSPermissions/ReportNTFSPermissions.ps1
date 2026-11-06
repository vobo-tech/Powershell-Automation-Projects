<#
.SYNOPSIS
  Report NTFS ACLs for folders/files with risk flags and export to CSV/JSONL.

.DESCRIPTION
  Walks a set of root paths and collects ACL entries:
    - Principal (resolved SID), Rights, AccessControlType (Allow/Deny), Inheritance, IsInherited
    - Flags potential risks: broad principals with high rights, Deny ACEs, disabled inheritance,
      unresolved SIDs, and unusual owners.
  Outputs flattened rows (objects, not formatted text) for analysis. Each row describes ONE ACE; it does not
  evaluate Deny precedence, group membership, share permissions, or any other condition needed to establish
  a principal's effective access.
  Enumeration/ACL errors are reported as non-terminating errors and a final warning; they are not hidden.
  Designed to run with least surprises in large trees.

.PARAMETER Path
  One or more root paths to scan (e.g., 'D:\Shares\Finance', '\\fs01\Projects').

.PARAMETER Recurse
  If set, recurse subfolders (default depth uses -MaxDepth).

.PARAMETER MaxDepth
  Maximum recursion depth (default: 5). Ignored if -Recurse not set.

.PARAMETER IncludeFiles
  If set, also emits file-level ACLs (may be expensive). Default: folder ACLs only.

.PARAMETER ResolveSIDs
  If set, resolves SIDs to names. If false, keeps raw SID strings (faster in large domains).

.PARAMETER BroadPrincipals
  Principals treated as "broad" (default: 'Everyone','Authenticated Users','Domain Users').

.PARAMETER HighRights
  Rights considered "high" (default: Modify, FullControl). Used for risk flagging.

.PARAMETER OutputCsv
  Optional CSV path to write results.

.PARAMETER OutputJsonl
  Optional newline-delimited JSON file path.

.PARAMETER ErrorLog
  Optional path to write errors encountered during traversal (access denied, path not found, etc.).

.EXAMPLES
  # Inventory a share tree (folders only), recurse 4 levels, export CSV
  .\ReportNTFSPermissions.ps1 -Path '\\fs01\Projects' -Recurse -MaxDepth 4 -OutputCsv .\ntfs_projects.csv -Verbose

  # Include files, resolve SIDs, JSONL output for SIEM
  .\ReportNTFSPermissions.ps1 -Path 'D:\Data' -Recurse -IncludeFiles -ResolveSIDs -OutputJsonl .\ntfs.jsonl

.NOTES (Environment adjustments & future GUI prompts)
  - Target roots: -Path (folder picker / multi-select; allow UNC)
  - Depth & scope: -Recurse, -MaxDepth, -IncludeFiles
  - Name resolution: -ResolveSIDs (domain size may affect speed)
  - Risk tuning: -BroadPrincipals, -HighRights
  - Exports: -OutputCsv, -OutputJsonl; error log path
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
  [string[]]$BroadPrincipals = @('Everyone','Authenticated Users','Domain Users'),

  [Parameter()]
  [ValidateSet('Modify','FullControl')]
  [string[]]$HighRights = @('Modify','FullControl'),

  [Parameter()]
  [string]$OutputCsv,

  [Parameter()]
  [string]$OutputJsonl,

  [Parameter()]
  [string]$ErrorLog
)

begin {
  # --- Prepare shared rights interpretation and partial-error reporting ---
  . (Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'Shared/FileSystemRights.ps1')
  $script:ErrorCount = 0
  $script:ErrorLogPath = $ErrorLog

  function Resolve-PrincipalName {
    param($IdentityReference, [switch]$DoResolve)
    try {
      if (-not $DoResolve) { return $IdentityReference.Value }
      $sid = try { New-Object System.Security.Principal.SecurityIdentifier($IdentityReference.Value) } catch { $null }
      if ($sid) { return ($sid.Translate([System.Security.Principal.NTAccount])).Value }
      return $IdentityReference.Value
    } catch { return $IdentityReference.Value }
  }

  function Write-Err {
    param([string]$Msg)
    $script:ErrorCount++
    if ($script:ErrorLogPath) {
      try { "[$(Get-Date -Format s)] $Msg" | Out-File -FilePath $script:ErrorLogPath -Append -Encoding utf8 -ErrorAction Stop }
      catch { Write-Warning "Could not write to ErrorLog '$script:ErrorLogPath': $($_.Exception.Message)" }
    }
    # Non-terminating error: visible in $Error / -ErrorVariable, never silently dropped
    Write-Error -Message $Msg
  }

  $rows = New-Object System.Collections.Generic.List[Object]
}

process {
  # --- Enumerate requested paths and collect individual ACEs ---
  foreach ($root in $Path) {
    if (-not (Test-Path -LiteralPath $root)) {
      Write-Err "Path not found: $root"
      continue
    }

    # Enumerate targets
    $targets = @($root)
    if ($Recurse) {
      try {
        $enumErrors = @()
        $dirs = @(Get-ChildItem -LiteralPath $root -Directory -Recurse -ErrorAction SilentlyContinue -ErrorVariable +enumErrors)
        if ($IncludeFiles) {
          $files = @(Get-ChildItem -LiteralPath $root -File -Recurse -ErrorAction SilentlyContinue -ErrorVariable +enumErrors)
          $targets += $files.FullName
        }
        $targets += $dirs.FullName
        foreach ($e in $enumErrors) { Write-Err "Enumeration error under $root : $($e.Exception.Message)" }
      } catch {
        Write-Err "Enumeration failed at $root : $($_.Exception.Message)"
      }

      # Trim by depth
      if ($MaxDepth -gt 0) {
        $baseDepth = ($root -split '[\\/]').Count
        $targets = $targets | Where-Object { (($_ -split '[\\/]').Count - $baseDepth) -le $MaxDepth }
      }
    }

    foreach ($t in ($targets | Sort-Object -Unique)) {
      try {
        $acl = Get-Acl -LiteralPath $t
      } catch {
        Write-Err "Get-Acl failed for $t : $($_.Exception.Message)"
        continue
      }

      $owner = $acl.Owner

      # Each object is one ACE, not a calculation of the principal's effective access.
      foreach ($ace in $acl.Access) {
        $principal = Resolve-PrincipalName -IdentityReference $ace.IdentityReference -DoResolve:$ResolveSIDs.IsPresent
        $right     = Convert-FileSystemRightsLabel -Rights $ace.FileSystemRights
        $isDeny    = ($ace.AccessControlType -eq 'Deny')
        $broadHigh = ($BroadPrincipals -contains $principal.Split('\')[-1]) -and ($HighRights -contains $right)

        $rows.Add([pscustomobject]@{
          Path             = $t
          Owner            = $owner
          Principal        = $principal
          Rights           = $right
          AccessType       = $ace.AccessControlType
          InheritanceFlags = $ace.InheritanceFlags
          PropagationFlags = $ace.PropagationFlags
          IsInherited      = $ace.IsInherited
          InheritanceOn    = -not $acl.AreAccessRulesProtected
          Risk_BroadHigh   = $broadHigh
          Risk_Deny        = $isDeny
          Risk_Unresolved  = ($principal -match '^S-\d-\d+') # unresolved SID shows as S-1-...
          Caveat           = 'Single-ACE inventory row; not an effective-access determination. Deny precedence, share permissions, group membership, and token/application policy are not evaluated.'
        })
      }

      # Warn on owner anomalies (optional heuristic)
      if ($owner -match '^S-\d-\d+') {
        $rows.Add([pscustomobject]@{
          Path             = $t
          Owner            = $owner
          Principal        = $null
          Rights           = $null
          AccessType       = $null
          InheritanceFlags = $null
          PropagationFlags = $null
          IsInherited      = $null
          InheritanceOn    = -not $acl.AreAccessRulesProtected
          Risk_BroadHigh   = $false
          Risk_Deny        = $false
          Risk_Unresolved  = $true
          Caveat           = 'Owner inventory row; it does not determine effective access.'
        })
      }
    }
  }
}

end {
  $out = $rows | Sort-Object Path, Principal, Rights

  if ($OutputCsv) {
    try { $out | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8 -ErrorAction Stop } catch { Write-Error "CSV export failed: $($_.Exception.Message)"; $script:ErrorCount++ }
  }
  if ($OutputJsonl) {
    try { $out | ForEach-Object { $_ | ConvertTo-Json -Depth 6 -Compress } | Out-File -FilePath $OutputJsonl -Encoding UTF8 -ErrorAction Stop } catch { Write-Error "JSONL export failed: $($_.Exception.Message)"; $script:ErrorCount++ }
  }

  if ($script:ErrorCount -gt 0) {
    Write-Warning "$($script:ErrorCount) error(s) occurred during the scan. The results are INCOMPLETE; see the error stream and -ErrorLog."
  }

  # Objects are emitted to the pipeline (no Format-Table) so callers can filter, export, or test them.
  $out | Select-Object Path,Owner,Principal,Rights,AccessType,IsInherited,InheritanceOn,Risk_BroadHigh,Risk_Deny,Risk_Unresolved,Caveat
}

# ██████╗░██╗░░░██╗███████╗███████╗  ███╗░░██╗███████╗██████╗░██████╗░
# ██╔══██╗██║░░░██║██╔════╝██╔════╝  ████╗░██║██╔════╝██╔══██╗██╔══██╗
# ██████╦╝██║░░░██║█████╗░░█████╗░░  ██╔██╗██║█████╗░░██████╔╝██║░░██║
# ██╔══██╗██║░░░██║██╔══╝░░██╔══╝░░  ██║╚████║██╔══╝░░██╔══██╗██║░░██║
# ██████╦╝╚██████╔╝██║░░░░░██║░░░░░  ██║░╚███║███████╗██║░░██║██████╔╝
# ╚═════╝░░╚═════╝░╚═╝░░░░░╚═╝░░░░░  ╚═╝░░╚══╝╚══════╝╚═╝░░╚═╝╚═════╝░
# -------Script by Aaron Voborny---https://github.com/buffnerd--------

<#
.SYNOPSIS
  Reports AD users inactive for N days; optional disable and move to quarantine OU.

.DESCRIPTION
  - Calculates inactivity via lastLogonTimestamp -> DateTime. lastLogonTimestamp is replicated lazily and can lag
    real logons by roughly 14 days; it also does not reflect many non-interactive or token-based sign-ins.
    Results are CANDIDATES for review, not authoritative evidence of inactivity. Confirm with other sources
    (for example per-DC lastLogon, sign-in logs, or the owner) before disabling or moving anything.
  - Emits report objects to the pipeline (no Format-Table). Remediation outcomes are recorded per account.
  - Filters by OU (SearchBase) and can include disabled users if requested.
  - Optional remediation: Disable-ADAccount and/or Move-ADObject.
  - Exports to CSV.

.REQUIREMENTS
  - RSAT Active Directory module.
  - Rights to query, disable, and move AD objects as applicable.

.EXAMPLES
  PS> .\InactiveAccountReport.ps1 -DaysInactive 90 -SearchBase "OU=Staff,OU=Corp,DC=contoso,DC=com" -ExportCsv .\inactive.csv -Verbose
  PS> .\InactiveAccountReport.ps1 -DaysInactive 180 -Disable -MoveToOU "OU=Disabled,OU=Corp,DC=contoso,DC=com" -WhatIf -Verbose
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter()]
  [ValidateRange(1, 3650)]
  [int]$DaysInactive = 90,

  [Parameter()]
  [string]$SearchBase,            # OU DN to scope search

  [Parameter()]
  [switch]$IncludeDisabled,

  [Parameter()]
  [string]$ExportCsv,

  [Parameter()]
  [switch]$Disable,               # Disable found accounts

  [Parameter()]
  [string]$MoveToOU               # Move found accounts to this OU (DN)
)

begin {
  # --- Prepare a scoped candidate search ---
  # Helper lives inside begin{}: a script that mixes top-level functions with begin/process/end blocks does not parse as intended.
  function Convert-LLTToDate {
    param([long]$LLT)
    if (-not $LLT) { return $null }
    return [DateTime]::FromFileTime($LLT)
  }

  try { Import-Module ActiveDirectory -ErrorAction Stop } catch { throw "Missing ActiveDirectory module." }

  $filter = if ($IncludeDisabled) { "*" } else { "(Enabled -eq $true)" }
  $props  = @("SamAccountName","Enabled","LastLogonTimeStamp","DistinguishedName","whenCreated","DisplayName")
  $getParams = @{
    Filter       = $filter
    Properties   = $props
    ErrorAction  = 'Stop'
  }
  if ($SearchBase) { $getParams['SearchBase'] = $SearchBase }

  $now = Get-Date
  $cutoff = $now.AddDays(-$DaysInactive)
  $results = New-Object System.Collections.Generic.List[Object]
}

process {
  # --- Collect candidates ---
  # Replicated lastLogonTimestamp is approximate; a candidate requires independent review.
  try {
    $users = Get-ADUser @getParams
  } catch {
    throw "Failed to query AD users: $($_.Exception.Message)"
  }

  foreach ($u in $users) {
    $lastLogon = Convert-LLTToDate -LLT $u.LastLogonTimeStamp
    # If lastLogon is null, consider account inactive since creation date
    $lastActive = if ($lastLogon) { $lastLogon } else { $u.whenCreated }
    if ($lastActive -lt $cutoff) {
      $results.Add([pscustomobject]@{
        SamAccountName = $u.SamAccountName
        DisplayName    = $u.DisplayName
        Enabled        = $u.Enabled
        LastLogon      = $lastLogon
        ConsideredInactiveSince = $lastActive
        DaysInactive   = [int]($now - $lastActive).TotalDays
        DN             = $u.DistinguishedName
        InactivityBasis = if ($lastLogon) { 'LastLogonTimestamp (approximate)' } else { 'whenCreated (no LastLogonTimestamp recorded)' }
        DisableStatus  = 'NotRequested'
        MoveStatus     = 'NotRequested'
        RemediationErrors = @()
      })
    }
  }
}

end {
  # --- Apply requested remediation and return evidence ---
  # A failed disable blocks the requested move; statuses and errors remain on each result object.
  if ($Disable -or $MoveToOU) {
    foreach ($r in $results) {
      $errs = New-Object System.Collections.Generic.List[string]
      if ($Disable) {
        if ($PSCmdlet.ShouldProcess("User '$($r.SamAccountName)'", "Disable")) {
          try {
            Disable-ADAccount -Identity $r.SamAccountName -ErrorAction Stop
            $r.DisableStatus = 'Succeeded'
            Write-Verbose "Disabled '$($r.SamAccountName)'."
          } catch {
            $r.DisableStatus = 'Failed'
            $errs.Add("Failed to disable '$($r.SamAccountName)': $($_.Exception.Message)")
          }
        } else { $r.DisableStatus = 'Skipped' }
      }
      if ($MoveToOU) {
        if ($r.DisableStatus -eq 'Failed') {
          # Do not move an account that was supposed to be disabled first
          $r.MoveStatus = 'Blocked'
          $errs.Add("Move of '$($r.SamAccountName)' blocked because the disable failed.")
        }
        elseif ($PSCmdlet.ShouldProcess("User '$($r.SamAccountName)'", "Move to '$MoveToOU'")) {
          try {
            Move-ADObject -Identity $r.DN -TargetPath $MoveToOU -ErrorAction Stop
            $r.MoveStatus = 'Succeeded'
            Write-Verbose "Moved '$($r.SamAccountName)' to '$MoveToOU'."
          } catch {
            $r.MoveStatus = 'Failed'
            $errs.Add("Failed to move '$($r.SamAccountName)': $($_.Exception.Message)")
          }
        } else { $r.MoveStatus = 'Skipped' }
      }
      $r.RemediationErrors = $errs.ToArray()
      foreach ($e in $errs) { Write-Error $e }
    }
  }

  $sorted = @($results | Sort-Object DaysInactive -Descending)

  if ($ExportCsv) {
    try {
      $sorted | Select-Object * -ExcludeProperty RemediationErrors | Export-Csv -Path $ExportCsv -NoTypeInformation -ErrorAction Stop
      Write-Verbose "Exported report to '$ExportCsv'."
    } catch {
      Write-Error "Failed to export report: $($_.Exception.Message)"
    }
  }

  # Objects are emitted (no Format-Table) so callers can consume them programmatically.
  $sorted
}

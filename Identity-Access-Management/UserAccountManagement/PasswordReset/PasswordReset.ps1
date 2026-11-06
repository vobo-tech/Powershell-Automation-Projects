# ██████╗░██╗░░░██╗███████╗███████╗  ███╗░░██╗███████╗██████╗░██████╗░
# ██╔══██╗██║░░░██║██╔════╝██╔════╝  ████╗░██║██╔════╝██╔══██╗██╔══██╗
# ██████╦╝██║░░░██║█████╗░░█████╗░░  ██╔██╗██║█████╗░░██████╔╝██║░░██║
# ██╔══██╗██║░░░██║██╔══╝░░██╔══╝░░  ██║╚████║██╔══╝░░██╔══██╗██║░░██║
# ██████╦╝╚██████╔╝██║░░░░░██║░░░░░  ██║░╚███║███████╗██║░░██║██████╔╝
# ╚═════╝░░╚═════╝░╚═╝░░░░░╚═╝░░░░░  ╚═╝░░╚══╝╚══════╝╚═╝░░╚═╝╚═════╝░
# -------Script by Aaron Voborny---https://github.com/buffnerd--------

<#
.SYNOPSIS
  Resets passwords for one or more AD users, with optional unlock and forced change on next logon.

.DESCRIPTION
  - Accepts user identities directly or via CSV.
  - Can generate random strong passwords and export results.
  - Supports -WhatIf, -Confirm, and -Verbose.

.REQUIREMENTS
  - RSAT Active Directory module.
  - Rights to reset passwords and unlock accounts.

.CSV SCHEMA (when using -CsvPath):
  Identity  (SamAccountName or DN)
  NewPassword (optional; if omitted and -GenerateRandom is used, script will generate)

.EXAMPLES
  PS> .\PasswordReset.ps1 -Identity alice,bob -NewPassword (Read-Host "New" -AsSecureString) -ForceChangeAtLogon -Verbose -WhatIf
  PS> .\PasswordReset.ps1 -CsvPath .\reset.csv -GenerateRandom -ExportCsv .\reset-out.csv -Unlock
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification='Existing behavior: converts a generated or CSV-supplied password to SecureString for Set-ADAccountPassword. See ADIdentityOps README for the migration path.')]
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [Parameter(ParameterSetName='Direct', Mandatory=$false)]
  [string[]]$Identity,

  [Parameter(ParameterSetName='Csv', Mandatory=$true)]
  [ValidateScript({ Test-Path $_ })]
  [string]$CsvPath,

  [Parameter()]
  [SecureString]$NewPassword,   # If omitted AND -GenerateRandom is used, passwords are generated.

  [Parameter()]
  [switch]$GenerateRandom,

  [Parameter()]
  [switch]$ForceChangeAtLogon,

  [Parameter()]
  [switch]$Unlock,

  [Parameter()]
  [string]$ExportCsv  # When generating random passwords, export results here (plain text password)
)

begin {
  # Helper lives inside begin{}: a script that mixes top-level functions with begin/process/end blocks does not parse as intended.
  function New-RandomPassword {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification='Generates a string in memory only; changes nothing.')]
    [CmdletBinding()]
    param([int]$Length = 16)
    # Simple strong generator; customize for your policy
    $chars = (33..126) | ForEach-Object {[char]$_} | Where-Object { $_ -notin @('"','`','\') }
    -join (1..$Length | ForEach-Object { $chars | Get-Random })
  }

  try { Import-Module ActiveDirectory -ErrorAction Stop } catch { throw "Missing ActiveDirectory module." }

  $items = @()
  switch ($PSCmdlet.ParameterSetName) {
    'Direct' {
      if (-not $Identity) { throw "Provide -Identity or use -CsvPath." }
      $items = $Identity | ForEach-Object { [pscustomobject]@{ Identity = $_; NewPassword = $null } }
    }
    'Csv' {
      $items = Import-Csv -Path $CsvPath
      if (-not $items) { throw "CSV '$CsvPath' is empty or unreadable." }
    }
  }

  $results = New-Object System.Collections.Generic.List[Object]
}

process {
  foreach ($item in $items) {
    $id = $item.Identity
    if (-not $id) { Write-Warning "Row missing Identity; skipping."; continue }

    $pwdPlain = $null
    $pwdSecure = $NewPassword
    if (-not $pwdSecure) {
      if ($GenerateRandom) {
        $pwdPlain = New-RandomPassword
        $pwdSecure = ConvertTo-SecureString -String $pwdPlain -AsPlainText -Force
      } elseif ($item.PSObject.Properties.Match('NewPassword').Count -gt 0 -and $item.NewPassword) {
        $pwdSecure = ConvertTo-SecureString -String $item.NewPassword -AsPlainText -Force
      } else {
        throw "No password provided for '$id'. Provide -NewPassword, include NewPassword in CSV, or use -GenerateRandom."
      }
    }

    if ($PSCmdlet.ShouldProcess("AD User '$id'", "Reset password")) {
      $unlocked = $false; $forced = $false; $errs = New-Object System.Collections.Generic.List[string]
      $changed = $false
      try {
        Set-ADAccountPassword -Identity $id -NewPassword $pwdSecure -Reset -ErrorAction Stop
        $changed = $true
        Write-Verbose "Password reset for '$id'."
      } catch {
        $errs.Add("Failed to reset '$id': $($_.Exception.Message)")
      }
      # Follow-up steps are only attempted after a successful reset, and their failures are reported, not suppressed
      if ($changed -and $Unlock) {
        try { Unlock-ADAccount -Identity $id -ErrorAction Stop; $unlocked = $true }
        catch { $errs.Add("Password reset for '$id' succeeded but unlock failed: $($_.Exception.Message)") }
      }
      if ($changed -and $ForceChangeAtLogon) {
        try { Set-ADUser -Identity $id -ChangePasswordAtLogon $true -ErrorAction Stop; $forced = $true }
        catch { $errs.Add("Password reset for '$id' succeeded but ChangePasswordAtLogon failed: $($_.Exception.Message)") }
      }
      foreach ($e in $errs) { Write-Error $e }
      $results.Add([pscustomobject]@{
        Identity   = $id
        Password   = $pwdPlain  # null if not generated/known
        Changed    = $changed
        ForcedCPW  = $forced    # true only if the change was actually applied
        Unlocked   = $unlocked  # true only if the unlock was actually applied
        Errors     = $errs.ToArray()
      })
    }
  }
}

end {
  if ($ExportCsv) {
    try {
      $results | Select-Object * -ExcludeProperty Errors | Export-Csv -Path $ExportCsv -NoTypeInformation -ErrorAction Stop
      Write-Verbose "Results exported to '$ExportCsv'."
    } catch {
      Write-Error "Failed to export results: $($_.Exception.Message)"
    }
  }
  # Objects are emitted (no Format-Table). NOTE: -GenerateRandom passwords appear in this output and in
  # -ExportCsv; treat both as secrets. See the ADIdentityOps README for the migration guidance.
  $results
}
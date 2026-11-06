function ConvertTo-CsvSafeText {
    <#
    .SYNOPSIS
        Neutralizes spreadsheet formula injection by prefixing risky leading characters with an apostrophe.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()]$Value)
    $s = if ($null -eq $Value) { '' } else { [string]$Value }
    if ($s -match '^\s*[=+\-@]' -or $s -match '^[\t\r\n]') { return "'" + $s }
    $s
}

# Encode values before inserting them into HTML rather than interpreting them as markup.
function ConvertTo-HtmlText {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '' }
    [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

# Render headers and cells with HTML encoding, including an explicit empty-state message.
function ConvertTo-HtmlTable {
    [CmdletBinding()]
    [OutputType([string])]
    param([string[]]$Headers, [AllowEmptyCollection()][object[]]$Rows)
    if (@($Rows).Count -eq 0) { return '<p class="muted">None.</p>' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<table><thead><tr>')
    foreach ($h in $Headers) { [void]$sb.Append('<th>' + (ConvertTo-HtmlText $h) + '</th>') }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($row in $Rows) {
        [void]$sb.Append('<tr>')
        foreach ($cell in @($row)) { [void]$sb.Append('<td>' + (ConvertTo-HtmlText $cell) + '</td>') }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table>')
    $sb.ToString()
}

function Export-ADIdentityReport {
    <#
    .SYNOPSIS
        Exports offboarding evidence as JSON, CSV (action summary), and a self-contained HTML report.

    .DESCRIPTION
        Untrusted values (names, DNs, error text, request metadata) are HTML-encoded in the HTML report
        and neutralized against spreadsheet formula injection in the CSV. The HTML contains no scripts
        or external resources. Captured error text is sanitized on a best-effort basis; callers must not
        supply credentials in report objects or labels and should protect the resulting evidence files.

    .PARAMETER Plan
        Plan object (required).

    .PARAMETER Result
        Result from Invoke-ADOffboardingPlan (optional; without it the report shows the proposal only).

    .PARAMETER Verification
        Output of Test-ADOffboardingResult (optional).

    .PARAMETER Snapshot
        Output of Get-ADIdentitySnapshot to include as before-state evidence (optional).

    .PARAMETER Label
        Banner text shown at the top of the HTML report, e.g. to mark simulated data.

    .PARAMETER Config
        Optional configuration used to select the report directory when OutputDirectory is omitted.

    .PARAMETER OutputDirectory
        Directory to receive the three evidence files.

    .OUTPUTS
        An object identifying the generated report paths, or no object when ShouldProcess declines.

    .EXAMPLE
        Export-ADIdentityReport -Plan $plan -Result $r -Verification $v -Snapshot $before -OutputDirectory .\reports
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]$Plan,
        $Result,
        $Verification,
        $Snapshot,
        $Config,
        [string]$OutputDirectory,
        [string]$Label
    )

    if (-not $OutputDirectory) {
        if ($null -eq $Config) { throw 'Specify -OutputDirectory or -Config (Output.ReportDirectory).' }
        $OutputDirectory = (Resolve-ADIdentityConfig -Config $Config).Output.ReportDirectory
    }
    $planGuid = [guid]::Empty
    if (-not [guid]::TryParse([string]$Plan.PlanId, [ref]$planGuid)) { throw 'Plan has an invalid PlanId.' }
    $generated = Get-UtcNow
    $base = 'ADIdentityReport-{0}-{1}' -f $planGuid.ToString('D'), $generated.ToString('yyyyMMdd\THHmmssfff\Z', [System.Globalization.CultureInfo]::InvariantCulture)
    $jsonPath = Join-Path $OutputDirectory "$base.json"
    $csvPath = Join-Path $OutputDirectory "$base-actions.csv"
    $htmlPath = Join-Path $OutputDirectory "$base.html"

    # --- Assemble action evidence ---
    # Match each plan action to its reported and independently verified status when supplied.
    $rows = foreach ($a in @($Plan.Actions)) {
        $res = $null; $ver = $null
        if ($Result) { $res = @($Result.Actions | Where-Object { $_.ActionId -eq $a.ActionId }) | Select-Object -First 1 }
        if ($Verification) { $ver = @($Verification.Items | Where-Object { $_.ActionId -eq $a.ActionId }) | Select-Object -First 1 }
        $verText = if ($ver) { if ($ver.Verified) { 'Verified' } else { 'NotVerified' } } else { 'NotChecked' }
        $obj = if ($a.Group) { [string]$a.Group.Name } else { [string]$Plan.Target.SamAccountName }
        [pscustomobject][ordered]@{
            PlanId = [string]$Plan.PlanId; TicketReference = [string]$Plan.Request.TicketReference
            Target = [string]$Plan.Target.SamAccountName; TargetObjectGuid = [string]$Plan.Target.ObjectGuid
            ActionId = [string]$a.ActionId; Type = [string]$a.Type; Object = $obj
            ReportedStatus = $(if ($res) { [string]$res.Status } else { 'Planned' })
            Attempts = $(if ($res) { [string]$res.Attempts } else { '0' })
            StartedUtc = $(if ($res) { [string]$res.StartedUtc } else { '' })
            EndedUtc = $(if ($res) { [string]$res.EndedUtc } else { '' })
            Verification = $verText
            Error = $(if ($res) { [string]$res.Error } else { '' })
        }
    }
    $rows = @($rows)

    # WhatIf must stop before JSON, CSV, or HTML files are created.
    if (-not $PSCmdlet.ShouldProcess($OutputDirectory, 'Write identity report files')) { return $null }

    $report = [ordered]@{
        ReportSchemaVersion = '1.0'
        GeneratedUtc        = Get-UtcTimestamp -DateTime $generated
        Label               = $Label
        Snapshot            = $Snapshot
        Plan                = $Plan
        Result              = $Result
        Verification        = $Verification
    }
    [void](Write-Utf8File -Path $jsonPath -Content (ConvertTo-Json -InputObject ([pscustomobject]$report) -Depth 16))

    # --- Encode each output for its consumer ---
    # CSV cells may be opened in spreadsheets; neutralize formula prefixes before CSV quoting.
    $safeRows = foreach ($row in $rows) {
        $o = [ordered]@{}
        foreach ($pr in $row.PSObject.Properties) { $o[$pr.Name] = ConvertTo-CsvSafeText $pr.Value }
        [pscustomobject]$o
    }
    $csv = if (@($safeRows).Count -gt 0) { (@($safeRows) | ConvertTo-Csv -NoTypeInformation) -join "`r`n" } else { '"PlanId"' }
    [void](Write-Utf8File -Path $csvPath -Content $csv)

    # --- Build self-contained HTML ---
    # Encode dynamic text and use a restrictive content-security policy; do not treat names as markup.
    $h = New-Object System.Text.StringBuilder
    $e = { param($v) ConvertTo-HtmlText $v }
    [void]$h.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
    [void]$h.AppendLine('<meta http-equiv="Content-Security-Policy" content="default-src ''none''; style-src ''unsafe-inline''">')
    [void]$h.AppendLine('<title>AD Identity Offboarding Report</title><style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1b1b1b}table{border-collapse:collapse;margin:8px 0 20px}th,td{border:1px solid #bbb;padding:4px 8px;text-align:left;vertical-align:top;font-size:13px}th{background:#eee}.banner{background:#fff3cd;border:1px solid #d4a72c;padding:8px;font-weight:bold}.muted{color:#666}.bad{color:#a40000;font-weight:bold}.good{color:#1a6b1a;font-weight:bold}code{background:#f3f3f3;padding:0 3px}</style></head><body>')
    [void]$h.AppendLine('<h1>AD Identity Offboarding Report</h1>')
    if ($Label) { [void]$h.AppendLine('<p class="banner">' + (& $e $Label) + '</p>') }
    [void]$h.AppendLine('<p class="muted">Generated ' + (& $e (Get-UtcTimestamp -DateTime $generated)) + '. Evidence from this toolkit is point-in-time and limited as described below.</p>')

    [void]$h.AppendLine('<h2>Target and request</h2>')
    [void]$h.AppendLine((ConvertTo-HtmlTable -Headers 'Field', 'Value' -Rows @(
                , @('Account', $Plan.Target.SamAccountName); , @('ObjectGUID', $Plan.Target.ObjectGuid); , @('SID', $Plan.Target.Sid)
                , @('Distinguished name (at planning)', $Plan.Target.DistinguishedName); , @('Ticket / reference', $Plan.Request.TicketReference)
                , @('Requested by (metadata, not authorization)', $Plan.Request.RequestedBy); , @('Reason', $Plan.Request.Reason)
                , @('Plan ID', $Plan.PlanId); , @('Created / expires (UTC)', "$($Plan.CreatedUtc) / $($Plan.ExpiresUtc)")
                , @('Integrity hash (modification check only)', $Plan.Integrity.Hash); , @('Domain controller', $Plan.DomainController)
                , @('Configuration fingerprint', $Plan.ConfigFingerprint))))

    [void]$h.AppendLine('<h2>Scope and eligibility</h2>')
    if ($Plan.Eligibility.IsEligible) { [void]$h.AppendLine('<p class="good">Eligible for execution (subject to live preflight checks).</p>') }
    else { [void]$h.AppendLine('<p class="bad">NOT eligible. Execution is blocked.</p>' + (ConvertTo-HtmlTable -Headers 'Reason' -Rows @($Plan.Eligibility.BlockReasons | ForEach-Object { , @($_) }))) }
    [void]$h.AppendLine((ConvertTo-HtmlTable -Headers 'Observed at planning', 'Value' -Rows @(, @('Enabled', $Plan.ObservedState.Enabled); , @('Parent OU', $Plan.ObservedState.ParentDn); , @('Direct groups', (@($Plan.ObservedState.DirectGroups | ForEach-Object { $_.Name }) -join '; ')))))

    if ($Snapshot) {
        [void]$h.AppendLine('<h2>Before-state evidence (snapshot)</h2>')
        [void]$h.AppendLine((ConvertTo-HtmlTable -Headers 'Membership', 'Group', 'Path' -Rows @(@($Snapshot.DirectGroups) + @($Snapshot.NestedGroups) | ForEach-Object { , @($_.Membership, $_.Name, (@($_.Path) -join ' > ')) })))
        [void]$h.AppendLine('<p class="muted">Group membership is not proof of effective access.</p>')
    }

    [void]$h.AppendLine('<h2>Proposed changes and results</h2>')
    [void]$h.AppendLine((ConvertTo-HtmlTable -Headers 'Action', 'Type', 'Object', 'Reported status', 'Attempts', 'Started (UTC)', 'Ended (UTC)', 'Verification', 'Error' -Rows @($rows | ForEach-Object { , @($_.ActionId, $_.Type, $_.Object, $_.ReportedStatus, $_.Attempts, $_.StartedUtc, $_.EndedUtc, $_.Verification, $_.Error) })))

    [void]$h.AppendLine('<h2>Exclusions (retained / not removable)</h2>')
    [void]$h.AppendLine((ConvertTo-HtmlTable -Headers 'Type', 'Group', 'Reason', 'Path(s)' -Rows @($Plan.Exclusions | ForEach-Object { , @($_.Type, $_.Group.Name, $_.Reason, $(if ($_.PSObject.Properties['Paths']) { (@($_.Paths | ForEach-Object { @($_) -join ' > ' }) -join ' | ') } else { '' })) })))

    if (@($Plan.Warnings).Count -gt 0) {
        [void]$h.AppendLine('<h2>Plan warnings</h2>' + (ConvertTo-HtmlTable -Headers 'Warning' -Rows @($Plan.Warnings | ForEach-Object { , @($_) })))
    }

    if ($Result) {
        [void]$h.AppendLine('<h2>Execution</h2>')
        [void]$h.AppendLine((ConvertTo-HtmlTable -Headers 'Field', 'Value' -Rows @(, @('Run ID', $Result.RunId); , @('Resumed from run', $Result.ResumedFromRunId); , @('Mode', $Result.Mode); , @('Status', $Result.Status); , @('Status detail', $Result.StatusReason); , @('Started / ended (UTC)', "$($Result.StartedUtc) / $($Result.EndedUtc)"))))
        if ($Result.OriginalState) {
            [void]$h.AppendLine('<h3>Original state (recovery evidence, not a rollback)</h3>')
            [void]$h.AppendLine((ConvertTo-HtmlTable -Headers 'Field', 'Value' -Rows @(, @('Enabled', $Result.OriginalState.Enabled); , @('Original parent OU', $Result.OriginalState.ParentDn); , @('Original direct groups', (@($Result.OriginalState.DirectGroups | ForEach-Object { $_.Name }) -join '; ')))))
        }
    }

    if ($Verification) {
        [void]$h.AppendLine('<h2>Verification</h2>')
        if ($Verification.Passed) { [void]$h.AppendLine('<p class="good">PASSED: every planned change is satisfied in live state.</p>') } else { [void]$h.AppendLine('<p class="bad">NOT PASSED.</p>') }
        [void]$h.AppendLine((ConvertTo-HtmlTable -Headers 'Item', 'Category', 'Reported', 'Expected', 'Observed', 'Verified' -Rows @($Verification.Items | ForEach-Object { , @($_.ActionId, $_.Category, $_.ReportedStatus, $_.Expected, $_.Observed, $_.Verified) })))
        [void]$h.AppendLine((ConvertTo-HtmlTable -Headers 'Check', 'Passed', 'Detail' -Rows @($Verification.Checks | ForEach-Object { , @($_.Name, $_.Passed, $_.Detail) })))
        if (@($Verification.Discrepancies).Count -gt 0) { [void]$h.AppendLine('<h3>Discrepancies</h3>' + (ConvertTo-HtmlTable -Headers 'Discrepancy' -Rows @($Verification.Discrepancies | ForEach-Object { , @($_) }))) }
        if (@($Verification.ResidualInheritedMemberships).Count -gt 0) {
            [void]$h.AppendLine('<h3>Inherited memberships that remain (informational)</h3>' + (ConvertTo-HtmlTable -Headers 'Group', 'Path' -Rows @($Verification.ResidualInheritedMemberships | ForEach-Object { , @($_.Group, (@($_.Path) -join ' > ')) })))
        }
    }

    $incompleteIds = @()
    if ($Result -and $Result.Summary) { $incompleteIds = @($Result.Summary.IncompleteActionIds) }
    elseif (-not $Result) { $incompleteIds = @($Plan.Actions | ForEach-Object { $_.ActionId }) }
    [void]$h.AppendLine('<h2>Incomplete work</h2>')
    if ($incompleteIds.Count -eq 0) { [void]$h.AppendLine('<p class="good">None reported.</p>') }
    else { [void]$h.AppendLine('<p class="bad">' + (& $e ($incompleteIds -join ', ')) + '</p>') }

    [void]$h.AppendLine('<h2>Limitations</h2>' + (ConvertTo-HtmlTable -Headers 'Statement' -Rows @($Plan.Limitations | ForEach-Object { , @($_) })))
    [void]$h.AppendLine('</body></html>')
    [void](Write-Utf8File -Path $htmlPath -Content $h.ToString())

    [pscustomobject][ordered]@{
        GeneratedUtc = Get-UtcTimestamp -DateTime $generated
        JsonPath     = [System.IO.Path]::GetFullPath($jsonPath)
        CsvPath      = [System.IO.Path]::GetFullPath($csvPath)
        HtmlPath     = [System.IO.Path]::GetFullPath($htmlPath)
        Actions      = $rows
    }
}

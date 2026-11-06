Set-StrictMode -Version Latest

# Static statements embedded in plans and reports so they travel with the evidence.
$script:ToolkitLimitations = @(
    'Disabling an on-prem AD account does not by itself terminate existing sessions, Kerberos tickets, cached credentials, tokens, or cloud (Entra ID/M365) access.',
    'Group membership shown here is not proof of effective access; effective access also depends on resource ACLs, deny entries, token contents, and application policy.',
    'Only direct memberships can be removed. Memberships inherited through nested groups are reported, never removed as if direct.',
    'Primary group membership (primaryGroupID) is not part of memberOf and is not collected or changed.',
    'There is no transactional rollback. Original OU and direct memberships are preserved as recovery evidence only; recovery is a manual, separately authorized process.',
    'The plan integrity hash detects accidental or casual modification only. It does not establish approval, authorship, or authenticity.',
    'Execution authorization comes from Active Directory permissions and the organization change process, not from any field in the plan.'
)

# Obtain a single UTC time source for plan and result timestamps.
function Get-UtcNow {
    [CmdletBinding()]
    [OutputType([datetime])]
    param()
    [datetime]::UtcNow
}

# Format evidence timestamps consistently and independently of the host locale.
function Get-UtcTimestamp {
    [CmdletBinding()]
    [OutputType([string])]
    param([datetime]$DateTime = (Get-UtcNow))
    $DateTime.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
}

# Interpret saved timestamp values as UTC for expiry comparisons.
function ConvertTo-UtcDateTime {
    [CmdletBinding()]
    [OutputType([datetime])]
    param([Parameter(Mandatory)]$Value)
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles)
}

function Get-Sha256Hex {
    # Hashing is an integrity comparison, not a signature or proof of authorization.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))
        ($bytes | ForEach-Object { $_.ToString('x2') }) -join ''
    }
    finally { $sha.Dispose() }
}

# Escape a string deterministically for the canonical hash representation.
function ConvertTo-CanonicalString {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ($null -eq $Text) { return 'null' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    foreach ($ch in $Text.ToCharArray()) {
        $code = [int]$ch
        if ($ch -eq '"') { [void]$sb.Append('\"') }
        elseif ($ch -eq '\') { [void]$sb.Append('\\') }
        elseif ($code -lt 32) { [void]$sb.Append(('\u{0:x4}' -f $code)) }
        else { [void]$sb.Append($ch) }
    }
    [void]$sb.Append('"')
    $sb.ToString()
}

function ConvertTo-CanonicalJson {
    <#
    .SYNOPSIS
        Deterministic JSON used only for hashing (sorted keys, UTC timestamps, no version-specific escaping).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()]$InputObject)

    if ($null -eq $InputObject) { return 'null' }
    if ($InputObject -is [string]) { return (ConvertTo-CanonicalString -Text $InputObject) }
    if ($InputObject -is [bool]) { if ($InputObject) { return 'true' } else { return 'false' } }
    if ($InputObject -is [datetime]) { return (ConvertTo-CanonicalString -Text (Get-UtcTimestamp -DateTime $InputObject)) }
    if ($InputObject -is [int] -or $InputObject -is [long] -or $InputObject -is [int16] -or $InputObject -is [byte] -or $InputObject -is [uint32] -or $InputObject -is [uint64]) {
        return [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0}', $InputObject)
    }
    # Sort keys ordinally while retaining array order, so the same data hashes consistently.
    if ($InputObject -is [System.Collections.IDictionary]) {
        $keys = [string[]]@($InputObject.Keys | ForEach-Object { [string]$_ })
        [Array]::Sort($keys, [System.StringComparer]::Ordinal)
        $parts = foreach ($k in $keys) { (ConvertTo-CanonicalString -Text $k) + ':' + (ConvertTo-CanonicalJson -InputObject $InputObject[$k]) }
        return '{' + (@($parts) -join ',') + '}'
    }
    if ($InputObject -is [System.Collections.IEnumerable]) {
        $parts = foreach ($item in $InputObject) { ConvertTo-CanonicalJson -InputObject $item }
        return '[' + (@($parts) -join ',') + ']'
    }
    if ($InputObject -is [pscustomobject]) {
        $table = @{}
        foreach ($p in $InputObject.PSObject.Properties) { $table[$p.Name] = $p.Value }
        return (ConvertTo-CanonicalJson -InputObject $table)
    }
    ConvertTo-CanonicalString -Text ([string]$InputObject)
}

function Get-SanitizedText {
    <#
    .SYNOPSIS
        Removes control characters, redacts credential-looking assignments, and bounds length.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$Text, [int]$MaxLength = 500)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    # This is best-effort redaction of common assignment patterns, not a guarantee of secret removal.
    $clean = $Text -replace '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', ' '
    $clean = $clean -replace '(?i)\b(password|passwd|pwd|secret|token|bearer|api[-_]?key|credential)\b(\s*[=:]\s*|\s+)("[^"]*"|''[^'']*''|\S+)', '$1=[REDACTED]'
    if ($clean.Length -gt $MaxLength) { $clean = $clean.Substring(0, $MaxLength) + '...[truncated]' }
    $clean
}

function Write-Utf8File {
    <#
    .SYNOPSIS
        Writes a local file as UTF-8 without BOM. Deliberately not Set-Content so -WhatIf/-Confirm
        preferences of callers cannot silently swallow or prompt for evidence files.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowEmptyString()][string]$Content)
    $full = [System.IO.Path]::GetFullPath($Path)
    $dir = [System.IO.Path]::GetDirectoryName($full)
    if (-not (Test-Path -LiteralPath $dir)) { [void][System.IO.Directory]::CreateDirectory($dir) }
    [System.IO.File]::WriteAllText($full, $Content, (New-Object System.Text.UTF8Encoding($false)))
    $full
}

# Load saved evidence while preserving date-like strings when PowerShell supports that option.
function Read-JsonFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "File not found: $Path" }
    $raw = [System.IO.File]::ReadAllText([System.IO.Path]::GetFullPath($Path))
    $cmd = Get-Command ConvertFrom-Json
    # Keep ISO-looking strings as strings where supported so hashes recompute identically.
    if ($cmd.Parameters.ContainsKey('DateKind')) { return ($raw | ConvertFrom-Json -DateKind String) }
    $raw | ConvertFrom-Json
}

# Convert an optional AD identifier to trimmed text for portable evidence.
function ConvertTo-IdString {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    ([string]$Value).Trim()
}

function ConvertTo-NormalizedIdentifier {
    <#
    .SYNOPSIS
        Normalizes a GUID, SID, or DN so identifiers can be compared case-insensitively.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $v = $Value.Trim()
    $g = [guid]::Empty
    if ([guid]::TryParse($v, [ref]$g)) { return 'guid:' + $g.ToString('D') }
    if ($v -match '^S-1-\d+(-\d+)+$') { return 'sid:' + $v.ToUpperInvariant() }
    if ($v -match '^[A-Za-z][A-Za-z0-9-]*=') { return 'dn:' + (($v -replace '\s*,\s*', ',').ToLowerInvariant()) }
    'name:' + $v.ToLowerInvariant()
}

# Classify a normalized identifier before allowing it in safety-sensitive configuration.
function Get-IdentifierKind {
    [CmdletBinding()]
    [OutputType([string])]
    param([string]$Value)
    $n = ConvertTo-NormalizedIdentifier -Value $Value
    if (-not $n) { return 'empty' }
    $n.Substring(0, $n.IndexOf(':'))
}

function Test-IdentifierInList {
    <#
    .SYNOPSIS
        True when any of the candidate identifiers equals any configured identifier (GUID/SID/DN).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([string[]]$Candidate, [string[]]$List)
    $set = @{}
    foreach ($l in @($List)) { $n = ConvertTo-NormalizedIdentifier -Value $l; if ($n) { $set[$n] = $true } }
    foreach ($c in @($Candidate)) {
        $n = ConvertTo-NormalizedIdentifier -Value $c
        if ($n -and $set.ContainsKey($n)) { return $true }
    }
    $false
}

# Derive the parent DN while respecting escaped commas in a distinguished name.
function Get-ParentDN {
    <#
    .SYNOPSIS
        Returns the parent container DN, honoring backslash-escaped commas in the first RDN.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$DistinguishedName)
    $m = [regex]::Match($DistinguishedName, '^(?:\\.|[^,\\])+,(.+)$')
    if (-not $m.Success) { return $null }
    $m.Groups[1].Value
}

# Compare a DN with the configured OU boundary instead of matching an arbitrary text suffix.
function Test-DnUnderOu {
    <#
    .SYNOPSIS
        True when Dn equals or is a descendant of OuDn (component-aware, case-insensitive).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][string]$Dn, [Parameter(Mandatory)][string]$OuDn)
    $d = ($Dn -replace '\s*,\s*', ',').ToLowerInvariant()
    $o = ($OuDn -replace '\s*,\s*', ',').ToLowerInvariant()
    ($d -eq $o) -or $d.EndsWith(',' + $o)
}

# Reject date-like free text that could be converted during a JSON round trip and change the plan hash.
function Assert-NoIsoDateLikeText {
    [CmdletBinding()]
    param([string]$Name, [string]$Value)
    if ($Value -match '^\s*\d{4}-\d{2}-\d{2}T') {
        throw "$Name must not be formatted like an ISO-8601 timestamp (it would not round-trip through JSON hashing)."
    }
}

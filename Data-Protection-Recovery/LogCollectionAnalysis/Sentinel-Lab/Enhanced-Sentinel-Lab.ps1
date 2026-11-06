# ██████╗░██╗░░░██╗███████╗███████╗  ███╗░░██╗███████╗██████╗░██████╗░
# ██╔══██╗██║░░░██║██╔════╝██╔════╝  ████╗░██║██╔════╝██╔══██╗██╔══██╗
# ██████╦╝██║░░░██║█████╗░░█████╗░░  ██╔██╗██║█████╗░░██████╔╝██║░░██║
# ██╔══██╗██║░░░██║██╔══╝░░██╔══╝░░  ██║╚████║██╔══╝░░██╔══██╗██║░░██║
# ██████╦╝╚██████╔╝██║░░░░░██║░░░░░  ██║░╚███║███████╗██║░░██║██████╔╝
# ╚═════╝░░╚═════╝░╚═╝░░░░░╚═╝░░░░░  ╚═╝░░╚══╝╚══════╝╚═╝░░╚═╝╚═════╝░
# -------Script by Aaron Voborny---https://github.com/buffnerd--------
# Enhanced Azure Sentinel SIEM Integration with Advanced Security Monitoring

<#
.SYNOPSIS
    Enhanced Azure Sentinel Failed RDP Login Monitor
.DESCRIPTION
    Monitors failed RDP login attempts with geolocation data for Azure Sentinel SIEM.
    Includes enhanced error handling, security features, and professional logging.
.PARAMETER ApiKey
    API key for ipgeolocation.io service. If omitted, IPGEOLOCATION_API_KEY must be set in the process environment.
.PARAMETER LogPath
    Custom path for log file (default: C:\ProgramData\failed_rdp.log)
.PARAMETER MonitoringInterval
    Interval in seconds between event checks (default: 1)
.EXAMPLE
    .\Enhanced-Sentinel-Lab.ps1 -ApiKey $env:IPGEOLOCATION_API_KEY -LogPath "C:\Logs\sentinel.log"
.NOTES
    Author: PowerShell Automation Portfolio
    Requires: Administrator privileges, Internet connection
    Version: 2.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ApiKey,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\ProgramData\failed_rdp.log",
    
    [Parameter(Mandatory=$false)]
    [int]$MonitoringInterval = 1
)

if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    $ApiKey = $env:IPGEOLOCATION_API_KEY
}
if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    throw "Provide -ApiKey or set IPGEOLOCATION_API_KEY in the process environment."
}

# Configuration
$API_ENDPOINT_BASE = "https://api.ipgeolocation.io/ipgeo"
$MAX_RETRIES = 3
$RATE_LIMIT_DELAY = 2

# Event filter for failed RDP logins (Event ID 4625)
$XMLFilter = @'
<QueryList> 
   <Query Id="0" Path="Security">
         <Select Path="Security">
              *[System[(EventID='4625')]]
          </Select>
    </Query>
</QueryList> 
'@

# Enhanced logging function
function Write-LogMessage {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [ConsoleColor]$Color = "White"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    Write-Information -MessageData $logEntry -Tags $Color.ToString() -InformationAction Continue
    
    # Optional: Write to system log
    # Write-EventLog -LogName Application -Source "SentinelLab" -EntryType Information -EventId 1001 -Message $logEntry
}

# Function to create sample training data
function New-SampleLogData {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param()

    Write-LogMessage "Creating sample training data..." "INFO" "Yellow"

    if ($PSCmdlet.ShouldProcess($LogPath, "Append synthetic sample data")) {
        $sampleData = @(
            "latitude:47.91542,longitude:-120.60306,destinationhost:samplehost,username:fakeuser,sourcehost:24.16.97.222,state:Washington,country:United States,label:United States - 24.16.97.222,timestamp:2021-10-26 03:28:29",
            "latitude:-22.90906,longitude:-47.06455,destinationhost:samplehost,username:lnwbaq,sourcehost:20.195.228.49,state:Sao Paulo,country:Brazil,label:Brazil - 20.195.228.49,timestamp:2021-10-26 05:46:20",
            "latitude:52.37022,longitude:4.89517,destinationhost:samplehost,username:CSNYDER,sourcehost:89.248.165.74,state:North Holland,country:Netherlands,label:Netherlands - 89.248.165.74,timestamp:2021-10-26 06:12:56",
            "latitude:40.71455,longitude:-74.00714,destinationhost:samplehost,username:ADMINISTRATOR,sourcehost:72.45.247.218,state:New York,country:United States,label:United States - 72.45.247.218,timestamp:2021-10-26 10:44:07",
            "latitude:33.99762,longitude:-6.84737,destinationhost:samplehost,username:AZUREUSER,sourcehost:102.50.242.216,state:Rabat-Salé-Kénitra,country:Morocco,label:Morocco - 102.50.242.216,timestamp:2021-10-26 11:03:13"
        )

        foreach ($entry in $sampleData) {
            $entry | Out-File $LogPath -Append -Encoding utf8
        }

        Write-LogMessage "Sample data created successfully" "INFO" "Green"
    }
}

# Function to get geolocation data with error handling
function Get-GeolocationData {
    param([string]$IPAddress)
    
    for ($attempt = 1; $attempt -le $MAX_RETRIES; $attempt++) {
        try {
            Write-LogMessage "Getting geolocation for IP: $IPAddress (Attempt $attempt/$MAX_RETRIES)" "DEBUG" "Cyan"
            $apiUrl = '{0}?apiKey={1}' -f $API_ENDPOINT_BASE, [uri]::EscapeDataString($ApiKey)
            $response = Invoke-WebRequest -UseBasicParsing -Uri $apiUrl -TimeoutSec 10
            
            if ($response.StatusCode -eq 200) {
                $data = $response.Content | ConvertFrom-Json
                
                return @{
                    Success = $true
                    Latitude = $data.latitude
                    Longitude = $data.longitude
                    State = if ($data.state_prov) { $data.state_prov } else { "null" }
                    Country = if ($data.country_name) { $data.country_name } else { "null" }
                    City = if ($data.city) { $data.city } else { "null" }
                }
            }
        }
        catch {
            Write-LogMessage "API request failed (Attempt $attempt); response details suppressed to protect the API key." "WARN" "Yellow"
            
            if ($attempt -lt $MAX_RETRIES) {
                Start-Sleep -Seconds ($RATE_LIMIT_DELAY * $attempt)
            }
        }
    }
    
    # Return default values if all attempts fail
    Write-LogMessage "Failed to get geolocation for $IPAddress after $MAX_RETRIES attempts" "ERROR" "Red"
    return @{
        Success = $false
        Latitude = "0"
        Longitude = "0"
        State = "Unknown"
        Country = "Unknown"
        City = "Unknown"
    }
}

# Function to format timestamp
function Format-EventTimestamp {
    param([DateTime]$DateTime)
    
    return $DateTime.ToString("yyyy-MM-dd HH:mm:ss")
}

# Function to check if running as administrator
function Test-IsAdministrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to validate IP address
function Test-ValidIPAddress {
    param([string]$IPAddress)
    
    if ([string]::IsNullOrWhiteSpace($IPAddress)) { return $false }
    if ($IPAddress.Length -lt 7) { return $false }
    if ($IPAddress -match "^127\.") { return $false }  # Localhost
    if ($IPAddress -match "^192\.168\.") { return $false }  # Private network
    if ($IPAddress -match "^10\.") { return $false }  # Private network
    if ($IPAddress -match "^172\.(1[6-9]|2[0-9]|3[01])\.") { return $false }  # Private network
    
    try {
        [System.Net.IPAddress]::Parse($IPAddress) | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

# Main execution
try {
    Write-LogMessage "Starting Enhanced Sentinel Lab Monitor" "INFO" "Green"
    Write-LogMessage "Log Path: $LogPath" "INFO" "Cyan"
    Write-LogMessage "Monitoring Interval: $MonitoringInterval seconds" "INFO" "Cyan"
    
    # Check administrator privileges
    if (-not (Test-IsAdministrator)) {
        Write-LogMessage "WARNING: Script not running as Administrator. May not be able to read Security Event Log." "WARN" "Yellow"
    }
    
    # Initialize log file
    if (-not (Test-Path $LogPath)) {
        try {
            New-Item -ItemType File -Path $LogPath -Force | Out-Null
            New-SampleLogData
            Write-LogMessage "Log file created: $LogPath" "INFO" "Green"
        }
        catch {
            Write-LogMessage "Failed to create log file: $($_.Exception.Message)" "ERROR" "Red"
            exit 1
        }
    }
    else {
        Write-LogMessage "Using existing log file: $LogPath" "INFO" "Cyan"
    }
    
    Write-LogMessage "Starting continuous monitoring..." "INFO" "Green"
    
    # Main monitoring loop
    while ($true) {
        try {
            Start-Sleep -Seconds $MonitoringInterval
            
            # Get failed login events
            $events = Get-WinEvent -FilterXml $XMLFilter -ErrorAction SilentlyContinue
            
            if ($events) {
                Write-LogMessage "Found $($events.Count) failed login event(s)" "INFO" "Yellow"
                
                foreach ($eventItem in $events) {
                    # Extract event properties
                    $sourceIP = $eventItem.Properties[19].Value
                    
                    if (Test-ValidIPAddress -IPAddress $sourceIP) {
                        $timestamp = Format-EventTimestamp -DateTime $eventItem.TimeCreated
                        $username = $eventItem.Properties[5].Value
                        $destinationHost = $eventItem.MachineName
                        
                        # Check for duplicate entries
                        $logContent = Get-Content -Path $LogPath -ErrorAction SilentlyContinue
                        if ($logContent -and ($logContent -match [regex]::Escape("timestamp:$timestamp"))) {
                            Write-LogMessage "Event already logged, skipping..." "DEBUG" "Gray"
                            continue
                        }
                        
                        # Get geolocation data
                        $geoData = Get-GeolocationData -IPAddress $sourceIP
                        
                        # Create log entry
                        $logEntry = "latitude:$($geoData.Latitude),longitude:$($geoData.Longitude),destinationhost:$destinationHost,username:$username,sourcehost:$sourceIP,state:$($geoData.State),country:$($geoData.Country),label:$($geoData.Country) - $sourceIP,timestamp:$timestamp"
                        
                        # Write to log file
                        $logEntry | Out-File $LogPath -Append -Encoding utf8
                        
                        # Display processed event
                        Write-LogMessage $logEntry "EVENT" "Magenta"
                        
                        # Rate limiting
                        Start-Sleep -Seconds $RATE_LIMIT_DELAY
                    }
                    else {
                        Write-LogMessage "Skipping invalid/local IP address: $sourceIP" "DEBUG" "Gray"
                    }
                }
            }
        }
        catch {
            Write-LogMessage "Error in monitoring loop: $($_.Exception.Message)" "ERROR" "Red"
            Start-Sleep -Seconds 5  # Wait before retrying
        }
    }
}
catch {
    Write-LogMessage "Fatal error: $($_.Exception.Message)" "ERROR" "Red"
    exit 1
}
finally {
    Write-LogMessage "Sentinel Lab Monitor stopped" "INFO" "Yellow"
}
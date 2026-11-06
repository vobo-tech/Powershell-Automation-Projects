```
██████╗░██╗░░░██╗███████╗███████╗  ███╗░░██╗███████╗██████╗░██████╗░
██╔══██╗██║░░░██║██╔════╝██╔════╝  ████╗░██║██╔════╝██╔══██╗██╔══██╗
██████╦╝██║░░░██║█████╗░░█████╗░░  ██╔██╗██║█████╗░░██████╔╝██║░░██║
██╔══██╗██║░░░██║██╔══╝░░██╔══╝░░  ██║╚████║██╔══╝░░██╔══██╗██║░░██║
██████╦╝╚██████╔╝██║░░░░░██║░░░░░  ██║░╚███║███████╗██║░░██║██████╔╝
╚═════╝░░╚═════╝░╚═╝░░░░░╚═╝░░░░░  ╚═╝░░╚══╝╚══════╝╚═╝░░╚═╝╚═════╝░
-------Script by Aaron Voborny---https://github.com/buffnerd--------
Azure Sentinel SIEM Integration with RDP Geolocation Analysis
```

# 🔍 Sentinel Lab - Failed RDP Login Monitoring

This PowerShell script monitors failed RDP login attempts and converts source IP addresses to full geolocation data for Azure Sentinel SIEM analysis.

## 🎯 Project Overview

This script creates a comprehensive security monitoring solution that:
- Monitors Windows Security Event Log for failed RDP logins (Event ID 4625)
- Retrieves geolocation data for source IP addresses using external API
- Creates formatted log files compatible with Azure Sentinel
- Provides sample data for Log Analytics workspace training

## 🔧 Prerequisites

- **Windows System** with Event Viewer access
- **Administrator Privileges** to read Security Event Log
- **Internet Connection** for geolocation API calls
- **API Key** from [ipgeolocation.io](https://ipgeolocation.io/)

## 📋 Features

### ⚡ Real-time Monitoring
- Continuous monitoring of Windows Security Event Log
- Automatic detection of failed RDP login attempts
- Duplicate event prevention to avoid log pollution

### 🌍 Geolocation Integration
- Converts IP addresses to geographic coordinates
- Retrieves country, state/province information
- Includes city and region data when available

### 📊 Azure Sentinel Compatible
- Generates logs in format optimized for Azure Sentinel
- Includes sample data for Log Analytics training
- Structured data format for easy parsing

### 🎨 Visual Feedback
- Color-coded console output for easy monitoring
- Real-time display of processed events
- Detailed logging information

## 🚀 Usage

### Setup
1. **Get API Key**: Register at [ipgeolocation.io](https://ipgeolocation.io/) and obtain your API key
2. **Configure Runtime Secret**: Set `IPGEOLOCATION_API_KEY` in the script process environment through an approved secret store or secure launcher. Never put the key in either script, source control, or a command-line literal.
3. **Set Permissions**: Ensure script runs with administrator privileges

### Execution
```powershell
# Run after securely configuring IPGEOLOCATION_API_KEY in this process
.\Sentinel-Lab.ps1

# The enhanced variant also accepts the environment variable, or an explicitly supplied runtime parameter.
.\Enhanced-Sentinel-Lab.ps1 -ApiKey $env:IPGEOLOCATION_API_KEY

# The script will:
# 1. Create log file at C:\ProgramData\failed_rdp.log
# 2. Generate sample data for training
# 3. Begin monitoring for failed RDP attempts
# 4. Process and log geolocation data for each event
```

Both scripts require a runtime key and stop before monitoring if it is missing. Request error details are intentionally
suppressed because the provider API accepts its key in the request URI.

## 📁 Output Format

The script generates log entries in the following format:
```
latitude:40.71455,longitude:-74.00714,destinationhost:DESKTOP-PC,username:admin,sourcehost:192.168.1.100,state:New York,country:United States,label:United States - 192.168.1.100,timestamp:2021-10-26 10:44:07
```

### Field Descriptions
- **latitude/longitude**: Geographic coordinates of source IP
- **destinationhost**: Target machine name
- **username**: Attempted login username
- **sourcehost**: Source IP address
- **state**: State/Province of source IP
- **country**: Country of source IP
- **label**: Human-readable location label
- **timestamp**: Event timestamp

## 🔒 Security Considerations

- **API Key Protection**: Keep your geolocation API key secure
- **Rate Limiting**: Script includes delays to prevent API rate limiting
- **Log File Security**: Ensure log file permissions are appropriately restricted
- **Network Security**: Monitor for suspicious patterns in failed login attempts

The previously embedded API key has been removed from the current scripts. Treat any previously committed key as
exposed: revoke or rotate it with the provider, review usage/billing logs, and update the approved runtime secret source.
Changing the current files does not remove copies from Git history, other branches, forks, or downloaded artifacts.
Review those locations after revocation; coordinate any history rewrite with repository owners and collaborators.

## 🏗️ Azure Sentinel Integration

### Log Analytics Workspace Setup
1. Create custom log table in Azure Sentinel
2. Use sample data to train field extraction
3. Configure data connector for log file ingestion
4. Create custom queries and alerts

### Sample KQL Queries
```kql
// Show failed logins by country
CustomLog_CL
| where label_s contains "-"
| summarize count() by country_s
| order by count_ desc

// Map failed login attempts
CustomLog_CL
| where destinationhost_s != "samplehost"
| project latitude_d, longitude_d, country_s, sourcehost_s
```

## 🎛️ Customization Options

- **Modify API Provider**: Change geolocation service if needed
- **Adjust Monitoring Interval**: Modify sleep duration for different polling rates
- **Custom Log Format**: Adapt output format for specific SIEM requirements
- **Additional Event IDs**: Extend to monitor other security events

## 🐛 Troubleshooting

### Common Issues
- **API Quota Exceeded**: Check API usage limits and consider upgrading plan
- **Permission Denied**: Ensure script runs with administrator privileges
- **Network Connectivity**: Verify internet connection for API calls
- **Event Log Access**: Confirm Security Event Log is accessible

### Performance Optimization
- Consider batching API requests for high-volume environments
- Implement caching for frequently seen IP addresses
- Add local IP range filtering to reduce API calls

## 📈 Monitoring & Alerting

Set up alerts for:
- High volume of failed login attempts
- Login attempts from suspicious geographic locations
- Repeated attempts from same source IP
- Attempts using common/default usernames

This script provides a foundation for comprehensive RDP security monitoring and can be integrated into broader security operations workflows.
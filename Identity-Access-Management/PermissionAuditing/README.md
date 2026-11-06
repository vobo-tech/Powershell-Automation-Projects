# Permission Auditing

Scripts to **inventory NTFS permissions** and **detect over-permissioned accounts** across Windows file servers and shares. Outputs are flattened (CSV/JSONL) for quick triage, spreadsheet review, or SIEM ingestion. Findings describe ACL entries and group membership; they do not establish effective access.

---

## Prerequisites
- Local admin or equivalent rights to read ACLs on target paths
- Sufficient permissions to enumerate subfolders and files if `-Recurse`/`-IncludeFiles`
- (Optional) **RSAT ActiveDirectory** module if using `-ExpandADGroups`
- Adequate time & disk if scanning very large trees (use depth filters)

---

## Scripts

### 1) ReportNTFSPermissions.ps1
Inventory ACLs (folders by default; files optional) and flag potential risks:
- **Broad principals** (default: Everyone / Authenticated Users / Domain Users) with **Modify/Full**
- **Explicit Deny** ACEs
- **Inheritance disabled**
- **Unresolved SIDs** (orphaned accounts)
- **Owner anomalies**
- **Caveat** on each row: an individual ACE or owner record does not determine effective access

**Examples**
```powershell
# Recurse 4 levels, folders only, export CSV
.\ReportNTFSPermissions.ps1 -Path "\\fs01\Projects" -Recurse -MaxDepth 4 -OutputCsv .\ntfs_projects.csv

# Include files and resolve SIDs; JSONL output
.\ReportNTFSPermissions.ps1 -Path "D:\Data" -Recurse -IncludeFiles -ResolveSIDs -OutputJsonl .\ntfs.jsonl
```

**Adjust for your environment**
- **Paths**: `-Path` (UNC/local)
- **Depth & scope**: `-Recurse`, `-MaxDepth`, `-IncludeFiles`
- **Name resolution**: `-ResolveSIDs`
- **Risk policy**: `-BroadPrincipals`, `-HighRights`
- **Output**: `-OutputCsv`, `-OutputJsonl` (+ `-ErrorLog`)

### 2) DetectOverPermissionedAccounts.ps1
Flag Modify/Full/Write rights granted to users/groups outside an allow-list. Optional AD expansion lists user members of flagged groups; it does not establish effective access for those users.

**Examples**
```powershell
# Flag >= Modify not in allowed list
.\DetectOverPermissionedAccounts.ps1 -Path "\\fs01\HR" -Recurse -MaxDepth 5 `
  -AllowedPrincipals 'CONTOSO\FileAdmins','CONTOSO\HR-Managers' -OutputCsv .\overperm.csv

# Expand groups to list their user members (requires RSAT AD; not an effective-access calculation)
.\DetectOverPermissionedAccounts.ps1 -Path "D:\Data" -Recurse -ExpandADGroups -ResolveSIDs -MinRight Write -Verbose
```

**Adjust for your environment**
- **Scope**: `-Path`, `-Recurse`, `-MaxDepth`, `-IncludeFiles`
- **Threshold**: `-MinRight` (Write/Modify/FullControl)
- **Policy**: `-AllowedPrincipals`, `-ExcludePrincipals`
- **Filters**: `-IncludePathLike`, `-ExcludePathLike`
- **Identity resolution**: `-ResolveSIDs`, `-ExpandADGroups`, `-Domain`
- **Output**: `-OutputCsv`

---

## Analysis Capabilities

### Permission Risk Assessment
- **Broad Access Detection**: Identifies overly permissive assignments to large groups
- **Privilege Escalation Paths**: Maps potential attack vectors through file system permissions
- **Orphaned Account Detection**: Finds permissions assigned to deleted/disabled accounts
- **Inheritance Analysis**: Reviews permission inheritance patterns and anomalies
- **Explicit Deny Monitoring**: Identifies potentially problematic deny ACEs

### Export Formats
- **CSV**: Structured tabular data for Excel analysis and reporting
- **JSONL**: JSON Lines format for SIEM ingestion and big data analytics
- **Error Logs**: Comprehensive error tracking for access denied scenarios

### Enterprise Features
- **Multi-path Analysis**: Sequential scanning across multiple file system roots
- **Depth Control**: Configurable recursion limits for performance management
- **SID Resolution**: Optional name resolution for improved readability
- **AD Integration**: Optional recursive group membership enumeration; it does not calculate effective access.

Each finding is based on one ACE. The scripts do not combine ACEs, apply deny precedence, evaluate share permissions, or
model the user's access token and application policy. Group expansion reports member names only. Review findings
against the complete resource and identity context before making access decisions.

---

## Common Use Cases

### Security Auditing
- **Compliance Reporting**: Generate detailed permission reports for regulatory requirements
- **Access Reviews**: Periodic review of file system permissions across infrastructure
- **Risk Assessment**: Identify and prioritize permission-based security risks
- **Incident Response**: Analyze file system permissions during security investigations

### IT Administration
- **Permission Cleanup**: Identify and remediate excessive or inappropriate permissions
- **Migration Planning**: Document current permissions before file server migrations
- **Change Management**: Track permission changes over time
- **Troubleshooting**: Diagnose file access issues through permission analysis

### Forensic Analysis
- **Data Exfiltration Investigation**: Analyze who had access to sensitive data
- **Insider Threat Detection**: Identify unusual permission patterns or escalations
- **Evidence Collection**: Document file system permissions for legal proceedings
- **Timeline Reconstruction**: Map permission changes to security events

---

## Performance Considerations

### Scanning Scope
- Start with narrow scope (single share, shallow depth) to validate performance
- Use `-MaxDepth` to limit recursion depth and control scan time
- Consider `-IncludeFiles` impact on large file systems
- Monitor network traffic when scanning UNC paths

### Memory Management
- Large file systems generate substantial data - monitor memory usage
- Use CSV output for very large datasets instead of console display
- Consider breaking large scans into multiple smaller operations

### Active Directory Integration
- `-ResolveSIDs` can be slow in large domains - test performance
- `-ExpandADGroups` requires RSAT and may take time for nested groups
- Cache AD queries when possible for repeated operations

---

## Security Considerations

### Access Requirements
- Administrative privileges required for comprehensive ACL reading
- Network access needed for UNC path scanning
- Domain credentials may be required for cross-domain analysis

### Data Sensitivity
- Permission reports contain sensitive security information
- Secure storage and transmission of output files
- Consider encryption for sensitive permission data
- Implement access controls for generated reports

### Operational Security
- Audit trail for permission scanning activities
- Monitor for potential reconnaissance attempts
- Rate limiting for large-scale scans
- Coordinate with security teams for enterprise-wide scanning

---

## Tips

### Best Practices
- Start narrow (one share, shallow depth) to validate speed and permissions
- Keep an allow-list of platform/service groups that legitimately need high rights
- Use ReportNTFSPermissions to inventory and locate hotspots; then run DetectOverPermissionedAccounts on those hotspots with a tuned allow-list
- For remediation, prefer group-based ACEs over direct user ACEs; move users into least-privilege groups

### Remediation Workflow
1. **Discovery**: Use ReportNTFSPermissions to inventory current state
2. **Analysis**: Run DetectOverPermissionedAccounts with baseline allow-lists
3. **Risk Assessment**: Review findings and prioritize by business impact
4. **Remediation**: Implement least-privilege principles
5. **Validation**: Re-scan to verify changes and maintain compliance

### Integration Points
- **SIEM Integration**: Export JSONL format for automated ingestion
- **Ticketing Systems**: Generate reports for IT remediation workflows
- **Compliance Tools**: Automate permission reporting for audit requirements
- **Change Management**: Integrate scanning into file server maintenance procedures

---

## Requirements
- Windows PowerShell 5.1+ or PowerShell Core 7+
- Administrative privileges for ACL access
- Network connectivity for remote file system access
- RSAT ActiveDirectory module (optional, for AD group expansion)
- Sufficient disk space for report outputs

---

## Future GUI Integration Ideas
- **Folder pickers** with depth sliders
- **Risk policy editor** (broad principals / high rights thresholds)
- **AD group expansion toggle** with domain selector
- **One-click export bundles** (CSV + JSONL + ZIP)
- **Progress indicators** with estimated completion times
- **Real-time filtering** and search capabilities
- **Visual risk heat maps** for file system hierarchies
- **Interactive remediation workflows** with approval processes
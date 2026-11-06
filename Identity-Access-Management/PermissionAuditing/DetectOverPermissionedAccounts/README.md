# DetectOverPermissionedAccounts - Permission Risk Detection & Analysis

## Overview
PowerShell script for finding NTFS ACEs that meet a configured rights threshold and are outside an allow-list. Optional Active Directory expansion lists user members of a flagged group; it does not establish those users' effective access.

## Key Features
- **Policy-Based Detection**: Configurable allow/deny lists for permission validation
- **Risk Thresholds**: Customizable minimum rights levels for flagging
- **AD Group Expansion**: Recursive group membership analysis (requires RSAT)
- **Path Filtering**: Include/exclude patterns for targeted analysis
- **Group Member Enumeration**: Lists recursively expanded user membership for a flagged group
- **Remediation Guidance**: Provides context for addressing findings

## Detection Logic

### Over-Permission Criteria
1. **High Rights Assignment**: Accounts with Write/Modify/FullControl permissions
2. **Allow-List Validation**: Not in approved principals list
3. **Exclusion Filtering**: Not in excluded principals list
4. **Access Type**: Focuses on Allow ACEs (not Deny)
5. **Path Matching**: Meets include/exclude path patterns

### Risk Assessment Factors
- **Inheritance Status**: Inherited vs. explicit permissions
- **Group Membership**: Expanded membership is contextual evidence, not effective access
- **Permission Level**: Write, Modify, or FullControl classification
- **Path Sensitivity**: Location-based risk assessment

## Usage Examples

### Basic Over-Permission Detection
```powershell
# Flag accounts with Modify+ rights outside allow-list
.\DetectOverPermissionedAccounts.ps1 -Path "\\fs01\Projects" -Recurse -MaxDepth 4 -AllowedPrincipals @("CONTOSO\FileAdmins","CONTOSO\ProjectLeads") -OutputCsv .\overperm.csv

# Lower threshold detection (Write and above)
.\DetectOverPermissionedAccounts.ps1 -Path "D:\Sensitive" -MinRight Write -Recurse -Verbose
```

### Advanced Analysis with AD Expansion
```powershell
# Expand group memberships to identify at-risk users
.\DetectOverPermissionedAccounts.ps1 -Path "\\finance-fs\confidential" -Recurse -ExpandADGroups -ResolveSIDs -Domain "contoso.com" -OutputCsv .\finance_risks.csv

# Multi-path analysis with comprehensive settings
.\DetectOverPermissionedAccounts.ps1 -Path @("\\hr-fs\personnel","\\legal-fs\contracts") -Recurse -MaxDepth 3 -ExpandADGroups -ResolveSIDs -MinRight Write -AllowedPrincipals @("CONTOSO\FileAdmins","CONTOSO\LegalTeam","CONTOSO\HRManagers") -OutputCsv .\multi_analysis.csv
```

### Targeted Analysis with Filtering
```powershell
# Focus on specific paths with pattern matching
.\DetectOverPermissionedAccounts.ps1 -Path "\\corp-fs\shares" -Recurse -IncludePathLike "*\Confidential\*" -ExcludePathLike "*\Public\*" -MinRight Modify -OutputCsv .\confidential_risks.csv

# Exclude system accounts from analysis
.\DetectOverPermissionedAccounts.ps1 -Path "D:\Data" -Recurse -ExcludePrincipals @("BUILTIN\Administrators","NT AUTHORITY\SYSTEM","DOMAIN\BackupOperators") -OutputCsv .\filtered_analysis.csv
```

## Parameters

### Core Parameters
| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `Path` | String[] | Root paths to analyze (UNC or local) | **Required** |
| `Recurse` | Switch | Enable recursive scanning | False |
| `MaxDepth` | Int | Maximum recursion depth (1-64) | 5 |
| `IncludeFiles` | Switch | Analyze file-level permissions | False |

### Risk Configuration
| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `MinRight` | String | Minimum right to flag (Write/Modify/FullControl) | Modify |
| `AllowedPrincipals` | String[] | Approved accounts (not flagged) | BUILTIN\Administrators, NT AUTHORITY\SYSTEM |
| `ExcludePrincipals` | String[] | Accounts to ignore completely | None |

### Filtering Options
| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `IncludePathLike` | String | Wildcard pattern for paths to include | All paths |
| `ExcludePathLike` | String | Wildcard pattern for paths to exclude | None |

### Identity Resolution
| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `ResolveSIDs` | Switch | Resolve SIDs to account names | False |
| `ExpandADGroups` | Switch | Expand AD group memberships | False |
| `Domain` | String | AD domain for group queries | None |

### Output Options
| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `OutputCsv` | String | CSV output file path | None |

## Output Schema

### Finding Fields
- **Path**: File system path with over-permissions
- **Principal**: Account or group with excessive rights
- **Rights**: Permission level (Write, Modify, FullControl)
- **IsInherited**: Whether permission is inherited
- **InheritanceOn**: Whether inheritance is enabled on object
- **AccessType**: ACE type (typically Allow)
- **IncludeReason**: Explanation for why this was flagged
- **ExpandedGroupMembers**: User members returned by recursive AD group expansion (if `-ExpandADGroups` is used)
- **EffectiveUsers**: Compatibility field containing the same expanded group-member list; it does not mean effective access
- **Caveat**: States that the finding is based on one ACE and is not an effective-access determination

## Active Directory Integration

### Group Expansion (not effective-access evaluation)
When `-ExpandADGroups` is enabled:
- Recursively expands nested group membership and lists user members
- Does not combine ACL entries, apply deny precedence, evaluate share permissions, or model tokens/application policy
- Requires RSAT ActiveDirectory module
- Populates `ExpandedGroupMembers`; the legacy `EffectiveUsers` field is retained as a compatibility alias

### Performance Considerations
- AD queries can significantly impact scan time
- Network latency to domain controllers affects performance
- Large nested groups may generate extensive output
- Consider caching for repeated operations

## Risk Assessment Workflow

### 1. Discovery Phase
```powershell
# Initial broad scan to identify potential issues
.\DetectOverPermissionedAccounts.ps1 -Path "\\file-server\shares" -Recurse -MaxDepth 2 -MinRight Write -ResolveSIDs -OutputCsv .\discovery.csv
```

### 2. Policy Refinement
```powershell
# Refine with approved accounts from discovery results
.\DetectOverPermissionedAccounts.ps1 -Path "\\file-server\shares" -Recurse -AllowedPrincipals @("CORP\FileAdmins","CORP\BackupSvc","CORP\ApprovedGroup") -OutputCsv .\policy_scan.csv
```

### 3. Detailed Analysis
```powershell
# Deep dive with group expansion for remediation planning
.\DetectOverPermissionedAccounts.ps1 -Path "\\file-server\sensitive" -Recurse -ExpandADGroups -AllowedPrincipals @("CORP\SensitiveDataAdmins") -Domain "corp.contoso.com" -OutputCsv .\detailed_findings.csv
```

## Integration Examples

### Compliance Reporting
```powershell
# Quarterly compliance scan
$allowedAccounts = @("CORP\FileAdmins","CORP\BackupOperators","CORP\SystemAdmins")
.\DetectOverPermissionedAccounts.ps1 -Path (Get-Content .\compliance_paths.txt) -Recurse -MaxDepth 4 -AllowedPrincipals $allowedAccounts -ResolveSIDs -OutputCsv ".\compliance\overperm_$(Get-Date -Format 'yyyyQQ').csv"
```

### Security Audit
```powershell
# High-risk area audit with user enumeration
.\DetectOverPermissionedAccounts.ps1 -Path "\\finance-fs\restricted" -Recurse -ExpandADGroups -MinRight Write -Domain "finance.corp.com" -AllowedPrincipals @("FINANCE\DataAdmins","FINANCE\CFOOffice") -OutputCsv .\security_audit.csv
```

### Remediation Planning
```powershell
# Generate remediation list with context
.\DetectOverPermissionedAccounts.ps1 -Path "\\legacy-fs\old-shares" -Recurse -MinRight Modify -ResolveSIDs -ExcludePrincipals @("BUILTIN\Administrators","NT AUTHORITY\SYSTEM") -OutputCsv .\remediation_plan.csv
```

## Best Practices

### Policy Development
- Start with broad scans to understand current state
- Develop allow-lists based on business requirements
- Document approved exceptions and their justifications
- Regular review and update of allow/deny lists

### Scanning Strategy
- Begin with narrow scope and shallow depth
- Test performance impact before large-scale scans
- Use path filtering to focus on sensitive areas
- Schedule intensive scans during off-peak hours

### Remediation Approach
1. **Prioritize by Risk**: Focus on high-rights violations first
2. **Group-Based Changes**: Prefer group membership changes over ACL modifications
3. **Least Privilege**: Remove unnecessary permissions rather than adding restrictions
4. **Documentation**: Track changes and maintain approval records

## Performance Optimization

### Scanning Efficiency
- Use `-MaxDepth` to limit recursion scope
- Implement path filtering to reduce scan area
- Avoid `-IncludeFiles` on large file systems initially
- Monitor memory usage during extensive operations

### AD Query Optimization
- Enable `-ExpandADGroups` selectively for detailed analysis
- Consider network impact of recursive group queries
- Cache group membership data for repeated scans
- Use specific domain controllers for consistent performance

## Troubleshooting

### Common Issues
- **No Results**: Verify allow-lists aren't too broad
- **Performance Issues**: Reduce scope or disable AD expansion
- **AD Errors**: Check RSAT installation and domain connectivity
- **Access Denied**: Verify administrative privileges

### Optimization Tips
- Start with high-level scans before detailed analysis
- Use verbose output to monitor progress
- Test with small sample paths first
- Implement filtering to reduce false positives

## Requirements
- Windows PowerShell 5.1+ or PowerShell Core 7+
- Administrative privileges for ACL reading
- RSAT ActiveDirectory module (for `-ExpandADGroups`)
- Network access for UNC paths and AD queries
- Domain connectivity for SID resolution and group expansion
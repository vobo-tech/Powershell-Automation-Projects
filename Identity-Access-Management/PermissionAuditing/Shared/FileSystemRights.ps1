# Shared helpers for the permission auditing scripts. Dot-source this file.
# FileSystemRights is a [Flags] enum whose composite members overlap (ReadAndExecute is a subset of Modify,
# which is a subset of FullControl). A label therefore applies only when ALL bits of its mask are present;
# testing "any bit" (-band alone) mislabels read-only ACEs as Modify/FullControl.

function Test-FileSystemRight {
    <#
    .SYNOPSIS
      Returns $true only when every bit of -Required is present in -Rights.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][System.Security.AccessControl.FileSystemRights]$Rights,
        [Parameter(Mandatory)][System.Security.AccessControl.FileSystemRights]$Required
    )
    # -band returns shared bits; equality is necessary to require the entire composite mask.
    return (($Rights -band $Required) -eq $Required)
}

function Convert-FileSystemRightsLabel {
    <#
    .SYNOPSIS
      Maps a FileSystemRights value to the highest simplified label whose full mask is present.
    .DESCRIPTION
      Labels: FullControl, Modify, Write, ReadExecute, Read. Anything else (for example ReadData only,
      or a custom combination) is returned as the enum's own string so it is never silently upgraded.
      The label describes ONE access control entry; it is not the effective access of any principal.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][System.Security.AccessControl.FileSystemRights]$Rights)

    $fsr = [System.Security.AccessControl.FileSystemRights]
    if (Test-FileSystemRight -Rights $Rights -Required $fsr::FullControl)    { return 'FullControl' }
    if (Test-FileSystemRight -Rights $Rights -Required $fsr::Modify)         { return 'Modify' }
    if (Test-FileSystemRight -Rights $Rights -Required $fsr::Write)          { return 'Write' }
    if (Test-FileSystemRight -Rights $Rights -Required $fsr::ReadAndExecute) { return 'ReadExecute' }
    if (Test-FileSystemRight -Rights $Rights -Required $fsr::Read)           { return 'Read' }
    # ReadData and ListDirectory are aliases; use a stable label across .NET platforms.
    if ($Rights -eq $fsr::ReadData) { return 'ReadData' }
    return $Rights.ToString()
}

<#
.SYNOPSIS
    Collects domain-controller audit data into an ACL-restricted folder.

.DESCRIPTION
    Writes audit files to -OutputFolder. When -OutputFolder is omitted, the
    folder is "$env:ProgramData\<computer name> DC Audit", under
    $env:ProgramData. The Desktop is not used.

    A new folder is created with its ACL already in place. Inheritance is
    disabled, and FullControl is granted only to BUILTIN\Administrators
    (S-1-5-32-544) and the user running this script. Child files inherit
    that ACL. Windows PowerShell 5.1 creates it with
    Directory.CreateDirectory. PowerShell 7 and later uses
    FileSystemAclExtensions.Create. If the new folder is not empty, the
    script stops before writing audit data.

    An existing folder is reused only when three checks all pass: it and
    any parent below ProgramData are not junctions or symbolic links, its
    owner is Administrators or the current user, and it contains the marker
    file .dc-audit-output. The marker is not accepted by itself. For an
    output path outside ProgramData, the same link check continues up to
    the drive root. Audit output can include administrator membership,
    password policy, shares, and credential manager listings.

    -Cleanup applies that same restricted ACL, checks it, and only then
    deletes anything. It removes top-level regular files and then the
    directory. A child folder, junction, or symbolic link stops cleanup
    before those files are deleted. The marker is removed and created
    again instead of being rewritten, and a marker with more than one
    hard link is refused. Drive roots, the Windows directory, and Desktop
    paths are refused. Folders left on the Desktop by older copies of
    this script are not removed automatically.

.PARAMETER OutputFolder
    Folder that receives the audit files. Defaults to a directory under
    $env:ProgramData named "<computer name> DC Audit". The parent directory
    must already exist and must not be a junction or symbolic link. This
    cannot be the Desktop, a drive root, or the Windows directory.

.PARAMETER Cleanup
    Remove the audit output folder and exit. Does not collect new data.
    The folder must be owned by Administrators or the current user and must
    contain the .dc-audit-output marker. The restricted ACL is applied and
    checked before anything is deleted. Only top-level regular files are
    removed. A child folder, junction, or symbolic link stops the cleanup.

.EXAMPLE
    .\DC-Audit.ps1

    Writes audit files under $env:ProgramData with a restricted ACL.

.EXAMPLE
    .\DC-Audit.ps1 -OutputFolder 'D:\SecureAudits\DC1'

.EXAMPLE
    .\DC-Audit.ps1 -Cleanup

    Deletes the default ProgramData audit folder created by this script.

.NOTES
    The marker file .dc-audit-output records that this script created the
    folder. An existing marker is deleted and a new file is created in its
    place. A junction, symbolic link, or hard link (more than one name for
    the same file) is refused. -Cleanup also requires the owner check and
    the restricted ACL before it deletes anything.
#>
[CmdletBinding()]
param(
    [string]$OutputFolder = "$env:ProgramData\$env:COMPUTERNAME DC Audit",
    [switch]$Cleanup
)

$MarkerName = '.dc-audit-output'
$MarkerValue = 'DC-Audit.ps1'
$AdministratorsSid = 'S-1-5-32-544'

function Get-DcAuditMarkerPath {
    param([Parameter(Mandatory)][string]$Folder)
    return (Join-Path -Path $Folder -ChildPath $MarkerName)
}

function Test-DcAuditMarker {
    param([Parameter(Mandatory)][string]$Folder)
    $markerPath = Get-DcAuditMarkerPath -Folder $Folder
    if (-not (Test-DcAuditPathExists -Path $markerPath)) {
        return $false
    }
    # A link named as the marker is not evidence the folder was created here.
    if (Test-DcAuditReparsePoint -Path $markerPath) {
        return $false
    }
    $attributes = [System.IO.File]::GetAttributes($markerPath)
    if (([int]$attributes -band [int][System.IO.FileAttributes]::Directory) -ne 0) {
        return $false
    }
    $text = Get-Content -LiteralPath $markerPath -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $false
    }
    return [string]::Equals($text.Trim(), $MarkerValue, [System.StringComparison]::Ordinal)
}

function Test-DcAuditSameOrChildPath {
    param(
        [Parameter(Mandatory)][string]$Candidate,
        [Parameter(Mandatory)][string]$Parent
    )
    if ([string]::IsNullOrWhiteSpace($Parent)) {
        return $false
    }
    $parentFull = [System.IO.Path]::GetFullPath($Parent).TrimEnd('\', '/')
    $candidateFull = $Candidate.TrimEnd('\', '/')
    if ([string]::Equals($candidateFull, $parentFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    return $candidateFull.StartsWith($parentFull + '\', [System.StringComparison]::OrdinalIgnoreCase) -or
        $candidateFull.StartsWith($parentFull + '/', [System.StringComparison]::OrdinalIgnoreCase)
}

function Resolve-DcAuditOutputFolder {
    param([Parameter(Mandatory)][string]$Folder)

    if ([string]::IsNullOrWhiteSpace($Folder)) {
        throw 'OutputFolder cannot be empty.'
    }
    if ($Folder -match '[\*\?\[\]]') {
        throw "OutputFolder cannot contain wildcard characters (* ? [ ]): $Folder"
    }

    $full = [System.IO.Path]::GetFullPath($Folder)
    $trimmed = $full.TrimEnd('\', '/')
    $root = [System.IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrWhiteSpace($root)) {
        throw "OutputFolder is not a usable path: $Folder"
    }
    $rootTrimmed = $root.TrimEnd('\', '/')
    if ([string]::Equals($trimmed, $rootTrimmed, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "OutputFolder cannot be a drive or share root: $full"
    }

    foreach ($candidate in @(
            $env:ProgramData
            $env:USERPROFILE
            $env:PUBLIC
            ${env:ProgramFiles}
            ${env:ProgramFiles(x86)}
        )) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }
        $blocked = [System.IO.Path]::GetFullPath($candidate).TrimEnd('\', '/')
        if ([string]::Equals($trimmed, $blocked, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "OutputFolder cannot be '$full'. Choose a dedicated subdirectory. The default is a folder under ProgramData."
        }
    }

    foreach ($windowsPath in @($env:SystemRoot, $env:windir)) {
        if (Test-DcAuditSameOrChildPath -Candidate $trimmed -Parent $windowsPath) {
            throw "OutputFolder cannot be inside the Windows directory: $full"
        }
    }

    $desktopPaths = @()
    foreach ($desktopParent in @($env:USERPROFILE, $env:PUBLIC, $env:OneDrive, $env:OneDriveCommercial)) {
        if (-not [string]::IsNullOrWhiteSpace($desktopParent)) {
            $desktopPaths += (Join-Path -Path $desktopParent -ChildPath 'Desktop')
        }
    }
    try {
        $knownDesktop = [Environment]::GetFolderPath('Desktop')
        if (-not [string]::IsNullOrWhiteSpace($knownDesktop)) {
            $desktopPaths += $knownDesktop
        }
        $commonDesktop = [Environment]::GetFolderPath('CommonDesktopDirectory')
        if (-not [string]::IsNullOrWhiteSpace($commonDesktop)) {
            $desktopPaths += $commonDesktop
        }
    } catch {
        # Folder-path lookup is best-effort. The explicit Desktop paths above still apply.
    }
    foreach ($desktopPath in $desktopPaths) {
        if (Test-DcAuditSameOrChildPath -Candidate $trimmed -Parent $desktopPath) {
            throw "OutputFolder cannot be on the Desktop: $full. The default folder is under ProgramData."
        }
    }

    return $trimmed
}

function Get-DcAuditDaclSddl {
    param([Parameter(Mandatory)][string]$UserSid)
    # Protected DACL (P): inheritance off.
    # A;OICI;FA: Allow, object+container inherit, FullControl.
    $sddl = "D:P(A;OICI;FA;;;$AdministratorsSid)"
    if (-not [string]::Equals($UserSid, $AdministratorsSid, [System.StringComparison]::OrdinalIgnoreCase)) {
        $sddl += "(A;OICI;FA;;;$UserSid)"
    }
    return $sddl
}

function Get-DcAuditCurrentUserSid {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($null -eq $currentUser -or [string]::IsNullOrWhiteSpace($currentUser.Value)) {
        throw 'Unable to resolve the current user security identifier for the audit folder ACL.'
    }
    return $currentUser.Value
}

function New-DcAuditDirectorySecurity {
    param([Parameter(Mandatory)][string]$UserSid)
    $security = New-Object System.Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    $rights = [System.Security.AccessControl.FileSystemRights]::FullControl
    $inheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $administrators = New-Object System.Security.Principal.SecurityIdentifier $AdministratorsSid
    $security.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                $administrators, $rights, $inheritance, $propagation, $allow)))
    if (-not [string]::Equals($UserSid, $AdministratorsSid, [System.StringComparison]::OrdinalIgnoreCase)) {
        $currentUser = New-Object System.Security.Principal.SecurityIdentifier $UserSid
        $security.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $currentUser, $rights, $inheritance, $propagation, $allow)))
    }
    return $security
}

function New-DcAuditRestrictedDirectory {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][System.Security.AccessControl.DirectorySecurity]$Security
    )
    # Apply the ACL as the directory is created. Windows PowerShell 5.1 and
    # PowerShell 7 expose that through different APIs.
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        $directoryInfo = New-Object System.IO.DirectoryInfo $Path
        [void][System.IO.FileSystemAclExtensions]::Create($directoryInfo, $Security)
        return
    }
    [void][System.IO.Directory]::CreateDirectory($Path, $Security)
}

function Test-DcAuditPathExists {
    param([Parameter(Mandatory)][string]$Path)
    try {
        $null = [System.IO.File]::GetAttributes($Path)
        return $true
    } catch [System.IO.FileNotFoundException] {
        return $false
    } catch [System.IO.DirectoryNotFoundException] {
        return $false
    }
}

function Test-DcAuditReparsePoint {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-DcAuditPathExists -Path $Path)) {
        return $false
    }
    # Both signals are checked. GetAttributes and Get-Item inspect the final
    # path component itself and do not treat a parent link as this component.
    $attributes = [System.IO.File]::GetAttributes($Path)
    $isReparse = (([int]$attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0)
    $linkType = [string](Get-Item -LiteralPath $Path -Force -ErrorAction Stop).LinkType
    # Hard links are not reparse points. Junctions and symbolic links are.
    $isNamedLink = [string]::Equals($linkType, 'SymbolicLink', [System.StringComparison]::OrdinalIgnoreCase) -or
        [string]::Equals($linkType, 'Junction', [System.StringComparison]::OrdinalIgnoreCase)
    return ($isReparse -or $isNamedLink)
}

function Test-DcAuditIsDirectory {
    param([Parameter(Mandatory)][string]$Path)
    if (Test-DcAuditReparsePoint -Path $Path) {
        return $false
    }
    $attributes = [System.IO.File]::GetAttributes($Path)
    return (([int]$attributes -band [int][System.IO.FileAttributes]::Directory) -ne 0)
}

function Get-DcAuditReparseCheckPaths {
    param([Parameter(Mandatory)][string]$Folder)
    $full = [System.IO.Path]::GetFullPath($Folder).TrimEnd('\', '/')
    $stop = $null
    if (-not [string]::IsNullOrWhiteSpace($env:ProgramData)) {
        $programData = [System.IO.Path]::GetFullPath($env:ProgramData).TrimEnd('\', '/')
        if (Test-DcAuditSameOrChildPath -Candidate $full -Parent $programData) {
            # ProgramData is the trust boundary. Check the folder and every
            # parent strictly below it, not ProgramData itself.
            $stop = $programData
        }
    }
    $paths = @($full)
    $current = $full
    while ($true) {
        $parent = [System.IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrWhiteSpace($parent)) {
            break
        }
        $parent = $parent.TrimEnd('\', '/')
        if ([string]::IsNullOrWhiteSpace($parent)) {
            break
        }
        if ($null -ne $stop -and [string]::Equals($parent, $stop, [System.StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $root = [System.IO.Path]::GetPathRoot($parent)
        if (-not [string]::IsNullOrWhiteSpace($root) -and
            [string]::Equals($parent, $root.TrimEnd('\', '/'), [System.StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $paths += $parent
        $current = $parent
    }
    return $paths
}

function Assert-DcAuditNoReparsePoint {
    param([Parameter(Mandatory)][string]$Folder)
    foreach ($path in @(Get-DcAuditReparseCheckPaths -Folder $Folder)) {
        if (-not (Test-DcAuditPathExists -Path $path)) {
            continue
        }
        if (Test-DcAuditReparsePoint -Path $path) {
            throw "Refusing to use '$path' because it is a junction or symbolic link."
        }
    }
}

function Assert-DcAuditOwner {
    param([Parameter(Mandatory)][string]$Folder)
    $acl = Get-Acl -LiteralPath $Folder
    $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
    if ($null -eq $owner -or [string]::IsNullOrWhiteSpace($owner.Value)) {
        throw "Refusing to use '$Folder' because its owner could not be read."
    }
    $userSid = Get-DcAuditCurrentUserSid
    $ownerAllowed = [string]::Equals($owner.Value, $AdministratorsSid, [System.StringComparison]::OrdinalIgnoreCase) -or
        [string]::Equals($owner.Value, $userSid, [System.StringComparison]::OrdinalIgnoreCase)
    if (-not $ownerAllowed) {
        throw "Refusing to use '$Folder' because its owner is not Administrators or the current user."
    }
}

function Set-DcAuditFolderAcl {
    param([Parameter(Mandatory)][string]$Folder)

    $userSid = Get-DcAuditCurrentUserSid
    Assert-DcAuditNoReparsePoint -Folder $Folder

    if (Test-DcAuditPathExists -Path $Folder) {
        if (-not (Test-DcAuditIsDirectory -Path $Folder)) {
            throw "Output path exists and is not a directory: $Folder"
        }
        # The marker only identifies the folder. Owner and link checks are required too.
        Assert-DcAuditOwner -Folder $Folder
        if (-not (Test-DcAuditMarker -Folder $Folder)) {
            throw "Refusing to reuse '$Folder' because it is not a DC audit output folder."
        }
        Set-DcAuditRestrictedAcl -Folder $Folder -UserSid $userSid
        return $userSid
    }

    $parent = Split-Path -Path $Folder -Parent
    if ([string]::IsNullOrWhiteSpace($parent) -or -not (Test-DcAuditPathExists -Path $parent)) {
        throw "Parent directory does not exist: $parent"
    }
    $security = New-DcAuditDirectorySecurity -UserSid $userSid
    New-DcAuditRestrictedDirectory -Path $Folder -Security $security
    Assert-DcAuditNoReparsePoint -Folder $Folder
    $children = @(Get-ChildItem -LiteralPath $Folder -Force -ErrorAction Stop)
    if ($children.Count -gt 0) {
        throw "Refusing to continue because '$Folder' is not empty."
    }
    Assert-DcAuditOwner -Folder $Folder
    Assert-DcAuditAcl -Folder $Folder -UserSid $userSid
    return $userSid
}

function Assert-DcAuditAcl {
    param(
        [Parameter(Mandatory)][string]$Folder,
        [Parameter(Mandatory)][string]$UserSid
    )

    $acl = Get-Acl -LiteralPath $Folder
    if (-not $acl.AreAccessRulesProtected) {
        throw "ACL inheritance is still enabled on '$Folder'. Aborting before writing audit output."
    }

    $allowed = @{
        $AdministratorsSid = $true
        $UserSid           = $true
    }
    $present = @{}
    $objectInherit = [int][System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $containerInherit = [int][System.Security.AccessControl.InheritanceFlags]::ContainerInherit
    $inheritOnly = [int][System.Security.AccessControl.PropagationFlags]::InheritOnly

    foreach ($ace in @($acl.Access)) {
        if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
            throw "Non-allow ACE on '$Folder' for $($ace.IdentityReference). Aborting before writing audit output."
        }
        $sid = $ace.IdentityReference
        if ($sid -isnot [System.Security.Principal.SecurityIdentifier]) {
            $sid = $sid.Translate([System.Security.Principal.SecurityIdentifier])
        }
        if (-not $allowed.ContainsKey($sid.Value)) {
            throw "Unexpected principal $($ace.IdentityReference) ($($sid.Value)) on '$Folder'. The ACL must be limited to Administrators and the current user. Aborting before writing audit output."
        }
        $flags = [int]$ace.InheritanceFlags
        if ((($flags -band $objectInherit) -eq 0) -or (($flags -band $containerInherit) -eq 0)) {
            throw "ACE for $($sid.Value) on '$Folder' does not inherit to child files. Aborting before writing audit output."
        }
        if (([int]$ace.PropagationFlags -band $inheritOnly) -ne 0) {
            throw "ACE for $($sid.Value) on '$Folder' does not apply to the folder itself. Aborting before writing audit output."
        }
        $present[$sid.Value] = $true
    }

    foreach ($requiredSid in @($allowed.Keys)) {
        if (-not $present.ContainsKey($requiredSid)) {
            throw "Missing allow ACE for $requiredSid on '$Folder'. Aborting before writing audit output."
        }
    }
}

function Set-DcAuditRestrictedAcl {
    param(
        [Parameter(Mandatory)][string]$Folder,
        [Parameter(Mandatory)][string]$UserSid
    )
    $acl = Get-Acl -LiteralPath $Folder
    $ownerAndGroup = $acl.GetSecurityDescriptorSddlForm(
        [System.Security.AccessControl.AccessControlSections]'Owner, Group')
    if ([string]::IsNullOrWhiteSpace($ownerAndGroup)) {
        $ownerAndGroup = "O:$UserSid"
    }
    $acl.SetSecurityDescriptorSddlForm($ownerAndGroup + (Get-DcAuditDaclSddl -UserSid $UserSid))
    Set-Acl -LiteralPath $Folder -AclObject $acl
    Assert-DcAuditAcl -Folder $Folder -UserSid $UserSid
}

function Get-DcAuditHardLinkCount {
    param([Parameter(Mandatory)][string]$Path)
    # Hard links do not have the reparse-point attribute, so the link count
    # is checked separately. More than one name means this path is not the
    # only name for the file.
    if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Unix) {
        $rawCount = & stat -c '%h' -- $Path
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to read the hard-link count for '$Path'."
        }
        $countText = "$rawCount".Trim()
        if ($countText -notmatch '^\d+$') {
            throw "Unable to read the hard-link count for '$Path'."
        }
        return [int]$countText
    }
    if (-not ('DcAuditNative.FileLinks' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace DcAuditNative {
    public static class FileLinks {
        [StructLayout(LayoutKind.Sequential)]
        struct ByHandleFileInformation {
            public uint FileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr CreateFile(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandle(IntPtr handle, out ByHandleFileInformation info);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr handle);
        public static int GetLinkCount(string path) {
            IntPtr handle = CreateFile(path, 0x80, 7, IntPtr.Zero, 3, 0, IntPtr.Zero);
            if (handle == new IntPtr(-1)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            try {
                ByHandleFileInformation info;
                if (!GetFileInformationByHandle(handle, out info)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                return (int)info.NumberOfLinks;
            } finally {
                CloseHandle(handle);
            }
        }
    }
}
'@
    }
    return [DcAuditNative.FileLinks]::GetLinkCount($Path)
}

function Assert-DcAuditMarkerFile {
    param([Parameter(Mandatory)][string]$Folder)
    $markerPath = Get-DcAuditMarkerPath -Folder $Folder
    if (-not (Test-DcAuditPathExists -Path $markerPath)) {
        return
    }
    if (Test-DcAuditReparsePoint -Path $markerPath) {
        throw "Refusing to use '$markerPath' because it is a junction or symbolic link."
    }
    $attributes = [System.IO.File]::GetAttributes($markerPath)
    if (([int]$attributes -band [int][System.IO.FileAttributes]::Directory) -ne 0) {
        throw "Refusing to use '$markerPath' because it is a folder."
    }
    $linkCount = Get-DcAuditHardLinkCount -Path $markerPath
    if ($linkCount -gt 1) {
        throw "Refusing to use '$markerPath' because it has $linkCount hard links."
    }
}

function Write-DcAuditMarker {
    param([Parameter(Mandatory)][string]$Folder)
    $markerPath = Get-DcAuditMarkerPath -Folder $Folder
    if (Test-DcAuditPathExists -Path $markerPath) {
        Assert-DcAuditMarkerFile -Folder $Folder
        [System.IO.File]::Delete($markerPath)
    }
    if (Test-DcAuditPathExists -Path $markerPath) {
        throw "Refusing to create '$markerPath' because the previous marker is still present."
    }
    $stream = New-Object System.IO.FileStream (
        $markerPath,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None)
    try {
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($MarkerValue + "`r`n")
        $stream.Write($bytes, 0, $bytes.Length)
    } finally {
        $stream.Dispose()
    }
}

function Test-DcAuditChildBlocked {
    param([Parameter(Mandatory)][string]$Path)
    if (Test-DcAuditReparsePoint -Path $Path) {
        return $true
    }
    $attributes = [System.IO.File]::GetAttributes($Path)
    return (([int]$attributes -band [int][System.IO.FileAttributes]::Directory) -ne 0)
}

function Remove-DcAuditTopLevelFiles {
    param(
        [Parameter(Mandatory)][string]$Folder,
        [switch]$KeepMarker
    )
    if (Test-DcAuditReparsePoint -Path $Folder) {
        throw "Refusing to delete anything in '$Folder' because it is a junction or symbolic link."
    }
    # This script never creates subfolders. A folder or reparse point is
    # unexpected, so stop before deleting any name in the directory.
    $children = @(Get-ChildItem -LiteralPath $Folder -Force -ErrorAction Stop)
    foreach ($child in $children) {
        $blocked = Test-DcAuditChildBlocked -Path $child.FullName
        if ($blocked) {
            throw "Refusing to delete anything in '$Folder' because '$($child.Name)' is a folder, junction, or symbolic link. Remove it manually and run the script again."
        }
    }
    foreach ($child in $children) {
        if ($KeepMarker -and $child.Name -eq $MarkerName) {
            continue
        }
        if (-not (Test-DcAuditPathExists -Path $child.FullName)) {
            continue
        }
        if (Test-DcAuditChildBlocked -Path $child.FullName) {
            throw "Stopped deleting '$Folder' because '$($child.Name)' is no longer a regular file."
        }
        [System.IO.File]::Delete($child.FullName)
    }
}

function Clear-DcAuditFiles {
    param([Parameter(Mandatory)][string]$Folder)
    Assert-DcAuditMarkerFile -Folder $Folder
    Remove-DcAuditTopLevelFiles -Folder $Folder -KeepMarker
}

function Remove-DcAuditOutputFolder {
    param([Parameter(Mandatory)][string]$Folder)
    Assert-DcAuditNoReparsePoint -Folder $Folder
    if (-not (Test-DcAuditPathExists -Path $Folder)) {
        Write-Host "DC audit output folder is not present: $Folder"
        return
    }
    if (-not (Test-DcAuditIsDirectory -Path $Folder)) {
        throw "Refusing to remove '$Folder' because it is not a directory."
    }
    if (-not (Test-DcAuditMarker -Folder $Folder)) {
        throw "Refusing to remove '$Folder' because it is not a DC audit output folder (missing $MarkerName marker)."
    }
    Assert-DcAuditMarkerFile -Folder $Folder
    # The marker is not sufficient. The owner must also be Administrators or the current user.
    Assert-DcAuditOwner -Folder $Folder
    if (Test-DcAuditReparsePoint -Path $Folder) {
        throw "Refusing to remove '$Folder' because it is a junction or symbolic link."
    }
    $userSid = Get-DcAuditCurrentUserSid
    Set-DcAuditRestrictedAcl -Folder $Folder -UserSid $userSid
    if (Test-DcAuditReparsePoint -Path $Folder) {
        throw "Refusing to remove '$Folder' because it is a junction or symbolic link."
    }
    Remove-DcAuditTopLevelFiles -Folder $Folder
    $remaining = @(Get-ChildItem -LiteralPath $Folder -Force -ErrorAction Stop)
    if ($remaining.Count -gt 0) {
        throw "Refusing to remove '$Folder' because items are still present."
    }
    if (Test-DcAuditReparsePoint -Path $Folder) {
        throw "Refusing to remove '$Folder' because it is a junction or symbolic link."
    }
    [System.IO.Directory]::Delete($Folder, $false)
    Write-Host "Removed DC audit output folder: $Folder"
}

if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    throw 'OutputFolder cannot be empty. The default folder is under $env:ProgramData.'
}
if (-not $PSBoundParameters.ContainsKey('OutputFolder')) {
    if ([string]::IsNullOrWhiteSpace($env:ProgramData)) {
        throw 'ProgramData is not set, so the default audit folder cannot be chosen. Pass -OutputFolder. Audit output is not written to the Desktop.'
    }
    $OutputFolder = Join-Path -Path $env:ProgramData -ChildPath "$env:COMPUTERNAME DC Audit"
}

$OutputFolder = Resolve-DcAuditOutputFolder -Folder $OutputFolder

if ($Cleanup) {
    Remove-DcAuditOutputFolder -Folder $OutputFolder
    return
}

[void](Set-DcAuditFolderAcl -Folder $OutputFolder)
if (Test-DcAuditMarker -Folder $OutputFolder) {
    Clear-DcAuditFiles -Folder $OutputFolder
}
Write-DcAuditMarker -Folder $OutputFolder

Write-Host "Writing DC audit output to $OutputFolder"
Write-Host "ACL: FullControl for Administrators and the current user only. Pass -Cleanup later to remove this folder."

Net LocalGroup Administrators | Out-File -FilePath (Join-Path $OutputFolder '1.Local_Admins.txt')
Get-ADGroupMember -Identity "Administrators" -Recursive | %{Get-ADUser -Identity $_.distinguishedName} | Select Name, Enabled | Out-File -FilePath (Join-Path $OutputFolder '2.Admins.txt') -append
Net Group "Domain Admins" | Out-File -FilePath (Join-Path $OutputFolder '2.Admins.txt') -append
Get-ADGroupMember -Identity "Domain Admins" -Recursive | %{Get-ADUser -Identity $_.distinguishedName} | Select Name, Enabled | Out-File -FilePath (Join-Path $OutputFolder '2.Admins.txt') -append
Net Group "Enterprise Admins" | Out-File -FilePath (Join-Path $OutputFolder '2.Admins.txt') -append
Get-ADGroupMember -Identity "Enterprise Admins" -Recursive | %{Get-ADUser -Identity $_.distinguishedName} | Select Name, Enabled | Out-File -FilePath (Join-Path $OutputFolder '2.Admins.txt') -append
Get-ADGroupMember -Identity "Guests" -Recursive | %{Get-ADUser -Identity $_.distinguishedName} | Select Name, Enabled | Out-File -FilePath (Join-Path $OutputFolder '3.Guests.txt')
systeminfo | Out-File -FilePath (Join-Path $OutputFolder '4.SysteminfoandUpdates.txt')
wmic qfe list | Out-File -FilePath (Join-Path $OutputFolder '4.SysteminfoandUpdates.txt') -append
gpresult -h (Join-Path $OutputFolder '5.DCFollowedGPOs.html')
vaultcmd /listschema | Out-File -FilePath (Join-Path $OutputFolder '6.CredentialManager.txt')
vaultcmd /list | Out-File -FilePath (Join-Path $OutputFolder '6.CredentialManager.txt') -append
net share | Out-File -FilePath (Join-Path $OutputFolder '7.Shares.txt')
dir C:\Users | Out-File -FilePath (Join-Path $OutputFolder '8.UsersOnHost.txt')
netsh advfirewall show allprofiles | Out-File -FilePath (Join-Path $OutputFolder '9.WindowsFirewall.txt')
powercfg /A | Out-File -FilePath (Join-Path $OutputFolder '10.SleepMode.txt')
ipconfig /all | Out-File -FilePath (Join-Path $OutputFolder '11.BridgedAdapters.txt')
get-gporeport -all -reporttype HTML -path (Join-Path $OutputFolder '12.DomainGPOs.html')
auditpol.exe /get /category:* | Out-File -FilePath (Join-Path $OutputFolder '13.AuditPolicySettings.txt')
net accounts | Out-File -FilePath (Join-Path $OutputFolder '14.PasswordPolicySettings.txt')
Get-ADDefaultDomainPasswordPolicy | Out-File -FilePath (Join-Path $OutputFolder '14.PasswordPolicySettings.txt') -append

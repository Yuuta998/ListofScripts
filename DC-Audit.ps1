<#
.SYNOPSIS
    Collects domain-controller audit data into an ACL-restricted folder.

.DESCRIPTION
    Writes audit files to -OutputFolder. When -OutputFolder is omitted, the
    folder is "$env:ProgramData\<computer name> DC Audit", under
    $env:ProgramData. The Desktop is not used.

    The folder is created with inheritance disabled. Its ACL grants
    FullControl only to BUILTIN\Administrators (S-1-5-32-544) and the user
    running this script, and child files inherit that ACL. Audit output can
    include administrator membership, password policy, shares, and credential
    manager listings, so it stays in that restricted folder.

    -Cleanup removes the output folder and exits without collecting. Removal
    runs only when this script's marker file (.dc-audit-output) is present.
    Drive roots, the Windows directory, and Desktop paths are refused.

    Folders left on the Desktop by older copies of this script are not
    removed automatically.

.PARAMETER OutputFolder
    Folder that receives the audit files. Defaults to a directory under
    $env:ProgramData named "<computer name> DC Audit". The parent directory
    must already exist. This cannot be the Desktop, a drive root, or the
    Windows directory.

.PARAMETER Cleanup
    Remove the audit output folder and exit. Does not collect new data.
    The folder must contain the .dc-audit-output marker written by this script.

.EXAMPLE
    .\DC-Audit.ps1

    Writes audit files under $env:ProgramData with a restricted ACL.

.EXAMPLE
    .\DC-Audit.ps1 -OutputFolder 'D:\SecureAudits\DC1'

.EXAMPLE
    .\DC-Audit.ps1 -Cleanup

    Deletes the default ProgramData audit folder created by this script.

.NOTES
    The marker file .dc-audit-output identifies a folder this script created.
    -Cleanup will not delete a path that lacks that marker.
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
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
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

function Set-DcAuditFolderAcl {
    param([Parameter(Mandatory)][string]$Folder)

    $userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($null -eq $userSid -or [string]::IsNullOrWhiteSpace($userSid.Value)) {
        throw 'Unable to resolve the current user security identifier for the audit folder ACL.'
    }

    $created = $false
    if (Test-Path -LiteralPath $Folder) {
        if (-not (Test-Path -LiteralPath $Folder -PathType Container)) {
            throw "Output path exists and is not a directory: $Folder"
        }
        if (-not (Test-DcAuditMarker -Folder $Folder)) {
            throw "Refusing to reuse '$Folder' because it is not a DC-Audit.ps1 output folder."
        }
    } else {
        $parent = Split-Path -Path $Folder -Parent
        if ([string]::IsNullOrWhiteSpace($parent) -or -not (Test-Path -LiteralPath $parent -PathType Container)) {
            throw "Parent directory does not exist: $parent"
        }
        # Create the directory first, then replace its ACL before any audit file is written.
        New-Item -ItemType Directory -Path $Folder -ErrorAction Stop | Out-Null
        $created = $true
    }

    try {
        $acl = Get-Acl -LiteralPath $Folder
        # Keep the current owner and group; replace only the DACL.
        $ownerAndGroup = $acl.GetSecurityDescriptorSddlForm(
            [System.Security.AccessControl.AccessControlSections]'Owner, Group')
        if ([string]::IsNullOrWhiteSpace($ownerAndGroup)) {
            $ownerAndGroup = "O:$($userSid.Value)"
        }
        $acl.SetSecurityDescriptorSddlForm($ownerAndGroup + (Get-DcAuditDaclSddl -UserSid $userSid.Value))
        Set-Acl -LiteralPath $Folder -AclObject $acl
        Assert-DcAuditAcl -Folder $Folder -UserSid $userSid.Value
    } catch {
        if ($created) {
            Remove-Item -LiteralPath $Folder -Recurse -Force -ErrorAction SilentlyContinue
        }
        throw
    }

    return $userSid.Value
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

function Write-DcAuditMarker {
    param([Parameter(Mandatory)][string]$Folder)
    Set-Content -LiteralPath (Get-DcAuditMarkerPath -Folder $Folder) -Value $MarkerValue -Encoding ascii -ErrorAction Stop
}

function Clear-DcAuditFiles {
    param([Parameter(Mandatory)][string]$Folder)
    Get-ChildItem -LiteralPath $Folder -Force -ErrorAction Stop |
        Where-Object { $_.Name -ne $MarkerName } |
        Remove-Item -Recurse -Force -ErrorAction Stop
}

function Remove-DcAuditOutputFolder {
    param([Parameter(Mandatory)][string]$Folder)
    if (-not (Test-Path -LiteralPath $Folder)) {
        Write-Host "DC audit output folder is not present: $Folder"
        return
    }
    if (-not (Test-Path -LiteralPath $Folder -PathType Container)) {
        throw "Refusing to remove '$Folder' because it is not a directory."
    }
    if (-not (Test-DcAuditMarker -Folder $Folder)) {
        throw "Refusing to remove '$Folder' because it is not a DC-Audit.ps1 output folder (missing $MarkerName marker)."
    }
    Remove-Item -LiteralPath $Folder -Recurse -Force -ErrorAction Stop
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

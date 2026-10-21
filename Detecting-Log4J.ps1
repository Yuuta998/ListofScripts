$PortableEverythingURL = "https://www.voidtools.com/Everything-1.4.1.1009.x64.zip"
# SHA256 published by voidtools in Everything-1.4.1.1009.sha256.
$ExpectedEverythingSha256 = "f61b601acba59d61fb0631a654e48a564db34e279b6f2cc45e20a42ce9d9c466"
# PSEverything 3.3.0 is the current stable ModuleVersion in powercode/PSEverything.
$PSEverythingVersion = "3.3.0"
$PSEverythingGuid = "f262ec02-4a88-49e5-94da-e25aab9cbf7a"
$LocalSystemSid = "S-1-5-18"
$AdministratorsSid = "S-1-5-32-544"
$Log4JToolName = "Detecting-Log4J"

$KnownEverythingZipHashes = @{
    $PortableEverythingURL = $ExpectedEverythingSha256
}

function Assert-Log4JElevated {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity -or $null -eq $identity.User -or [string]::IsNullOrWhiteSpace($identity.User.Value)) {
        throw "Unable to resolve the current Windows identity."
    }
    $isSystem = [string]::Equals($identity.User.Value, $LocalSystemSid, [System.StringComparison]::OrdinalIgnoreCase)
    $principal = New-Object System.Security.Principal.WindowsPrincipal $identity
    $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not ($isSystem -or $isAdmin)) {
        throw "Detecting-Log4J.ps1 must run as SYSTEM or an elevated administrator."
    }
}

function Test-Log4JPathExists {
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

function Test-Log4JReparsePoint {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Log4JPathExists -Path $Path)) {
        return $false
    }
    $attributes = [System.IO.File]::GetAttributes($Path)
    $isReparse = (([int]$attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0)
    $linkType = [string](Get-Item -LiteralPath $Path -Force -ErrorAction Stop).LinkType
    $isNamedLink = [string]::Equals($linkType, "SymbolicLink", [System.StringComparison]::OrdinalIgnoreCase) -or
        [string]::Equals($linkType, "Junction", [System.StringComparison]::OrdinalIgnoreCase)
    return ($isReparse -or $isNamedLink)
}

function Test-Log4JIsDirectory {
    param([Parameter(Mandatory)][string]$Path)
    if (Test-Log4JReparsePoint -Path $Path) {
        return $false
    }
    $attributes = [System.IO.File]::GetAttributes($Path)
    return (([int]$attributes -band [int][System.IO.FileAttributes]::Directory) -ne 0)
}

function Assert-Log4JNoReparsePoint {
    param([Parameter(Mandatory)][string]$Folder)
    $full = [System.IO.Path]::GetFullPath($Folder).TrimEnd('\', '/')
    $stop = $null
    if (-not [string]::IsNullOrWhiteSpace($env:ProgramData)) {
        $stop = [System.IO.Path]::GetFullPath($env:ProgramData).TrimEnd('\', '/')
    }
    $current = $full
    while ($true) {
        if ((Test-Log4JPathExists -Path $current) -and (Test-Log4JReparsePoint -Path $current)) {
            throw "Refusing to use '$current' because it is a junction or symbolic link."
        }
        $parent = [System.IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrWhiteSpace($parent)) {
            break
        }
        $parent = $parent.TrimEnd('\', '/')
        if ([string]::IsNullOrWhiteSpace($parent) -or [string]::Equals($parent, $current, [System.StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        # ProgramData is the trust boundary. Check this folder and every parent below it.
        if ($null -ne $stop -and [string]::Equals($parent, $stop, [System.StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $current = $parent
    }
}

function New-Log4JDirectorySecurity {
    # Same creation pattern as DC-Audit.ps1: protected DACL, object and container inherit, FullControl.
    # This folder allows only LOCAL SYSTEM and BUILTIN\Administrators.
    $security = New-Object System.Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    $rights = [System.Security.AccessControl.FileSystemRights]::FullControl
    $inheritance = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    foreach ($sidValue in @($LocalSystemSid, $AdministratorsSid)) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier $sidValue
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sid, $rights, $inheritance, $propagation, $allow)
        $security.AddAccessRule($rule)
    }
    return $security
}

function New-Log4JRestrictedDirectory {
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

function Assert-Log4JOwner {
    param([Parameter(Mandatory)][string]$Folder)
    $acl = Get-Acl -LiteralPath $Folder
    $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
    if ($null -eq $owner -or [string]::IsNullOrWhiteSpace($owner.Value)) {
        throw "Refusing to use '$Folder' because its owner could not be read."
    }
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $allowed = [string]::Equals($owner.Value, $LocalSystemSid, [System.StringComparison]::OrdinalIgnoreCase) -or
        [string]::Equals($owner.Value, $AdministratorsSid, [System.StringComparison]::OrdinalIgnoreCase) -or
        [string]::Equals($owner.Value, $currentUser, [System.StringComparison]::OrdinalIgnoreCase)
    if (-not $allowed) {
        throw "Refusing to use '$Folder' because its owner is not SYSTEM, Administrators, or the current user."
    }
}

function Assert-Log4JAcl {
    param([Parameter(Mandatory)][string]$Folder)
    $acl = Get-Acl -LiteralPath $Folder
    if (-not $acl.AreAccessRulesProtected) {
        throw "ACL inheritance is still enabled on '$Folder'. Aborting before writing."
    }

    $allowed = @{
        $LocalSystemSid    = $true
        $AdministratorsSid = $true
    }
    $present = @{}
    $objectInherit = [int][System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $containerInherit = [int][System.Security.AccessControl.InheritanceFlags]::ContainerInherit
    $inheritOnly = [int][System.Security.AccessControl.PropagationFlags]::InheritOnly
    $fullControl = [System.Security.AccessControl.FileSystemRights]::FullControl

    foreach ($ace in @($acl.Access)) {
        if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
            throw "Non-allow ACE on '$Folder' for $($ace.IdentityReference). Aborting before writing."
        }
        $sid = $ace.IdentityReference
        if ($sid -isnot [System.Security.Principal.SecurityIdentifier]) {
            $sid = $sid.Translate([System.Security.Principal.SecurityIdentifier])
        }
        if (-not $allowed.ContainsKey($sid.Value)) {
            throw "Unexpected principal $($ace.IdentityReference) ($($sid.Value)) on '$Folder'. The ACL must be limited to SYSTEM and Administrators."
        }
        if (($ace.FileSystemRights -band $fullControl) -ne $fullControl) {
            throw "ACE for $($sid.Value) on '$Folder' is not FullControl."
        }
        $flags = [int]$ace.InheritanceFlags
        if ((($flags -band $objectInherit) -eq 0) -or (($flags -band $containerInherit) -eq 0)) {
            throw "ACE for $($sid.Value) on '$Folder' does not inherit to child files."
        }
        if (([int]$ace.PropagationFlags -band $inheritOnly) -ne 0) {
            throw "ACE for $($sid.Value) on '$Folder' does not apply to the folder itself."
        }
        $present[$sid.Value] = $true
    }

    foreach ($requiredSid in @($allowed.Keys)) {
        if (-not $present.ContainsKey($requiredSid)) {
            throw "Missing allow ACE for $requiredSid on '$Folder'."
        }
    }
}

function Set-Log4JRestrictedAcl {
    param([Parameter(Mandatory)][string]$Folder)
    $acl = Get-Acl -LiteralPath $Folder
    $ownerAndGroup = $acl.GetSecurityDescriptorSddlForm(
        [System.Security.AccessControl.AccessControlSections]"Owner, Group")
    if ([string]::IsNullOrWhiteSpace($ownerAndGroup)) {
        throw "Unable to read the owner of '$Folder'. Aborting before writing."
    }
    $dacl = "D:P(A;OICI;FA;;;$LocalSystemSid)(A;OICI;FA;;;$AdministratorsSid)"
    $acl.SetSecurityDescriptorSddlForm($ownerAndGroup + $dacl)
    Set-Acl -LiteralPath $Folder -AclObject $acl
    Assert-Log4JAcl -Folder $Folder
}

function New-Log4JLockedDirectory {
    param([Parameter(Mandatory)][string]$Path)
    $parent = [System.IO.Path]::GetDirectoryName($Path)
    if ([string]::IsNullOrWhiteSpace($parent) -or -not (Test-Log4JPathExists -Path $parent)) {
        throw "Parent directory does not exist: $parent"
    }
    Assert-Log4JNoReparsePoint -Folder $parent
    if (Test-Log4JPathExists -Path $Path) {
        throw "Refusing to reuse existing path '$Path'."
    }
    $security = New-Log4JDirectorySecurity
    try {
        New-Log4JRestrictedDirectory -Path $Path -Security $security
    } catch {
        throw "Unable to create '$Path' with a SYSTEM and Administrators ACL. $($_.Exception.Message)"
    }
    Assert-Log4JNoReparsePoint -Folder $Path
    if (-not (Test-Log4JIsDirectory -Path $Path)) {
        throw "Locked path is not a directory: $Path"
    }
    $children = @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop)
    if ($children.Count -gt 0) {
        throw "Refusing to use '$Path' because it is not empty."
    }
    Assert-Log4JOwner -Folder $Path
    Assert-Log4JAcl -Folder $Path
}

function Initialize-Log4JToolRoot {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Log4JPathExists -Path $Path)) {
        New-Log4JLockedDirectory -Path $Path
        return
    }
    Assert-Log4JNoReparsePoint -Folder $Path
    if (-not (Test-Log4JIsDirectory -Path $Path)) {
        throw "Tool folder exists and is not a directory: $Path"
    }
    Assert-Log4JOwner -Folder $Path
    try {
        Set-Log4JRestrictedAcl -Folder $Path
    } catch {
        throw "Unable to lock the ACL on '$Path'. $($_.Exception.Message)"
    }
}

function Assert-Log4JDownloadHash {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$ZipPath,
        [Parameter(Mandatory)][hashtable]$KnownHashes
    )
    # The file name is irrelevant. An unknown URL or a blank pin fails closed.
    if (-not $KnownHashes.ContainsKey($Url)) {
        throw "No known SHA256 is pinned for '$Url'. Refusing to extract or run the download."
    }
    $expected = [string]$KnownHashes[$Url]
    if ([string]::IsNullOrWhiteSpace($expected)) {
        throw "No known SHA256 is pinned for '$Url'. Refusing to extract or run the download."
    }
    $actual = (Get-FileHash -LiteralPath $ZipPath -Algorithm SHA256 -ErrorAction Stop).Hash
    if ([string]::IsNullOrWhiteSpace($actual) -or
        -not [string]::Equals($actual.Trim(), $expected.Trim(), [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "SHA256 mismatch for the Everything download. Expected $expected but computed '$actual'."
    }
}

function Assert-Log4JZipEntries {
    param([Parameter(Mandatory)][string]$ZipPath)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead(([System.IO.Path]::GetFullPath($ZipPath)))
    try {
        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName.Replace('\', '/')
            if ([string]::IsNullOrWhiteSpace($name)) {
                continue
            }
            $segments = $name.Split('/')
            $escapes = $name.StartsWith('/') -or ($segments -contains '..') -or
                [System.IO.Path]::IsPathRooted($entry.FullName)
            if ($escapes) {
                throw "Zip entry '$($entry.FullName)' escapes the extraction folder."
            }
        }
    } finally {
        $archive.Dispose()
    }
}

function Get-Log4JZipEntrySha256 {
    param(
        [Parameter(Mandatory)][string]$ZipPath,
        [Parameter(Mandatory)][string]$EntryLeaf
    )
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead(([System.IO.Path]::GetFullPath($ZipPath)))
    try {
        $found = @($archive.Entries | Where-Object {
            $full = $_.FullName.Replace('\', '/').TrimEnd('/')
            $slash = $full.LastIndexOf('/')
            $directory = ''
            $leaf = $full
            if ($slash -ge 0) {
                $directory = $full.Substring(0, $slash)
                $leaf = $full.Substring($slash + 1)
            }
            $leaf.Equals($EntryLeaf, [System.StringComparison]::OrdinalIgnoreCase) -and
                [string]::IsNullOrWhiteSpace($directory)
        })
        if ($found.Count -ne 1) {
            throw "Expected one root $EntryLeaf entry in the verified zip, found $($found.Count)."
        }
        $stream = $found[0].Open()
        try {
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try {
                $bytes = $sha.ComputeHash($stream)
            } finally {
                $sha.Dispose()
            }
            $hash = ([System.BitConverter]::ToString($bytes)).Replace('-', '')
            if ([string]::IsNullOrWhiteSpace($hash)) {
                throw "Could not compute the pinned SHA256 of $EntryLeaf from the verified zip."
            }
            return $hash
        } finally {
            $stream.Dispose()
        }
    } finally {
        $archive.Dispose()
    }
}

function Assert-Log4JEverythingExe {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$PinnedSha256
    )
    if ([string]::IsNullOrWhiteSpace($PinnedSha256)) {
        throw "No pinned SHA256 for Everything.exe. Refusing to run it."
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Everything.exe was not found at '$Path'."
    }
    if (Test-Log4JReparsePoint -Path $Path) {
        throw "Everything.exe is a junction or symbolic link. Refusing to run it."
    }
    $full = [System.IO.Path]::GetFullPath($Path)
    $actual = (Get-FileHash -LiteralPath $full -Algorithm SHA256 -ErrorAction Stop).Hash
    $signature = Get-AuthenticodeSignature -LiteralPath $full -ErrorAction Stop
    $hashOk = -not [string]::IsNullOrWhiteSpace($actual) -and
        [string]::Equals($actual.Trim(), $PinnedSha256.Trim(), [System.StringComparison]::OrdinalIgnoreCase)
    $subject = ""
    if ($null -ne $signature.SignerCertificate) {
        $subject = [string]$signature.SignerCertificate.Subject
    }
    $signatureOk = ($signature.Status -eq "Valid") -and ($subject -like "*voidtools*")
    if (-not $hashOk) {
        throw "Extracted Everything.exe SHA256 mismatch. Expected $PinnedSha256 but computed '$actual'."
    }
    if (-not $signatureOk) {
        if ($signature.Status -ne "Valid") {
            throw "Everything.exe Authenticode status is $($signature.Status). Refusing to run it."
        }
        throw "Everything.exe signer '$subject' is not voidtools. Refusing to run it."
    }
}

function Assert-Log4JUnderRoot {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Candidate
    )
    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $candidateFull = [System.IO.Path]::GetFullPath($Candidate)
    $prefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
    if (-not $candidateFull.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Path '$candidateFull' is outside '$rootFull'."
    }
}

function Get-Log4JEverythingServiceNames {
    $names = @()
    foreach ($svc in @(Get-Service -ErrorAction Stop)) {
        $name = [string]$svc.Name
        $display = [string]$svc.DisplayName
        if ($name -like "*Everything*" -or $display -like "*Everything*") {
            $names += $name
        }
    }
    return @($names)
}

function Uninstall-Log4JService {
    param([Parameter(Mandatory)][string]$Name)
    # 1062 means the service is already stopped.
    $stopOutput = & sc.exe stop $Name 2>&1
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1062) {
        $detail = ($stopOutput | Out-String).Trim()
        throw "sc.exe stop $Name failed with exit code ${LASTEXITCODE}. $detail"
    }
    $deleteOutput = & sc.exe delete $Name 2>&1
    if ($LASTEXITCODE -ne 0) {
        $detail = ($deleteOutput | Out-String).Trim()
        throw "sc.exe delete $Name failed with exit code ${LASTEXITCODE}. $detail"
    }
}

function Assert-Log4JSavedModule {
    param(
        [Parameter(Mandatory)][string]$ExtractDir,
        [Parameter(Mandatory)][string]$ModuleRoot
    )
    $manifests = @(Get-ChildItem -LiteralPath $ModuleRoot -Recurse -Filter "PSEverything.psd1" -File -ErrorAction Stop)
    if ($manifests.Count -ne 1) {
        throw "Expected one saved PSEverything manifest, found $($manifests.Count)."
    }
    $manifestPath = $manifests[0].FullName
    Assert-Log4JUnderRoot -Root $ExtractDir -Candidate $manifestPath
    $data = Import-PowerShellDataFile -LiteralPath $manifestPath
    if ([version]$data.ModuleVersion -ne [version]$PSEverythingVersion) {
        throw "Saved PSEverything version '$($data.ModuleVersion)' is not $PSEverythingVersion."
    }
    if (-not [string]::Equals([string]$data.GUID, $PSEverythingGuid, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Saved PSEverything GUID '$($data.GUID)' is not $PSEverythingGuid."
    }

    # The gallery package is not consistently Authenticode-signed. A signature
    # that is present must be Valid and name the publisher. Any other status
    # fails closed. An unsigned file is accepted only because the version and
    # GUID are pinned and the files stay inside the locked folder.
    $dll = Join-Path (Split-Path -Parent $manifestPath) "PSEverything.dll"
    foreach ($file in @($manifestPath, $dll)) {
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
            throw "Saved PSEverything file is missing: $file"
        }
        $signature = Get-AuthenticodeSignature -LiteralPath $file -ErrorAction Stop
        if ($signature.Status -eq "NotSigned") {
            continue
        }
        if ($signature.Status -ne "Valid") {
            throw "PSEverything file '$file' has Authenticode status $($signature.Status). Refusing to import it."
        }
        $subject = ""
        if ($null -ne $signature.SignerCertificate) {
            $subject = [string]$signature.SignerCertificate.Subject
        }
        if ($subject -notlike "*Gustafsson*" -and $subject -notlike "*PowerCode*") {
            throw "PSEverything file '$file' is signed by '$subject', not the expected publisher."
        }
    }
    return $manifestPath
}

function Initialize-Log4JEverythingIpc {
    if ("Log4JEverythingIpc" -as [type]) {
        return
    }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class Log4JEverythingIpc {
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

    [DllImport("user32.dll", SetLastError = true)]
    public static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
}
'@
}

function Wait-Log4JEverythingReady {
    param(
        [Parameter(Mandatory)][System.Diagnostics.Process]$Process,
        [int]$TimeoutSeconds = 120
    )
    # Everything 1.4 IPC window class and DB status messages from everything_ipc.h.
    Initialize-Log4JEverythingIpc
    $windowClass = "EVERYTHING_TASKBAR_NOTIFICATION"
    $windowMessage = [uint32]0x0400
    $isDbLoaded = [IntPtr]401
    $isDbBusy = [IntPtr]402
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $Process.Refresh()
        $hwnd = [Log4JEverythingIpc]::FindWindow($windowClass, $null)
        if ($hwnd -ne [IntPtr]::Zero) {
            $loaded = [Log4JEverythingIpc]::SendMessage($hwnd, $windowMessage, $isDbLoaded, [IntPtr]::Zero)
            $busy = [Log4JEverythingIpc]::SendMessage($hwnd, $windowMessage, $isDbBusy, [IntPtr]::Zero)
            if ($loaded -ne [IntPtr]::Zero -and $busy -eq [IntPtr]::Zero) {
                return
            }
        }
        if ($Process.HasExited -and $hwnd -eq [IntPtr]::Zero) {
            throw "Everything exited with code $($Process.ExitCode) before its IPC window was ready."
        }
        Start-Sleep -Milliseconds 250
    }
    throw "Everything index or IPC was not ready within $TimeoutSeconds seconds."
}

function Clear-Log4JRuntime {
    [CmdletBinding()]
    param(
        [string]$ExtractDir,
        $StartedPid,
        [string[]]$InstalledServiceNames = @(),
        $PreExistingServiceNames,
        [bool]$ServiceBaselineReady = $false
    )

    if ($null -ne $StartedPid) {
        try {
            $alive = $true
            try {
                $null = Get-Process -Id $StartedPid -ErrorAction Stop
            } catch {
                $alive = $false
            }
            if ($alive) {
                Stop-Process -Id $StartedPid -Force -ErrorAction Stop
                $deadline = (Get-Date).AddSeconds(15)
                do {
                    Start-Sleep -Milliseconds 200
                    $alive = $true
                    try {
                        $null = Get-Process -Id $StartedPid -ErrorAction Stop
                    } catch {
                        $alive = $false
                    }
                } while ($alive -and (Get-Date) -lt $deadline)
                if ($alive) {
                    Write-Warning "Everything process $StartedPid is still running after Stop-Process."
                }
            }
        } catch {
            Write-Warning "Failed to stop Everything process ${StartedPid}: $($_.Exception.Message)"
        }
    }

    if (-not $ServiceBaselineReady) {
        if (@($InstalledServiceNames).Count -gt 0) {
            Write-Warning "Everything service baseline was not recorded. Leaving every service in place."
        }
    } else {
        $seen = @()
        try {
            $seen = @(Get-Log4JEverythingServiceNames)
        } catch {
            Write-Warning "Failed to list Everything services during cleanup: $($_.Exception.Message)"
        }
        $candidates = New-Object System.Collections.Generic.List[string]
        foreach ($candidateName in @($seen + @($InstalledServiceNames))) {
            if ([string]::IsNullOrWhiteSpace([string]$candidateName)) {
                continue
            }
            if (-not $candidates.Contains([string]$candidateName)) {
                $candidates.Add([string]$candidateName)
            }
        }
        foreach ($name in $candidates) {
            $wasThere = @($PreExistingServiceNames) -contains $name
            $weInstalled = @($InstalledServiceNames) -contains $name
            if ($wasThere) {
                continue
            }
            if (-not $weInstalled) {
                Write-Warning "Everything service '$name' appeared during the run, but this script did not install it. Leaving it in place."
                continue
            }
            try {
                Uninstall-Log4JService -Name $name
            } catch {
                Write-Warning "Failed to remove Everything service '${name}': $($_.Exception.Message)"
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ExtractDir)) {
        try {
            if (Get-Module -Name PSEverything -ErrorAction Stop) {
                Remove-Module -Name PSEverything -Force -ErrorAction Stop
            }
        } catch {
            Write-Warning "Failed to unload PSEverything before deleting '$ExtractDir': $($_.Exception.Message)"
        }
        try {
            if (Test-Path -LiteralPath $ExtractDir) {
                Remove-Item -LiteralPath $ExtractDir -Recurse -Force -ErrorAction Stop
            }
        } catch {
            Write-Warning "Failed to remove '$ExtractDir': $($_.Exception.Message)"
        }
    }
}

function Invoke-DetectingLog4J {
    $ErrorActionPreference = "Stop"
    # Under SYSTEM, $env:TEMP is C:\Windows\Temp. Do not extract or run from there.
    Assert-Log4JElevated
    if ([string]::IsNullOrWhiteSpace($env:ProgramData)) {
        throw "ProgramData is not set. Refusing to fall back to TEMP."
    }

    $extractDir = $null
    $startedPid = $null
    $installedServiceNames = @()
    $preExistingServiceNames = $null
    $serviceBaselineReady = $false
    try {
        $preExistingServiceNames = @(Get-Log4JEverythingServiceNames)
        $serviceBaselineReady = $true

        $programData = [System.IO.Path]::GetFullPath($env:ProgramData).TrimEnd('\', '/')
        $toolRoot = Join-Path $programData $Log4JToolName
        $toolFull = [System.IO.Path]::GetFullPath($toolRoot)
        $prefix = $programData + [System.IO.Path]::DirectorySeparatorChar
        if (-not $toolFull.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Tool folder '$toolFull' is not under ProgramData."
        }
        Initialize-Log4JToolRoot -Path $toolFull

        $extractDir = Join-Path $toolFull ([guid]::NewGuid().ToString())
        New-Log4JLockedDirectory -Path $extractDir

        $zipPath = Join-Path $extractDir "Everything-1.4.1.1009.x64.zip"
        Invoke-WebRequest -UseBasicParsing -Uri $PortableEverythingURL -OutFile $zipPath -ErrorAction Stop
        Assert-Log4JDownloadHash -Url $PortableEverythingURL -ZipPath $zipPath -KnownHashes $KnownEverythingZipHashes
        Assert-Log4JZipEntries -ZipPath $zipPath

        # Pin Everything.exe to the hash of that entry inside the verified zip.
        # Extraction must reproduce those bytes. This does not depend on the file name.
        $pinnedExeSha256 = Get-Log4JZipEntrySha256 -ZipPath $zipPath -EntryLeaf "Everything.exe"

        # The directory is new. Do not use -Force; a colliding file must fail closed.
        Expand-Archive -Path $zipPath -DestinationPath $extractDir -ErrorAction Stop

        $exeItems = @(Get-ChildItem -LiteralPath $extractDir -Force -File | Where-Object {
            $_.Name -eq "Everything.exe"
        })
        if ($exeItems.Count -ne 1) {
            throw "Expected one Everything.exe in the extraction folder, found $($exeItems.Count)."
        }
        $everythingExe = $exeItems[0].FullName
        Assert-Log4JUnderRoot -Root $extractDir -Candidate $everythingExe
        Assert-Log4JEverythingExe -Path $everythingExe -PinnedSha256 $pinnedExeSha256

        $moduleRoot = Join-Path $extractDir "PSModules"
        New-Item -ItemType Directory -Path $moduleRoot -ErrorAction Stop | Out-Null
        # -Force skips the untrusted-repository confirmation so a non-interactive
        # SYSTEM run can finish. It does not change PSGallery's InstallationPolicy
        # and it does not install the module for the machine. The files stay in
        # this locked folder, are imported from that path, and are removed in finally.
        Save-Module -Name PSEverything -RequiredVersion $PSEverythingVersion -Path $moduleRoot -Repository PSGallery -Force -ErrorAction Stop
        $manifestPath = Assert-Log4JSavedModule -ExtractDir $extractDir -ModuleRoot $moduleRoot
        # Import-Module -Force reloads this saved copy. It does not register the module for the machine.
        Import-Module -LiteralPath $manifestPath -Force -ErrorAction Stop

        Assert-Log4JEverythingExe -Path $everythingExe -PinnedSha256 $pinnedExeSha256
        # Portable instance only. A rerun does not look for an existing client
        # service and does not reuse an exe left in TEMP. Each run starts the
        # process it will stop.
        $everythingProcess = Start-Process -FilePath $everythingExe -WorkingDirectory $extractDir -PassThru -ArgumentList @(
            "-startup",
            "-noapp-data",
            "-disable-update-notification",
            "-disable-run-as-admin"
        )
        if ($null -eq $everythingProcess) {
            throw "Start-Process did not return an Everything process."
        }
        $startedPid = $everythingProcess.Id
        Wait-Log4JEverythingReady -Process $everythingProcess

        $ScanResults = search-everything -global -extension jar
        if ($ScanResults) {
            Write-Host "Potential vulnerable JAR files found. Please investigate:"
            Write-Host "all Results:"
            $scanresults
            Write-Host "All Results with vulnerable class:"
            # Select-String reads each result path as text. It cannot see
            # JndiLookup.class inside a compressed jar. That limitation was
            # already present before this change.
            ($ScanResults | ForEach-Object { Select-String "JndiLookup.class" $_ }).path
        }
        else {
            Write-Host "Did not find any vulnerable files."
        }
    } finally {
        Clear-Log4JRuntime -ExtractDir $extractDir -StartedPid $startedPid -InstalledServiceNames $installedServiceNames -PreExistingServiceNames $preExistingServiceNames -ServiceBaselineReady:$serviceBaselineReady
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-DetectingLog4J
}

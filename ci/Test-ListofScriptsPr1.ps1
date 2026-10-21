param([Parameter(Mandatory)][string]$ShellExe)
$ErrorActionPreference = 'Continue'
$repo = Split-Path $PSScriptRoot -Parent
$results = [ordered]@{}
$admin = 'S-1-5-32-544'
& $ShellExe -NoProfile -Command '$PSVersionTable.PSVersion.ToString(); $PSVersionTable.PSEdition' | Write-Host
function Run([string]$cmd) {
  $out = & $ShellExe -NoProfile -ExecutionPolicy Bypass -Command $cmd 2>&1
  $code = $LASTEXITCODE
  $out | ForEach-Object { Write-Host "  | $_" }
  Write-Host "  exit code: $code"
  return $code
}

Write-Host "=== Parse check (all .ps1 in PR under $ShellExe) ==="
foreach ($f in 'DC-Audit.ps1','Detecting-Log4J.ps1') {
  $p = Join-Path $repo $f
  $code = Run "`$e=`$null; [void][System.Management.Automation.Language.Parser]::ParseFile('$p',[ref]`$null,[ref]`$e); if(`$e){`$e | % { `$_.Extent.StartLineNumber.ToString() + ': ' + `$_.Message }; exit 1} else {'parse OK'}"
  $results["parse $f"] = ($code -eq 0)
}

Write-Host "=== Log4J: SHA256 gate passes for genuine zip ==="
$lines = Get-Content (Join-Path $repo 'Detecting-Log4J.ps1')
$end = ($lines | Select-String -SimpleMatch 'Set-PSRepository' | Select-Object -First 1).LineNumber - 1
$gate = Join-Path $env:RUNNER_TEMP 'gate.ps1'
$lines[0..($end-1)] + @('"GATE PASSED"') | Set-Content $gate
Remove-Item "$env:TEMP\Everything.zip" -Force -ErrorAction SilentlyContinue
$code = Run "& '$gate'"
$results['Log4J hash gate accepts genuine zip'] = ($code -eq 0 -and (Test-Path "$env:TEMP\Everything.zip"))

Write-Host "=== Log4J: SHA256 mismatch deletes zip and throws ==="
$bad = Join-Path $env:RUNNER_TEMP 'gate-bad.ps1'
(Get-Content $gate) -replace 'f61b601acba59d61fb0631a654e48a564db34e279b6f2cc45e20a42ce9d9c466','0000000000000000000000000000000000000000000000000000000000000000' | Set-Content $bad
$code = Run "& '$bad'"
$results['Log4J hash mismatch throws + deletes zip'] = ($code -ne 0 -and -not (Test-Path "$env:TEMP\Everything.zip"))

Write-Host "=== DC-Audit: default run creates ProgramData folder with restricted ACL ==="
$folder = Join-Path $env:ProgramData "$env:COMPUTERNAME DC Audit"
Remove-Item -LiteralPath $folder -Recurse -Force -ErrorAction SilentlyContinue
$code = Run "& '$(Join-Path $repo 'DC-Audit.ps1')'"
Write-Host "  (non-zero exit expected: runner is not a domain controller, AD cmdlets unavailable)"
$exists = Test-Path -LiteralPath $folder
$results['DC-Audit output folder under ProgramData'] = $exists
$desk = Join-Path ([Environment]::GetFolderPath('Desktop')) "$env:COMPUTERNAME DC Audit"
$results['DC-Audit nothing written to Desktop'] = -not (Test-Path -LiteralPath $desk)
if ($exists) {
  $acl = Get-Acl -LiteralPath $folder
  $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $rules = @($acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]))
  $sids = @($rules | % { $_.IdentityReference.Value }) | Sort-Object -Unique
  $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  Write-Host "  owner=$owner protected=$($acl.AreAccessRulesProtected) sids=$($sids -join ',') me=$me"
  $rules | % { Write-Host "   ACE $($_.IdentityReference) $($_.AccessControlType) $($_.FileSystemRights) inherited=$($_.IsInherited)" }
  $results['DC-Audit ACL = Administrators + current user only, inheritance off'] = ($acl.AreAccessRulesProtected -and @($sids | ? { $_ -notin @($admin,$me) }).Count -eq 0)
  Get-ChildItem -LiteralPath $folder -Force | % { Write-Host "  file: $($_.Name) $($_.Length)" }
  $results['DC-Audit marker + 1.Local_Admins.txt written'] = (Test-Path (Join-Path $folder '.dc-audit-output')) -and (Test-Path (Join-Path $folder '1.Local_Admins.txt'))
}

Write-Host "=== DC-Audit: refuses Desktop / drive root OutputFolder ==="
$code = Run "& '$(Join-Path $repo 'DC-Audit.ps1')' -OutputFolder '$desk'"
$results['DC-Audit refuses Desktop OutputFolder'] = ($code -ne 0 -and -not (Test-Path -LiteralPath $desk))
$code = Run "& '$(Join-Path $repo 'DC-Audit.ps1')' -OutputFolder 'C:\'"
$results['DC-Audit refuses drive root OutputFolder'] = ($code -ne 0)

Write-Host "=== DC-Audit: -Cleanup removes folder ==="
$code = Run "& '$(Join-Path $repo 'DC-Audit.ps1')' -Cleanup"
$results['DC-Audit -Cleanup removes folder'] = ($code -eq 0 -and -not (Test-Path -LiteralPath $folder))

Write-Host "=== DC-Audit: -Cleanup refuses unmarked folder ==="
New-Item -ItemType Directory -Force $folder | Out-Null; Set-Content (Join-Path $folder 'keep.txt') 'x'
$code = Run "& '$(Join-Path $repo 'DC-Audit.ps1')' -Cleanup"
$results['DC-Audit -Cleanup refuses unmarked folder'] = ($code -ne 0 -and (Test-Path (Join-Path $folder 'keep.txt')))
Remove-Item -LiteralPath $folder -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "=== SUMMARY ($ShellExe) ==="
$fail = $false
foreach ($k in $results.Keys) { $v = $results[$k]; $s = if ($v -eq $true) {'PASS'} else {'FAIL'; $fail=$true}; Write-Host "RESULT | $s | $k" }
if ($fail) { exit 1 }
exit 0

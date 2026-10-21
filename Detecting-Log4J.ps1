$PortableEverythingURL = "https://www.voidtools.com/Everything-1.4.1.1009.x64.zip"
# SHA256 of Everything-1.4.1.1009.x64.zip from the Scoop manifest.
$ExpectedEverythingSha256 = "f61b601acba59d61fb0631a654e48a564db34e279b6f2cc45e20a42ce9d9c466"
# Latest stable PSEverything ModuleVersion (powercode/PSEverything).
$PSEverythingVersion = "3.3.0"

$extractDir = $null
try {
    $extractDir = Join-Path $env:TEMP ([guid]::NewGuid())
    New-Item -ItemType Directory -Path $extractDir -ErrorAction Stop | Out-Null

    $zipPath = Join-Path $extractDir "Everything-1.4.1.1009.x64.zip"
    Invoke-WebRequest -UseBasicParsing -Uri $PortableEverythingURL -OutFile $zipPath -ErrorAction Stop

    $zipName = ([Uri]$PortableEverythingURL).Segments[-1]
    if ($zipName -eq "Everything-1.4.1.1009.x64.zip") {
        $actualHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256 -ErrorAction Stop).Hash
        if ([string]::IsNullOrWhiteSpace($actualHash) -or
            -not [string]::Equals($actualHash.Trim(), $ExpectedEverythingSha256, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "SHA256 mismatch for Everything-1.4.1.1009.x64.zip. Expected $ExpectedEverythingSha256 but computed '$actualHash'."
        }
    }

    Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force -ErrorAction Stop

    $everythingExe = Join-Path $extractDir "everything.exe"
    if (-not (Test-Path -LiteralPath $everythingExe -PathType Leaf)) {
        throw "everything.exe was not found in the extraction folder."
    }

    if (!(Get-Service "Everything Client" -ErrorAction SilentlyContinue)) {
        & $everythingExe -install-client-service
        & $everythingExe -reindex
        Start-Sleep 3
        Install-Module PSEverything -RequiredVersion $PSEverythingVersion -Force
    }
    else {
        & $everythingExe -reindex
        Install-Module PSEverything -RequiredVersion $PSEverythingVersion -Force
    }

    $ScanResults = search-everything -global -extension jar
    if ($ScanResults) {
        Write-Host "Potential vulnerable JAR files found. Please investigate:"
        Write-Host "all Results:"
        $scanresults
        Write-Host "All Results with vulnerable class:"
        ($ScanResults | ForEach-Object { Select-String "JndiLookup.class" $_ }).path
    }
    else {
        Write-Host "Did not find any vulnerable files."
    }
}
finally {
    if ($extractDir -and (Test-Path -LiteralPath $extractDir)) {
        Remove-Item -LiteralPath $extractDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

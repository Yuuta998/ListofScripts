$PortableEverythingURL = "https://www.voidtools.com/Everything-1.4.1.1009.x64.zip"
# This value comes from voidtools' official Everything-1.4.1.1009.sha256, as mirrored in the Scoop manifest.
$ExpectedEverythingSha256 = "f61b601acba59d61fb0631a654e48a564db34e279b6f2cc45e20a42ce9d9c466"

$EverythingZip = Join-Path $env:TEMP "Everything.zip"
Invoke-WebRequest -UseBasicParsing -Uri $PortableEverythingURL -OutFile $EverythingZip -ErrorAction Stop
$ActualEverythingSha256 = (Get-FileHash -LiteralPath $EverythingZip -Algorithm SHA256 -ErrorAction Stop).Hash
if ([string]::IsNullOrWhiteSpace($ActualEverythingSha256) -or
    (-not [string]::Equals($ActualEverythingSha256.Trim(), $ExpectedEverythingSha256, [System.StringComparison]::OrdinalIgnoreCase))) {
    Remove-Item -LiteralPath $EverythingZip -Force -ErrorAction SilentlyContinue
    throw "SHA256 mismatch for Everything-1.4.1.1009.x64.zip. Expected $ExpectedEverythingSha256 but computed '$ActualEverythingSha256'. Aborting before unzip or execution."
}

Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
Expand-Archive -Path $EverythingZip -DestinationPath $($ENV:Temp) -Force
if (!(Get-Service "Everything Client" -ErrorAction SilentlyContinue)) {
   & "$($ENV:TEMP)\everything.exe" -install-client-service
   & "$($ENV:TEMP)\everything.exe" -reindex
    start-sleep 3
    Install-Module PSEverything
}
else {
       & "$($ENV:TEMP)\everything.exe" -reindex
    Install-Module PSEverything

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

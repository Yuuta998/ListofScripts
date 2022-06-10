$AlertPercent = "70"
 
& powercfg /batteryreport /XML /OUTPUT "batteryreport.xml"
Start-Sleep 1
[xml]$Report = Get-Content "batteryreport.xml"
     
$BatteryStatus = $Report.BatteryReport.Batteries |
ForEach-Object {
    [PSCustomObject]@{
        DesignCapacity     = $_.Battery.DesignCapacity
        FullChargeCapacity = $_.Battery.FullChargeCapacity
        CycleCount         = $_.Battery.CycleCount
        Id                 = $_.Battery.id
    }
}
 
if (!$BatteryStatus) {
    Write-Host "This device does not have batteries, or we could not find the status of the batteries."
}
 
foreach ($Battery in $BatteryStatus) {
    if ([int64]$Battery.FullChargeCapacity * 100 / [int64]$Battery.DesignCapacity -lt $AlertPercent) {
        Write-host "The battery health is less than expect. The battery was designed for $($battery.DesignCapacity) but the maximum charge is $($Battery.FullChargeCapacity). The battery info is $($Battery.id)"
 
    }
}
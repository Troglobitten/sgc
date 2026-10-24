<#
.SYNOPSIS
    The two whole-machine tests a release needs, one after the other.
.DESCRIPTION
    Test-Installer.ps1 (a fresh install of the current source, through every
    step), then Test-UpgradeFromPrevious.ps1 (the newest published release
    updating itself to the current source). Each prints one line per step;
    their full output is in the logs they name. Stops at the first test that
    fails. Takes about an hour.
#>
[CmdletBinding()]
param()

$started = Get-Date
$results = [ordered]@{}
foreach ($test in 'Test-Installer.ps1', 'Test-UpgradeFromPrevious.ps1') {
    Write-Host ''
    Write-Host "=== $test" -ForegroundColor Cyan
    try {
        & "$PSScriptRoot\$test"
        $results[$test] = 'passed'
    } catch {
        $results[$test] = "FAILED: $($_.Exception.Message)"
        break
    }
}

$minutes = [int][math]::Round(((Get-Date) - $started).TotalMinutes)
Write-Host ''
foreach ($entry in $results.GetEnumerator()) {
    $colour = if ($entry.Value -eq 'passed') { 'Green' } else { 'Red' }
    Write-Host ('{0,-32} {1}' -f $entry.Key, $entry.Value) -ForegroundColor $colour
}
if ($results.Count -lt 2 -or @($results.Values | Where-Object { $_ -ne 'passed' }).Count -gt 0) {
    Write-Host "Not ready for a release ($minutes minutes)." -ForegroundColor Red
    exit 1
}
Write-Host "Both tests passed in $minutes minutes: ready for a release." -ForegroundColor Green

<#
.SYNOPSIS
    Tests the installer on the clean test machine.

.DESCRIPTION
    1. Builds a release signed with a throwaway test key, plus three
       deliberately bad variants (see make-test-release.sh).
    2. Resets the test machine and checks that every bad variant is refused
       and leaves nothing behind.
    3. Checks that the genuine release installs, runs as an unprivileged
       service, and can be installed a second time without harm.

    The real release key is never involved. Requires the test machine from
    test/e2e/vm.
#>
[CmdletBinding()]
param()

. "$PSScriptRoot\..\vm\Common.ps1"

$repo        = (Resolve-Path "$PSScriptRoot\..\..\..").Path
$releaseDir  = Join-Path $StateDir 'test-release'
$version     = (Get-Content (Join-Path $repo 'VERSION') -Raw).Trim()

Write-Host "Building a test release of $version ..."
wsl -d $WslDistro --exec bash (ConvertTo-WslPath "$PSScriptRoot\make-test-release.sh") (ConvertTo-WslPath $releaseDir)
if ($LASTEXITCODE -ne 0) { throw 'Building the test release failed.' }

Write-Host "Resetting the test machine ..."
& "$PSScriptRoot\..\vm\Reset-TestVM.ps1" | Out-Null
$address = Get-TestVMAddress

$sshArguments = Get-SshArguments
Invoke-TestVMCommand -Address $address -Command 'rm -rf /tmp/release /tmp/cases.sh'
& scp @sshArguments -q -r $releaseDir "${VmUser}@${address}:/tmp/release"
& scp @sshArguments -q "$PSScriptRoot\cases.sh" "${VmUser}@${address}:/tmp/cases.sh"
if ($LASTEXITCODE -ne 0) { throw 'Copying the test release to the test machine failed.' }

$failed = 0
foreach ($mode in 'refused', 'accepted') {
    Write-Host ""
    Invoke-TestVMCommand -Address $address -Command "bash /tmp/cases.sh $mode $version"
    if ($LASTEXITCODE -ne 0) { $failed++ }
}

Write-Host ""
if ($failed -gt 0) { throw "Installer test FAILED." }
Write-Host "Installer test passed."

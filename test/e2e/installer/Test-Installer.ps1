<#
.SYNOPSIS
    Tests the installer and the installed SGC on the clean test machine.

.DESCRIPTION
    1. Builds a release signed with a throwaway test key, plus three
       deliberately bad variants (see make-test-release.sh).
    2. Resets the test machine and checks that every bad variant is refused
       and leaves nothing behind.
    3. Installs the genuine release and checks the service, the one-time
       setup link, sign-in, the dashboard data and the root helper.
    4. Restarts the machine through SGC and checks that everything comes
       back by itself.

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
Invoke-TestVMCommand -Address $address -Command 'rm -rf /tmp/release ~/cases.sh ~/sgc-test-*'
& scp @sshArguments -q -r $releaseDir "${VmUser}@${address}:/tmp/release"
& scp @sshArguments -q "$PSScriptRoot\cases.sh" "${VmUser}@${address}:cases.sh"
if ($LASTEXITCODE -ne 0) { throw 'Copying the test release to the test machine failed.' }

$failed = 0
function Invoke-Cases {
    param([string]$Mode)
    Write-Host ""
    Invoke-TestVMCommand -Address $script:address -Command "bash ~/cases.sh $Mode $version"
    if ($LASTEXITCODE -ne 0) { $script:failed++ }
}

Invoke-Cases refused
Invoke-Cases accepted
Invoke-Cases restart

# The machine is now going down. Wait until it has actually stopped answering
# before waiting for it to come back.
Write-Host ""
Write-Host "Waiting for the machine to go down and come back ..."
Wait-TestVMSshDown -Address $address
$address = Wait-TestVMSsh

Invoke-Cases after-restart

Write-Host ""
if ($failed -gt 0) { throw "Installer test FAILED." }
Write-Host "Installer test passed."

<#
.SYNOPSIS
    Tests updating from the previous published release to the current source.

.DESCRIPTION
    An update is carried out by the version that is already installed. So a
    new release has to work with what the previous release's updater does
    with it, and that is not something the other tests see: they install the
    current source and update it with its own updater.

    1. Builds the previous release from its tag and the current source, both
       signed with a throwaway key (see make-upgrade-release.sh).
    2. Installs the previous release on the clean test machine and creates an
       admin account.
    3. Lets it update itself to the current source, through its own updater.
    4. Checks what that left, then runs the steps of the installer test that
       exercise the current version's features on the machine that got here
       by updating: the firewall, SSH, a restart, the command line.

    Run it before a release, next to Test-Installer.ps1. The real release
    key is never involved. Requires the test machine from test/e2e/vm.

.PARAMETER PreviousTag
    The release to update from. Default: the newest release tag.
#>
[CmdletBinding()]
param([string]$PreviousTag)

. "$PSScriptRoot\..\vm\Common.ps1"

$repo       = (Resolve-Path "$PSScriptRoot\..\..\..").Path
$releaseDir = Join-Path $StateDir 'upgrade-release'

if (-not $PreviousTag) {
    $PreviousTag = (& git -C $repo tag --list 'v*' --sort=-v:refname | Select-Object -First 1)
    if (-not $PreviousTag) { throw 'No release tag found to update from.' }
}

Write-Host "Building $PreviousTag as it was published, and the current source ..."
$output = wsl -d $WslDistro --exec bash (ConvertTo-WslPath "$PSScriptRoot\make-upgrade-release.sh") $PreviousTag (ConvertTo-WslPath $releaseDir)
if ($LASTEXITCODE -ne 0) { $output | Write-Host; throw 'Building failed.' }
$output | Select-Object -SkipLast 1 | Write-Host
$previous, $new = ($output | Select-Object -Last 1).Trim() -split ' '

$sshArguments = Get-SshArguments
Write-Host "Resetting the test machine ..."
& "$PSScriptRoot\..\vm\Reset-TestVM.ps1" | Out-Null
$address = Get-TestVMAddress
Invoke-TestVMCommand -Address $address -Command 'rm -rf /tmp/release ~/cases.sh ~/sgc-test-*'
# Keeps Debian's own daily run from starting in the middle (see Test-Installer.ps1).
Invoke-TestVMCommand -Address $address -Command 'sudo systemctl stop apt-daily.timer apt-daily-upgrade.timer; sudo touch /var/lib/systemd/timers/stamp-apt-daily.timer /var/lib/systemd/timers/stamp-apt-daily-upgrade.timer'
& scp @sshArguments -q -r $releaseDir "${VmUser}@${address}:/tmp/release"
& scp @sshArguments -q "$PSScriptRoot\cases.sh" "${VmUser}@${address}:cases.sh"
if ($LASTEXITCODE -ne 0) { throw 'Copying the releases to the test machine failed.' }

$failed = 0
function Invoke-Cases {
    param([string]$Mode, [string]$Version, [string]$NewVersion = '')
    Write-Host ""
    Invoke-TestVMCommand -Address $script:address -Command "bash ~/cases.sh $Mode $Version $NewVersion"
    if ($LASTEXITCODE -ne 0) { $script:failed++ }
}

# The previous release, installed and set up as its owner would have it.
Invoke-Cases old-install $previous
Invoke-Cases update-setup $previous

# The update itself, carried out by the previous release's updater.
Invoke-Cases upgrade $previous $new

# The current version's features, on the machine that got here by updating.
Invoke-Cases firewall $new
Invoke-Cases ssh $new
# Updates for the device, the other way round from Test-Installer.ps1: set to
# install by themselves, and Debian's own daily run then does the installing.
Invoke-Cases os-updates-auto $new
Invoke-Cases dns $new
Invoke-Cases log2ram $new
Invoke-Cases restart $new

Write-Host ""
Write-Host "Waiting for the machine to go down and come back ..."
Wait-TestVMSshDown -Address $address
$address = Wait-TestVMSsh

Invoke-Cases after-restart $new
Invoke-Cases cli $new

Write-Host ""
if ($failed -gt 0) { throw "Upgrade test FAILED." }
Write-Host "Upgrade test passed: $previous updated itself to $new, and everything works on the updated machine."

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
       Then the firewall: an unconfirmed change undoes itself, a confirmed
       one stays, and from then on a public address is refused. And SSH: a
       key added in the page gets in; "keys only" undoes itself unless a
       login with a key is seen, and stays if one is.
    4. Points SGC at a local test update source and checks updating: a
       tampered update is refused, a genuine one installs, a signed but
       broken one is rolled back, an older one is never installed, and
       "sgc update" works over SSH.
    5. Makes an export, then restarts the machine through SGC and checks
       that everything comes back by itself, the firewall included. Then
       "sgc doctor", "sgc firewall off" and "sgc ssh allow-passwords"
       over SSH.
    6. Wipes the machine, installs again and restores the export: the
       account, the settings and the history must be what they were.

    The real release key is never involved. Requires the test machine from
    test/e2e/vm.
#>
[CmdletBinding()]
param()

. "$PSScriptRoot\..\vm\Common.ps1"

$repo        = (Resolve-Path "$PSScriptRoot\..\..\..").Path
$releaseDir  = Join-Path $StateDir 'test-release'
$carryDir    = Join-Path $StateDir 'test-carry'
$version     = (Get-Content (Join-Path $repo 'VERSION') -Raw).Trim()

# What has to survive the wipe in step 6: the export, its passphrase, the
# password of the account inside it, and the private half of the SSH key
# that is in the export (the owner's own computer keeps that one in real
# life). All throwaway values made by the test.
$carried = 'sgc-test-export.age', 'sgc-test-passphrase', 'sgc-test-password', 'sgc-test-ssh-key2'

Write-Host "Building a test release of $version ..."
wsl -d $WslDistro --exec bash (ConvertTo-WslPath "$PSScriptRoot\make-test-release.sh") (ConvertTo-WslPath $releaseDir)
if ($LASTEXITCODE -ne 0) { throw 'Building the test release failed.' }

$sshArguments = Get-SshArguments

function Reset-AndPrepare {
    # A clean machine with the test release and the test script on it.
    & "$PSScriptRoot\..\vm\Reset-TestVM.ps1" | Out-Null
    $script:address = Get-TestVMAddress
    Invoke-TestVMCommand -Address $script:address -Command 'rm -rf /tmp/release ~/cases.sh ~/sgc-test-*'
    # Debian installs its updates by itself once a day, and after a reset it
    # believes it has missed a day: within the hour it would start installing,
    # at a moment of its own choosing in the middle of the test. Its two
    # timers are stopped and marked as having just run. The test starts
    # Debian's daily run itself where it wants to see it.
    Invoke-TestVMCommand -Address $script:address -Command 'sudo systemctl stop apt-daily.timer apt-daily-upgrade.timer; sudo touch /var/lib/systemd/timers/stamp-apt-daily.timer /var/lib/systemd/timers/stamp-apt-daily-upgrade.timer'
    & scp @sshArguments -q -r $releaseDir "${VmUser}@${script:address}:/tmp/release"
    & scp @sshArguments -q "$PSScriptRoot\cases.sh" "${VmUser}@${script:address}:cases.sh"
    if ($LASTEXITCODE -ne 0) { throw 'Copying the test release to the test machine failed.' }
}

$failed = 0
function Invoke-Cases {
    param([string]$Mode)
    Write-Host ""
    Invoke-TestVMCommand -Address $script:address -Command "bash ~/cases.sh $Mode $version"
    if ($LASTEXITCODE -ne 0) { $script:failed++ }
}

Write-Host "Resetting the test machine ..."
Reset-AndPrepare

Invoke-Cases refused
Invoke-Cases accepted

# The firewall, switched on before the rest, so that everything after it
# (updating, exporting, restarting) is tested with the firewall on. Every
# later step also arrives over a new SSH connection, which is itself the
# check that SSH from this PC still gets in.
Invoke-Cases firewall

# SSH keys and "keys only", likewise before the rest. A change that waits for
# a login with a key must never be left waiting at the end of a step: the
# next step's own SSH connection would be that login.
Invoke-Cases ssh

# Updates for the device itself (Debian's packages): by hand first, which
# installs what the machine's image has waiting, then set to install by
# themselves, which is how the rest of the test finds it.
Invoke-Cases os-updates

# AdGuard Home, which the installer put there (a real download of the pinned
# release): answering, blocking, switched off and on, and let in by the
# firewall from inside only.
Invoke-Cases dns

# Logs in memory (log2ram), which the installer put there switched off:
# refused when the logs do not fit, then switched on. It takes effect at the
# restart further down, where after-restart looks at it in memory.
Invoke-Cases log2ram

# Updating: a tampered update, a genuine one, a signed-but-broken one that
# must roll back, an older one, and the command-line way.
Invoke-Cases update-setup
Invoke-Cases update-refused
Invoke-Cases update-good
Invoke-Cases update-broken
Invoke-Cases update-downgrade
Invoke-Cases update-cli

# An export of everything so far, taken off the machine.
Invoke-Cases export
if (Test-Path $carryDir) { Remove-Item -Recurse -Force $carryDir }
New-Item -ItemType Directory -Path $carryDir | Out-Null
foreach ($file in $carried) {
    & scp @sshArguments -q "${VmUser}@${address}:$file" (Join-Path $carryDir $file)
    if ($LASTEXITCODE -ne 0) { throw "Could not fetch $file from the test machine." }
}

# The maintenance window: SGC restarts the machine by itself. (The Restart
# button is tested by Test-UpgradeFromPrevious.ps1.)
Invoke-Cases maintenance

# The machine is now going down. Wait until it has actually stopped answering
# before waiting for it to come back.
Write-Host ""
Write-Host "Waiting for the machine to go down and come back ..."
Wait-TestVMSshDown -Address $address
$address = Wait-TestVMSsh

Invoke-Cases after-restart
Invoke-Cases after-window-restart

# The command line: the doctor, and switching the firewall off from the
# machine itself.
Invoke-Cases cli

# The promise of the export: wipe the machine, install again, restore.
Write-Host ""
Write-Host "Wiping the test machine ..."
Reset-AndPrepare
foreach ($file in $carried) {
    & scp @sshArguments -q (Join-Path $carryDir $file) "${VmUser}@${address}:$file"
    if ($LASTEXITCODE -ne 0) { throw "Could not copy $file to the test machine." }
}
Invoke-Cases restore

Remove-Item -Recurse -Force $carryDir

Write-Host ""
if ($failed -gt 0) { throw "Installer test FAILED." }
Write-Host "Installer test passed."

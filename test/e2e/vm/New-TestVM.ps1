<#
.SYNOPSIS
    Builds the Hyper-V test machine "sgc-test" from Debian's official cloud image.

.DESCRIPTION
    The test machine stands in for a freshly installed Debian server or
    Raspberry Pi. This script creates it from scratch:

      1. downloads and verifies the Debian 13 image (once; cached afterwards)
      2. creates the virtual machine with 2 CPU cores, 2 GB memory, 16 GB disk
      3. lets the machine set itself up: a user "tester" with passwordless
         sudo (as on Raspberry Pi OS) that accepts only the SSH key
      4. shuts it down, takes a checkpoint named "clean", and starts it again

    Reset-TestVM.ps1 returns the machine to that checkpoint in seconds.

    Requirements: Hyper-V, membership of the "Hyper-V Administrators" group,
    and a Debian WSL distribution with qemu-utils and cloud-image-utils.

.PARAMETER Force
    Delete an existing test machine and build a new one.
#>
[CmdletBinding()]
param([switch]$Force)

. "$PSScriptRoot\Common.ps1"

$existing = Get-OurVM
if ($existing) {
    if (-not $Force) {
        throw "The test machine already exists. Use Reset-TestVM.ps1 to return it to its clean state, or -Force to delete and rebuild it."
    }
    Write-Host "Removing the existing test machine ..."
    if ($existing.State -ne 'Off') { Stop-VM -Name $VmName -TurnOff -Force }
    Remove-VM -Name $VmName -Force
}

if (-not (Test-Path "$SshKey.pub")) {
    throw "SSH key not found at $SshKey. Create it with: ssh-keygen -t ed25519 -f `"$SshKey`""
}

$vmDir   = Join-Path (Get-VMHost).VirtualHardDiskPath $VmName
$disk    = Join-Path $vmDir "$VmName.vhdx"
$seedIso = Join-Path $vmDir 'seed.iso'

# --- 1. Image ---------------------------------------------------------------
New-Item -ItemType Directory -Force -Path $ImageDir | Out-Null
wsl -d $WslDistro --exec bash (ConvertTo-WslPath "$PSScriptRoot\fetch-image.sh") (ConvertTo-WslPath $ImageDir)
if ($LASTEXITCODE -ne 0) { throw 'Preparing the Debian image failed.' }

# --- 2. Disk ----------------------------------------------------------------
if (Test-Path $vmDir) { Remove-Item -Recurse -Force $vmDir }
New-Item -ItemType Directory -Path $vmDir | Out-Null
Copy-Item (Join-Path $ImageDir 'debian-13-generic-amd64.vhdx') $disk
# Hyper-V refuses disk files marked as sparse, which converted images can be.
fsutil sparse setflag $disk 0 | Out-Null
Resize-VHD -Path $disk -SizeBytes 16GB

# --- 3. First-boot instructions ---------------------------------------------
# Debian's image reads these from a small attached disc on first boot.
$publicKey = (Get-Content "$SshKey.pub" -Raw).Trim()
$userData = @"
#cloud-config
hostname: $VmName
users:
  - name: $VmUser
    gecos: SGC test user
    shell: /bin/bash
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    lock_passwd: true
    ssh_authorized_keys:
      - $publicKey
ssh_pwauth: false
"@
$metaData = "instance-id: $VmName-$(Get-Date -Format yyyyMMddHHmmss)`nlocal-hostname: $VmName`n"

# Linux needs these files without a byte-order mark and with Unix line endings.
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[IO.File]::WriteAllText((Join-Path $vmDir 'user-data'), ($userData -replace "`r`n", "`n") + "`n", $utf8NoBom)
[IO.File]::WriteAllText((Join-Path $vmDir 'meta-data'), $metaData, $utf8NoBom)

$wslVmDir = ConvertTo-WslPath $vmDir
wsl -d $WslDistro --exec cloud-localds "$wslVmDir/seed.iso" "$wslVmDir/user-data" "$wslVmDir/meta-data"
if ($LASTEXITCODE -ne 0) { throw 'Creating the first-boot disc failed.' }

# --- 4. Virtual machine -----------------------------------------------------
Write-Host "Creating the virtual machine ..."
New-VM -Name $VmName -Generation 2 -MemoryStartupBytes 2GB -VHDPath $disk -SwitchName 'Default Switch' | Out-Null
Set-VM -Name $VmName -Notes $VmMarker -ProcessorCount 2 -StaticMemory `
    -AutomaticCheckpointsEnabled $false -CheckpointType Standard `
    -AutomaticStartAction Nothing -AutomaticStopAction ShutDown
# Secure Boot is off to match the Raspberry Pi, which has none.
Set-VMFirmware -VMName $VmName -EnableSecureBoot Off
Add-VMDvdDrive -VMName $VmName -Path $seedIso

# --- 5. First boot ----------------------------------------------------------
if (Test-Path $KnownHosts) { Remove-Item $KnownHosts }
Start-VM -Name $VmName
Write-Host "Waiting for the machine to set itself up ..."
$address = Wait-TestVMSsh
Invoke-TestVMCommand -Address $address -Command 'cloud-init status --wait >/dev/null; cloud-init status'

# --- 6. Clean checkpoint ----------------------------------------------------
# Taken while the machine is off, so restoring it is a normal cold boot with
# a correct clock rather than a resume from frozen memory.
Write-Host "Taking the clean checkpoint ..."
Invoke-TestVMCommand -Address $address -Command 'sudo systemctl poweroff' 2>$null
Wait-TestVMOff
Checkpoint-VM -Name $VmName -SnapshotName $CheckpointName
Start-VM -Name $VmName
$address = Wait-TestVMSsh

Write-Host ""
Write-Host "Test machine ready at $address"
Write-Host "Connect with:  ssh -i `"$SshKey`" -o UserKnownHostsFile=`"$KnownHosts`" $VmUser@$address"

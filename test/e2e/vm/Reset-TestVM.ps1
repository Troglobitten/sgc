<#
.SYNOPSIS
    Returns the test machine "sgc-test" to its clean checkpoint and starts it.

.DESCRIPTION
    Use before every installer or hardening test, so each test starts from a
    freshly installed Debian. Everything done on the machine since the
    checkpoint is discarded.
#>
[CmdletBinding()]
param()

. "$PSScriptRoot\Common.ps1"

if (-not (Get-OurVM)) {
    throw "The test machine does not exist yet. Create it with New-TestVM.ps1."
}

Restore-VMCheckpoint -VMName $VmName -Name $CheckpointName -Confirm:$false
Start-VM -Name $VmName
$address = Wait-TestVMSsh

Write-Host "Test machine reset to clean and ready at $address"

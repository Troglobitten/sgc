# Shared settings and helpers for the test-machine scripts.
# Dot-source this file. It defines settings and functions and changes nothing by itself.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$VmName         = 'sgc-test'
$VmUser         = 'tester'
$CheckpointName = 'clean'
$WslDistro      = 'Debian'

# Written into the VM's notes. The scripts refuse to modify or delete any
# virtual machine that does not carry this marker, so a machine that merely
# shares the name can never be destroyed by accident.
$VmMarker = 'Managed by sgc/test/e2e/vm. Safe to delete and rebuild.'

# Everything the scripts keep outside the repository lives in these places.
$StateDir   = Join-Path $env:LOCALAPPDATA 'sgc-dev'
$ImageDir   = Join-Path $StateDir 'images'
$KnownHosts = Join-Path $StateDir 'known_hosts'
$SshKey     = Join-Path $env:USERPROFILE '.ssh\sgc-test'

function ConvertTo-WslPath {
    param([Parameter(Mandatory)][string]$WindowsPath)
    # --exec passes arguments straight to the program instead of through a
    # shell, so paths containing spaces arrive intact.
    $converted = wsl -d $WslDistro --exec wslpath -a ($WindowsPath -replace '\\', '/')
    if ($LASTEXITCODE -ne 0) { throw "Could not convert '$WindowsPath' to a WSL path." }
    return $converted.Trim()
}

function Get-OurVM {
    # Returns the test machine, $null if it does not exist, and throws if a
    # machine with that name exists but is not ours.
    $vm = Get-VM -Name $VmName -ErrorAction SilentlyContinue
    if ($vm -and $vm.Notes -ne $VmMarker) {
        throw "A virtual machine named '$VmName' exists but was not created by these scripts. Refusing to touch it."
    }
    return $vm
}

function Get-TestVMAddress {
    # The guest runs no Hyper-V guest services, so Hyper-V cannot report its
    # address. Instead, look up the machine's network card in this PC's
    # neighbour table, and fall back to the name the Default Switch gives it.
    $adapter = Get-VMNetworkAdapter -VMName $VmName
    if ($adapter.IPAddresses) {
        $reported = $adapter.IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1
        if ($reported) { return $reported }
    }

    $mac = ($adapter.MacAddress -replace '(..)(?!$)', '$1-')
    $neighbour = Get-NetNeighbor -LinkLayerAddress $mac -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.State -notin 'Unreachable', 'Incomplete' } |
        Select-Object -First 1
    if ($neighbour) { return $neighbour.IPAddress }

    try {
        $resolved = Resolve-DnsName -Name "$VmName.mshome.net" -Type A -DnsOnly -ErrorAction Stop |
            Where-Object { $_.Type -eq 'A' } | Select-Object -First 1
        if ($resolved) { return $resolved.IPAddress }
    } catch { }

    return $null
}

function Get-SshArguments {
    # A separate known_hosts file: the machine is rebuilt often, and its changing
    # host keys should not pile up in (or trigger warnings from) the user's own file.
    return @(
        '-i', $SshKey,
        '-o', 'IdentitiesOnly=yes',
        '-o', "UserKnownHostsFile=$KnownHosts",
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', 'BatchMode=yes',
        '-o', 'ConnectTimeout=5',
        '-o', 'LogLevel=ERROR'
    )
}

function Invoke-TestVMCommand {
    # Runs one command on the test machine and returns its output.
    param(
        [Parameter(Mandatory)][string]$Address,
        [Parameter(Mandatory)][string]$Command
    )
    $sshArguments = Get-SshArguments
    # Windows PowerShell strips double quotes from arguments it hands to other
    # programs, which silently corrupts shell commands. Sending the command
    # base64-encoded sidesteps quoting altogether.
    $unixText = $Command -replace "`r`n", "`n"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($unixText))
    & ssh @sshArguments "$VmUser@$Address" "echo $encoded | base64 -d | bash"
}

function Wait-TestVMSsh {
    # Waits until the machine answers over SSH and returns its address.
    param([int]$TimeoutSeconds = 240)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $address = Get-TestVMAddress
        if ($address) {
            $reply = Invoke-TestVMCommand -Address $address -Command 'echo ready' 2>$null
            if ($LASTEXITCODE -eq 0 -and $reply -eq 'ready') { return $address }
        }
        Start-Sleep -Seconds 3
    }
    throw "The test machine did not answer over SSH within $TimeoutSeconds seconds."
}

function Wait-TestVMOff {
    param([int]$TimeoutSeconds = 90)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if ((Get-VM -Name $VmName).State -eq 'Off') { return }
        Start-Sleep -Seconds 2
    }
    # A clean shutdown was asked for and did not happen; cut the power instead.
    Stop-VM -Name $VmName -TurnOff -Force
}

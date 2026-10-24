<#
    The short version of a whole-machine test on the screen: one line per
    step, with how long it took, and the failed checks when there are any.
    Everything else goes to a log file whose name is printed first.
    Dot-sourced by Test-Installer.ps1 and Test-UpgradeFromPrevious.ps1,
    after test/e2e/vm/Common.ps1.
#>

function Start-TestLog {
    param(
        [Parameter(Mandatory)][string]$Name,
        # The test script itself: its Invoke-Cases lines are counted, so
        # that the total stays right when a step is added.
        [Parameter(Mandatory)][string]$Script
    )
    $dir = Join-Path $StateDir 'logs'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $script:TestLog = Join-Path $dir ('{0}-{1}.log' -f $Name, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $script:TestStarted = Get-Date
    $script:StepNumber = 0
    $script:StepTotal = @(Select-String -Path $Script -Pattern '^\s*Invoke-Cases\s').Count
    New-Item -ItemType File -Force -Path $script:TestLog | Out-Null
    Write-Host "Full output: $script:TestLog"
}

function Format-Elapsed {
    param([datetime]$Since)
    $span = (Get-Date) - $Since
    if ($span.TotalMinutes -ge 1) { return '{0}m{1:00}s' -f [int][math]::Floor($span.TotalMinutes), $span.Seconds }
    return '{0}s' -f [int]$span.TotalSeconds
}

# Write-Log adds lines to the log only.
function Write-Log {
    param([Parameter(ValueFromPipeline)][object]$Line)
    process { Add-Content -Path $script:TestLog -Value ([string]$Line) -Encoding UTF8 }
}

# Invoke-Logged runs a program with all of its output in the log only, and
# returns its exit code. Common.ps1 makes errors stop the script, and Windows
# PowerShell turns every line a program writes to its error stream into one
# when the stream is redirected: here that is switched off for the program.
#
# A plain function on purpose, arguments taken from $args: with declared
# parameters PowerShell adds its own (-Debug, -Verbose, ...) and takes a
# program's "-d" for "-Debug" (it did, for wsl's -d).
function Invoke-Logged {
    $program, $arguments = $args
    $ErrorActionPreference = 'Continue'
    & $program @arguments 2>&1 | ForEach-Object { Write-Log "$_" }
    return $LASTEXITCODE
}

# Start-Phase and Stop-Phase put "what is happening ... done (time)" on one
# line, for the parts that are not steps (building, restarting, wiping).
function Start-Phase {
    param([string]$What)
    $script:PhaseStarted = Get-Date
    Write-Host -NoNewline ('        {0} ... ' -f $What)
    Write-Log "===== $What"
}

function Stop-Phase {
    Write-Host ('done ({0})' -f (Format-Elapsed $script:PhaseStarted))
}

# Invoke-Step runs one mode of cases.sh on the test machine and reports it in
# one line. Returns $true if every check of the step passed.
function Invoke-Step {
    param([string]$Address, [string]$Mode, [string]$Arguments)
    $script:StepNumber++
    $started = Get-Date
    Write-Host -NoNewline ('{0,-34}' -f ('[{0,2}/{1}] {2}' -f $script:StepNumber, $script:StepTotal, $Mode))
    # 2>&1 on the test machine: everything arrives as one stream, in order.
    $output = @(Invoke-TestVMCommand -Address $Address -Command "bash ~/cases.sh $Mode $Arguments 2>&1")
    $code = $LASTEXITCODE
    Write-Log "##### $Mode #####"
    $output | Write-Log
    if ($code -eq 0) {
        Write-Host ('passed  {0}' -f (Format-Elapsed $started))
        return $true
    }
    Write-Host ('FAILED  {0}' -f (Format-Elapsed $started)) -ForegroundColor Red
    $output | Where-Object { $_ -match '^\s+FAIL\s' } | ForEach-Object { Write-Host ('        {0}' -f $_.Trim()) -ForegroundColor Red }
    return $false
}

function Write-TestEnd {
    param([string]$Message, [bool]$Passed)
    Write-Host ''
    $line = '{0} (in {1})' -f $Message, (Format-Elapsed $script:TestStarted)
    if ($Passed) { Write-Host $line -ForegroundColor Green } else { Write-Host $line -ForegroundColor Red; Write-Host "Details: $script:TestLog" }
    Write-Log $line
}

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

$port = 8765
$pythonExe = Join-Path $projectRoot ".venv\Scripts\python.exe"
$outputDir = Join-Path $projectRoot "output"
$logPath = Join-Path $outputDir "start-admin.log"

if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

function Write-Log {
    param([string]$Message)
    Add-Content -Path $logPath -Value "$(Get-Date -Format s) $Message"
}

Write-Log "start-admin.ps1 invoked"

if (-not (Test-Path $pythonExe)) {
    Write-Log "python missing: $pythonExe"
    throw "Python executable not found: $pythonExe"
}

$listener = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($listener) {
    Write-Log "existing listener found on port ${port}; pid=$($listener.OwningProcess)"
    try {
        Stop-Process -Id $listener.OwningProcess -Force -ErrorAction Stop
        Start-Sleep -Seconds 1
        Write-Log "stopped existing pid=$($listener.OwningProcess)"
    }
    catch {
        Write-Log "failed to stop pid=$($listener.OwningProcess); $($_.Exception.Message)"
        Write-Warning "Failed to stop process $($listener.OwningProcess) on port ${port}: $($_.Exception.Message)"
    }
}
else {
    Write-Log "no existing listener on port $port"
}

$env:STORAGECHECK_PORT = "$port"
$process = Start-Process -WorkingDirectory $projectRoot -FilePath $pythonExe -ArgumentList "start.py" -PassThru
Write-Log "started new process pid=$($process.Id)"

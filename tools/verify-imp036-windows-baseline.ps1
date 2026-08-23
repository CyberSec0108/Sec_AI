[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$projectRoot = Split-Path -Parent $PSScriptRoot
$runtimeRoot = Join-Path $projectRoot "runtime"
$venvRoot = Join-Path $runtimeRoot "imp036-collector-venv"
$pythonPath = Join-Path $venvRoot "Scripts\python.exe"
$embeddedPython = Join-Path $runtimeRoot "imp034-python3146\python.exe"
$lockedSitePackages = Join-Path $runtimeRoot "imp029-collector-venv\Lib\site-packages"
$useEmbeddedRuntime = (
    (Test-Path -LiteralPath $embeddedPython -PathType Leaf) -and
    (Test-Path -LiteralPath $lockedSitePackages -PathType Container)
)
if ($useEmbeddedRuntime) {
    $pythonPath = $embeddedPython
} elseif (-not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) {
    New-Item -ItemType Directory -Path $runtimeRoot -Force | Out-Null
    if (Test-Path -LiteralPath $embeddedPython -PathType Leaf) {
        & $embeddedPython -m venv --clear $venvRoot
    } else {
        & py -3.14 -m venv --clear $venvRoot
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to create the locked Windows Collector environment."
    }
    & $pythonPath -m pip install `
        --disable-pip-version-check `
        --require-hashes `
        -r (Join-Path $projectRoot "requirements\lock\collector.lock")
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to install the locked Windows Collector dependencies."
    }
}
$previousPythonPath = $env:PYTHONPATH
$previousPythonUtf8 = $env:PYTHONUTF8
try {
    $sourceRoot = Join-Path $projectRoot "src"
    $env:PYTHONPATH = if ($useEmbeddedRuntime) {
        "$sourceRoot;$lockedSitePackages"
    } else {
        $sourceRoot
    }
    $env:PYTHONUTF8 = "1"
    $composeFiles = @(
        (Join-Path $projectRoot "deploy\compose\compose.yml"),
        (Join-Path $projectRoot "deploy\compose\compose.dev.yml")
    )
    $composeArguments = @("--project-directory", $projectRoot)
    foreach ($composeFile in $composeFiles) {
        $composeArguments += @("-f", $composeFile)
    }
    $dockerOutput = @(& docker compose @composeArguments ps -a --format json)
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read Docker Core status."
    }
    $expectedServices = @(
        "postgres", "redis", "aistor", "clamav",
        "api", "worker", "scheduler", "gateway"
    )
    $dockerStatus = @(
        foreach ($line in $dockerOutput) {
            $row = $line | ConvertFrom-Json
            if ($row.Service -in $expectedServices) {
                [ordered]@{
                    service = [string]$row.Service
                    running = ([string]$row.State -eq "running")
                    healthy = ([string]$row.Health -eq "healthy")
                }
            }
        }
    )
    $dockerStatusPath = Join-Path $runtimeRoot "imp036-docker-status.json"
    [System.IO.File]::WriteAllText(
        $dockerStatusPath,
        ($dockerStatus | ConvertTo-Json -Depth 3),
        [System.Text.UTF8Encoding]::new($false)
    )
    & $pythonPath `
        (Join-Path $PSScriptRoot "verify_imp036_windows_baseline.py") `
        $dockerStatusPath
    if ($LASTEXITCODE -ne 0) {
        throw "IMP-036 Windows baseline verification failed."
    }
} finally {
    $env:PYTHONPATH = $previousPythonPath
    $env:PYTHONUTF8 = $previousPythonUtf8
}

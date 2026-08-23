[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$projectRoot = Split-Path -Parent $PSScriptRoot
$runtimeRoot = Join-Path $projectRoot "runtime"
$venvRoot = Join-Path $runtimeRoot "imp029-collector-venv"
$pythonPath = Join-Path $venvRoot "Scripts\python.exe"
if (-not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) {
    New-Item -ItemType Directory -Path $runtimeRoot -Force | Out-Null
    & py -3.14 -m venv $venvRoot
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
    $env:PYTHONPATH = Join-Path $projectRoot "src"
    $env:PYTHONUTF8 = "1"
    & $pythonPath (Join-Path $PSScriptRoot "verify_imp030_windows_safety.py")
    if ($LASTEXITCODE -ne 0) {
        throw "IMP-030 Windows safety verification failed."
    }
} finally {
    $env:PYTHONPATH = $previousPythonPath
    $env:PYTHONUTF8 = $previousPythonUtf8
}

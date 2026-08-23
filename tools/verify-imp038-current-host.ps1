[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$projectRoot = Split-Path -Parent $PSScriptRoot
$runtimeRoot = Join-Path $projectRoot "runtime"
$administratorEvidence = Join-Path $runtimeRoot "imp037-administrator-evidence.json"
$pythonPath = Join-Path $runtimeRoot "imp034-python3146\python.exe"
$lockedSitePackages = Join-Path $runtimeRoot "imp029-collector-venv\Lib\site-packages"
if (
    -not (Test-Path -LiteralPath $pythonPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $lockedSitePackages -PathType Container) -or
    -not (Test-Path -LiteralPath $administratorEvidence -PathType Leaf)
) {
    throw "The locked runtime or prior consented administrator evidence is unavailable."
}

$previousPythonPath = $env:PYTHONPATH
$previousPythonUtf8 = $env:PYTHONUTF8
try {
    $env:PYTHONPATH = (
        (Join-Path $projectRoot "src") + ";" + $lockedSitePackages
    )
    $env:PYTHONUTF8 = "1"
    & $pythonPath `
        (Join-Path $PSScriptRoot "verify_imp038_current_host.py") `
        $administratorEvidence `
        "-"
    if ($LASTEXITCODE -ne 0) {
        throw "IMP-038 current-host regression failed."
    }
} finally {
    $env:PYTHONPATH = $previousPythonPath
    $env:PYTHONUTF8 = $previousPythonUtf8
}

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$runtimeRoot = Join-Path $projectRoot "runtime"
$pythonPath = Join-Path $runtimeRoot "imp034-python3146\python.exe"
$lockedSitePackages = Join-Path $runtimeRoot "imp029-collector-venv\Lib\site-packages"
if (
    -not (Test-Path -LiteralPath $pythonPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $lockedSitePackages -PathType Container)
) {
    throw "The locked Windows Collector runtime is unavailable."
}

$previousPythonPath = $env:PYTHONPATH
$previousPythonUtf8 = $env:PYTHONUTF8
try {
    $env:PYTHONPATH = (
        (Join-Path $projectRoot "src") + ";" + $lockedSitePackages
    )
    $env:PYTHONUTF8 = "1"
    & $pythonPath (Join-Path $PSScriptRoot "verify_imp042_result_guidance.py")
    if ($LASTEXITCODE -ne 0) {
        throw "IMP-042 result guidance verification failed."
    }
}
finally {
    $env:PYTHONPATH = $previousPythonPath
    $env:PYTHONUTF8 = $previousPythonUtf8
}

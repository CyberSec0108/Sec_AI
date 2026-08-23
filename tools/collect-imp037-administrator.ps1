[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [switch]$ConsentToReadAdministratorItems,
    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole(
    [System.Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    throw "An already-elevated administrator process is required."
}
if (-not $ConsentToReadAdministratorItems) {
    throw "Explicit consent is required."
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$runtimeRoot = Join-Path $projectRoot "runtime"
$pythonPath = Join-Path $runtimeRoot "imp034-python3146\python.exe"
$lockedSitePackages = Join-Path $runtimeRoot "imp029-collector-venv\Lib\site-packages"
if (
    -not (Test-Path -LiteralPath $pythonPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $lockedSitePackages -PathType Container)
) {
    throw "The locked Windows Collector runtime is unavailable."
}
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputPath)
$resolvedRuntime = [System.IO.Path]::GetFullPath($runtimeRoot)
if (-not $resolvedOutput.StartsWith(
    $resolvedRuntime + [System.IO.Path]::DirectorySeparatorChar,
    [System.StringComparison]::OrdinalIgnoreCase
)) {
    throw "Administrator evidence must remain inside project runtime."
}

$previousPythonPath = $env:PYTHONPATH
$previousPythonUtf8 = $env:PYTHONUTF8
try {
    $env:PYTHONPATH = (
        (Join-Path $projectRoot "src") + ";" + $lockedSitePackages
    )
    $env:PYTHONUTF8 = "1"
    & $pythonPath `
        (Join-Path $PSScriptRoot "collect_imp037_administrator.py") `
        $resolvedOutput
    if ($LASTEXITCODE -ne 0) {
        throw "IMP-037 administrator collection failed."
    }
} finally {
    $env:PYTHONPATH = $previousPythonPath
    $env:PYTHONUTF8 = $previousPythonUtf8
}

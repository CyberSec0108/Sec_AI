[CmdletBinding()]
param(
    [switch]$ConsentToAdministratorCollection
)

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$projectRoot = Split-Path -Parent $PSScriptRoot
$runtimeRoot = Join-Path $projectRoot "runtime"
$administratorEvidence = Join-Path $runtimeRoot "imp037-administrator-evidence.json"
$pythonPath = Join-Path $runtimeRoot "imp034-python3146\python.exe"
$lockedSitePackages = Join-Path $runtimeRoot "imp029-collector-venv\Lib\site-packages"
if (
    -not (Test-Path -LiteralPath $pythonPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $lockedSitePackages -PathType Container)
) {
    throw "The locked Windows Collector runtime is unavailable."
}

if (-not $ConsentToAdministratorCollection) {
    throw @"
Administrator collection was not started. Re-run with
-ConsentToAdministratorCollection after reviewing these five read-only items:
PC-02 password policy, PC-04 SMB shares, PC-06 installed programs,
PC-08 boot entries, PC-10 Windows update history.
"@
}

New-Item -ItemType Directory -Path $runtimeRoot -Force | Out-Null
$administratorScript = Join-Path $PSScriptRoot "collect-imp037-administrator.ps1"
$arguments = @(
    "-NoLogo",
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", "`"$administratorScript`"",
    "-ConsentToReadAdministratorItems",
    "-OutputPath", "`"$administratorEvidence`""
)
$process = Start-Process `
    -FilePath "powershell.exe" `
    -Verb RunAs `
    -ArgumentList $arguments `
    -Wait `
    -PassThru
if ($process.ExitCode -ne 0) {
    throw "Administrator collection was cancelled or failed."
}
if (-not (Test-Path -LiteralPath $administratorEvidence -PathType Leaf)) {
    throw "Administrator evidence was not produced."
}

$previousPythonPath = $env:PYTHONPATH
$previousPythonUtf8 = $env:PYTHONUTF8
try {
    $env:PYTHONPATH = (
        (Join-Path $projectRoot "src") + ";" + $lockedSitePackages
    )
    $env:PYTHONUTF8 = "1"
    & $pythonPath `
        (Join-Path $PSScriptRoot "verify_imp037_windows_collection.py") `
        $administratorEvidence
    if ($LASTEXITCODE -ne 0) {
        throw "IMP-037 Windows collection verification failed."
    }
} finally {
    $env:PYTHONPATH = $previousPythonPath
    $env:PYTHONUTF8 = $previousPythonUtf8
}

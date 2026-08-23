[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$ComposeFiles = @(
    (Join-Path $ProjectRoot "deploy\compose\compose.yml"),
    (Join-Path $ProjectRoot "deploy\compose\compose.dev.yml")
)
$FileArguments = @()
foreach ($ComposeFile in $ComposeFiles) {
    $FileArguments += @("-f", $ComposeFile)
}

Write-Host "[IMP-020] Core readiness"
& (Join-Path $PSScriptRoot "core.ps1") -Action Health
if ($LASTEXITCODE -ne 0) {
    throw "Core readiness verification failed."
}

Write-Host "[IMP-020] PASS / FAIL / ERROR / tamper / replay demonstration"
& docker compose --project-directory $ProjectRoot @FileArguments `
    exec -T api python database/verification/verify_imp020.py
if ($LASTEXITCODE -ne 0) {
    throw "IMP-020 demonstration verification failed."
}

Write-Host "[IMP-020] Package-to-Finding verification completed; demo Web UI is retired."

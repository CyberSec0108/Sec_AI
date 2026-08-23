[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$composeFiles = @(
    (Join-Path $projectRoot "deploy\compose\compose.yml"),
    (Join-Path $projectRoot "deploy\compose\compose.dev.yml")
)
$fileArguments = @()
foreach ($composeFile in $composeFiles) {
    $fileArguments += @("-f", $composeFile)
}

& docker compose `
    --project-directory $projectRoot `
    @fileArguments `
    run `
    --rm `
    dev-tools `
    tools/verify_imp032_online_submission.py
if ($LASTEXITCODE -ne 0) {
    throw "IMP-032 online submission verification failed."
}


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

& docker compose `
    --project-directory $ProjectRoot `
    @FileArguments `
    run --rm --no-deps api database/verification/verify_imp049.py
if ($LASTEXITCODE -ne 0) {
    throw "IMP-049 actual PostgreSQL evaluation failed."
}

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$ComposeFiles = @(
    (Join-Path $ProjectRoot "deploy\compose\compose.yml"),
    (Join-Path $ProjectRoot "deploy\compose\compose.dev.yml")
)
$FileArguments = @("--project-directory", $ProjectRoot)
foreach ($ComposeFile in $ComposeFiles) {
    $FileArguments += @("-f", $ComposeFile)
}

& docker compose @FileArguments run --rm dev-tools `
    "tools/verify_imp047_guide_source.py"
if ($LASTEXITCODE -ne 0) {
    throw "IMP-047 Guide source verification failed."
}

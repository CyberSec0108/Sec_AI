[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$ComposeFiles = @(
    (Join-Path $ProjectRoot "deploy\compose\compose.yml"),
    (Join-Path $ProjectRoot "deploy\compose\compose.dev.yml")
)
$arguments = @("--project-directory", $ProjectRoot)
foreach ($composeFile in $ComposeFiles) {
    $arguments += @("-f", $composeFile)
}
$arguments += @(
    "exec",
    "-T",
    "model-gateway",
    "python",
    "-m",
    "apps.model_gateway.verify_runtime"
)

& docker compose @arguments
if ($LASTEXITCODE -ne 0) {
    throw "IMP-050 model gateway verification failed."
}

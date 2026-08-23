[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$ComposeFiles = @(
    (Join-Path $ProjectRoot "deploy\compose\compose.yml"),
    (Join-Path $ProjectRoot "deploy\compose\compose.dev.yml")
)

function Invoke-Compose {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    $FileArguments = @()
    foreach ($ComposeFile in $ComposeFiles) {
        $FileArguments += @("-f", $ComposeFile)
    }
    & docker compose --project-directory $ProjectRoot @FileArguments @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose failed with exit code $LASTEXITCODE"
    }
}

Invoke-Compose -Arguments @("--profile", "tools", "run", "--rm", "migrate")
Invoke-Compose -Arguments @(
    "run", "--rm", "--no-deps",
    "api", "database/verification/verify_imp048.py"
)

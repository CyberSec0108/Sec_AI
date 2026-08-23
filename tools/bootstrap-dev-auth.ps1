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
        throw "Docker Compose command failed with exit code $LASTEXITCODE."
    }
}

& (Join-Path $PSScriptRoot "init-dev-secrets.ps1")
Invoke-Compose -Arguments @("--profile", "tools", "run", "--rm", "migrate")
Invoke-Compose -Arguments @("run", "--rm", "api", "-m", "apps.api.auth_bootstrap")

Write-Host "DEV-LOCAL login is ready."
Write-Host "Username: local-owner"
Write-Host "Password and MFA code remain in the ACL-protected runtime\dev-secrets directory."
Write-Host "Open only the canonical development address: http://localhost:18480/auth/login"

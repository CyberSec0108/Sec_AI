[CmdletBinding()]
param(
    [ValidateSet("Start", "Status", "Open", "Stop")]
    [string]$Action = "Start"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$ComposeFiles = @(
    (Join-Path $ProjectRoot "deploy\compose\compose.yml"),
    (Join-Path $ProjectRoot "deploy\compose\compose.dev.yml")
)
$AdminUrl = "http://127.0.0.1:18490"

function Invoke-Compose {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    $FileArguments = @()
    foreach ($ComposeFile in $ComposeFiles) {
        $FileArguments += @("-f", $ComposeFile)
    }
    & docker compose `
        --project-directory $ProjectRoot `
        @FileArguments `
        --profile admin-tools `
        @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose failed with exit code $LASTEXITCODE"
    }
}

switch ($Action) {
    "Start" {
        & (Join-Path $PSScriptRoot "init-dev-secrets.ps1")
        Invoke-Compose @("up", "-d", "--build", "postgres")
        Invoke-Compose @("--profile", "tools", "run", "--rm", "--build", "migrate")
        Invoke-Compose @("up", "-d", "--build", "pgadmin")
        for ($Attempt = 0; $Attempt -lt 30; $Attempt++) {
            try {
                $Ping = Invoke-WebRequest `
                    -Uri "$AdminUrl/misc/ping" `
                    -UseBasicParsing `
                    -TimeoutSec 2
                if ($Ping.StatusCode -eq 200) {
                    break
                }
            } catch {
                Start-Sleep -Seconds 1
            }
        }
        Write-Host "pgAdmin: $AdminUrl"
        Write-Host "Login ID: admin@secai.dev"
        Write-Host "pgAdmin password file: runtime\dev-secrets\pgadmin_default_password"
        Write-Host "Database password file: runtime\dev-secrets\postgres_db_admin_password"
        Start-Process $AdminUrl
    }
    "Status" {
        Invoke-Compose @("ps", "postgres", "pgadmin")
    }
    "Open" {
        Start-Process $AdminUrl
    }
    "Stop" {
        Invoke-Compose @("stop", "pgadmin")
    }
}

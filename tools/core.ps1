[CmdletBinding()]
param(
    [ValidateSet("Init", "Config", "Build", "Up", "UpWithoutAIStor", "Status", "Health", "Restart", "Logs", "Down")]
    [string]$Action = "Status",
    [string]$AIStorLicensePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$ComposeFiles = @(
    (Join-Path $ProjectRoot "deploy\compose\compose.yml"),
    (Join-Path $ProjectRoot "deploy\compose\compose.dev.yml")
)
$SecretsRoot = Join-Path $ProjectRoot "runtime\dev-secrets"
$CoreServices = @(
    "postgres",
    "redis",
    "clamav",
    "api",
    "worker",
    "maintenance-worker",
    "scheduler",
    "gateway"
)
$ProjectImages = @(
    "gateway",
    "api",
    "worker",
    "maintenance-worker",
    "scheduler",
    "model-gateway",
    "postgres",
    "redis",
    "aistor",
    "clamav",
    "pgadmin"
)

function Invoke-DockerCompose {
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

function Assert-DevelopmentSecrets {
    param([switch]$RequireAIStorLicense)

    $Required = @(
        "postgres_password",
        "postgres_runtime_password",
        "postgres_db_admin_password",
        "pgadmin_default_password",
        "demo_csrf_token",
        "auth_session_index_key",
        "auth_dev_password",
        "auth_dev_mfa_code",
        "redis_password",
        "redis_users.acl",
        "aistor_root_user",
        "aistor_root_password"
    )
    if ($RequireAIStorLicense) {
        $Required += "minio.license"
    }
    $Missing = @(
        foreach ($FileName in $Required) {
            $Path = Join-Path $SecretsRoot $FileName
            if (-not (Test-Path -LiteralPath $Path -PathType Leaf) -or (Get-Item -LiteralPath $Path).Length -eq 0) {
                $FileName
            }
        }
    )
    if ($Missing.Count -gt 0) {
        throw "Missing development secret files: $($Missing -join ', '). Run tools\core.ps1 -Action Init first."
    }
}

switch ($Action) {
    "Init" {
        $InitScript = Join-Path $PSScriptRoot "init-dev-secrets.ps1"
        & $InitScript -AIStorLicensePath $AIStorLicensePath
    }
    "Config" {
        Invoke-DockerCompose -Arguments @("config")
    }
    "Build" {
        Invoke-DockerCompose -Arguments (@("build") + $ProjectImages)
    }
    "Up" {
        Assert-DevelopmentSecrets
        Invoke-DockerCompose -Arguments @("up", "-d", "--build", "postgres")
        Invoke-DockerCompose -Arguments @("run", "--rm", "--build", "migrate")
        Invoke-DockerCompose -Arguments @(
            "run", "--rm", "--build", "--no-deps",
            "api", "-m", "apps.api.auth_bootstrap"
        )
        Invoke-DockerCompose -Arguments @("up", "-d", "--build")
    }
    "UpWithoutAIStor" {
        Assert-DevelopmentSecrets
        Invoke-DockerCompose -Arguments @("up", "-d", "--build", "postgres")
        Invoke-DockerCompose -Arguments @("run", "--rm", "--build", "migrate")
        Invoke-DockerCompose -Arguments @(
            "run", "--rm", "--build", "--no-deps",
            "api", "-m", "apps.api.auth_bootstrap"
        )
        Invoke-DockerCompose -Arguments (@("up", "-d", "--build") + $CoreServices)
    }
    "Status" {
        Invoke-DockerCompose -Arguments @("ps", "-a")
    }
    "Health" {
        & curl.exe --silent --show-error --fail "http://127.0.0.1:18480/health/live"
        if ($LASTEXITCODE -ne 0) {
            throw "Gateway live check failed."
        }
        Write-Host ""
        & curl.exe --silent --show-error "http://127.0.0.1:18480/health/ready"
        Write-Host ""
    }
    "Restart" {
        Invoke-DockerCompose -Arguments @("restart")
    }
    "Logs" {
        Invoke-DockerCompose -Arguments @("logs", "--tail", "200")
    }
    "Down" {
        Invoke-DockerCompose -Arguments @("down", "--remove-orphans")
    }
}

[CmdletBinding()]
param(
    [ValidateSet("Build", "Config", "Version", "Test", "Schema", "Lint", "Type", "All", "Shell")]
    [string]$Action = "All"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$ComposeFiles = @(
    (Join-Path $ProjectRoot "deploy\compose\compose.yml"),
    (Join-Path $ProjectRoot "deploy\compose\compose.dev.yml")
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

function Invoke-DevTool {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    Invoke-DockerCompose -Arguments (@("run", "--rm", "dev-tools") + $Arguments)
}

function Invoke-SelectedAction {
    param([Parameter(Mandatory = $true)][string]$SelectedAction)

    switch ($SelectedAction) {
        "Build" {
            Invoke-DockerCompose -Arguments @("build", "dev-tools")
        }
        "Config" {
            Invoke-DockerCompose -Arguments @("config")
        }
        "Version" {
            Invoke-DevTool -Arguments @("--version")
        }
        "Test" {
            Invoke-DevTool -Arguments @("-m", "pytest", "tests/unit", "tests/contract")
        }
        "Schema" {
            Invoke-DevTool -Arguments @("database/schemas/validate_examples.py")
        }
        "Lint" {
            Invoke-DevTool -Arguments @("-m", "ruff", "check", ".")
        }
        "Type" {
            Invoke-DevTool -Arguments @("-m", "mypy", "src", "apps", "tests")
        }
        "Shell" {
            Invoke-DockerCompose -Arguments @(
                "run", "--rm", "--entrypoint", "/bin/sh", "dev-tools"
            )
        }
        default {
            throw "Unsupported action: $SelectedAction"
        }
    }
}

if ($Action -eq "All") {
    foreach ($Step in @("Config", "Version", "Test", "Schema", "Lint", "Type")) {
        Write-Host "[Sec_AI] $Step"
        Invoke-SelectedAction -SelectedAction $Step
    }
} else {
    Invoke-SelectedAction -SelectedAction $Action
}

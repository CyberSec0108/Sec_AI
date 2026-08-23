[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SourceEnvironmentFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$SourcePath = [System.IO.Path]::GetFullPath($SourceEnvironmentFile)
$SecretRoot = Join-Path $ProjectRoot "runtime\dev-secrets"
$TargetEnvironment = Join-Path $ProjectRoot ".env"

function ConvertFrom-DotEnvValue {
    param([Parameter(Mandatory = $true)][string]$Value)

    $trimmed = $Value.Trim()
    if ($trimmed.Length -ge 2) {
        $first = $trimmed[0]
        $last = $trimmed[$trimmed.Length - 1]
        if (($first -eq '"' -and $last -eq '"') -or
            ($first -eq "'" -and $last -eq "'")) {
            return $trimmed.Substring(1, $trimmed.Length - 2)
        }
    }
    return $trimmed
}

if (-not (Test-Path -LiteralPath $SourcePath -PathType Leaf)) {
    throw "Source environment file was not found."
}

$sourceValues = @{}
foreach ($line in Get-Content -LiteralPath $SourcePath) {
    if ($line -match "^\s*#" -or $line -notmatch "=") {
        continue
    }
    $parts = $line -split "=", 2
    $sourceValues[$parts[0].Trim()] = ConvertFrom-DotEnvValue $parts[1]
}

foreach ($required in @("DEEPSEEK_API_BASE", "DEEPSEEK_API_KEY", "MODEL_NAME")) {
    if (-not $sourceValues.ContainsKey($required) -or
        [string]::IsNullOrWhiteSpace([string]$sourceValues[$required])) {
        throw "Required LLM setting is missing: $required"
    }
}

New-Item -ItemType Directory -Path $SecretRoot -Force | Out-Null

$apiKeyPath = Join-Path $SecretRoot "llm_api_key"
[System.IO.File]::WriteAllText(
    $apiKeyPath,
    [string]$sourceValues["DEEPSEEK_API_KEY"],
    [System.Text.UTF8Encoding]::new($false)
)

$gatewayTokenPath = Join-Path $SecretRoot "model_gateway_token"
if (-not (Test-Path -LiteralPath $gatewayTokenPath -PathType Leaf)) {
    $bytes = [byte[]]::new(32)
    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $random.GetBytes($bytes)
    } finally {
        $random.Dispose()
    }
    $token = [Convert]::ToBase64String($bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
    [System.IO.File]::WriteAllText(
        $gatewayTokenPath,
        $token,
        [System.Text.UTF8Encoding]::new($false)
    )
}

$targetValues = [ordered]@{
    "SECAI_LLM_API_BASE" = [string]$sourceValues["DEEPSEEK_API_BASE"]
    "SECAI_LLM_MODEL" = [string]$sourceValues["MODEL_NAME"]
    "SECAI_LLM_REASONING_EFFORT" = if ($sourceValues.ContainsKey("DEEPSEEK_REASONING_EFFORT")) {
        [string]$sourceValues["DEEPSEEK_REASONING_EFFORT"]
    } else {
        "low"
    }
    "SECAI_LLM_REQUEST_TIMEOUT_SECONDS" = if ($sourceValues.ContainsKey("LLM_REQUEST_TIMEOUT")) {
        [string]$sourceValues["LLM_REQUEST_TIMEOUT"]
    } else {
        "120"
    }
}

$lines = [System.Collections.Generic.List[string]]::new()
if (Test-Path -LiteralPath $TargetEnvironment -PathType Leaf) {
    foreach ($existingLine in Get-Content -LiteralPath $TargetEnvironment) {
        $lines.Add($existingLine)
    }
}

foreach ($entry in $targetValues.GetEnumerator()) {
    $prefix = "$($entry.Key)="
    $found = $false
    for ($index = 0; $index -lt $lines.Count; $index++) {
        if ($lines[$index].StartsWith($prefix, [System.StringComparison]::Ordinal)) {
            $lines[$index] = "$prefix$($entry.Value)"
            $found = $true
            break
        }
    }
    if (-not $found) {
        $lines.Add("$prefix$($entry.Value)")
    }
}

[System.IO.File]::WriteAllLines(
    $TargetEnvironment,
    $lines,
    [System.Text.UTF8Encoding]::new($false)
)

[pscustomobject]@{
    Imported = $true
    ApiBase = $targetValues["SECAI_LLM_API_BASE"]
    Model = $targetValues["SECAI_LLM_MODEL"]
    ReasoningEffort = $targetValues["SECAI_LLM_REASONING_EFFORT"]
    RequestTimeoutSeconds = $targetValues["SECAI_LLM_REQUEST_TIMEOUT_SECONDS"]
    ApiKey = "[REDACTED]"
    GatewayToken = "[GENERATED_OR_PRESERVED]"
}

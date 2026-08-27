[CmdletBinding()]
param(
    [string]$AIStorLicensePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$SecretsRoot = Join-Path $ProjectRoot "runtime\dev-secrets"
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function New-RandomSecret {
    param([int]$ByteCount = 32)

    $Bytes = New-Object byte[] $ByteCount
    $Generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $Generator.GetBytes($Bytes)
    } finally {
        $Generator.Dispose()
    }
    return [Convert]::ToBase64String($Bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

function Write-NewSecret {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Value
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        [System.IO.File]::WriteAllText($Path, $Value, $Utf8NoBom)
    }
}

New-Item -ItemType Directory -Force -Path $SecretsRoot | Out-Null

$PostgresPasswordPath = Join-Path $SecretsRoot "postgres_password"
$PostgresRuntimePasswordPath = Join-Path $SecretsRoot "postgres_runtime_password"
$PostgresDbAdminPasswordPath = Join-Path $SecretsRoot "postgres_db_admin_password"
$PgAdminDefaultPasswordPath = Join-Path $SecretsRoot "pgadmin_default_password"
$DemoCsrfTokenPath = Join-Path $SecretsRoot "demo_csrf_token"
$AuthSessionIndexKeyPath = Join-Path $SecretsRoot "auth_session_index_key"
$AuthDevPasswordPath = Join-Path $SecretsRoot "auth_dev_password"
$AuthDevMfaCodePath = Join-Path $SecretsRoot "auth_dev_mfa_code"
$RedisPasswordPath = Join-Path $SecretsRoot "redis_password"
$RedisAclPath = Join-Path $SecretsRoot "redis_users.acl"
$AIStorUserPath = Join-Path $SecretsRoot "aistor_root_user"
$AIStorPasswordPath = Join-Path $SecretsRoot "aistor_root_password"
$AIStorLicenseTarget = Join-Path $SecretsRoot "minio.license"
$ScanSidecarSigningKeyPath = Join-Path $SecretsRoot "scan_sidecar_signing_key"

Write-NewSecret -Path $PostgresPasswordPath -Value (New-RandomSecret)
Write-NewSecret -Path $PostgresRuntimePasswordPath -Value (New-RandomSecret)
Write-NewSecret -Path $PostgresDbAdminPasswordPath -Value (New-RandomSecret)
Write-NewSecret -Path $PgAdminDefaultPasswordPath -Value ("Pg1!" + (New-RandomSecret))
Write-NewSecret -Path $DemoCsrfTokenPath -Value (New-RandomSecret)
# 사이드카 서명용 Ed25519 seed입니다. 바꾸면 배포된 실행 파일이 사이드카를 거부합니다.
Write-NewSecret -Path $ScanSidecarSigningKeyPath -Value (New-RandomSecret)
Write-NewSecret -Path $AuthSessionIndexKeyPath -Value (New-RandomSecret)
Write-NewSecret -Path $AuthDevPasswordPath -Value ("Sa1!" + (New-RandomSecret))
if (-not (Test-Path -LiteralPath $AuthDevMfaCodePath)) {
    $MfaBytes = New-Object byte[] 4
    $MfaGenerator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $MfaGenerator.GetBytes($MfaBytes)
    } finally {
        $MfaGenerator.Dispose()
    }
    $MfaNumber = [BitConverter]::ToUInt32($MfaBytes, 0) % 1000000
    [System.IO.File]::WriteAllText(
        $AuthDevMfaCodePath,
        $MfaNumber.ToString("D6"),
        $Utf8NoBom
    )
}
Write-NewSecret -Path $RedisPasswordPath -Value (New-RandomSecret)
Write-NewSecret -Path $AIStorUserPath -Value ("secai_dev_" + (New-RandomSecret -ByteCount 9))
Write-NewSecret -Path $AIStorPasswordPath -Value (New-RandomSecret)

$RedisPassword = [System.IO.File]::ReadAllText($RedisPasswordPath, $Utf8NoBom).Trim()
$RedisAcl = @(
    "user default off",
    "user secai_celery on >$RedisPassword ~* +@all -flushall -flushdb -config -module -debug -shutdown"
) -join [Environment]::NewLine
[System.IO.File]::WriteAllText($RedisAclPath, $RedisAcl, $Utf8NoBom)

if (-not [string]::IsNullOrWhiteSpace($AIStorLicensePath)) {
    $ResolvedLicense = [System.IO.Path]::GetFullPath($AIStorLicensePath)
    if (-not (Test-Path -LiteralPath $ResolvedLicense -PathType Leaf)) {
        throw "AIStor license file does not exist: $ResolvedLicense"
    }
    if ((Get-Item -LiteralPath $ResolvedLicense).Length -eq 0) {
        throw "AIStor license file is empty: $ResolvedLicense"
    }
    [System.IO.File]::WriteAllBytes(
        $AIStorLicenseTarget,
        [System.IO.File]::ReadAllBytes($ResolvedLicense)
    )
}

$CurrentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$CurrentGrant = "*{0}:(OI)(CI)F" -f $CurrentSid
& icacls.exe $SecretsRoot /inheritance:r /grant:r $CurrentGrant "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Failed to restrict the development secret directory ACL."
}

Write-Host "Development secrets initialized under runtime\dev-secrets."
Write-Host "Secret values were not printed and are excluded from Git and portable bundles."
if (Test-Path -LiteralPath $AIStorLicenseTarget -PathType Leaf) {
    Write-Host "AIStor license: present"
} else {
    Write-Warning "AIStor license: missing. Full 9-service startup will remain blocked."
}

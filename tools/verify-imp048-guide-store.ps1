[CmdletBinding()]
param(
    [string]$ProductOrigin = "http://localhost:18480",
    [string]$PgAdminOrigin = "http://127.0.0.1:18490"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$SecretsRoot = Join-Path $ProjectRoot "runtime\dev-secrets"
$PasswordPath = Join-Path $SecretsRoot "auth_dev_password"
$MfaPath = Join-Path $SecretsRoot "auth_dev_mfa_code"

function Get-Csrf {
    param([Parameter(Mandatory = $true)][string]$Html)

    $Match = [regex]::Match($Html, 'name="csrf_token" value="([^"]+)"')
    if (-not $Match.Success) {
        throw "CSRF token was not present."
    }
    return $Match.Groups[1].Value
}

$Password = [System.IO.File]::ReadAllText($PasswordPath).Trim()
$MfaCode = [System.IO.File]::ReadAllText($MfaPath).Trim()
$Session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$BrowserHeaders = @{
    Origin = $ProductOrigin
    "Sec-Fetch-Site" = "same-origin"
}

try {
    $LoginPage = Invoke-WebRequest `
        -Uri "$ProductOrigin/auth/login?next=/ui/guide-store" `
        -WebSession $Session `
        -UseBasicParsing
    $LoginCsrf = Get-Csrf $LoginPage.Content
    Invoke-WebRequest `
        -Uri "$ProductOrigin/auth/login" `
        -Method Post `
        -WebSession $Session `
        -Headers $BrowserHeaders `
        -Body @{
            username = "local-owner"
            password = $Password
            csrf_token = $LoginCsrf
            next = "/ui/guide-store"
        } `
        -UseBasicParsing | Out-Null

    $MfaPage = Invoke-WebRequest `
        -Uri "$ProductOrigin/auth/mfa?next=/ui/guide-store" `
        -WebSession $Session `
        -UseBasicParsing
    $MfaCsrf = Get-Csrf $MfaPage.Content
    $GuidePage = Invoke-WebRequest `
        -Uri "$ProductOrigin/auth/mfa" `
        -Method Post `
        -WebSession $Session `
        -Headers $BrowserHeaders `
        -Body @{
            code = $MfaCode
            csrf_token = $MfaCsrf
            next = "/ui/guide-store"
        } `
        -UseBasicParsing
    if (-not $GuidePage.Content.Contains('data-ui-standard="guide-store-v1"') -or
        -not $GuidePage.Content.Contains("PostgreSQL") -or
        -not $GuidePage.Content.Contains("pgvector")) {
        throw "The authenticated guide-store page did not show the expected counts."
    }

    $Inventory = Invoke-RestMethod `
        -Uri "$ProductOrigin/api/v1/guide-store" `
        -WebSession $Session
    if ($Inventory.document_count -ne 1 -or
        $Inventory.chunk_count -ne 41 -or
        $Inventory.embedding_count -ne 41 -or
        $Inventory.raw_embeddings_included -ne $false) {
        throw "The safe guide-store API inventory did not match the database."
    }

    $Ping = Invoke-WebRequest `
        -Uri "$PgAdminOrigin/misc/ping" `
        -UseBasicParsing
    if ($Ping.StatusCode -ne 200 -or $Ping.Content.Trim() -ne "PING") {
        throw "The local pgAdmin health endpoint was unavailable."
    }

    [pscustomobject]@{
        ProductUi = "PASS"
        SafeInventoryApi = "PASS"
        DocumentCount = $Inventory.document_count
        ChunkCount = $Inventory.chunk_count
        EmbeddingCount = $Inventory.embedding_count
        RawEmbeddingExposed = $Inventory.raw_embeddings_included
        PgAdminLoopback = "PASS"
    } | Format-List
} finally {
    $Password = $null
    $MfaCode = $null
}

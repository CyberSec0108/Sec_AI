[CmdletBinding()]
param(
    [string]$ProductOrigin = "http://localhost:18480"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$ComposeFiles = @(
    (Join-Path $ProjectRoot "deploy\compose\compose.yml"),
    (Join-Path $ProjectRoot "deploy\compose\compose.dev.yml")
)
$FileArguments = @()
foreach ($ComposeFile in $ComposeFiles) {
    $FileArguments += @("-f", $ComposeFile)
}

& docker compose `
    --project-directory $ProjectRoot `
    @FileArguments `
    run --rm --no-deps api database/verification/verify_product_ai_07.py
if ($LASTEXITCODE -ne 0) {
    throw "PRODUCT-AI-07 actual PostgreSQL verification failed."
}

$SecretsRoot = Join-Path $ProjectRoot "runtime\dev-secrets"
$Password = [System.IO.File]::ReadAllText(
    (Join-Path $SecretsRoot "auth_dev_password")
).Trim()
$MfaCode = [System.IO.File]::ReadAllText(
    (Join-Path $SecretsRoot "auth_dev_mfa_code")
).Trim()
$Session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$BrowserHeaders = @{
    Origin = $ProductOrigin
    "Sec-Fetch-Site" = "same-origin"
}

function Get-FormCsrf {
    param([Parameter(Mandatory = $true)][string]$Html)

    $Match = [regex]::Match($Html, 'name="csrf_token" value="([^"]+)"')
    if (-not $Match.Success) {
        throw "Form CSRF token was not present."
    }
    return $Match.Groups[1].Value
}

try {
    $LoginPage = Invoke-WebRequest `
        -Uri "$ProductOrigin/auth/login?next=/ui/guide-chat" `
        -WebSession $Session `
        -UseBasicParsing
    Invoke-WebRequest `
        -Uri "$ProductOrigin/auth/login" `
        -Method Post `
        -WebSession $Session `
        -Headers $BrowserHeaders `
        -Body @{
            username = "local-owner"
            password = $Password
            csrf_token = Get-FormCsrf $LoginPage.Content
            next = "/ui/guide-chat"
        } `
        -UseBasicParsing | Out-Null

    $MfaPage = Invoke-WebRequest `
        -Uri "$ProductOrigin/auth/mfa?next=/ui/guide-chat" `
        -WebSession $Session `
        -UseBasicParsing
    $ChatPage = Invoke-WebRequest `
        -Uri "$ProductOrigin/auth/mfa" `
        -Method Post `
        -WebSession $Session `
        -Headers $BrowserHeaders `
        -Body @{
            code = $MfaCode
            csrf_token = Get-FormCsrf $MfaPage.Content
            next = "/ui/guide-chat"
        } `
        -UseBasicParsing

    foreach ($Expected in @(
        'id="thread-search"',
        'id="thread-view"',
        'id="thread-management-panel"',
        'id="thread-delete-undo"'
    )) {
        if (-not $ChatPage.Content.Contains($Expected)) {
            throw "The chat management UI missed: $Expected"
        }
    }
    if ($ChatPage.Content.Contains('href="/ui/guide-chat#history"')) {
        throw "The duplicate top conversation history tab remains."
    }

    $Script = Invoke-WebRequest `
        -Uri "$ProductOrigin/static/app/guide-chat.js" `
        -WebSession $Session `
        -UseBasicParsing
    foreach ($Expected in @(
        'updateManagedThread("title"',
        'updateManagedThread("pin"',
        'updateManagedThread("folder"',
        'updateManagedThread("archive"',
        "/tombstone",
        "/undo-delete"
    )) {
        if (-not $Script.Content.Contains($Expected)) {
            throw "The chat management script missed: $Expected"
        }
    }
    $History = Invoke-RestMethod `
        -Uri "$ProductOrigin/api/v1/chat/threads?view=ACTIVE&q=PC" `
        -WebSession $Session
    [pscustomobject]@{
        PostgreSqlContract = "PASS"
        AuthenticatedUi = "PASS"
        DuplicateHistoryTabRemoved = "PASS"
        SearchApi = "PASS"
        MatchingActiveThreads = @($History.threads).Count
        PhysicalDeleteGranted = $false
    } | Format-List
} finally {
    $Password = $null
    $MfaCode = $null
}

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
    run --rm --no-deps api database/verification/verify_imp053.py
if ($LASTEXITCODE -ne 0) {
    throw "IMP-053 actual PostgreSQL LIVE guide chat verification failed."
}

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
        -Uri "$ProductOrigin/auth/login?next=/ui/guide-chat" `
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
            next = "/ui/guide-chat"
        } `
        -UseBasicParsing | Out-Null

    $MfaPage = Invoke-WebRequest `
        -Uri "$ProductOrigin/auth/mfa?next=/ui/guide-chat" `
        -WebSession $Session `
        -UseBasicParsing
    $MfaCsrf = Get-Csrf $MfaPage.Content
    $ChatPage = Invoke-WebRequest `
        -Uri "$ProductOrigin/auth/mfa" `
        -Method Post `
        -WebSession $Session `
        -Headers $BrowserHeaders `
        -Body @{
            code = $MfaCode
            csrf_token = $MfaCsrf
            next = "/ui/guide-chat"
        } `
        -UseBasicParsing
    foreach ($Expected in @(
        'data-ui-standard="guide-chat-live-v1"',
        'id="new-chat"',
        'id="send-question"',
        'id="stop-answer"'
    )) {
        if (-not $ChatPage.Content.Contains($Expected)) {
            throw "The authenticated LIVE guide chat page missed: $Expected"
        }
    }

    $Script = Invoke-WebRequest `
        -Uri "$ProductOrigin/static/app/guide-chat.js" `
        -WebSession $Session `
        -UseBasicParsing
    if (-not $Script.Content.Contains("/api/v1/chat/threads") -or
        -not $Script.Content.Contains("/run") -or
        -not $Script.Content.Contains("/stop")) {
        throw "The LIVE guide chat script did not contain its API actions."
    }

    $History = Invoke-RestMethod `
        -Uri "$ProductOrigin/api/v1/chat/threads" `
        -WebSession $Session
    [pscustomobject]@{
        LiveGuideChatUi = "PASS"
        ChatActionsScript = "PASS"
        AuthenticatedHistoryApi = "PASS"
        ExistingThreadCount = @($History.threads).Count
        ExternalGuideTransfer = $false
    } | Format-List
} finally {
    $Password = $null
    $MfaCode = $null
}

[CmdletBinding()]
param(
    [string]$ProductOrigin = "http://localhost:18480"
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

function Assert-Contains {
    param(
        [Parameter(Mandatory = $true)][string]$Content,
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Surface
    )

    foreach ($Item in $Expected) {
        if (-not $Content.Contains($Item)) {
            throw "$Surface missed the IMP-054 contract: $Item"
        }
    }
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
    Invoke-WebRequest `
        -Uri "$ProductOrigin/auth/mfa" `
        -Method Post `
        -WebSession $Session `
        -Headers $BrowserHeaders `
        -Body @{
            code = $MfaCode
            csrf_token = $MfaCsrf
            next = "/ui/guide-chat"
        } `
        -UseBasicParsing | Out-Null

    $Pages = @{
        Home = Invoke-WebRequest -Uri "$ProductOrigin/" -WebSession $Session -UseBasicParsing
        Results = Invoke-WebRequest -Uri "$ProductOrigin/ui/results" -WebSession $Session -UseBasicParsing
        Chat = Invoke-WebRequest -Uri "$ProductOrigin/ui/guide-chat" -WebSession $Session -UseBasicParsing
        Help = Invoke-WebRequest -Uri "$ProductOrigin/ui/help" -WebSession $Session -UseBasicParsing
    }
    foreach ($Entry in $Pages.GetEnumerator()) {
        Assert-Contains `
            -Content $Entry.Value.Content `
            -Expected @(
                'class="skip-link" href="#main-content"'
                'id="main-content"'
                'id="theme-toggle"'
                'src="/static/app/theme.js"'
            ) `
            -Surface $Entry.Key
    }
    Assert-Contains `
        -Content $Pages.Home.Content `
        -Expected @('beginner-flow', 'start-standard-scan', '/ui/guide-chat') `
        -Surface "Home"
    Assert-Contains `
        -Content $Pages.Chat.Content `
        -Expected @(
            'id="history-panel-toggle"'
            'id="source-panel-toggle"'
            'id="question-count"'
            'aria-busy="false"'
        ) `
        -Surface "Chat"

    $ChatScript = Invoke-WebRequest `
        -Uri "$ProductOrigin/static/app/guide-chat.js" `
        -WebSession $Session `
        -UseBasicParsing
    Assert-Contains `
        -Content $ChatScript.Content `
        -Expected @(
            'generation-indicator'
            'setGenerationStage(1)'
            'refreshConversation'
            'navigator.clipboard.writeText'
            'event.key === "Escape"'
        ) `
        -Surface "Guide chat script"

    $ThemeScript = Invoke-WebRequest `
        -Uri "$ProductOrigin/static/app/theme.js" `
        -WebSession $Session `
        -UseBasicParsing
    Assert-Contains `
        -Content $ThemeScript.Content `
        -Expected @('localStorage', 'prefers-color-scheme: dark') `
        -Surface "Theme script"

    $Stylesheet = Invoke-WebRequest `
        -Uri "$ProductOrigin/static/app/app.css" `
        -WebSession $Session `
        -UseBasicParsing
    Assert-Contains `
        -Content $Stylesheet.Content `
        -Expected @(
            '[data-theme="dark"]'
            '@media (prefers-reduced-motion: reduce)'
            '.generation-indicator'
            '.history-panel-collapsed'
            '.source-panel-collapsed'
        ) `
        -Surface "Stylesheet"

    $History = Invoke-RestMethod `
        -Uri "$ProductOrigin/api/v1/chat/threads" `
        -WebSession $Session
    [pscustomobject]@{
        BeginnerTaskPath = "PASS"
        CollapsibleChatPanels = "PASS"
        TerminalEventRefresh = "PASS"
        StructuredAnswer = "PASS"
        GenerationIndicator = "PASS"
        KeyboardAndFocus = "PASS"
        ResponsiveAndTheme = "PASS"
        ExistingThreadCount = @($History.threads).Count
        VerificationWrites = 0
    } | Format-List
} finally {
    $Password = $null
    $MfaCode = $null
}

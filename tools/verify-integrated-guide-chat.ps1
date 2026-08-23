[CmdletBinding()]
param(
    [string]$ProductOrigin = "http://localhost:18480",
    [ValidateRange(30, 240)]
    [int]$TimeoutSeconds = 180
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$SecretsRoot = Join-Path $ProjectRoot "runtime\dev-secrets"
$PasswordPath = Join-Path $SecretsRoot "auth_dev_password"
$MfaPath = Join-Path $SecretsRoot "auth_dev_mfa_code"

function Get-FormCsrf {
    param([Parameter(Mandatory = $true)][string]$Html)

    $Match = [regex]::Match($Html, 'name="csrf_token" value="([^"]+)"')
    if (-not $Match.Success) {
        throw "Form CSRF token was not present."
    }
    return $Match.Groups[1].Value
}

function Get-ApiCsrf {
    param([Parameter(Mandatory = $true)][string]$Html)

    $Match = [regex]::Match($Html, 'name="csrf-token" content="([^"]+)"')
    if (-not $Match.Success) {
        throw "API CSRF token was not present."
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
    $LoginCsrf = Get-FormCsrf $LoginPage.Content
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
    $MfaCsrf = Get-FormCsrf $MfaPage.Content
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
    $ApiCsrf = Get-ApiCsrf $ChatPage.Content
    $ApiHeaders = @{
        Origin = $ProductOrigin
        "Sec-Fetch-Site" = "same-origin"
        "X-CSRF-Token" = $ApiCsrf
    }

    $Catalog = Invoke-RestMethod `
        -Uri "$ProductOrigin/api/v1/chat/guides" `
        -WebSession $Session
    $Guides = @($Catalog.guides)
    if ($Guides.Count -ne 1 -or $Catalog.searched_document_count -ne 8) {
        throw "The chat catalog did not expose one integrated scope over eight guides."
    }
    $Guide = $Guides[0]
    if ($Guide.guide_id -ne "secai-integrated-security-guides") {
        throw "The default chat target was not the integrated guide scope."
    }

    $ThreadBody = @{
        title = "통합 가이드 실제 검증"
        guide_id = $Guide.guide_id
        guide_version = $Guide.version
        scope_id = $Guide.scope_id
        profile = "FAST"
    } | ConvertTo-Json
    $Thread = Invoke-RestMethod `
        -Uri "$ProductOrigin/api/v1/chat/threads" `
        -Method Post `
        -WebSession $Session `
        -Headers $ApiHeaders `
        -ContentType "application/json" `
        -Body $ThreadBody

    $RequestKey = "unified-$([guid]::NewGuid().ToString('N'))"
    $QuestionBody = @{
        content = "AI 프롬프트 취약점이 무엇인가요?"
        idempotency_key = $RequestKey
        parent_message_id = $null
    } | ConvertTo-Json
    $Queued = Invoke-RestMethod `
        -Uri "$ProductOrigin/api/v1/chat/threads/$($Thread.thread_id)/messages" `
        -Method Post `
        -WebSession $Session `
        -Headers $ApiHeaders `
        -ContentType "application/json" `
        -Body $QuestionBody
    Invoke-RestMethod `
        -Uri "$ProductOrigin/api/v1/chat/generations/$($Queued.generation_id)/run" `
        -Method Post `
        -WebSession $Session `
        -Headers $ApiHeaders `
        -ContentType "application/json" `
        -Body "{}" | Out-Null

    $Deadline = [datetime]::UtcNow.AddSeconds($TimeoutSeconds)
    $Answer = $null
    do {
        try {
            $History = Invoke-RestMethod `
                -Uri "$ProductOrigin/api/v1/chat/threads/$($Thread.thread_id)/messages" `
                -WebSession $Session
            $Answer = @(
                $History.messages | Where-Object {
                    $_.role -eq "ASSISTANT" -and $_.status -eq "COMPLETED"
                }
            ) | Select-Object -Last 1
        } catch {
            $StatusCode = [int]$_.Exception.Response.StatusCode
            if ($StatusCode -notin @(502, 503, 504)) {
                throw
            }
        }
        if ($null -eq $Answer) {
            Start-Sleep -Seconds 1
        }
    } while ($null -eq $Answer -and [datetime]::UtcNow -lt $Deadline)

    if ($null -eq $Answer) {
        throw "The integrated guide answer did not complete within $TimeoutSeconds seconds."
    }
    $Citations = @($Answer.citations)
    $DistinctGuides = @($Citations | Select-Object -ExpandProperty guide_id -Unique)
    if ($Citations.Count -lt 1 -or -not $Answer.content.Contains("[1]")) {
        throw "The integrated answer did not persist its referenced source."
    }
    if ($DistinctGuides -contains "secai-integrated-security-guides") {
        throw "A virtual integrated scope was incorrectly stored as a source document."
    }
    if ($Answer.generation_trace.answer_mode -notin @(
            "LOCAL_VLLM",
            "REMOTE_OPENROUTER"
        ) -or $Answer.generation_trace.model_id -eq "secai-local-grounded-summary-v1") {
        throw "The integrated answer did not use the existing LLM answer pipeline."
    }
    if (-not $Answer.content.Contains("## 핵심 답변")) {
        throw "The integrated LLM answer did not preserve the structured answer format."
    }

    $FirstCitation = $Citations[0]
    $PdfResponse = Invoke-WebRequest `
        -Uri "$ProductOrigin/api/v1/guides/$($FirstCitation.guide_id)/$($FirstCitation.guide_version)/source.pdf?requested_page=$($FirstCitation.pdf_page_number)" `
        -WebSession $Session `
        -UseBasicParsing
    if ($PdfResponse.StatusCode -ne 200 -or $PdfResponse.RawContentLength -lt 100) {
        throw "The exact source PDF could not be opened from the integrated answer."
    }

    [pscustomobject]@{
        CatalogMode = "ONE_INTEGRATED_SCOPE"
        SearchedDocuments = $Catalog.searched_document_count
        AnswerStatus = $Answer.status
        PersistedCitations = $Citations.Count
        DistinctSourceDocuments = $DistinctGuides.Count
        AnswerMode = $Answer.generation_trace.answer_mode
        ModelId = $Answer.generation_trace.model_id
        ExternalDataTransfer = $Answer.generation_trace.external_data_transfer
        ExactSourcePdf = "PASS"
    } | Format-List
} finally {
    $Password = $null
    $MfaCode = $null
}

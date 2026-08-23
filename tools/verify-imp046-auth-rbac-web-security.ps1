[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Net.Http

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$SecretsRoot = Join-Path $ProjectRoot "runtime\dev-secrets"
$Origin = "http://localhost:18480"
$PasswordPath = Join-Path $SecretsRoot "auth_dev_password"
$MfaPath = Join-Path $SecretsRoot "auth_dev_mfa_code"
$Checks = New-Object System.Collections.Generic.List[object]

function Add-Check {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][bool]$Passed
    )

    $Checks.Add([ordered]@{ name = $Name; passed = $Passed })
    if (-not $Passed) {
        throw "IMP-046 verification failed: $Name"
    }
}

function Get-Body {
    param(
        [Parameter(Mandatory = $true)]
        [System.Net.Http.HttpResponseMessage]$Response
    )

    return $Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
}

function Get-Csrf {
    param([Parameter(Mandatory = $true)][string]$Html)

    $Match = [regex]::Match($Html, 'name="csrf_token" value="([^"]+)"')
    if (-not $Match.Success) {
        throw "CSRF token was not present in the expected page."
    }
    return $Match.Groups[1].Value
}

function Send-Request {
    param(
        [Parameter(Mandatory = $true)][System.Net.Http.HttpClient]$Client,
        [Parameter(Mandatory = $true)][System.Net.Http.HttpMethod]$Method,
        [Parameter(Mandatory = $true)][string]$Path,
        [hashtable]$Form,
        [hashtable]$Headers
    )

    $Request = [System.Net.Http.HttpRequestMessage]::new(
        $Method,
        ($Origin + $Path)
    )
    try {
        if ($null -ne $Form) {
            $Pairs = New-Object "System.Collections.Generic.Dictionary[string,string]"
            foreach ($Entry in $Form.GetEnumerator()) {
                $Pairs.Add([string]$Entry.Key, [string]$Entry.Value)
            }
            $Request.Content = [System.Net.Http.FormUrlEncodedContent]::new($Pairs)
        }
        if ($null -ne $Headers) {
            foreach ($Entry in $Headers.GetEnumerator()) {
                $Request.Headers.TryAddWithoutValidation(
                    [string]$Entry.Key,
                    [string]$Entry.Value
                ) | Out-Null
            }
        }
        return $Client.SendAsync($Request).GetAwaiter().GetResult()
    } finally {
        $Request.Dispose()
    }
}

if (-not (Test-Path -LiteralPath $PasswordPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $MfaPath -PathType Leaf)) {
    throw "Run tools\init-dev-secrets.ps1 before IMP-046 verification."
}

$Password = [System.IO.File]::ReadAllText($PasswordPath).Trim()
$MfaCode = [System.IO.File]::ReadAllText($MfaPath).Trim()
$Cookies = New-Object System.Net.CookieContainer
$Handler = New-Object System.Net.Http.HttpClientHandler
$Handler.AllowAutoRedirect = $false
$Handler.CookieContainer = $Cookies
$Client = New-Object System.Net.Http.HttpClient($Handler)
$Client.Timeout = [TimeSpan]::FromSeconds(10)

try {
    $Anonymous = Send-Request $Client ([System.Net.Http.HttpMethod]::Get) "/" $null $null
    Add-Check "anonymous_redirects_to_login" (
        [int]$Anonymous.StatusCode -eq 303 -and
        $Anonymous.Headers.Location.OriginalString -eq "/auth/login?next=/"
    )

    $LoginPage = Send-Request $Client ([System.Net.Http.HttpMethod]::Get) "/auth/login" $null $null
    $LoginBody = Get-Body $LoginPage
    Add-Check "login_page_available" (
        [int]$LoginPage.StatusCode -eq 200 -and
        $LoginBody.Contains('data-ui-standard="auth-login-v1"')
    )
    $LoginCsrf = Get-Csrf $LoginBody

    $Favicon = Send-Request $Client ([System.Net.Http.HttpMethod]::Get) "/favicon.ico" $null $null
    Add-Check "favicon_does_not_rotate_pre_auth_session" (
        [int]$Favicon.StatusCode -eq 204 -and
        -not $Favicon.Headers.Contains("Location")
    )

    $PasswordRequest = @{
        Client = $Client
        Method = [System.Net.Http.HttpMethod]::Post
        Path = "/auth/login"
        Form = @{
            username = "local-owner"
            password = $Password
            csrf_token = $LoginCsrf
            next = "/"
        }
        Headers = @{
            Origin = $Origin
            "Sec-Fetch-Site" = "same-origin"
        }
    }
    $PasswordResponse = Send-Request @PasswordRequest
    Add-Check "password_requires_second_factor" (
        [int]$PasswordResponse.StatusCode -eq 303 -and
        $PasswordResponse.Headers.Location.OriginalString.StartsWith("/auth/mfa")
    )

    $MfaPage = Send-Request `
        -Client $Client `
        -Method ([System.Net.Http.HttpMethod]::Get) `
        -Path $PasswordResponse.Headers.Location.OriginalString
    $MfaCsrf = Get-Csrf (Get-Body $MfaPage)
    Add-Check "mfa_page_available" ([int]$MfaPage.StatusCode -eq 200)

    $MfaRequest = @{
        Client = $Client
        Method = [System.Net.Http.HttpMethod]::Post
        Path = "/auth/mfa"
        Form = @{
            code = $MfaCode
            csrf_token = $MfaCsrf
            next = "/"
        }
        Headers = @{
            Origin = $Origin
            "Sec-Fetch-Site" = "same-origin"
        }
    }
    $MfaResponse = Send-Request @MfaRequest
    Add-Check "password_and_mfa_login_succeeds" (
        [int]$MfaResponse.StatusCode -eq 303 -and
        $MfaResponse.Headers.Location.OriginalString -eq "/"
    )

    $HomeResponse = Send-Request $Client ([System.Net.Http.HttpMethod]::Get) "/" $null $null
    Add-Check "authenticated_home_and_security_headers" (
        [int]$HomeResponse.StatusCode -eq 200 -and
        $HomeResponse.Headers.Contains("Content-Security-Policy") -and
        $HomeResponse.Headers.Contains("X-SecAI-Auth-Profile")
    )

    $OrganizationId = "46000000-0000-4000-8000-000000000001"
    $AssetId = "46000000-0000-4000-8000-000000000002"
    $OtherOrganizationId = "46000000-0000-4000-8000-000000000091"
    $OtherAssetId = "46000000-0000-4000-8000-000000000092"
    $BasePath = "/api/v1/security/organizations/$OrganizationId/assets/$AssetId"

    $Assigned = Send-Request $Client ([System.Net.Http.HttpMethod]::Get) $BasePath $null $null
    Add-Check "assigned_asset_is_available" ([int]$Assigned.StatusCode -eq 200)

    $OtherAsset = Send-Request `
        -Client $Client `
        -Method ([System.Net.Http.HttpMethod]::Get) `
        -Path $BasePath.Replace($AssetId, $OtherAssetId)
    Add-Check "other_asset_idor_is_hidden" ([int]$OtherAsset.StatusCode -eq 404)

    $OtherOrganization = Send-Request `
        -Client $Client `
        -Method ([System.Net.Http.HttpMethod]::Get) `
        -Path $BasePath.Replace($OrganizationId, $OtherOrganizationId)
    Add-Check "other_organization_idor_is_hidden" (
        [int]$OtherOrganization.StatusCode -eq 404
    )

    $FragmentPath = (
        $BasePath.Replace("/api/v1/", "/ui/") + "/fragment"
    )
    $Fragment = Send-Request `
        -Client $Client `
        -Method ([System.Net.Http.HttpMethod]::Get) `
        -Path $FragmentPath `
        -Headers @{ "HX-Request" = "true" }
    Add-Check "fragment_rechecks_scope" (
        [int]$Fragment.StatusCode -eq 200 -and
        (Get-Body $Fragment).Contains('data-fragment-contract="security-asset-v1"')
    )

    $Events = Send-Request `
        -Client $Client `
        -Method ([System.Net.Http.HttpMethod]::Get) `
        -Path ($BasePath + "/events") `
        -Headers @{ Accept = "text/event-stream" }
    Add-Check "sse_rechecks_scope" (
        [int]$Events.StatusCode -eq 200 -and
        (Get-Body $Events).Contains("security-status")
    )

    $Download = Send-Request `
        -Client $Client `
        -Method ([System.Net.Http.HttpMethod]::Get) `
        -Path ($BasePath + "/download")
    Add-Check "user_cannot_download_evidence" ([int]$Download.StatusCode -eq 403)

    $SessionPage = Send-Request `
        -Client $Client `
        -Method ([System.Net.Http.HttpMethod]::Get) `
        -Path "/auth/session"
    $SessionCsrf = Get-Csrf (Get-Body $SessionPage)
    $CrossSiteRequest = @{
        Client = $Client
        Method = [System.Net.Http.HttpMethod]::Post
        Path = "/auth/logout"
        Form = @{ csrf_token = $SessionCsrf }
        Headers = @{
            Origin = "http://invalid.example"
            "Sec-Fetch-Site" = "cross-site"
        }
    }
    $CrossSite = Send-Request @CrossSiteRequest
    Add-Check "cross_site_logout_is_rejected" ([int]$CrossSite.StatusCode -eq 403)

    $StillActive = Send-Request $Client ([System.Net.Http.HttpMethod]::Get) "/" $null $null
    Add-Check "rejected_csrf_does_not_end_session" (
        [int]$StillActive.StatusCode -eq 200
    )

    $LogoutRequest = @{
        Client = $Client
        Method = [System.Net.Http.HttpMethod]::Post
        Path = "/auth/logout"
        Form = @{ csrf_token = $SessionCsrf }
        Headers = @{
            Origin = $Origin
            "Sec-Fetch-Site" = "same-origin"
        }
    }
    $Logout = Send-Request @LogoutRequest
    Add-Check "valid_logout_revokes_session" ([int]$Logout.StatusCode -eq 303)

    $RevokedApi = Send-Request `
        -Client $Client `
        -Method ([System.Net.Http.HttpMethod]::Get) `
        -Path $BasePath
    Add-Check "revoked_session_cannot_reconnect" (
        [int]$RevokedApi.StatusCode -eq 401
    )
} finally {
    $Password = $null
    $MfaCode = $null
    $Client.Dispose()
    $Handler.Dispose()
}

$Result = [ordered]@{
    imp = "IMP-046"
    profile = "DEV-LOCAL"
    checks = $Checks.Count
    passed = @($Checks | Where-Object { $_.passed }).Count
    failed = @($Checks | Where-Object { -not $_.passed }).Count
    secrets_printed = $false
    pilot_authentication_approved = $false
}
$Result | ConvertTo-Json -Depth 5

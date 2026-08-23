[CmdletBinding()]
param(
    [string]$BaseUrl = 'http://localhost:18480'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$SecretsRoot = Join-Path $ProjectRoot 'runtime\dev-secrets'
$VmwareRoot = Join-Path $ProjectRoot '.runtime\vmware'
$KnownHosts = Join-Path $VmwareRoot 'known_hosts'

function Get-CsrfToken {
    param(
        [Parameter(Mandatory = $true)][string]$Html,
        [Parameter(Mandatory = $true)][string]$Pattern
    )

    $Value = [regex]::Match($Html, $Pattern).Groups[1].Value
    if (-not $Value) {
        throw 'CSRF token was not present in the expected page.'
    }
    return $Value
}

$Session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$LoginPage = Invoke-WebRequest `
    -Uri "$BaseUrl/auth/login?next=/ui/dev-downloads" `
    -WebSession $Session `
    -UseBasicParsing
$Csrf = Get-CsrfToken `
    -Html $LoginPage.Content `
    -Pattern 'name="csrf_token" value="([^"]+)"'
$Password = (Get-Content -Raw -LiteralPath (Join-Path $SecretsRoot 'auth_dev_password')).Trim()
$MfaPage = Invoke-WebRequest `
    -Uri "$BaseUrl/auth/login" `
    -WebSession $Session `
    -Method Post `
    -Body @{
        username = 'local-owner'
        password = $Password
        csrf_token = $Csrf
        next = '/ui/dev-downloads'
    } `
    -Headers @{
        Origin = $BaseUrl
        Referer = "$BaseUrl/auth/login"
        'Sec-Fetch-Site' = 'same-origin'
    } `
    -UseBasicParsing
$Csrf = Get-CsrfToken `
    -Html $MfaPage.Content `
    -Pattern 'name="csrf_token" value="([^"]+)"'
$MfaCode = (Get-Content -Raw -LiteralPath (Join-Path $SecretsRoot 'auth_dev_mfa_code')).Trim()
$DownloadsPage = Invoke-WebRequest `
    -Uri "$BaseUrl/auth/mfa" `
    -WebSession $Session `
    -Method Post `
    -Body @{
        code = $MfaCode
        csrf_token = $Csrf
        next = '/ui/dev-downloads'
    } `
    -Headers @{
        Origin = $BaseUrl
        Referer = "$BaseUrl/auth/mfa"
        'Sec-Fetch-Site' = 'same-origin'
    } `
    -UseBasicParsing
$PageCsrf = Get-CsrfToken `
    -Html $DownloadsPage.Content `
    -Pattern 'name="csrf-token" content="([^"]+)"'

$Targets = @(
    @{
        Name = 'Ubuntu'
        Platform = 'UBUNTU_24_04_X64'
        Ip = '192.168.110.146'
        Key = Join-Path $VmwareRoot 'secai-ubuntu-lab-ed25519'
        Temp = '/tmp/secai-linux-check-ubuntu24-x86_64'
    },
    @{
        Name = 'Rocky'
        Platform = 'ROCKY_9_X64'
        Ip = '192.168.110.148'
        Key = Join-Path $VmwareRoot 'secai-rocky-lab-ed25519'
        Temp = '/tmp/secai-linux-check-rocky9-x86_64'
    }
)

$Results = foreach ($Target in $Targets) {
    $Issued = Invoke-RestMethod `
        -Uri "$BaseUrl/api/v1/dev-downloads/codes" `
        -WebSession $Session `
        -Method Post `
        -Headers @{
            'X-CSRF-Token' = $PageCsrf
            Origin = $BaseUrl
        } `
        -ContentType 'application/json' `
        -Body (@{ platform = $Target.Platform } | ConvertTo-Json -Compress)

    $TunnelArguments = @(
        '-i', $Target.Key,
        '-o', 'IdentitiesOnly=yes',
        '-o', "UserKnownHostsFile=$KnownHosts",
        '-o', 'StrictHostKeyChecking=yes',
        '-o', 'BatchMode=yes',
        '-o', 'ExitOnForwardFailure=yes',
        '-o', 'ServerAliveInterval=10',
        '-N',
        '-R', '18480:127.0.0.1:18480',
        "secai-lab@$($Target.Ip)"
    )
    $Tunnel = Start-Process `
        -FilePath 'ssh.exe' `
        -ArgumentList $TunnelArguments `
        -PassThru `
        -WindowStyle Hidden
    try {
        Start-Sleep -Seconds 3
        if ($Tunnel.HasExited) {
            throw "$($Target.Name) reverse tunnel failed."
        }
        $RemoteCommand = @(
            'set -eu'
            'umask 077'
            "curl -fSs --data-binary @- http://127.0.0.1:18480$($Issued.fetch_url) -o $($Target.Temp)"
            "test `"`$(sha256sum $($Target.Temp) | cut -d ' ' -f1)`" = `"$($Issued.sha256)`""
            "chmod 700 $($Target.Temp)"
            "$($Target.Temp) --help >/dev/null"
            "rm -f $($Target.Temp)"
            "printf 'DOWNLOAD_HASH_EXEC=PASS\n'"
        ) -join '; '
        $RemoteOutput = $Issued.code | & ssh.exe `
            -i $Target.Key `
            -o IdentitiesOnly=yes `
            -o "UserKnownHostsFile=$KnownHosts" `
            -o StrictHostKeyChecking=yes `
            -o BatchMode=yes `
            -o ConnectTimeout=8 `
            "secai-lab@$($Target.Ip)" `
            $RemoteCommand
        if ($LASTEXITCODE -ne 0) {
            throw "$($Target.Name) remote download test failed."
        }
        [pscustomobject]@{
            VM = $Target.Name
            Platform = $Target.Platform
            Result = ($RemoteOutput -join '').Trim()
        }
    }
    finally {
        if (-not $Tunnel.HasExited) {
            Stop-Process -Id $Tunnel.Id -Force
        }
        $Tunnel.Dispose()
    }
}

$Results | Format-Table -AutoSize

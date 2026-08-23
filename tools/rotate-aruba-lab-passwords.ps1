[CmdletBinding()]
param(
    [string]$PipeName = 'secai-aruba-aos-cx-console',
    [string]$MachineRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if ([string]::IsNullOrWhiteSpace($MachineRoot)) {
    $MachineRoot = Join-Path $projectRoot '.runtime\vmware\aruba-aos-cx-10.13.1170-lab'
}
$machinePath = [System.IO.Path]::GetFullPath($MachineRoot)
$allowedRoot = [System.IO.Path]::GetFullPath((Join-Path $projectRoot '.runtime\vmware'))
if (-not $machinePath.StartsWith(
    "$allowedRoot$([System.IO.Path]::DirectorySeparatorChar)",
    [System.StringComparison]::OrdinalIgnoreCase
)) {
    throw 'Aruba VM 경로는 .runtime/vmware 아래에 있어야 합니다.'
}

function New-LabPassword {
    $bytes = [byte[]]::new(18)
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    } finally {
        $generator.Dispose()
    }
    $token = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', 'A').Replace('/', 'B')
    return "Sx!9$token"
}

function Protect-Value([string]$Value) {
    return ConvertFrom-SecureString (ConvertTo-SecureString $Value -AsPlainText -Force)
}

function Unprotect-Value([string]$Value) {
    $secure = ConvertTo-SecureString $Value
    return [Net.NetworkCredential]::new('', $secure).Password
}

function Read-Until(
    [IO.Pipes.NamedPipeClientStream]$Pipe,
    [string]$Pattern,
    [int]$TimeoutSeconds = 30
) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $text = [Text.StringBuilder]::new()
    while ([DateTime]::UtcNow -lt $deadline) {
        $buffer = [byte[]]::new(4096)
        $pending = $Pipe.BeginRead($buffer, 0, $buffer.Length, $null, $null)
        $remaining = [Math]::Max(1, [int]($deadline - [DateTime]::UtcNow).TotalMilliseconds)
        if (-not $pending.AsyncWaitHandle.WaitOne($remaining)) {
            throw "AOS-CX 콘솔 응답 제한 시간을 초과했습니다: $Pattern"
        }
        $count = $Pipe.EndRead($pending)
        if ($count -eq 0) {
            throw 'AOS-CX 직렬 콘솔 연결이 종료되었습니다.'
        }
        [void]$text.Append([Text.Encoding]::UTF8.GetString($buffer, 0, $count))
        if ($text.Length -gt 1MB) {
            throw 'AOS-CX 콘솔 응답이 허용 크기를 초과했습니다.'
        }
        if ($text.ToString() -match $Pattern) {
            return $text.ToString()
        }
    }
    throw "AOS-CX 콘솔 응답 제한 시간을 초과했습니다: $Pattern"
}

function Send-Line([IO.Pipes.NamedPipeClientStream]$Pipe, [string]$Value) {
    $bytes = [Text.Encoding]::UTF8.GetBytes("$Value`r`n")
    $Pipe.Write($bytes, 0, $bytes.Length)
    $Pipe.Flush()
}

function Send-AndWait(
    [IO.Pipes.NamedPipeClientStream]$Pipe,
    [string]$Command,
    [string]$Pattern = '(?m)switch(?:\([^\r\n]+\))?[#>]\s*$'
) {
    Send-Line $Pipe $Command
    [void](Read-Until $Pipe $Pattern 45)
}

function Login(
    [IO.Pipes.NamedPipeClientStream]$Pipe,
    [string]$UserName,
    [string]$Password
) {
    Send-Line $Pipe $UserName
    [void](Read-Until $Pipe '(?im)Password:\s*$' 20)
    Send-Line $Pipe $Password
    [void](Read-Until $Pipe '(?m)switch#\s*$' 45)
}

function Set-UserPassword(
    [IO.Pipes.NamedPipeClientStream]$Pipe,
    [string]$Command,
    [string]$Password
) {
    Send-Line $Pipe $Command
    [void](Read-Until $Pipe '(?im)Enter password:\s*$' 20)
    Send-Line $Pipe $Password
    [void](Read-Until $Pipe '(?im)Confirm password:\s*$' 20)
    Send-Line $Pipe $Password
    [void](Read-Until $Pipe '(?m)switch\(config\)#\s*$' 30)
}

$credentialPath = Join-Path $machinePath 'credentials.dpapi.json'
$pendingPath = Join-Path $machinePath 'credentials.rotation-pending.dpapi.json'
$credentialText = [IO.File]::ReadAllText($credentialPath, [Text.Encoding]::UTF8)
$credentials = $credentialText | ConvertFrom-Json
$oldLabAdminPassword = Unprotect-Value $credentials.lab_admin
$newAdminPassword = New-LabPassword
$newLabAdminPassword = New-LabPassword
$newAuditPassword = New-LabPassword
$newLimitedPassword = New-LabPassword

$rotated = $credentialText | ConvertFrom-Json
$rotated.admin = Protect-Value $newAdminPassword
$rotated.lab_admin = Protect-Value $newLabAdminPassword
$rotated.audit = Protect-Value $newAuditPassword
$rotated.limited = Protect-Value $newLimitedPassword
$utf8NoBom = [Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText($pendingPath, ($rotated | ConvertTo-Json), $utf8NoBom)
$credentialAcl = Get-Acl -LiteralPath $credentialPath
Set-Acl -LiteralPath $pendingPath -AclObject $credentialAcl

$pipe = [IO.Pipes.NamedPipeClientStream]::new(
    '.',
    $PipeName,
    [IO.Pipes.PipeDirection]::InOut,
    [IO.Pipes.PipeOptions]::Asynchronous
)

try {
    $pipe.Connect(30000)
    $pipe.WriteByte(3)
    Send-Line $pipe ''
    $state = Read-Until $pipe '(?m)(switch login:|switch(?:\([^\r\n]+\))?[#>]\s*$)' 30
    if ($state -notmatch 'switch login:\s*$') {
        if ($state -match 'switch\([^\r\n]+\)#\s*$') {
            Send-AndWait $pipe 'end' '(?m)switch#\s*$'
        }
        Send-Line $pipe 'exit'
        [void](Read-Until $pipe '(?m)switch login:\s*$' 30)
    }

    Login $pipe 'secai-lab-admin' $oldLabAdminPassword
    Send-AndWait $pipe 'configure terminal' '(?m)switch\(config\)#\s*$'
    Set-UserPassword $pipe 'user secai-audit group operators password' $newAuditPassword
    Set-UserPassword $pipe 'user secai-limited group auditors password' $newLimitedPassword
    Set-UserPassword $pipe 'user admin password' $newAdminPassword
    Set-UserPassword $pipe 'user secai-lab-admin group administrators password' $newLabAdminPassword
    Send-AndWait $pipe 'end' '(?m)switch#\s*$'
    Send-AndWait $pipe 'copy running-config startup-config' '(?m)switch#\s*$'

    Send-Line $pipe 'exit'
    [void](Read-Until $pipe '(?m)switch login:\s*$' 30)
    Login $pipe 'secai-lab-admin' $newLabAdminPassword
    Send-AndWait $pipe 'show version' '(?m)switch#\s*$'
    Send-Line $pipe 'exit'

    Move-Item -LiteralPath $pendingPath -Destination $credentialPath -Force
    Set-Acl -LiteralPath $credentialPath -AclObject $credentialAcl
    Write-Output 'AOS-CX 시험 계정 4개의 비밀번호 회전과 관리자 재로그인 검증을 완료했습니다.'
} finally {
    $oldLabAdminPassword = $null
    $newAdminPassword = $null
    $newLabAdminPassword = $null
    $newAuditPassword = $null
    $newLimitedPassword = $null
    $credentials = $null
    $rotated = $null
    $pipe.Dispose()
}

#Requires -Version 7.2

[CmdletBinding()]
param(
    [string]$CredentialFile = '',
    [ValidateSet(
        'ubuntu_24_04_lts',
        'rocky_linux_9',
        'ubuntu_22_04_lts',
        'debian_12',
        'almalinux_9'
    )]
    [string[]]$TargetId = @(),
    [switch]$KeepStarted
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$runtimeRoot = Join-Path $projectRoot '.runtime\vmware'
$allowedSecretRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $projectRoot 'runtime\dev-secrets')
)
if ([string]::IsNullOrWhiteSpace($CredentialFile)) {
    $CredentialFile = Join-Path $allowedSecretRoot 'lab_vm_credentials.json'
}
$credentialPath = [System.IO.Path]::GetFullPath($CredentialFile)
if (-not $credentialPath.StartsWith(
    "$allowedSecretRoot$([System.IO.Path]::DirectorySeparatorChar)",
    [System.StringComparison]::OrdinalIgnoreCase
)) {
    throw 'VM 자격증명 파일은 runtime/dev-secrets 아래에 있어야 합니다.'
}
if (-not (Test-Path -LiteralPath $credentialPath -PathType Leaf)) {
    throw '통합 VM 자격증명 파일을 찾을 수 없습니다.'
}

$vmrun = 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
$ssh = (Get-Command ssh -ErrorAction Stop).Source
$knownHosts = Join-Path $runtimeRoot 'known_hosts'
if (-not (Test-Path -LiteralPath $vmrun -PathType Leaf)) {
    throw 'VMware vmrun 실행 파일을 찾을 수 없습니다.'
}
if (-not (Test-Path -LiteralPath $knownHosts -PathType Leaf)) {
    throw 'Linux VM known_hosts 파일을 찾을 수 없습니다.'
}

$credentialText = [System.IO.File]::ReadAllText(
    $credentialPath,
    [System.Text.Encoding]::UTF8
)
$credentials = $credentialText | ConvertFrom-Json
$common = $credentials.linux.common_credential
$username = [string]$common.username
$password = [string]$common.password
if ($username -notmatch '^[a-z_][a-z0-9_-]{0,31}$') {
    throw 'Linux 공통 사용자 이름이 올바르지 않습니다.'
}
if ([string]::IsNullOrWhiteSpace($password) -or $password.Length -gt 128) {
    throw 'Linux 공통 비밀번호가 비어 있거나 너무 깁니다.'
}

$targets = @(
    @{
        Id = 'ubuntu_24_04_lts'
        Label = 'Ubuntu 24.04 LTS'
        Vmx = 'ubuntu-24.04-lab\SecAI-Ubuntu-24.04-Lab.vmx'
        IpAddress = '192.168.110.146'
    },
    @{
        Id = 'rocky_linux_9'
        Label = 'Rocky Linux 9'
        Vmx = 'rocky-9-lab\SecAI-Rocky-9-Lab.vmx'
        IpAddress = '192.168.110.148'
    },
    @{
        Id = 'ubuntu_22_04_lts'
        Label = 'Ubuntu 22.04 LTS'
        Vmx = 'ubuntu-22.04-cloud-lab\SecAI-Ubuntu-22.04-Cloud-Lab.vmx'
        IpAddress = '192.168.110.154'
    },
    @{
        Id = 'debian_12'
        Label = 'Debian 12'
        Vmx = 'debian-12-lab\SecAI-Debian-12-Lab.vmx'
        IpAddress = '192.168.110.155'
    },
    @{
        Id = 'almalinux_9'
        Label = 'AlmaLinux 9'
        Vmx = 'almalinux-9-lab\SecAI-AlmaLinux-9-Lab.vmx'
        IpAddress = '192.168.110.156'
    }
)
if ($TargetId.Count -gt 0) {
    $targets = @($targets | Where-Object { $_.Id -in $TargetId })
}

function Invoke-Process(
    [string]$FileName,
    [string[]]$Arguments,
    [string]$StandardInput = '',
    [hashtable]$Environment = @{},
    [int]$TimeoutSeconds = 90
) {
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FileName
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.RedirectStandardInput = $true
    foreach ($argument in $Arguments) {
        $startInfo.ArgumentList.Add($argument)
    }
    foreach ($entry in $Environment.GetEnumerator()) {
        $startInfo.Environment[[string]$entry.Key] = [string]$entry.Value
    }
    $process = [System.Diagnostics.Process]::Start($startInfo)
    try {
        if (-not [string]::IsNullOrEmpty($StandardInput)) {
            $process.StandardInput.Write($StandardInput)
        }
        $process.StandardInput.Close()
        $outputTask = $process.StandardOutput.ReadToEndAsync()
        $errorTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill($true)
            throw '외부 명령이 제한 시간을 초과했습니다.'
        }
        $output = $outputTask.GetAwaiter().GetResult()
        $errorOutput = $errorTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            $safeError = ("$errorOutput $output" -replace '[\r\n]+', ' ').Trim()
            if ($safeError.Length -gt 300) {
                $safeError = $safeError.Substring(0, 300)
            }
            throw "외부 명령이 실패했습니다. $safeError"
        }
        return $output
    } finally {
        $process.Dispose()
    }
}

function Invoke-KeyAuthenticatedScript(
    [string]$IpAddress,
    [string]$PrivateKey,
    [string]$Script
) {
    try {
        return Invoke-Process -FileName $ssh -Arguments @(
            '-o', 'BatchMode=yes',
            '-o', 'ConnectTimeout=8',
            '-o', 'StrictHostKeyChecking=yes',
            '-o', "UserKnownHostsFile=$knownHosts",
            '-i', $PrivateKey,
            "$username@$IpAddress",
            'sudo sh -s'
        ) -StandardInput $Script -TimeoutSeconds 60
    } catch {
        throw "SSH 키 기반 설정 단계가 실패했습니다. $($_.Exception.Message)"
    }
}

function Test-TcpPort([string]$IpAddress, [int]$Port) {
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $pending = $client.ConnectAsync($IpAddress, $Port)
        return $pending.Wait(1500) -and $client.Connected
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

function Get-GuestIpAddress(
    [string]$VmxPath,
    [string]$FallbackIpAddress = ''
) {
    $vmxText = [IO.File]::ReadAllText($VmxPath, [Text.Encoding]::UTF8)
    $macMatch = [regex]::Match(
        $vmxText,
        '(?im)^ethernet0\.(?:address|generatedAddress)\s*=\s*"([0-9a-f:]{17})"'
    )
    if (-not $macMatch.Success) {
        throw 'VMX에서 Linux VM MAC 주소를 찾지 못했습니다.'
    }
    $arpMac = $macMatch.Groups[1].Value.Replace(':', '-').ToLowerInvariant()
    for ($attempt = 1; $attempt -le 40; $attempt++) {
        $candidates = [System.Collections.Generic.List[string]]::new()
        $parsedFallbackAddress = $null
        if (
            [Net.IPAddress]::TryParse(
                $FallbackIpAddress,
                [ref]$parsedFallbackAddress
            )
        ) {
            $candidates.Add($FallbackIpAddress)
        }
        try {
            $vmrunAddress = (Invoke-Process -FileName $vmrun -Arguments @(
                '-T', 'ws', 'getGuestIPAddress', $VmxPath
            ) -TimeoutSeconds 10).Trim()
            $parsedVmrunAddress = $null
            if ([Net.IPAddress]::TryParse($vmrunAddress, [ref]$parsedVmrunAddress)) {
                $candidates.Add($vmrunAddress)
            }
        } catch {
            # VMware Tools가 없는 시험 VM은 VMX MAC과 NAT ARP를 사용합니다.
        }
        $arpLine = arp.exe -a |
            Where-Object { $_.ToLowerInvariant().Contains($arpMac) } |
            Select-Object -First 1
        if ($null -ne $arpLine -and $arpLine -match '(\d+\.\d+\.\d+\.\d+)') {
            if (-not $candidates.Contains($Matches[1])) {
                $candidates.Add($Matches[1])
            }
        }
        foreach ($candidate in $candidates) {
            if (Test-TcpPort -IpAddress $candidate -Port 22) {
                return $candidate
            }
        }
        Start-Sleep -Seconds 3
    }
    throw 'Linux VM의 SSH 가능한 NAT 주소를 제한 시간 안에 확인하지 못했습니다.'
}

function Stop-GuestGracefully(
    [string]$VmxPath,
    [string]$IpAddress,
    [string]$PrivateKey
) {
    try {
        Invoke-KeyAuthenticatedScript `
            -IpAddress $IpAddress `
            -PrivateKey $PrivateKey `
            -Script "systemctl poweroff --no-block`n" |
            Out-Null
    } catch {
        # 전원 종료 과정에서 SSH 연결이 먼저 닫힐 수 있으므로 실제 VM 상태로 판정합니다.
    }
    for ($attempt = 1; $attempt -le 30; $attempt++) {
        $running = @(& $vmrun list | Select-Object -Skip 1)
        if ($running -notcontains $VmxPath) {
            return
        }
        Start-Sleep -Seconds 2
    }
    throw 'Linux VM을 게스트 OS 명령으로 정상 종료하지 못했습니다.'
}

function Test-PasswordAuthentication(
    [string]$IpAddress,
    [string]$AskPassPath
) {
    try {
        $output = Invoke-Process -FileName $ssh -Arguments @(
            '-o', 'BatchMode=no',
            '-o', 'ConnectTimeout=8',
            '-o', 'NumberOfPasswordPrompts=1',
            '-o', 'PreferredAuthentications=password',
            '-o', 'PubkeyAuthentication=no',
            '-o', 'KbdInteractiveAuthentication=no',
            '-o', 'StrictHostKeyChecking=yes',
            '-o', "UserKnownHostsFile=$knownHosts",
            "$username@$IpAddress",
            'printf SECAI_LAB_PASSWORD_LOGIN_OK'
        ) -Environment @{
            DISPLAY = 'secai-local'
            SSH_ASKPASS = $AskPassPath
            SSH_ASKPASS_REQUIRE = 'force'
            SECAI_LAB_PASSWORD = $password
        } -TimeoutSeconds 30
    } catch {
        throw "SSH 비밀번호 재로그인 단계가 실패했습니다. $($_.Exception.Message)"
    }
    return $output.Trim() -eq 'SECAI_LAB_PASSWORD_LOGIN_OK'
}

$askPassPath = Join-Path ([System.IO.Path]::GetTempPath()) (
    "secai-ssh-askpass-$([guid]::NewGuid().ToString('N')).exe"
)
$askPassSourcePath = [IO.Path]::ChangeExtension($askPassPath, '.cs')
$askPassSource = @'
using System;

public static class SecAiSshAskPass
{
    public static void Main()
    {
        Console.WriteLine(Environment.GetEnvironmentVariable("SECAI_LAB_PASSWORD"));
    }
}
'@
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $csc -PathType Leaf)) {
    throw 'SSH 비밀번호 검증용 임시 실행기를 만들 C# 컴파일러를 찾을 수 없습니다.'
}
[IO.File]::WriteAllText(
    $askPassSourcePath,
    $askPassSource,
    [Text.UTF8Encoding]::new($false)
)
Invoke-Process -FileName $csc -Arguments @(
    '/nologo',
    '/target:exe',
    "/out:$askPassPath",
    $askPassSourcePath
) | Out-Null

$runningBefore = @(& $vmrun list | Select-Object -Skip 1)
$results = [System.Collections.Generic.List[object]]::new()
try {
    foreach ($target in $targets) {
        $ipAddress = $null
        $targetConfig = $credentials.linux.targets.($target.Id)
        if ($null -eq $targetConfig) {
            throw "통합 파일에 Linux 대상이 없습니다: $($target.Id)"
        }
        $vmxPath = Join-Path $runtimeRoot $target.Vmx
        $privateKey = Join-Path $projectRoot ([string]$targetConfig.private_key_file)
        if (
            -not (Test-Path -LiteralPath $vmxPath -PathType Leaf) -or
            -not (Test-Path -LiteralPath $privateKey -PathType Leaf)
        ) {
            throw "VM 또는 SSH 개인키를 찾을 수 없습니다: $($target.Label)"
        }

        $wasRunning = $runningBefore -contains $vmxPath
        if (-not $wasRunning) {
            Invoke-Process -FileName $vmrun -Arguments @('start', $vmxPath, 'nogui') |
                Out-Null
        }
        try {
            $ipAddress = Get-GuestIpAddress `
                -VmxPath $vmxPath `
                -FallbackIpAddress $target.IpAddress
            Write-Host "설정·검증 중: $($target.Label)"

            $credentialLine = "$username`:$password`n"
            $credentialBase64 = [Convert]::ToBase64String(
                [System.Text.Encoding]::UTF8.GetBytes($credentialLine)
            )
            $remoteScript = @"
set -u
printf '%s' '$credentialBase64' | base64 -d | chpasswd || { printf 'STAGE_CHANGEPASS_FAILED\n'; exit 11; }
umask 077
printf '%s\n' 'PasswordAuthentication yes' 'PermitRootLogin no' 'MaxAuthTries 6' > /etc/ssh/sshd_config.d/00-secai-lab-password.conf || { printf 'STAGE_CONFIG_WRITE_FAILED\n'; exit 12; }
sshd -t || { printf 'STAGE_CONFIG_VALIDATE_FAILED\n'; exit 13; }
(systemctl reload sshd 2>/dev/null || systemctl reload ssh) || { printf 'STAGE_RELOAD_FAILED\n'; exit 14; }
sshd -T | grep -q '^passwordauthentication yes$' || { printf 'STAGE_EFFECTIVE_CONFIG_FAILED\n'; exit 15; }
passwd -S '$username' | grep -Eq '^$username[[:space:]]+P(S)?[[:space:]]' || { printf 'STAGE_ACCOUNT_UNLOCK_FAILED\n'; exit 16; }
printf 'SECAI_LAB_PASSWORD_CONFIGURED\n'
"@
            $remoteOutput = Invoke-KeyAuthenticatedScript `
                -IpAddress $ipAddress `
                -PrivateKey $privateKey `
                -Script $remoteScript
            if ($remoteOutput.Trim() -ne 'SECAI_LAB_PASSWORD_CONFIGURED') {
                throw "Linux 비밀번호 설정 검증에 실패했습니다: $($target.Label)"
            }
            if (-not (Test-PasswordAuthentication -IpAddress $ipAddress -AskPassPath $askPassPath)) {
                throw "Linux 비밀번호 로그인 시험에 실패했습니다: $($target.Label)"
            }
            $results.Add([pscustomobject]@{
                Target = $target.Label
                PasswordAuthentication = 'PASS'
                OriginalRunningStatePreserved = $wasRunning -or -not $KeepStarted
            })
        } finally {
            if (-not $wasRunning -and -not $KeepStarted) {
                if ([string]::IsNullOrWhiteSpace($ipAddress)) {
                    throw "원래 꺼져 있던 VM의 정상 종료 주소를 확인하지 못했습니다: $($target.Label)"
                }
                Stop-GuestGracefully `
                    -VmxPath $vmxPath `
                    -IpAddress $ipAddress `
                    -PrivateKey $privateKey
            }
        }
    }
} finally {
    $password = $null
    $credentials = $null
    Remove-Item -LiteralPath $askPassPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $askPassSourcePath -Force -ErrorAction SilentlyContinue
}

$results | Format-Table -AutoSize

[CmdletBinding()]
param(
    [ValidateSet('Prepare', 'Start', 'Stop', 'Snapshot', 'Restore', 'Status')]
    [string]$Action = 'Status',
    [ValidateSet('22.04', '24.04')]
    [string]$Version = '24.04',
    [ValidatePattern('^[A-Za-z0-9._-]{1,64}$')]
    [string]$SnapshotName = 'secai-initial-vulnerable'
)

if ($Version -eq '22.04') {
    $cloudLabScript = Join-Path $PSScriptRoot 'rocky-lab.ps1'
    & $cloudLabScript -Action $Action -Distribution Ubuntu22 -SnapshotName $SnapshotName
    exit 0
}

$ErrorActionPreference = 'Stop'
$vmwareRoot = 'C:\Program Files (x86)\VMware\VMware Workstation'
$vmrun = Join-Path $vmwareRoot 'vmrun.exe'
$ovfTool = Join-Path $vmwareRoot 'OVFTool\ovftool.exe'
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$runtimeRoot = Join-Path $projectRoot '.runtime\vmware'
$downloadRoot = Join-Path $runtimeRoot 'downloads'
$releaseCode = if ($Version -eq '22.04') { 'jammy' } else { 'noble' }
$versionToken = $Version.Replace('.', '')
$hostname = "secai-ubuntu-$versionToken-lab"
$vmName = "SecAI-Ubuntu-$Version-Lab"
$machineRoot = Join-Path $runtimeRoot "ubuntu-$Version-lab"
$vmxPath = Join-Path $machineRoot "$vmName.vmx"
$privateKey = Join-Path $runtimeRoot "${hostname}-ed25519"
$publicKey = "$privateKey.pub"
$knownHosts = Join-Path $runtimeRoot 'known_hosts'
$ovaName = "ubuntu-$Version-server-cloudimg-amd64.ova"
$releaseBase = "https://cloud-images.ubuntu.com/releases/$releaseCode/release"
$ovaPath = Join-Path $downloadRoot $ovaName
$checksumsPath = Join-Path $downloadRoot "SHA256SUMS-ubuntu-$Version"
$cloudInitTemplate = Join-Path $PSScriptRoot 'ubuntu-cloud-init.yaml.tmpl'

function Assert-Tool([string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label 실행 파일을 찾을 수 없습니다: $Path"
    }
}

function Invoke-Vmrun([string[]]$Arguments) {
    & $vmrun @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "vmrun 명령이 실패했습니다: $($Arguments -join ' ')"
    }
}

function Test-VmRunning {
    if (-not (Test-Path -LiteralPath $vmxPath -PathType Leaf)) {
        return $false
    }
    $running = & $vmrun list
    if ($LASTEXITCODE -ne 0) {
        throw '실행 중인 VMware VM 목록을 확인하지 못했습니다.'
    }
    return $running -contains $vmxPath
}

function Get-SnapshotNames {
    if (-not (Test-Path -LiteralPath $vmxPath -PathType Leaf)) {
        return @()
    }
    $lines = & $vmrun listSnapshots $vmxPath
    if ($LASTEXITCODE -ne 0) {
        throw 'VMware 스냅샷 목록을 확인하지 못했습니다.'
    }
    return @($lines | Select-Object -Skip 1)
}

function Add-OrReplaceVmxValue(
    [System.Collections.Generic.List[string]]$Lines,
    [string]$Key,
    [string]$Value
) {
    $prefix = "$Key ="
    for ($index = $Lines.Count - 1; $index -ge 0; $index--) {
        if ($Lines[$index].StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            $Lines.RemoveAt($index)
        }
    }
    $Lines.Add("$Key = `"$Value`"")
}

function Set-IsolatedVmConfiguration([string]$EncodedUserData) {
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.AddRange([string[]](Get-Content -LiteralPath $vmxPath))
    Add-OrReplaceVmxValue $lines 'displayName' "SecAI Ubuntu $Version Isolated Lab"
    Add-OrReplaceVmxValue $lines 'ethernet0.connectionType' 'nat'
    Add-OrReplaceVmxValue $lines 'ethernet0.addressType' 'generated'
    Add-OrReplaceVmxValue $lines 'guestinfo.userdata' $EncodedUserData
    Add-OrReplaceVmxValue $lines 'guestinfo.userdata.encoding' 'base64'
    Add-OrReplaceVmxValue $lines 'guestinfo.metadata' ([Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes("instance-id: $hostname`nlocal-hostname: $hostname`n")
    ))
    Add-OrReplaceVmxValue $lines 'guestinfo.metadata.encoding' 'base64'
    Set-Content -LiteralPath $vmxPath -Value $lines -Encoding utf8
}

function Get-VerifiedOva {
    New-Item -ItemType Directory -Force -Path $downloadRoot | Out-Null
    Invoke-WebRequest -Uri "$releaseBase/SHA256SUMS" -OutFile $checksumsPath
    $escapedName = [regex]::Escape($ovaName)
    $match = Select-String -LiteralPath $checksumsPath -Pattern "^([a-f0-9]{64}) \*?$escapedName$"
    if ($null -eq $match -or $match.Matches.Count -ne 1) {
        throw 'Ubuntu 공식 SHA256SUMS에서 VMware OVA 확인값을 찾지 못했습니다.'
    }
    $expected = $match.Matches[0].Groups[1].Value
    if (-not (Test-Path -LiteralPath $ovaPath -PathType Leaf)) {
        Start-BitsTransfer -Source "$releaseBase/$ovaName" -Destination $ovaPath
    }
    $actual = (Get-FileHash -LiteralPath $ovaPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw 'Ubuntu OVA SHA-256 확인값이 공식 배포값과 일치하지 않습니다.'
    }
    return $ovaPath
}

function Get-OrCreateSshKey {
    if ((Test-Path -LiteralPath $privateKey) -and (Test-Path -LiteralPath $publicKey)) {
        return (Get-Content -LiteralPath $publicKey -Raw).Trim()
    }
    $sshKeygen = (Get-Command ssh-keygen -ErrorAction Stop).Source
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $sshKeygen
    $startInfo.UseShellExecute = $false
    foreach ($argument in @('-q', '-t', 'ed25519', '-N', '', '-C', "$hostname-isolated", '-f', $privateKey)) {
        $startInfo.ArgumentList.Add($argument)
    }
    $process = [System.Diagnostics.Process]::Start($startInfo)
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw '격리 실습 VM용 SSH 키를 생성하지 못했습니다.'
    }
    return (Get-Content -LiteralPath $publicKey -Raw).Trim()
}

function Wait-LabReady {
    $ip = (& $vmrun getGuestIPAddress $vmxPath -wait).Trim()
    $parsedIp = $null
    if (
        $LASTEXITCODE -ne 0 -or
        -not [System.Net.IPAddress]::TryParse($ip, [ref]$parsedIp)
    ) {
        throw '격리 VM의 NAT 주소를 확인하지 못했습니다.'
    }
    $ssh = (Get-Command ssh -ErrorAction Stop).Source
    for ($attempt = 1; $attempt -le 90; $attempt++) {
        & $ssh -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=accept-new `
            -o "UserKnownHostsFile=$knownHosts" -i $privateKey `
            "secai-lab@$ip" 'test -f /var/lib/secai-lab/initial-vulnerable-ready' 2>$null
        if ($LASTEXITCODE -eq 0) {
            return $ip
        }
        Start-Sleep -Seconds 3
    }
    throw 'Ubuntu cloud-init 초기화가 제한 시간 안에 완료되지 않았습니다.'
}

function Prepare-Lab {
    Assert-Tool $vmrun 'VMware vmrun'
    Assert-Tool $ovfTool 'VMware OVF Tool'
    New-Item -ItemType Directory -Force -Path $runtimeRoot | Out-Null
    $key = Get-OrCreateSshKey
    $template = Get-Content -LiteralPath $cloudInitTemplate -Raw
    $userData = $template.Replace('__SSH_PUBLIC_KEY__', $key).Replace(
        'secai-ubuntu-lab',
        $hostname
    )
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($userData))
    if (-not (Test-Path -LiteralPath $vmxPath -PathType Leaf)) {
        $sourceOva = Get-VerifiedOva
        New-Item -ItemType Directory -Force -Path $machineRoot | Out-Null
        & $ovfTool "--name=$vmName" `
            "--prop:instance-id=$hostname" `
            "--prop:hostname=$hostname" `
            "--prop:public-keys=$key" `
            "--prop:user-data=$encoded" `
            $sourceOva $vmxPath
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $vmxPath)) {
            throw 'Ubuntu OVA를 VMware VM으로 가져오지 못했습니다.'
        }
    }
    Set-IsolatedVmConfiguration $encoded
    if (-not (Test-VmRunning)) {
        Invoke-Vmrun @('start', $vmxPath, 'nogui')
    }
    $ip = Wait-LabReady
    if ((Get-SnapshotNames) -notcontains 'secai-initial-vulnerable') {
        Invoke-Vmrun @('stop', $vmxPath, 'soft')
        Invoke-Vmrun @('snapshot', $vmxPath, 'secai-initial-vulnerable')
    }
    Write-Output "VM 준비 완료: $vmxPath"
    Write-Output "초기 취약 상태 스냅샷: secai-initial-vulnerable"
    Write-Output "마지막 NAT 주소: $ip"
}

Assert-Tool $vmrun 'VMware vmrun'
switch ($Action) {
    'Prepare' { Prepare-Lab }
    'Start' {
        if (-not (Test-VmRunning)) { Invoke-Vmrun @('start', $vmxPath, 'nogui') }
        Write-Output "Ubuntu $Version 실습 VM을 실행했습니다."
    }
    'Stop' {
        if (Test-VmRunning) { Invoke-Vmrun @('stop', $vmxPath, 'soft') }
        Write-Output "Ubuntu $Version 실습 VM을 정지했습니다."
    }
    'Snapshot' {
        if ((Get-SnapshotNames) -contains $SnapshotName) {
            throw "같은 이름의 스냅샷이 이미 있습니다: $SnapshotName"
        }
        Invoke-Vmrun @('snapshot', $vmxPath, $SnapshotName)
        Write-Output "스냅샷을 만들었습니다: $SnapshotName"
    }
    'Restore' {
        if ((Get-SnapshotNames) -notcontains $SnapshotName) {
            throw "복원할 스냅샷을 찾지 못했습니다: $SnapshotName"
        }
        if (Test-VmRunning) { Invoke-Vmrun @('stop', $vmxPath, 'hard') }
        Invoke-Vmrun @('revertToSnapshot', $vmxPath, $SnapshotName)
        Invoke-Vmrun @('start', $vmxPath, 'nogui')
        Write-Output "스냅샷으로 복원했습니다: $SnapshotName"
    }
    'Status' {
        [pscustomobject]@{
            VmxPath = $vmxPath
            Imported = Test-Path -LiteralPath $vmxPath -PathType Leaf
            Running = Test-VmRunning
            Snapshots = (Get-SnapshotNames) -join ', '
            Network = 'NAT'
            Distribution = "Ubuntu $Version"
            Login = 'secai-lab (SSH key only)'
        } | Format-List
    }
}

[CmdletBinding()]
param(
    [ValidateSet('Prepare', 'Start', 'Stop', 'Snapshot', 'Restore', 'Status')]
    [string]$Action = 'Status',
    [ValidateSet('Ubuntu22', 'Rocky9', 'Debian12', 'RHEL9', 'AlmaLinux9')]
    [string]$Distribution = 'Rocky9',
    [string]$SourceImagePath = '',
    [ValidatePattern('^$|^[a-fA-F0-9]{64}$')]
    [string]$SourceImageSha256 = '',
    [ValidatePattern('^[A-Za-z0-9._-]{1,64}$')]
    [string]$SnapshotName = 'secai-initial-vulnerable'
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$vmwareRoot = 'C:\Program Files (x86)\VMware\VMware Workstation'
$vmrun = Join-Path $vmwareRoot 'vmrun.exe'
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$runtimeRoot = Join-Path $projectRoot '.runtime\vmware'
$downloadRoot = Join-Path $runtimeRoot 'downloads'
$distributionCatalog = @{
    Ubuntu22 = @{
        Label = 'Ubuntu Server 22.04 LTS'
        Slug = 'ubuntu-22.04-cloud'
        Hostname = 'secai-ubuntu2204-cloud-lab'
        VmName = 'SecAI-Ubuntu-22.04-Cloud-Lab'
        GuestOs = 'ubuntu-64'
        AdminGroup = 'sudo'
        Platform = 'ubuntu-22.04'
        StaticMac = '00:50:56:3a:90:22'
        ImageName = 'ubuntu-22.04-server-cloudimg-amd64.img'
        ReleaseBase = 'https://cloud-images.ubuntu.com/releases/jammy/release'
        ChecksumName = 'SHA256SUMS'
        ChecksumAlgorithm = 'SHA256'
        ChecksumStyle = 'SUMS'
    }
    Rocky9 = @{
        Label = 'Rocky Linux 9'
        Slug = 'rocky-9'
        Hostname = 'secai-rocky9-lab'
        VmName = 'SecAI-Rocky-9-Lab'
        GuestOs = 'rhel9-64'
        AdminGroup = 'wheel'
        Platform = 'rocky-linux-9'
        StaticMac = '00:50:56:3a:90:09'
        ImageName = 'Rocky-9-GenericCloud-Base-9.8-20260525.0.x86_64.qcow2'
        ReleaseBase = 'https://download.rockylinux.org/pub/rocky/9.8/images/x86_64'
        ChecksumName = 'Rocky-9-GenericCloud-Base-9.8-20260525.0.x86_64.qcow2.CHECKSUM'
        ChecksumAlgorithm = 'SHA256'
        ChecksumStyle = 'ROCKY'
    }
    Debian12 = @{
        Label = 'Debian 12'
        Slug = 'debian-12'
        Hostname = 'secai-debian12-lab'
        VmName = 'SecAI-Debian-12-Lab'
        GuestOs = 'debian12-64'
        AdminGroup = 'sudo'
        Platform = 'debian-12'
        StaticMac = '00:50:56:3a:90:12'
        ImageName = 'debian-12-genericcloud-amd64.qcow2'
        ReleaseBase = 'https://cloud.debian.org/images/cloud/bookworm/latest'
        ChecksumName = 'SHA512SUMS'
        ChecksumAlgorithm = 'SHA512'
        ChecksumStyle = 'SUMS'
    }
    RHEL9 = @{
        Label = 'Red Hat Enterprise Linux 9'
        Slug = 'rhel-9'
        Hostname = 'secai-rhel9-lab'
        VmName = 'SecAI-RHEL-9-Lab'
        GuestOs = 'rhel9-64'
        AdminGroup = 'wheel'
        Platform = 'rhel-9'
        StaticMac = '00:50:56:3a:90:19'
        ImageName = 'rhel-9-guest-image.x86_64.qcow2'
        ReleaseBase = ''
        ChecksumName = ''
        ChecksumAlgorithm = 'SHA256'
        ChecksumStyle = 'LOCAL'
    }
    AlmaLinux9 = @{
        Label = 'AlmaLinux 9'
        Slug = 'almalinux-9'
        Hostname = 'secai-alma9-lab'
        VmName = 'SecAI-AlmaLinux-9-Lab'
        GuestOs = 'rhel9-64'
        AdminGroup = 'wheel'
        Platform = 'almalinux-9'
        StaticMac = '00:50:56:3a:90:29'
        ImageName = 'AlmaLinux-9-GenericCloud-latest.x86_64.qcow2'
        ReleaseBase = 'https://repo.almalinux.org/almalinux/9/cloud/x86_64/images'
        ChecksumName = 'CHECKSUM'
        ChecksumAlgorithm = 'SHA256'
        ChecksumStyle = 'SUMS'
    }
}
$lab = $distributionCatalog[$Distribution]
$machineDirectoryName = "$($lab.Slug)-lab"
$machineRoot = Join-Path $runtimeRoot $machineDirectoryName
$vmxPath = Join-Path $machineRoot "$($lab.VmName).vmx"
$diskFileName = "$($lab.VmName).vmdk"
$diskPath = Join-Path $machineRoot $diskFileName
$seedRoot = Join-Path $machineRoot 'cloud-init-seed'
$seedFileName = "$($lab.Slug)-cloud-init.iso"
$seedIsoPath = Join-Path $machineRoot $seedFileName
$privateKey = Join-Path $runtimeRoot "$($lab.Hostname)-ed25519"
$publicKey = "$privateKey.pub"
$knownHosts = Join-Path $runtimeRoot 'known_hosts'
$imageName = [string]$lab.ImageName
$releaseBase = [string]$lab.ReleaseBase
$imagePath = Join-Path $downloadRoot $imageName
$checksumPath = Join-Path $downloadRoot "$($lab.Slug)-$($lab.ChecksumName)"
$cloudInitTemplate = Join-Path $PSScriptRoot 'rocky-cloud-init.yaml.tmpl'
$converterDockerfile = Join-Path $PSScriptRoot 'Dockerfile.qemu-img'
$converterImage = 'secai/vmware-qemu-img:alpine3.22-v2'
$staticMac = [string]$lab.StaticMac

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

function Stop-LabVm([string]$GuestIp = '') {
    if (-not [string]::IsNullOrWhiteSpace($GuestIp)) {
        $ssh = (Get-Command ssh -ErrorAction Stop).Source
        & $ssh -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=accept-new `
            -o "UserKnownHostsFile=$knownHosts" -i $privateKey `
            "secai-lab@$GuestIp" 'sudo systemctl poweroff' 2>$null | Out-Null
        for ($attempt = 1; $attempt -le 20; $attempt++) {
            if (-not (Test-VmRunning)) {
                return
            }
            Start-Sleep -Seconds 2
        }
    }
    if (Test-VmRunning) {
        & $vmrun stop $vmxPath hard 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "$($lab.Label) VM을 정지하지 못했습니다."
        }
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

function Get-VerifiedCloudImage {
    New-Item -ItemType Directory -Force -Path $downloadRoot | Out-Null
    $checksumStyle = [string]$lab.ChecksumStyle
    if ($checksumStyle -eq 'LOCAL') {
        if (
            [string]::IsNullOrWhiteSpace($SourceImagePath) -or
            -not (Test-Path -LiteralPath $SourceImagePath -PathType Leaf) -or
            [string]::IsNullOrWhiteSpace($SourceImageSha256)
        ) {
            throw 'RHEL 9는 Red Hat 구독으로 받은 qcow2 경로와 SHA-256을 함께 지정해야 합니다.'
        }
        $source = [System.IO.Path]::GetFullPath($SourceImagePath)
        $expected = $SourceImageSha256.ToLowerInvariant()
        $sourceActual = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($sourceActual -ne $expected) {
            throw '지정한 RHEL 9 이미지 SHA-256이 입력한 확인값과 일치하지 않습니다.'
        }
        if (-not (Test-Path -LiteralPath $imagePath -PathType Leaf)) {
            Copy-Item -LiteralPath $source -Destination $imagePath
        }
    } else {
        $checksumUri = "$releaseBase/$($lab.ChecksumName)"
        Invoke-WebRequest -Uri $checksumUri -OutFile $checksumPath
        $checksumText = Get-Content -LiteralPath $checksumPath -Raw
        $escapedName = [regex]::Escape($imageName)
        $hashLength = if ($lab.ChecksumAlgorithm -eq 'SHA512') { 128 } else { 64 }
        if ($checksumStyle -eq 'ROCKY') {
            $pattern = "SHA256 \($escapedName\) = ([a-fA-F0-9]{64})"
        } else {
            $pattern = "(?m)^([a-fA-F0-9]{$hashLength})\s+\*?$escapedName\s*$"
        }
        $match = [regex]::Match($checksumText, $pattern)
        if (-not $match.Success) {
            throw "$($lab.Label) 공식 확인값에서 qcow2 항목을 찾지 못했습니다."
        }
        $expected = $match.Groups[1].Value.ToLowerInvariant()
        if (-not (Test-Path -LiteralPath $imagePath -PathType Leaf)) {
            Start-BitsTransfer -Source "$releaseBase/$imageName" -Destination $imagePath
        }
    }
    $actual = (Get-FileHash -LiteralPath $imagePath -Algorithm $lab.ChecksumAlgorithm).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "$($lab.Label) qcow2 확인값이 공식 또는 입력 배포값과 일치하지 않습니다."
    }
    return $imagePath
}

function Get-OrCreateSshKey {
    if ((Test-Path -LiteralPath $privateKey) -and (Test-Path -LiteralPath $publicKey)) {
        return (Get-Content -LiteralPath $publicKey -Raw).Trim()
    }
    $sshKeygen = (Get-Command ssh-keygen -ErrorAction Stop).Source
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $sshKeygen
    $startInfo.UseShellExecute = $false
    foreach ($argument in @('-q', '-t', 'ed25519', '-N', '', '-C', "$($lab.Hostname)-isolated", '-f', $privateKey)) {
        $startInfo.ArgumentList.Add($argument)
    }
    $process = [System.Diagnostics.Process]::Start($startInfo)
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw '격리 실습 VM용 SSH 키를 생성하지 못했습니다.'
    }
    return (Get-Content -LiteralPath $publicKey -Raw).Trim()
}

function Assert-ConverterImage {
    & docker image inspect $converterImage 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        return
    }
    & docker build --pull -f $converterDockerfile -t $converterImage $projectRoot
    if ($LASTEXITCODE -ne 0) {
        throw 'Linux qcow2를 VMware VMDK로 변환할 도구 이미지를 만들지 못했습니다.'
    }
}

function Convert-ToVmwareDisk {
    if (Test-Path -LiteralPath $diskPath -PathType Leaf) {
        return
    }
    New-Item -ItemType Directory -Force -Path $machineRoot | Out-Null
    Assert-ConverterImage
    $mount = "type=bind,source=$runtimeRoot,target=/vmware"
    & docker run --rm --mount $mount $converterImage convert -p -f qcow2 -O vmdk `
        -o 'subformat=monolithicSparse,compat6' `
        "/vmware/downloads/$imageName" "/vmware/$machineDirectoryName/$diskFileName"
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $diskPath -PathType Leaf)) {
        throw "$($lab.Label) qcow2를 VMware VMDK로 변환하지 못했습니다."
    }
}

function New-NoCloudSeed([string]$SshPublicKey) {
    if (Test-Path -LiteralPath $seedIsoPath -PathType Leaf) {
        return
    }
    Assert-ConverterImage
    New-Item -ItemType Directory -Force -Path $seedRoot | Out-Null
    $template = Get-Content -LiteralPath $cloudInitTemplate -Raw
    $userData = $template.Replace('__SSH_PUBLIC_KEY__', $SshPublicKey)
    $userData = $userData.Replace('__HOSTNAME__', [string]$lab.Hostname)
    $userData = $userData.Replace('__ADMIN_GROUP__', [string]$lab.AdminGroup)
    $userData = $userData.Replace('__PLATFORM__', [string]$lab.Platform)
    $userData = $userData.Replace('__DISTRIBUTION_LABEL__', [string]$lab.Label)
    Set-Content -LiteralPath (Join-Path $seedRoot 'user-data') -Value $userData -Encoding utf8
    Set-Content -LiteralPath (Join-Path $seedRoot 'meta-data') `
        -Value "instance-id: $($lab.Hostname)`nlocal-hostname: $($lab.Hostname)`n" `
        -Encoding utf8
    $mount = "type=bind,source=$runtimeRoot,target=/vmware"
    & docker run --rm --mount $mount --entrypoint xorriso $converterImage `
        -as mkisofs -output "/vmware/$machineDirectoryName/$seedFileName" `
        -volid cidata -joliet -rock `
        "/vmware/$machineDirectoryName/cloud-init-seed/user-data" `
        "/vmware/$machineDirectoryName/cloud-init-seed/meta-data"
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $seedIsoPath -PathType Leaf)) {
        throw "$($lab.Label) NoCloud 초기 설정 ISO를 만들지 못했습니다."
    }
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

function Set-LinuxVmxHardwareCompatibility {
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.AddRange([string[]](Get-Content -LiteralPath $vmxPath))
    Add-OrReplaceVmxValue $lines 'pciBridge0.present' 'TRUE'
    Add-OrReplaceVmxValue $lines 'pciBridge0.pciSlotNumber' '17'
    $bridgeSlots = @{ 4 = '21'; 5 = '22'; 6 = '23'; 7 = '24' }
    foreach ($bridge in 4..7) {
        Add-OrReplaceVmxValue $lines "pciBridge$bridge.present" 'TRUE'
        Add-OrReplaceVmxValue $lines "pciBridge$bridge.virtualDev" 'pcieRootPort'
        Add-OrReplaceVmxValue $lines "pciBridge$bridge.functions" '8'
        Add-OrReplaceVmxValue $lines "pciBridge$bridge.pciSlotNumber" $bridgeSlots[$bridge]
    }
    Add-OrReplaceVmxValue $lines 'scsi0.virtualDev' 'pvscsi'
    Add-OrReplaceVmxValue $lines 'scsi0.pciSlotNumber' '160'
    Add-OrReplaceVmxValue $lines 'ethernet0.virtualDev' 'vmxnet3'
    Add-OrReplaceVmxValue $lines 'ethernet0.pciSlotNumber' '192'
    Add-OrReplaceVmxValue $lines 'ethernet0.addressType' 'static'
    Add-OrReplaceVmxValue $lines 'ethernet0.address' $staticMac
    Add-OrReplaceVmxValue $lines 'ide1:0.present' 'TRUE'
    Add-OrReplaceVmxValue $lines 'ide1:0.deviceType' 'cdrom-image'
    Add-OrReplaceVmxValue $lines 'ide1:0.fileName' (Split-Path -Leaf $seedIsoPath)
    Add-OrReplaceVmxValue $lines 'ide1:0.startConnected' 'TRUE'
    Add-OrReplaceVmxValue $lines 'ide1:0.autodetect' 'FALSE'
    Add-OrReplaceVmxValue $lines 'ide1:0.clientDevice' 'FALSE'
    Set-Content -LiteralPath $vmxPath -Value $lines -Encoding utf8
}

function New-LinuxVmx([string]$EncodedUserData) {
    $metadata = [Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes(
            "instance-id: $($lab.Hostname)`nlocal-hostname: $($lab.Hostname)`n"
        )
    )
    $diskName = Split-Path -Leaf $diskPath
    $lines = @(
        '.encoding = "UTF-8"'
        'config.version = "8"'
        'virtualHW.version = "20"'
        "displayName = `"SecAI $($lab.Label) Isolated Lab`""
        'annotation = "SecAI KISA UNIX read-only validation lab"'
        "guestOS = `"$($lab.GuestOs)`""
        'firmware = "efi"'
        'memsize = "4096"'
        'numvcpus = "2"'
        'cpuid.coresPerSocket = "2"'
        'pciBridge0.present = "TRUE"'
        'pciBridge4.present = "TRUE"'
        'pciBridge4.virtualDev = "pcieRootPort"'
        'pciBridge4.functions = "8"'
        'pciBridge5.present = "TRUE"'
        'pciBridge5.virtualDev = "pcieRootPort"'
        'pciBridge5.functions = "8"'
        'pciBridge6.present = "TRUE"'
        'pciBridge6.virtualDev = "pcieRootPort"'
        'pciBridge6.functions = "8"'
        'pciBridge7.present = "TRUE"'
        'pciBridge7.virtualDev = "pcieRootPort"'
        'pciBridge7.functions = "8"'
        'scsi0.present = "TRUE"'
        'scsi0.virtualDev = "pvscsi"'
        'scsi0:0.present = "TRUE"'
        "scsi0:0.fileName = `"$diskName`""
        'ethernet0.present = "TRUE"'
        'ethernet0.connectionType = "nat"'
        'ethernet0.addressType = "static"'
        "ethernet0.address = `"$staticMac`""
        'ethernet0.virtualDev = "vmxnet3"'
        'ide1:0.present = "TRUE"'
        'ide1:0.deviceType = "cdrom-image"'
        "ide1:0.fileName = `"$seedFileName`""
        'ide1:0.startConnected = "TRUE"'
        'ide1:0.autodetect = "FALSE"'
        'ide1:0.clientDevice = "FALSE"'
        'usb.present = "FALSE"'
        'sound.present = "FALSE"'
        'mks.enable3d = "FALSE"'
        'tools.syncTime = "TRUE"'
        'isolation.tools.copy.disable = "TRUE"'
        'isolation.tools.paste.disable = "TRUE"'
        'isolation.tools.dragAndDrop.disable = "TRUE"'
        'isolation.tools.hgfs.disable = "TRUE"'
        "guestinfo.userdata = `"$EncodedUserData`""
        'guestinfo.userdata.encoding = "base64"'
        "guestinfo.metadata = `"$metadata`""
        'guestinfo.metadata.encoding = "base64"'
    )
    Set-Content -LiteralPath $vmxPath -Value $lines -Encoding utf8
}

function Wait-LabReady {
    $ssh = (Get-Command ssh -ErrorAction Stop).Source
    $ip = $null
    $macForArp = $staticMac.Replace(':', '-').ToLowerInvariant()
    for ($attempt = 1; $attempt -le 120; $attempt++) {
        $guestAddress = & $vmrun -T ws getGuestIPAddress $vmxPath 2>$null | Select-Object -First 1
        if ($LASTEXITCODE -eq 0 -and $guestAddress -match '^\d+\.\d+\.\d+\.\d+$') {
            $ip = $guestAddress.Trim()
        }
        if ([string]::IsNullOrWhiteSpace($ip)) {
            $arpLine = arp.exe -a | Where-Object { $_.ToLowerInvariant().Contains($macForArp) } |
                Select-Object -First 1
            if ($null -ne $arpLine -and $arpLine -match '(\d+\.\d+\.\d+\.\d+)') {
                $ip = $Matches[1]
            }
        }
        if ([string]::IsNullOrWhiteSpace($ip)) {
            Start-Sleep -Seconds 3
            continue
        }
        & $ssh -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=accept-new `
            -o "UserKnownHostsFile=$knownHosts" -i $privateKey `
            "secai-lab@$ip" 'test -f /var/lib/secai-lab/initial-vulnerable-ready' 2>$null
        if ($LASTEXITCODE -eq 0) {
            return $ip
        }
        $ip = $null
        Start-Sleep -Seconds 3
    }
    throw "$($lab.Label) cloud-init 초기화가 제한 시간 안에 완료되지 않았습니다."
}

function Prepare-Lab {
    Assert-Tool $vmrun 'VMware vmrun'
    if ($null -eq (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw 'qcow2 변환에 필요한 Docker CLI를 찾을 수 없습니다.'
    }
    New-Item -ItemType Directory -Force -Path $runtimeRoot | Out-Null
    $key = Get-OrCreateSshKey
    Get-VerifiedCloudImage | Out-Null
    Convert-ToVmwareDisk
    New-NoCloudSeed $key
    if (-not (Test-Path -LiteralPath $vmxPath -PathType Leaf)) {
        $template = Get-Content -LiteralPath $cloudInitTemplate -Raw
        $userData = $template.Replace('__SSH_PUBLIC_KEY__', $key)
        $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($userData))
        New-LinuxVmx $encoded
    }
    Set-LinuxVmxHardwareCompatibility
    if (-not (Test-VmRunning)) {
        Invoke-Vmrun @('start', $vmxPath, 'nogui')
    }
    $ip = Wait-LabReady
    if ((Get-SnapshotNames) -notcontains 'secai-initial-vulnerable') {
        Stop-LabVm $ip
        Invoke-Vmrun @('snapshot', $vmxPath, 'secai-initial-vulnerable')
    }
    Write-Output "VM 준비 완료: $vmxPath"
    Write-Output '초기 취약 상태 스냅샷: secai-initial-vulnerable'
    Write-Output "마지막 NAT 주소: $ip"
    Write-Output "SSH 사용자: secai-lab (키: $privateKey)"
}

Assert-Tool $vmrun 'VMware vmrun'
switch ($Action) {
    'Prepare' { Prepare-Lab }
    'Start' {
        if (-not (Test-Path -LiteralPath $vmxPath -PathType Leaf)) {
        throw "$($lab.Label) VM이 아직 준비되지 않았습니다. -Action Prepare를 먼저 실행하세요."
        }
        if (-not (Test-VmRunning)) { Invoke-Vmrun @('start', $vmxPath, 'nogui') }
        Write-Output "$($lab.Label) 실습 VM을 백그라운드에서 실행했습니다."
    }
    'Stop' {
        if (Test-VmRunning) { Stop-LabVm }
        Write-Output "$($lab.Label) 실습 VM을 정지했습니다."
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
            Distribution = $lab.Label
            Login = 'secai-lab (SSH key only)'
        } | Format-List
    }
}

# IMP-029 fixed read-only Windows context and PC-07 storage probe.
# This script intentionally accepts no parameters and contains no setting mutation.
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

function Convert-BusType {
    param([object]$Value)
    $text = ([string]$Value).Trim().ToUpperInvariant()
    switch ($text) {
        "NVME" { return "NVME" }
        "SATA" { return "SATA" }
        "SAS" { return "SAS" }
        "USB" { return "USB" }
        "FILE BACKED VIRTUAL" { return "FILE_BACKED_VIRTUAL" }
        "STORAGE SPACES" { return "STORAGE_SPACES" }
        default { return "UNKNOWN" }
    }
}

function Convert-DriveType {
    param([object]$Value)
    $text = ([string]$Value).Trim().ToUpperInvariant()
    switch ($text) {
        "FIXED" { return "FIXED" }
        "REMOVABLE" { return "REMOVABLE" }
        "NETWORK" { return "NETWORK" }
        "CD-ROM" { return "CDROM" }
        "CDROM" { return "CDROM" }
        "RAM DISK" { return "RAMDISK" }
        "RAMDISK" { return "RAMDISK" }
        default { return "UNKNOWN" }
    }
}

function Convert-HealthStatus {
    param([object]$Value)
    $text = ([string]$Value).Trim().ToUpperInvariant()
    switch ($text) {
        "HEALTHY" { return "HEALTHY" }
        "WARNING" { return "WARNING" }
        "UNHEALTHY" { return "UNHEALTHY" }
        default { return "UNKNOWN" }
    }
}

function Convert-OperationalStatus {
    param([object]$Value)
    $values = @($Value)
    $text = (($values | ForEach-Object { [string]$_ }) -join ",").ToUpperInvariant()
    if ($text.Contains("ERROR")) { return "ERROR" }
    if ($text.Contains("OFFLINE")) { return "OFFLINE" }
    if ($text.Contains("DEGRADED")) { return "DEGRADED" }
    if ($text.Contains("OK") -or $text.Contains("ONLINE")) { return "OK" }
    return "UNKNOWN"
}

function Get-PartitionIdentity {
    param([object]$Partition)
    $gptType = ([string]$Partition.GptType).Trim("{}").ToUpperInvariant()
    $role = "UNKNOWN"
    $trusted = $false
    switch ($gptType) {
        "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" {
            $role = "EFI_SYSTEM"
            $trusted = $true
        }
        "E3C9E316-0B5C-4DB8-817D-F92DF00215AE" {
            $role = "MICROSOFT_RESERVED"
            $trusted = $true
        }
        "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC" {
            $role = "WINDOWS_RECOVERY"
            $trusted = $true
        }
        "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7" {
            $role = "DATA"
            $trusted = $true
        }
        default {
            if ($Partition.IsBoot -or $Partition.IsSystem) {
                $role = "DATA"
            }
        }
    }
    return @{
        gpt_type = if ($gptType -match "^[0-9A-F-]{36}$") {
            $gptType
        } else {
            "00000000-0000-0000-0000-000000000000"
        }
        role = $role
        trusted = $trusted
    }
}

function Get-VolumeClass {
    param(
        [object]$Partition,
        [object]$Disk,
        [object]$Volume,
        [hashtable]$Identity,
        [string]$MountKind
    )
    switch ($Identity.role) {
        "EFI_SYSTEM" { return "EFI_SYSTEM_PARTITION" }
        "MICROSOFT_RESERVED" { return "MICROSOFT_RESERVED_PARTITION" }
        "WINDOWS_RECOVERY" { return "WINDOWS_RECOVERY_PARTITION" }
    }
    if ($Partition.IsBoot -or $Partition.IsSystem) { return "WINDOWS_OS_VOLUME" }
    $driveType = if ($null -eq $Volume) { "UNKNOWN" } else { Convert-DriveType $Volume.DriveType }
    if ($driveType -eq "REMOVABLE") { return "REMOVABLE_VOLUME" }
    if ($driveType -eq "CDROM") { return "OPTICAL_VOLUME" }
    if ($driveType -eq "RAMDISK") { return "VOLATILE_RAM_DISK" }
    $busType = Convert-BusType $Disk.BusType
    if ($busType -eq "FILE_BACKED_VIRTUAL") { return "ATTACHED_VHD_VOLUME" }
    if ($busType -eq "STORAGE_SPACES") { return "STORAGE_SPACES_LOGICAL_VOLUME" }
    if ($MountKind -eq "FOLDER_MOUNT") { return "MOUNTED_FOLDER_VOLUME" }
    return "LOCAL_FIXED_DATA_VOLUME"
}

function Get-BitLockerMap {
    $result = @{}
    if ($null -eq (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
        return $result
    }
    try {
        foreach ($item in @(Get-BitLockerVolume -ErrorAction Stop)) {
            $mountPoint = ([string]$item.MountPoint).TrimEnd("\").ToUpperInvariant()
            if ([string]::IsNullOrWhiteSpace($mountPoint)) { continue }
            if (([string]$item.LockStatus).ToUpperInvariant() -eq "LOCKED") {
                $result[$mountPoint] = "LOCKED"
            } elseif (([string]$item.ProtectionStatus).ToUpperInvariant() -eq "ON") {
                $result[$mountPoint] = "UNLOCKED_PROTECTED"
            } else {
                $result[$mountPoint] = "UNLOCKED_UNPROTECTED"
            }
        }
    } catch {
        # Access failure is intentionally represented later as UNKNOWN when
        # filesystem visibility is also unavailable. It is never a FAIL.
    }
    return $result
}

$currentVersion = Get-ItemProperty `
    -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" `
    -ErrorAction Stop
$buildNumber = [int]$currentVersion.CurrentBuild
$productName = [string]$currentVersion.ProductName
$installationType = [string]$currentVersion.InstallationType
if ($buildNumber -ge 22000 -and $productName -like "*Windows 10*") {
    $productName = $productName.Replace("Windows 10", "Windows 11")
}
$isWindowsClient = $installationType -eq "Client"
$osVersion = if (-not $isWindowsClient) {
    "UNSUPPORTED"
} elseif ($buildNumber -ge 22000) {
    "11"
} elseif ($buildNumber -ge 10240) {
    "10"
} else {
    "UNSUPPORTED"
}
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
$isAdministrator = $principal.IsInRole(
    [System.Security.Principal.WindowsBuiltInRole]::Administrator
)
$integrityCandidates = @(
    $identity.Groups |
        ForEach-Object { $_.Value } |
        Where-Object { $_ -like "S-1-16-*" }
)
$integritySid = if ($integrityCandidates.Count -gt 0) {
    $integrityCandidates[0]
} else {
    ""
}
$integrityLevel = switch ($integritySid) {
    "S-1-16-4096" { "LOW" }
    "S-1-16-8192" { "MEDIUM" }
    "S-1-16-8448" { "MEDIUM_PLUS" }
    "S-1-16-12288" { "HIGH" }
    "S-1-16-16384" { "SYSTEM" }
    default { "UNKNOWN" }
}

$context = [ordered]@{
    os_family = "WINDOWS"
    os_version = $osVersion
    product_name = $productName
    display_version = [string]$currentVersion.DisplayVersion
    build_number = [string]$buildNumber
    ubr = [int]$currentVersion.UBR
    architecture = if ([Environment]::Is64BitOperatingSystem) { "x86_64" } else { "x86" }
    process_sid = [string]$identity.User.Value
    is_administrator = [bool]$isAdministrator
    integrity_level = $integrityLevel
    collected_at_utc = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

$disks = @{}
foreach ($disk in @(Get-Disk -ErrorAction Stop)) {
    $disks[[int]$disk.Number] = $disk
}
$partitions = @(
    Get-Partition -ErrorAction Stop |
        Sort-Object -Property DiskNumber, PartitionNumber
)
$bitLocker = Get-BitLockerMap
$subjects = [System.Collections.Generic.List[object]]::new()
$sequence = 0

foreach ($partition in $partitions) {
    $sequence += 1
    $volumeId = "vol-{0:D3}" -f $sequence
    $diskId = "disk-{0}" -f [int]$partition.DiskNumber
    $disk = $disks[[int]$partition.DiskNumber]
    if ($null -eq $disk) { throw "DISK_RELATION_UNAVAILABLE" }

    $volume = $null
    try {
        $volume = $partition | Get-Volume -ErrorAction Stop
    } catch {
        $volume = $null
    }
    $driveLetter = if ($null -ne $volume -and $null -ne $volume.DriveLetter) {
        ([string]$volume.DriveLetter).Trim().ToUpperInvariant()
    } else {
        $null
    }
    $hasFolderMount = @(
        $partition.AccessPaths |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace([string]$_) -and
                ([string]$_) -notlike "\\?\Volume{*"
            }
    ).Count -gt 0
    $mountKind = if (-not [string]::IsNullOrWhiteSpace($driveLetter)) {
        "DRIVE_LETTER"
    } elseif ($hasFolderMount) {
        "FOLDER_MOUNT"
    } else {
        "NO_MOUNT"
    }
    $partitionIdentity = Get-PartitionIdentity $partition
    $volumeClass = Get-VolumeClass $partition $disk $volume $partitionIdentity $mountKind
    $busType = Convert-BusType $disk.BusType
    $isVirtual = $busType -in @("FILE_BACKED_VIRTUAL", "STORAGE_SPACES")
    $storageKind = switch ($busType) {
        "FILE_BACKED_VIRTUAL" { "VHDX" }
        "STORAGE_SPACES" { "STORAGE_SPACES_LOGICAL" }
        default { "BASIC_DISK" }
    }
    $filesystem = if ($null -eq $volume -or [string]::IsNullOrWhiteSpace([string]$volume.FileSystem)) {
        $null
    } else {
        [string]$volume.FileSystem
    }
    $mountPoint = if ($null -eq $driveLetter) { "" } else { "$driveLetter`:" }
    $bitLockerState = if ($bitLocker.ContainsKey($mountPoint)) {
        $bitLocker[$mountPoint]
    } elseif ($null -eq $filesystem -and $volumeClass -notin @(
        "EFI_SYSTEM_PARTITION",
        "MICROSOFT_RESERVED_PARTITION",
        "WINDOWS_RECOVERY_PARTITION"
    )) {
        "UNKNOWN"
    } else {
        "NONE"
    }

    $subjects.Add([ordered]@{
        disk = [ordered]@{
            volume_id = $volumeId
            disk_id = $diskId
            volume_class = $volumeClass
            bus_type = $busType
            is_virtual = [bool]$isVirtual
            is_removable = [bool]($busType -eq "USB")
            is_online = [bool](([string]$disk.OperationalStatus) -notmatch "Offline")
            storage_kind = $storageKind
            disk_image_state = if ($isVirtual) { "ATTACHED" } else { "NOT_APPLICABLE" }
        }
        partition = [ordered]@{
            volume_id = $volumeId
            partition_role = $partitionIdentity.role
            gpt_type = $partitionIdentity.gpt_type
            trusted_role_identity = [bool]$partitionIdentity.trusted
            is_system = [bool]$partition.IsSystem
            is_boot = [bool]$partition.IsBoot
            is_hidden = [bool]$partition.IsHidden
        }
        volume = [ordered]@{
            volume_id = $volumeId
            filesystem = $filesystem
            volume_class = $volumeClass
            drive_type = if ($null -eq $volume) { "FIXED" } else { Convert-DriveType $volume.DriveType }
            drive_letter = $driveLetter
            mount_kind = $mountKind
            health_status = if ($null -eq $volume) { "UNKNOWN" } else { Convert-HealthStatus $volume.HealthStatus }
            operational_status = if ($null -eq $volume) { "UNKNOWN" } else { Convert-OperationalStatus $volume.OperationalStatus }
            bitlocker_state = $bitLockerState
        }
    })
}

$output = [ordered]@{
    schema_version = "1.0.0"
    context = $context
    subjects = @($subjects)
}
[Console]::Out.Write(($output | ConvertTo-Json -Depth 8 -Compress))

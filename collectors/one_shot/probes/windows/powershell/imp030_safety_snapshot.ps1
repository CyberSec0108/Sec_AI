# IMP-030 fixed read-only snapshot of settings the Collector must not change.
# Output contains only a SHA-256 digest and timestamp, never raw host settings.
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

function Read-ExecutionPolicyValue {
    param(
        [string]$LiteralPath
    )
    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Container)) {
        return "Undefined"
    }
    $item = Get-ItemProperty -LiteralPath $LiteralPath -ErrorAction Stop
    $property = $item.PSObject.Properties["ExecutionPolicy"]
    if ($null -eq $property -or [string]::IsNullOrWhiteSpace(
        [string]$property.Value
    )) {
        return "Undefined"
    }
    return [string]$property.Value
}

$executionPolicies = @(
    [ordered]@{
        scope = "MachinePolicy"
        execution_policy = Read-ExecutionPolicyValue `
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
    },
    [ordered]@{
        scope = "UserPolicy"
        execution_policy = Read-ExecutionPolicyValue `
            "HKCU:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
    },
    [ordered]@{
        scope = "Process"
        execution_policy = if ([string]::IsNullOrWhiteSpace(
            [string]$env:PSExecutionPolicyPreference
        )) {
            "Undefined"
        } else {
            [string]$env:PSExecutionPolicyPreference
        }
    },
    [ordered]@{
        scope = "CurrentUser"
        execution_policy = Read-ExecutionPolicyValue `
            "HKCU:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell"
    },
    [ordered]@{
        scope = "LocalMachine"
        execution_policy = Read-ExecutionPolicyValue `
            "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell"
    }
)

$disks = try {
    @(
        Get-Disk -ErrorAction Stop |
            Sort-Object -Property Number |
            ForEach-Object {
                [ordered]@{
                    number = [int]$_.Number
                    is_offline = [bool]$_.IsOffline
                    is_read_only = [bool]$_.IsReadOnly
                    partition_style = [string]$_.PartitionStyle
                }
            }
    )
} catch {
    @([ordered]@{ availability = "UNAVAILABLE" })
}

$partitions = try {
    @(
        Get-Partition -ErrorAction Stop |
            Sort-Object -Property DiskNumber, PartitionNumber |
            ForEach-Object {
                [ordered]@{
                    disk_number = [int]$_.DiskNumber
                    partition_number = [int]$_.PartitionNumber
                    drive_letter = if ($null -eq $_.DriveLetter) {
                        $null
                    } else {
                        [string]$_.DriveLetter
                    }
                    gpt_type = ([string]$_.GptType).Trim("{}").ToUpperInvariant()
                    is_active = [bool]$_.IsActive
                    is_hidden = [bool]$_.IsHidden
                    offset = [uint64]$_.Offset
                    size = [uint64]$_.Size
                }
            }
    )
} catch {
    @([ordered]@{ availability = "UNAVAILABLE" })
}

$volumes = try {
    @(
        Get-Volume -ErrorAction Stop |
            Sort-Object -Property DriveLetter, Path |
            ForEach-Object {
                [ordered]@{
                    drive_letter = if ($null -eq $_.DriveLetter) {
                        $null
                    } else {
                        [string]$_.DriveLetter
                    }
                    filesystem = [string]$_.FileSystem
                    drive_type = [string]$_.DriveType
                    size = [uint64]$_.Size
                }
            }
    )
} catch {
    @([ordered]@{ availability = "UNAVAILABLE" })
}

$bitLocker = @()
if ($null -ne (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
    try {
        $bitLocker = @(
            Get-BitLockerVolume -ErrorAction Stop |
                Sort-Object -Property MountPoint |
                ForEach-Object {
                    [ordered]@{
                        mount_point = [string]$_.MountPoint
                        lock_status = [string]$_.LockStatus
                        protection_status = [string]$_.ProtectionStatus
                    }
                }
        )
    } catch {
        $bitLocker = @([ordered]@{ availability = "UNAVAILABLE" })
    }
}

$surface = [ordered]@{
    execution_policies = $executionPolicies
    disks = $disks
    partitions = $partitions
    volumes = $volumes
    bitlocker = $bitLocker
}
$surfaceJson = $surface | ConvertTo-Json -Depth 7 -Compress
$hashAlgorithm = [System.Security.Cryptography.SHA256]::Create()
try {
    $digest = $hashAlgorithm.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($surfaceJson))
} finally {
    $hashAlgorithm.Dispose()
}
$output = [ordered]@{
    schema_version = "1.0.0"
    snapshot_sha256 = ([BitConverter]::ToString($digest) -replace "-", "").ToLowerInvariant()
    collected_at_utc = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}
[Console]::Out.Write(($output | ConvertTo-Json -Compress))

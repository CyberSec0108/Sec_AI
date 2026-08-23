# IMP-031 fixed standard-user Windows Probe set for PC-01~18.
# PC-07 storage remains in pc07_storage_context.ps1. This script accepts no
# parameters, changes no setting, requests no elevation, and emits JSON only.
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
$isAdministrator = $principal.IsInRole(
    [System.Security.Principal.WindowsBuiltInRole]::Administrator
)
if ($isAdministrator) {
    throw "STANDARD_PROCESS_MUST_NOT_BE_ELEVATED"
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
    is_administrator = $false
    integrity_level = $integrityLevel
    collected_at_utc = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

$results = [System.Collections.Generic.List[object]]::new()

function Add-ProbeResult {
    param(
        [string]$ProbeId,
        [string]$ControlId,
        [string]$AdapterId,
        [string]$AdapterVersion,
        [string]$Coverage,
        [scriptblock]$Reader
    )
    try {
        $records = @(& $Reader)
        $results.Add([ordered]@{
            probe_id = $ProbeId
            probe_version = "0.1.0"
            control_ids = @($ControlId)
            collection_status = "COLLECTED"
            error_code = "NONE"
            adapter_id = $AdapterId
            adapter_version = $AdapterVersion
            coverage = $Coverage
            records = $records
        })
    } catch {
        $caughtError = $_
        $message = [string]$caughtError.Exception.Message
        $fixedError = switch ($message) {
            "SOURCE_UNAVAILABLE" { "SOURCE_UNAVAILABLE" }
            "ADAPTER_UNSUPPORTED" { "ADAPTER_UNSUPPORTED" }
            default {
                if (
                    $caughtError.Exception -is [System.UnauthorizedAccessException] -or
                    $message -match "access.*denied|unauthorized|permission"
                ) {
                    "PERMISSION_DENIED"
                } else {
                    "QUERY_FAILED"
                }
            }
        }
        $results.Add([ordered]@{
            probe_id = $ProbeId
            probe_version = "0.1.0"
            control_ids = @($ControlId)
            collection_status = if ($fixedError -eq "ADAPTER_UNSUPPORTED") {
                "UNSUPPORTED"
            } else {
                "ERROR"
            }
            error_code = $fixedError
            adapter_id = $AdapterId
            adapter_version = $AdapterVersion
            coverage = $Coverage
            records = @()
        })
    }
}

function Read-RegistryValue {
    param(
        [string]$LiteralPath,
        [string]$Name
    )
    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Container)) {
        return $null
    }
    $item = Get-ItemProperty -LiteralPath $LiteralPath -ErrorAction Stop
    $property = $item.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

Add-ProbeResult `
    "win.security.password-age" "PC-01" "secai.windows-native" "0.1.0" `
    "EFFECTIVE_LOCAL_OR_DOMAIN_POLICY" {
        if ($null -eq ("SecAiNetPolicy" -as [type])) {
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class SecAiNetPolicy {
    [StructLayout(LayoutKind.Sequential)]
    private struct USER_MODALS_INFO_0 {
        public UInt32 min_passwd_len;
        public UInt32 max_passwd_age;
        public UInt32 min_passwd_age;
        public UInt32 force_logoff;
        public UInt32 password_hist_len;
    }
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern Int32 NetUserModalsGet(
        String servername, Int32 level, out IntPtr bufptr
    );
    [DllImport("netapi32.dll")]
    private static extern Int32 NetApiBufferFree(IntPtr buffer);
    public static UInt32 MaximumPasswordAgeSeconds() {
        IntPtr buffer;
        Int32 status = NetUserModalsGet(null, 0, out buffer);
        if (status != 0 || buffer == IntPtr.Zero) {
            throw new InvalidOperationException("SOURCE_UNAVAILABLE");
        }
        try {
            USER_MODALS_INFO_0 value =
                (USER_MODALS_INFO_0)Marshal.PtrToStructure(
                    buffer, typeof(USER_MODALS_INFO_0)
                );
            return value.max_passwd_age;
        } finally {
            NetApiBufferFree(buffer);
        }
    }
}
"@
        }
        $seconds = [int64][SecAiNetPolicy]::MaximumPasswordAgeSeconds()
        [ordered]@{
            maximum_password_age_days = [int][Math]::Floor($seconds / 86400)
            policy_defined = $true
            policy_source = "WINDOWS_EFFECTIVE"
        }
    }

Add-ProbeResult `
    "win.security.recovery-console" "PC-03" "secai.windows-registry" "0.1.0" `
    "EFFECTIVE_MACHINE_POLICY" {
        $value = Read-RegistryValue `
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" `
            "SecurityLevel"
        [ordered]@{
            automatic_admin_logon = if ($null -eq $value) {
                "NOT_DEFINED"
            } elseif ([int]$value -eq 0) {
                "DISABLED"
            } else {
                "ENABLED"
            }
            policy_defined = ($null -ne $value)
            policy_source = "WINDOWS_EFFECTIVE"
            os_edition = [string]$currentVersion.EditionID
            os_build = [string]$buildNumber
        }
    }

Add-ProbeResult `
    "win.services.inventory" "PC-05" "secai.windows-service-control-manager" "0.1.0" `
    "RAW_SERVICE_INVENTORY_REQUIRES_ORGANIZATION_POLICY" {
        foreach ($service in @(Get-Service -ErrorAction Stop | Sort-Object -Property Name)) {
            $serviceRegistry = Get-ItemProperty `
                -LiteralPath ("HKLM:\SYSTEM\CurrentControlSet\Services\" + $service.Name) `
                -ErrorAction Stop
            [ordered]@{
                service_key = [string]$service.Name
                state = ([string]$service.Status).ToUpperInvariant()
                start_mode = switch ([int]$serviceRegistry.Start) {
                    0 { "BOOT" }
                    1 { "SYSTEM" }
                    2 { "AUTO" }
                    3 { "MANUAL" }
                    4 { "DISABLED" }
                    default { "UNKNOWN" }
                }
            }
        }
    }

Add-ProbeResult `
    "win.browser.wininet-cache-policy" "PC-09" "secai.windows-registry" "0.1.0" `
    "CURRENT_USER_WININET_POLICY" {
        $cachePolicy = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Cache"
        $persistent = Read-RegistryValue $cachePolicy "Persistent"
        [ordered]@{
            applicability = if ($null -eq $persistent) { "UNKNOWN" } else { "APPLICABLE" }
            empty_cache_on_exit = if ($null -eq $persistent) { $null } else { [int]$persistent -eq 0 }
            evaluated_user_count = 1
            user_coverage_complete = $false
            policy_source = "CURRENT_USER"
        }
    }

Add-ProbeResult `
    "win.os.lifecycle" "PC-11" "secai.windows-native" "0.1.0" `
    "WINDOWS_PRODUCT_IDENTITY" {
        [ordered]@{
            product_name = $productName
            edition_group = [string]$currentVersion.EditionID
            display_version = [string]$currentVersion.DisplayVersion
            os_build = [string]$buildNumber
            ubr = [int]$currentVersion.UBR
            architecture = if ([Environment]::Is64BitOperatingSystem) { "x86_64" } else { "x86" }
        }
    }

Add-ProbeResult `
    "win.autologon.config" "PC-12" "secai.winlogon-native" "0.1.0" `
    "AUTO_LOGON_STATE_WITHOUT_SECRET_CONTENT" {
        $winlogon = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        $autoLogon = Read-RegistryValue $winlogon "AutoAdminLogon"
        $defaultPassword = Read-RegistryValue $winlogon "DefaultPassword"
        $defaultUser = Read-RegistryValue $winlogon "DefaultUserName"
        [ordered]@{
            auto_admin_logon_value = if ($null -eq $autoLogon) { "MISSING" } else { [string]$autoLogon }
            default_password_present = ($null -ne $defaultPassword)
            related_autologon_configuration_present = ($null -ne $defaultUser)
        }
    }

$defenderStatus = $null
try {
    if ($null -eq (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        throw "ADAPTER_UNSUPPORTED"
    }
    $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
} catch {
    $defenderStatus = $null
}

Add-ProbeResult `
    "win.antivirus.update-status" "PC-13" `
    "secai.microsoft-defender-antivirus" "0.1.0" "DEFENDER_BUILTIN_DRAFT_ADAPTER" {
        if ($null -eq $defenderStatus) { throw "ADAPTER_UNSUPPORTED" }
        [ordered]@{
            product_id = "MICROSOFT_DEFENDER_ANTIVIRUS"
            product_name = "Microsoft Defender Antivirus"
            product_present = [bool]$defenderStatus.AntivirusEnabled
            product_state = if ($defenderStatus.AntivirusEnabled) { "ACTIVE" } else { "INACTIVE" }
            service_enabled = [bool]$defenderStatus.AMServiceEnabled
            operating_mode = [string]$defenderStatus.AMRunningMode
            engine_version = [string]$defenderStatus.AMEngineVersion
            signature_version = [string]$defenderStatus.AntivirusSignatureVersion
            signature_updated_at = if ($null -eq $defenderStatus.AntivirusSignatureLastUpdated) {
                $null
            } else {
                ([DateTimeOffset]$defenderStatus.AntivirusSignatureLastUpdated).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            }
            automatic_updates_enabled = $null
            real_time_protection_enabled = [bool]$defenderStatus.RealTimeProtectionEnabled
            health_state = if ($defenderStatus.AntivirusEnabled) { "HEALTHY" } else { "INACTIVE" }
        }
    }

Add-ProbeResult `
    "win.antivirus.realtime-status" "PC-14" `
    "secai.microsoft-defender-antivirus" "0.1.0" "DEFENDER_BUILTIN_DRAFT_ADAPTER" {
        if ($null -eq $defenderStatus) { throw "ADAPTER_UNSUPPORTED" }
        [ordered]@{
            product_id = "MICROSOFT_DEFENDER_ANTIVIRUS"
            product_name = "Microsoft Defender Antivirus"
            product_present = [bool]$defenderStatus.AntivirusEnabled
            product_state = if ($defenderStatus.AntivirusEnabled) { "ACTIVE" } else { "INACTIVE" }
            service_enabled = [bool]$defenderStatus.AMServiceEnabled
            operating_mode = [string]$defenderStatus.AMRunningMode
            real_time_protection_enabled = [bool]$defenderStatus.RealTimeProtectionEnabled
            behavior_monitor_enabled = [bool]$defenderStatus.BehaviorMonitorEnabled
            ioav_protection_enabled = [bool]$defenderStatus.IoavProtectionEnabled
        }
    }

Add-ProbeResult `
    "win.firewall.effective-profiles" "PC-15" `
    "secai.windows-firewall" "0.1.0" "ACTIVE_STORE_DRAFT_ADAPTER" {
        if ($null -eq (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
            throw "ADAPTER_UNSUPPORTED"
        }
        foreach ($profile in @(
            Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop |
                Sort-Object -Property Name
        )) {
            [ordered]@{
                profile = ([string]$profile.Name).ToUpperInvariant()
                enabled = [bool]$profile.Enabled
                default_inbound_action = ([string]$profile.DefaultInboundAction).ToUpperInvariant()
                default_outbound_action = ([string]$profile.DefaultOutboundAction).ToUpperInvariant()
                policy_store = "ACTIVE_STORE"
            }
        }
    }

Add-ProbeResult `
    "win.user.screensaver-policy" "PC-16" "secai.windows-registry" "0.1.0" `
    "CURRENT_USER_ONLY_REQUIRES_ASSET_USER_COVERAGE" {
        $desktop = "HKCU:\Control Panel\Desktop"
        $active = Read-RegistryValue $desktop "ScreenSaveActive"
        $timeout = Read-RegistryValue $desktop "ScreenSaveTimeOut"
        $secure = Read-RegistryValue $desktop "ScreenSaverIsSecure"
        $executable = Read-RegistryValue $desktop "SCRNSAVE.EXE"
        [ordered]@{
            subject_id = "CURRENT_USER"
            screen_save_active = if ($null -eq $active) { "MISSING" } else { [string]$active }
            screen_save_timeout_seconds = if ($null -eq $timeout -or -not ([string]$timeout -match "^\d+$")) {
                $null
            } else {
                [int]$timeout
            }
            screen_saver_is_secure = if ($null -eq $secure) { "MISSING" } else { [string]$secure }
            screen_saver_executable_present = ($null -ne $executable)
            effective_policy_source = "CURRENT_USER"
            user_coverage_complete = $false
        }
    }

Add-ProbeResult `
    "win.media.autoplay-policy" "PC-17" "secai.windows-registry" "0.1.0" `
    "MACHINE_AND_CURRENT_USER_POLICY_NO_ORG_ATTESTATION" {
        $explorerPolicy = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        $noDriveType = Read-RegistryValue $explorerPolicy "NoDriveTypeAutoRun"
        $noAutorun = Read-RegistryValue $explorerPolicy "NoAutorun"
        $noNonVolume = Read-RegistryValue $explorerPolicy "NoAutoplayfornonVolume"
        [ordered]@{
            turn_off_autoplay_enabled = ($null -ne $noDriveType -and ([int]$noDriveType -band 255) -eq 255)
            autoplay_scope = if ($null -ne $noDriveType -and ([int]$noDriveType -band 255) -eq 255) {
                "ALL_DRIVES"
            } else {
                "PARTIAL_OR_UNDEFINED"
            }
            autorun_default_behavior = if ($null -ne $noAutorun -and [int]$noAutorun -eq 1) {
                "DO_NOT_EXECUTE"
            } else {
                "UNDEFINED_OR_EXECUTE"
            }
            non_volume_autoplay_disallowed = ($null -ne $noNonVolume -and [int]$noNonVolume -eq 1)
            effective_policy_source = "WINDOWS_EFFECTIVE"
        }
    }

Add-ProbeResult `
    "win.remote-assistance.policy" "PC-18" "secai.windows-registry" "0.1.0" `
    "MACHINE_POLICY" {
        $terminalServices = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
        $solicited = Read-RegistryValue $terminalServices "fAllowToGetHelp"
        $offered = Read-RegistryValue $terminalServices "fAllowUnsolicited"
        [ordered]@{
            f_allow_to_get_help = if ($null -eq $solicited) { "MISSING" } else { [string]$solicited }
            f_allow_unsolicited = if ($null -eq $offered) { "MISSING" } else { [string]$offered }
            effective_policy_source = "WINDOWS_EFFECTIVE"
        }
    }

$output = [ordered]@{
    schema_version = "1.0.0"
    context = $context
    results = @($results)
}
[Console]::Out.Write(($output | ConvertTo-Json -Depth 8 -Compress))

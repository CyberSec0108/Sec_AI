# IMP-031 fixed administrator Windows Probe set. This script never elevates
# itself. It exits unless an already-consented separate process is elevated.
param(
    [Parameter(Mandatory = $true)]
    [ValidateLength(1, 512)]
    [string]$SelectedProbeIdsCsv
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$allowedProbeIds = @(
        "win.security.password-policy",
        "win.network.smb-shares",
        "win.software.messengers",
        "win.boot.entries",
        "win.update.compliance"
)
$SelectedProbeIds = @($SelectedProbeIdsCsv.Split(","))

if (
    $SelectedProbeIds.Count -eq 0 -or
    @($SelectedProbeIds | Select-Object -Unique).Count -ne $SelectedProbeIds.Count -or
    @($SelectedProbeIds | Where-Object { $allowedProbeIds -notcontains $_ }).Count -ne 0
) {
    throw "ADMINISTRATOR_SELECTION_INVALID"
}

function Get-SecAiPropertyValue {
    param(
        [AllowNull()]
        [object]$InputObject,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    if ($null -eq $InputObject) { return $null }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-SecAiSha256Hex {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        $digest = $sha256.ComputeHash($bytes)
        return ([System.BitConverter]::ToString($digest)).Replace("-", "").ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}

function Test-SecAiWinloadBlock {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Lines
    )
    foreach ($line in $Lines) {
        if (
            ([string]$line).Trim() -match
            "(?i)(?:^|\s)\\windows\\system32\\winload\.(?:efi|exe)\s*$"
        ) {
            return $true
        }
    }
    return $false
}

function Get-SecAiBcdBlockValue {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Lines,
        [Parameter(Mandatory = $true)]
        [string[]]$Labels
    )
    foreach ($line in $Lines) {
        $text = ([string]$line).Trim()
        foreach ($label in $Labels) {
            $pattern = "(?i)^" + [regex]::Escape($label) + "\s+(.+?)\s*$"
            if ($text -match $pattern) {
                return ([string]$Matches[1]).Trim()
            }
        }
    }
    return $null
}

function Get-SecAiBootEntryRecord {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Lines
    )
    if (-not (Test-SecAiWinloadBlock -Lines $Lines)) {
        return $null
    }
    $koreanDescription = -join @([char]0xC124, [char]0xBA85)
    $koreanIdentifier = -join @([char]0xC2DD, [char]0xBCC4, [char]0xC790)
    $identifier = Get-SecAiBcdBlockValue `
        -Lines $Lines -Labels @("identifier", $koreanIdentifier)
    if ([string]::IsNullOrWhiteSpace($identifier)) {
        foreach ($line in $Lines) {
            $candidate = ([string]$line).Trim()
            if (
                $candidate -match
                "(?i)(\{(?:current|default|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\})\s*$"
            ) {
                $identifier = [string]$Matches[1]
                break
            }
        }
    }
    if ([string]::IsNullOrWhiteSpace($identifier)) {
        throw "EVIDENCE_INCOMPLETE"
    }
    $description = Get-SecAiBcdBlockValue `
        -Lines $Lines -Labels @("description", $koreanDescription)
    if ([string]::IsNullOrWhiteSpace($description)) {
        $description = "Windows boot entry"
    }
    return [ordered]@{
        record_type = "BOOT_ENTRY"
        display_name = [string]$description
        entry_identifier = [string]$identifier
    }
}

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
$isAdministrator = $principal.IsInRole(
    [System.Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdministrator) {
    throw "ADMINISTRATOR_PROCESS_REQUIRED"
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
$context = [ordered]@{
    os_family = "WINDOWS"
    os_version = $osVersion
    product_name = $productName
    display_version = [string]$currentVersion.DisplayVersion
    build_number = [string]$buildNumber
    ubr = [int]$currentVersion.UBR
    architecture = if ([Environment]::Is64BitOperatingSystem) { "x86_64" } else { "x86" }
    process_sid = [string]$identity.User.Value
    is_administrator = $true
    integrity_level = "HIGH"
    collected_at_utc = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

$results = [System.Collections.Generic.List[object]]::new()

function Add-ProbeResult {
    param(
        [string]$ProbeId,
        [string]$ControlId,
        [string]$AdapterId,
        [string]$Coverage,
        [scriptblock]$Reader
    )
    if ($SelectedProbeIds -notcontains $ProbeId) {
        return
    }
    try {
        $records = @(& $Reader)
        [void]$results.Add([ordered]@{
            probe_id = $ProbeId
            probe_version = "0.1.0"
            control_ids = @($ControlId)
            collection_status = "COLLECTED"
            error_code = "NONE"
            adapter_id = $AdapterId
            adapter_version = "0.1.0"
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
        [void]$results.Add([ordered]@{
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
            adapter_version = "0.1.0"
            coverage = $Coverage
            records = @()
        })
    }
}

Add-ProbeResult `
    "win.security.password-policy" "PC-02" "secai.windows-account-policy" `
    "PARTIAL_EFFECTIVE_POLICY_REQUIRES_ORGANIZATION_STANDARD" {
        if ($null -eq ("SecAiAdministratorNetPolicy" -as [type])) {
            Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class SecAiAdministratorNetPolicy {
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
    public static UInt32[] PasswordPolicyValues() {
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
            return new UInt32[] { value.min_passwd_len, value.max_passwd_age };
        } finally {
            NetApiBufferFree(buffer);
        }
    }
}
"@
        }
        $policyValues = @(
            [SecAiAdministratorNetPolicy]::PasswordPolicyValues()
        )
        if ($policyValues.Count -ne 2) { throw "QUERY_FAILED" }
        $maximumPasswordAgeSeconds = [uint32]$policyValues[1]
        $maximumPasswordAgeDays = if (
            $maximumPasswordAgeSeconds -eq [uint32]::MaxValue
        ) {
            0
        } else {
            [int][Math]::Floor(([double]$maximumPasswordAgeSeconds) / 86400.0)
        }
        $secedit = Join-Path $env:SystemRoot "System32\secedit.exe"
        if (-not (Test-Path -LiteralPath $secedit -PathType Leaf)) {
            throw "SOURCE_UNAVAILABLE"
        }
        $tempDirectory = [System.IO.Path]::GetFullPath(
            [System.IO.Path]::GetTempPath()
        ).TrimEnd("\")
        $tempPolicyPath = [System.IO.Path]::Combine(
            $tempDirectory,
            "secai-password-policy-" + [Guid]::NewGuid().ToString("N") + ".inf"
        )
        if (
            [System.IO.Path]::GetDirectoryName(
                [System.IO.Path]::GetFullPath($tempPolicyPath)
            ) -ne $tempDirectory
        ) {
            throw "QUERY_FAILED"
        }
        $minimumPasswordLength = $null
        $complexityEnabled = $null
        try {
            $null = & $secedit /export /cfg $tempPolicyPath `
                /areas SECURITYPOLICY /quiet 2>&1
            if (
                $LASTEXITCODE -ne 0 -or
                -not (Test-Path -LiteralPath $tempPolicyPath -PathType Leaf)
            ) {
                throw "QUERY_FAILED"
            }
            foreach ($line in @(Get-Content -LiteralPath $tempPolicyPath -ErrorAction Stop)) {
                $text = [string]$line
                if ($text -match "^\s*MinimumPasswordLength\s*=\s*(\d+)\s*$") {
                    $minimumPasswordLength = [int]$Matches[1]
                } elseif ($text -match "^\s*PasswordComplexity\s*=\s*([01])\s*$") {
                    $complexityEnabled = ([int]$Matches[1] -eq 1)
                }
            }
        } finally {
            if (Test-Path -LiteralPath $tempPolicyPath -PathType Leaf) {
                Remove-Item -LiteralPath $tempPolicyPath -Force -ErrorAction Stop
            }
        }
        if (
            $null -eq $minimumPasswordLength -or
            $null -eq $complexityEnabled
        ) {
            throw "QUERY_FAILED"
        }
        [ordered]@{
            minimum_password_length = [int]$minimumPasswordLength
            maximum_password_age_days = $maximumPasswordAgeDays
            complexity_enabled = [bool]$complexityEnabled
            password_required = ([int]$minimumPasswordLength -gt 0)
            policy_source = "WINDOWS_EFFECTIVE"
        }
    }

Add-ProbeResult `
    "win.network.smb-shares" "PC-04" "secai.windows-smb-native" `
    "SHARE_AND_ACCESS_INVENTORY_REQUIRES_ORGANIZATION_POLICY" {
        if ($null -eq (Get-Command Get-SmbShare -ErrorAction SilentlyContinue)) {
            throw "SOURCE_UNAVAILABLE"
        }
        $shares = @(Get-SmbShare -ErrorAction Stop | Sort-Object -Property Name)
        $adminShares = 0
        $regularShares = 0
        $everyoneUnrestricted = 0
        $broadWriteShares = 0
        $regularShareRecords = [System.Collections.Generic.List[object]]::new()
        $regularShareSafetyLimit = 192
        $broadPrincipalSids = @("S-1-1-0", "S-1-5-11", "S-1-5-32-545")
        $broadPrincipalNames = @(
            $broadPrincipalSids | ForEach-Object {
                ([System.Security.Principal.SecurityIdentifier]::new($_)).Translate(
                    [System.Security.Principal.NTAccount]
                ).Value
            }
        )
        $everyoneAccountName = $broadPrincipalNames[0]
        foreach ($share in $shares) {
            $shareNameValue = Get-SecAiPropertyValue $share "Name"
            if ([string]::IsNullOrWhiteSpace([string]$shareNameValue)) {
                throw "QUERY_FAILED"
            }
            $shareName = [string]$shareNameValue
            $isSpecial = [bool](Get-SecAiPropertyValue $share "Special")
            if ($isSpecial) {
                $adminShares += 1
            } else {
                $regularShares += 1
                if ($regularShares -gt $regularShareSafetyLimit) {
                    throw "QUERY_FAILED"
                }
            }
            $hasUnrestrictedEveryone = $false
            $hasBroadWrite = $false
            foreach ($access in @(Get-SmbShareAccess -Name $shareName -ErrorAction Stop)) {
                $accountName = [string](Get-SecAiPropertyValue $access "AccountName")
                $accessRight = [string](Get-SecAiPropertyValue $access "AccessRight")
                $accessControlType = [string](
                    Get-SecAiPropertyValue $access "AccessControlType"
                )
                $isEveryone = (
                    $accountName -eq "S-1-1-0" -or
                    $accountName.Equals(
                        $everyoneAccountName,
                        [System.StringComparison]::OrdinalIgnoreCase
                    )
                )
                $isBroadPrincipal = (
                    $broadPrincipalSids -contains $accountName -or
                    $broadPrincipalNames -contains $accountName
                )
                if (
                    $isEveryone -and
                    $accessRight -eq "Full" -and
                    $accessControlType -eq "Allow"
                ) {
                    $hasUnrestrictedEveryone = $true
                }
                if (
                    $isBroadPrincipal -and
                    $accessRight -in @("Change", "Full") -and
                    $accessControlType -eq "Allow"
                ) {
                    $hasBroadWrite = $true
                }
            }
            if ($hasUnrestrictedEveryone) {
                $everyoneUnrestricted += 1
            }
            if ($hasBroadWrite) {
                $broadWriteShares += 1
            }
            if (-not $isSpecial) {
                $shareId = Get-SecAiSha256Hex (
                    $shareName.Trim().ToLowerInvariant()
                )
                [void]$regularShareRecords.Add([ordered]@{
                    record_type = "REGULAR_SHARE"
                    share_name_sha256 = $shareId
                    everyone_full_access = $hasUnrestrictedEveryone
                    broad_write_access = $hasBroadWrite
                })
            }
        }
        $autoShare = Get-ItemProperty `
            -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
            -ErrorAction SilentlyContinue
        $autoShareWks = Get-SecAiPropertyValue $autoShare "AutoShareWks"
        [ordered]@{
            record_type = "SUMMARY"
            share_count = $shares.Count
            regular_share_count = $regularShares
            default_admin_share_count = $adminShares
            unrestricted_everyone_share_count = $everyoneUnrestricted
            broad_write_share_count = $broadWriteShares
            auto_share_wks_disabled = ($null -ne $autoShareWks -and $autoShareWks -eq 0)
        }
        foreach ($record in $regularShareRecords) {
            $record
        }
    }

Add-ProbeResult `
    "win.software.messengers" "PC-06" "secai.windows-installed-software-inventory" `
    "FIXED_MESSENGER_DETECTION_REQUIRES_ORGANIZATION_POLICY" {
        $messengerCatalog = @(
            [pscustomobject]@{
                Id = "KAKAOTALK"
                DisplayName = "KakaoTalk"
                RegistryPattern = "(^|[^A-Za-z0-9])Kakao\s*Talk([^A-Za-z0-9]|$)|\uCE74\uCE74\uC624\uD1A1"
                AppxPattern = "(^|[._-])KakaoTalk([._-]|$)"
                ProcessPattern = "^KakaoTalk$"
            },
            [pscustomobject]@{
                Id = "TELEGRAM_DESKTOP"
                DisplayName = "Telegram Desktop"
                RegistryPattern = "(^|[^A-Za-z0-9])Telegram(\s+Desktop)?([^A-Za-z0-9]|$)"
                AppxPattern = "(^|[._-])Telegram(Desktop)?([._-]|$)"
                ProcessPattern = "^(Telegram|TelegramDesktop)$"
            },
            [pscustomobject]@{
                Id = "LINE_MESSENGER"
                DisplayName = "LINE"
                RegistryPattern = "^LINE(\s+for\s+Windows)?(\s+\d+(\.\d+)*)?$"
                AppxPattern = "(^|[._-])(LINE|NAVER.LINEwin8)([._-]|$)"
                ProcessPattern = "^LINE$"
            },
            [pscustomobject]@{
                Id = "WHATSAPP"
                DisplayName = "WhatsApp"
                RegistryPattern = "(^|[^A-Za-z0-9])WhatsApp([^A-Za-z0-9]|$)"
                AppxPattern = "(^|[._-])WhatsApp(Desktop)?([._-]|$)"
                ProcessPattern = "^(WhatsApp|WhatsAppDesktop)$"
            },
            [pscustomobject]@{
                Id = "DISCORD"
                DisplayName = "Discord"
                RegistryPattern = "^Discord(\s+(PTB|Canary))?$"
                AppxPattern = "(^|[._-])Discord([._-]|$)"
                ProcessPattern = "^Discord(PTB|Canary)?$"
            },
            [pscustomobject]@{
                Id = "SLACK"
                DisplayName = "Slack"
                RegistryPattern = "^Slack(\s+Machine-Wide Installer)?$"
                AppxPattern = "(^|[._-])Slack([._-]|$)"
                ProcessPattern = "^slack$"
            },
            [pscustomobject]@{
                Id = "MICROSOFT_TEAMS"
                DisplayName = "Microsoft Teams"
                RegistryPattern = "^(Microsoft\s+)?Teams(\s+Machine-Wide Installer)?$"
                AppxPattern = "(^|[._-])(MSTeams|MicrosoftTeams|Teams)([._-]|$)"
                ProcessPattern = "^(Teams|ms-teams)$"
            },
            [pscustomobject]@{
                Id = "NATEON"
                DisplayName = "NateOn"
                RegistryPattern = "(^|[^A-Za-z0-9])NateOn([^A-Za-z0-9]|$)|\uB124\uC774\uD2B8\uC628"
                AppxPattern = "(^|[._-])NateOn([._-]|$)"
                ProcessPattern = "^NateOn$"
            },
            [pscustomobject]@{
                Id = "SIGNAL_DESKTOP"
                DisplayName = "Signal Desktop"
                RegistryPattern = "^Signal(\s+Desktop)?$"
                AppxPattern = "(^|[._-])Signal(Desktop)?([._-]|$)"
                ProcessPattern = "^Signal$"
            },
            [pscustomobject]@{
                Id = "WECHAT"
                DisplayName = "WeChat"
                RegistryPattern = "^(WeChat|Weixin)$"
                AppxPattern = "(^|[._-])(WeChat|Weixin)([._-]|$)"
                ProcessPattern = "^(WeChat|Weixin)$"
            }
        )
        $roots = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        )
        $installedProductCount = 0
        $matchStates = @{}
        $regexOptions = (
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
            [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
        )
        foreach ($catalogItem in $messengerCatalog) {
            $matchStates[[string]$catalogItem.Id] = [pscustomobject]@{
                Installed = $false
                Running = $false
            }
        }
        foreach ($root in $roots) {
            if (Test-Path -LiteralPath $root -PathType Container) {
                $products = @(
                    Get-ChildItem -LiteralPath $root -ErrorAction Stop |
                        Get-ItemProperty -ErrorAction SilentlyContinue
                )
                foreach ($product in $products) {
                    $displayNameValue = Get-SecAiPropertyValue $product "DisplayName"
                    if ([string]::IsNullOrWhiteSpace([string]$displayNameValue)) {
                        continue
                    }
                    $displayName = ([string]$displayNameValue).Trim()
                    $installedProductCount += 1
                    foreach ($catalogItem in $messengerCatalog) {
                        if (
                            [System.Text.RegularExpressions.Regex]::IsMatch(
                                $displayName,
                                [string]$catalogItem.RegistryPattern,
                                $regexOptions
                            )
                        ) {
                            $matchStates[[string]$catalogItem.Id].Installed = $true
                            break
                        }
                    }
                }
            }
        }
        if ($null -eq (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue)) {
            throw "SOURCE_UNAVAILABLE"
        }
        foreach ($package in @(Get-AppxPackage -AllUsers -ErrorAction Stop)) {
            $packageName = [string](Get-SecAiPropertyValue $package "Name")
            $packageFamily = [string](
                Get-SecAiPropertyValue $package "PackageFamilyName"
            )
            if (
                [string]::IsNullOrWhiteSpace($packageName) -and
                [string]::IsNullOrWhiteSpace($packageFamily)
            ) {
                continue
            }
            $installedProductCount += 1
            $packageIdentity = $packageName + " " + $packageFamily
            foreach ($catalogItem in $messengerCatalog) {
                if (
                    [System.Text.RegularExpressions.Regex]::IsMatch(
                        $packageIdentity,
                        [string]$catalogItem.AppxPattern,
                        $regexOptions
                    )
                ) {
                    $matchStates[[string]$catalogItem.Id].Installed = $true
                    break
                }
            }
        }
        foreach ($process in @(Get-Process -ErrorAction Stop)) {
            $processName = [string](Get-SecAiPropertyValue $process "ProcessName")
            if ([string]::IsNullOrWhiteSpace($processName)) {
                continue
            }
            foreach ($catalogItem in $messengerCatalog) {
                if (
                    [System.Text.RegularExpressions.Regex]::IsMatch(
                        $processName,
                        [string]$catalogItem.ProcessPattern,
                        $regexOptions
                    )
                ) {
                    $state = $matchStates[[string]$catalogItem.Id]
                    $state.Installed = $true
                    $state.Running = $true
                    break
                }
            }
        }
        $matchRecords = [System.Collections.Generic.List[object]]::new()
        $runningMessengerCount = 0
        foreach ($catalogItem in $messengerCatalog) {
            $state = $matchStates[[string]$catalogItem.Id]
            if (-not $state.Installed -and -not $state.Running) {
                continue
            }
            if ($state.Running) {
                $runningMessengerCount += 1
            }
            [void]$matchRecords.Add([ordered]@{
                record_type = "MESSENGER_MATCH"
                catalog_id = [string]$catalogItem.Id
                display_name = [string]$catalogItem.DisplayName
                installed = [bool]$state.Installed
                running = [bool]$state.Running
                match_confidence = "HIGH"
            })
        }
        [ordered]@{
            record_type = "SUMMARY"
            installed_product_count = $installedProductCount
            messenger_catalog_count = $messengerCatalog.Count
            detected_messenger_product_count = $matchRecords.Count
            running_messenger_product_count = $runningMessengerCount
            low_confidence_match_count = 0
        }
        foreach ($record in $matchRecords) {
            $record
        }
    }

Add-ProbeResult `
    "win.boot.entries" "PC-08" "secai.windows-bcdedit-native" `
    "OS_LOADER_WINLOAD_BLOCK_COUNT_WITH_NAMES" {
        $systemRoot = [Environment]::GetFolderPath("Windows")
        $bcdedit = Join-Path $systemRoot "System32\bcdedit.exe"
        if (-not (Test-Path -LiteralPath $bcdedit -PathType Leaf)) {
            throw "SOURCE_UNAVAILABLE"
        }
        $lines = @(& $bcdedit /enum OSLOADER /v)
        if ($LASTEXITCODE -ne 0) { throw "QUERY_FAILED" }
        $bootEntryRecords = [System.Collections.Generic.List[object]]::new()
        $currentBlock = [System.Collections.Generic.List[string]]::new()
        foreach ($line in $lines) {
            $text = [string]$line
            if ([string]::IsNullOrWhiteSpace($text)) {
                if ($currentBlock.Count -gt 0) {
                    $entry = Get-SecAiBootEntryRecord -Lines @($currentBlock)
                    if ($null -ne $entry) {
                        [void]$bootEntryRecords.Add($entry)
                    }
                }
                $currentBlock.Clear()
            } else {
                [void]$currentBlock.Add($text)
            }
        }
        if ($currentBlock.Count -gt 0) {
            $entry = Get-SecAiBootEntryRecord -Lines @($currentBlock)
            if ($null -ne $entry) {
                [void]$bootEntryRecords.Add($entry)
            }
        }
        [ordered]@{
            record_type = "SUMMARY"
            bootable_os_count = $bootEntryRecords.Count
            parser_profile = "BCDEDIT_OSLOADER_WINLOAD_BLOCK_COUNT_WITH_NAMES"
        }
        foreach ($record in $bootEntryRecords) {
            $record
        }
    }

Add-ProbeResult `
    "win.update.compliance" "PC-10" "secai.windows-update-history-build" `
    "UPDATE_HISTORY_AND_BUILD_REQUIRES_REFERENCE_AND_ORG_PROCEDURE" {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $total = $searcher.GetTotalHistoryCount()
        $successfulInstallHistory = @()
        $latest = @()
        if ($total -gt 0) {
            $history = @(
                $searcher.QueryHistory(0, [Math]::Min($total, 512))
            )
            $successfulInstallHistory = @(
                $history | Where-Object {
                    $operation = Get-SecAiPropertyValue $_ "Operation"
                    $resultCode = Get-SecAiPropertyValue $_ "ResultCode"
                    $null -ne $operation -and
                    $null -ne $resultCode -and
                    [int]$operation -eq 1 -and
                    [int]$resultCode -in @(2, 3)
                }
            )
            $latest = @($successfulInstallHistory |
                Sort-Object -Property Date -Descending |
                Select-Object -First 1)
        }
        $auPolicy = Get-ItemProperty `
            -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
            -ErrorAction SilentlyContinue
        $noAutoUpdate = Get-SecAiPropertyValue $auPolicy "NoAutoUpdate"
        $rebootPending = (
            Test-Path -LiteralPath `
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
        ) -or (
            Test-Path -LiteralPath `
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
        )
        [ordered]@{
            product_name = $productName
            display_version = [string]$currentVersion.DisplayVersion
            edition_group = [string]$currentVersion.EditionID
            os_build = [string]$buildNumber
            ubr = [int]$currentVersion.UBR
            update_inventory_source = "WINDOWS_UPDATE_HISTORY_AND_BUILD"
            history_record_count = $total
            successful_install_history_count = $successfulInstallHistory.Count
            latest_history_at = if ($latest.Count -eq 0) {
                $null
            } else {
                ([DateTimeOffset]$latest[0].Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            }
            automatic_updates_enabled = ($null -eq $noAutoUpdate -or $noAutoUpdate -ne 1)
            restart_pending = [bool]$rebootPending
        }
    }

$output = [ordered]@{
    schema_version = "1.0.0"
    context = $context
    results = @($results)
}
[Console]::Out.Write(($output | ConvertTo-Json -Depth 8 -Compress))

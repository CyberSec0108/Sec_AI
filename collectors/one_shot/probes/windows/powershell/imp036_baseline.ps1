# IMP-036 fixed, read-only, de-identified Windows development-host baseline.
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$currentVersion = Get-ItemProperty `
    -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" `
    -ErrorAction Stop
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
$integrityLevel = if ($integrityCandidates.Count -eq 0) {
    "UNKNOWN"
} else {
    switch ($integrityCandidates[0]) {
        "S-1-16-4096" { "LOW" }
        "S-1-16-8192" { "MEDIUM" }
        "S-1-16-8448" { "MEDIUM_PLUS" }
        "S-1-16-12288" { "HIGH" }
        "S-1-16-16384" { "SYSTEM" }
        default { "UNKNOWN" }
    }
}

$defender = try {
    if ($null -eq (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        throw "UNAVAILABLE"
    }
    $status = Get-MpComputerStatus -ErrorAction Stop
    [ordered]@{
        name = "Microsoft Defender Antivirus"
        state = if ($status.AntivirusEnabled) { "ACTIVE" } else { "INACTIVE" }
        detail_code = if ($status.RealTimeProtectionEnabled) {
            "REALTIME_PROTECTION_ENABLED"
        } else {
            "REALTIME_PROTECTION_DISABLED"
        }
    }
} catch {
    [ordered]@{
        name = "Microsoft Defender Antivirus"
        state = "CHECK_REQUIRED"
        detail_code = "STATUS_UNAVAILABLE"
    }
}

$firewall = try {
    if ($null -eq (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
        throw "UNAVAILABLE"
    }
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    $enabledCount = @($profiles | Where-Object { $_.Enabled }).Count
    [ordered]@{
        name = "Windows Defender Firewall"
        state = if ($profiles.Count -gt 0 -and $enabledCount -eq $profiles.Count) {
            "ACTIVE"
        } else {
            "PARTIAL"
        }
        detail_code = "PROFILES:$($profiles.Count):$enabledCount"
    }
} catch {
    [ordered]@{
        name = "Windows Defender Firewall"
        state = "CHECK_REQUIRED"
        detail_code = "STATUS_UNAVAILABLE"
    }
}

$buildNumber = [int]$currentVersion.CurrentBuild
$edition = [string]$currentVersion.ProductName
if ($buildNumber -ge 22000 -and $edition -like "*Windows 10*") {
    $edition = $edition -replace "Windows 10", "Windows 11"
}
$output = [ordered]@{
    schema_version = "1.0.0"
    observed_at_utc = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    operating_system = [ordered]@{
        edition = $edition
        display_version = [string]$currentVersion.DisplayVersion
        build = "$buildNumber.$([int]$currentVersion.UBR)"
        architecture = if ([Environment]::Is64BitOperatingSystem) { "x86_64" } else { "x86" }
    }
    token = [ordered]@{
        level = if ($isAdministrator) { "ADMINISTRATOR" } else { "STANDARD_USER" }
        integrity_level = $integrityLevel
    }
    security_products = @($defender, $firewall)
}
[Console]::Out.Write(($output | ConvertTo-Json -Depth 5 -Compress))

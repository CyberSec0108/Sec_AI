[CmdletBinding()]
param(
    [ValidateSet("DEV-UNSIGNED", "SIGNED-PILOT", "SIGNED-PRODUCTION")]
    [string]$ReleaseChannel = "DEV-UNSIGNED",
    [string]$SourceRevision = "WORKTREE-UNCOMMITTED",
    [string]$SigningKeyPath,
    [string]$SigningKeyId,
    [ValidateSet("PASS", "FAIL", "PENDING")]
    [string]$DependencyScan = "PENDING",
    [ValidateSet("PASS", "FAIL", "PENDING")]
    [string]$OsPackageScan = "PENDING",
    [ValidateSet("CLEAN", "INFECTED", "PENDING")]
    [string]$MalwareScan = "PENDING"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$Image = "sec-ai-mvp/linux-collector-builder:0.1.0"
$Dockerfile = Join-Path $ProjectRoot "deploy\docker\linux-collector-builder.Dockerfile"
$Timestamp = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
$OutputRoot = Join-Path $ProjectRoot "runtime\linux-oneshot-artifacts"
$OutputDirectory = Join-Path $OutputRoot ("build-" + $Timestamp)
$SidecarSigningKey = Join-Path $ProjectRoot "runtime\dev-secrets\scan_sidecar_signing_key"
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
if (-not (Test-Path -LiteralPath $SidecarSigningKey -PathType Leaf)) {
    throw "Sidecar signing seed is missing. Run tools\init-dev-secrets.ps1 first."
}

if ($ReleaseChannel -ne "DEV-UNSIGNED") {
    if (-not $SigningKeyPath -or -not $SigningKeyId) {
        throw "Signed channels require -SigningKeyPath and -SigningKeyId."
    }
    $ResolvedKey = [System.IO.Path]::GetFullPath($SigningKeyPath)
    if (-not (Test-Path -LiteralPath $ResolvedKey -PathType Leaf)) {
        throw "The external Ed25519 key file does not exist."
    }
    if ($ResolvedKey.StartsWith($ProjectRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "The private key must stay outside the project directory."
    }
}

docker build --pull --file $Dockerfile --tag $Image $ProjectRoot
if ($LASTEXITCODE -ne 0) {
    throw "Linux Collector builder image failed."
}
$ImageDigest = docker image inspect --format "{{.Id}}" $Image
if ($LASTEXITCODE -ne 0 -or -not $ImageDigest) {
    throw "Could not resolve the exact builder image digest."
}

$RunArguments = @(
    "run", "--rm", "--network", "none", "--read-only",
    "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
    "--pids-limit", "256", "--tmpfs", "/tmp:rw,nosuid,nodev,size=2g",
    "--mount", ("type=bind,source=" + $OutputRoot + ",target=/out"),
    "--mount", ("type=bind,source=" + $SidecarSigningKey + ",target=/run/secrets/scan-sidecar-signing-key,readonly"),
    $Image,
    "--output", ("/out/build-" + $Timestamp),
    "--source-revision", $SourceRevision,
    "--build-image-digest", $ImageDigest,
    "--release-channel", $ReleaseChannel,
    "--dependency-scan", $DependencyScan,
    "--os-package-scan", $OsPackageScan,
    "--malware-scan", $MalwareScan,
    "--sidecar-signing-key-file", "/run/secrets/scan-sidecar-signing-key"
)
if ($ReleaseChannel -ne "DEV-UNSIGNED") {
    $RunArguments = @(
        "run", "--rm", "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "256", "--tmpfs", "/tmp:rw,nosuid,nodev,size=2g",
        "--mount", ("type=bind,source=" + $OutputRoot + ",target=/out"),
        "--mount", ("type=bind,source=" + $ResolvedKey + ",target=/run/secrets/linux-release-key,readonly"),
        "--mount", ("type=bind,source=" + $SidecarSigningKey + ",target=/run/secrets/scan-sidecar-signing-key,readonly"),
        $Image,
        "--output", ("/out/build-" + $Timestamp),
        "--source-revision", $SourceRevision,
        "--build-image-digest", $ImageDigest,
        "--release-channel", $ReleaseChannel,
        "--signing-key-file", "/run/secrets/linux-release-key",
        "--signing-key-id", $SigningKeyId,
        "--dependency-scan", $DependencyScan,
        "--os-package-scan", $OsPackageScan,
        "--malware-scan", $MalwareScan,
        "--sidecar-signing-key-file", "/run/secrets/scan-sidecar-signing-key"
    )
}
docker @RunArguments
if ($LASTEXITCODE -ne 0) {
    throw "Linux Collector artifact build failed."
}

Write-Host "Linux Collector artifacts: $OutputDirectory"
Write-Host "DEV-UNSIGNED or incomplete security gates remain blocked from download."

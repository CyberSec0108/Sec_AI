[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = "1"

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$runtimeRoot = Join-Path $projectRoot "runtime"
$pythonRoot = Join-Path $runtimeRoot "imp034-python3146"
$pythonPath = Join-Path $pythonRoot "python.exe"
$venvRoot = Join-Path $runtimeRoot "imp034-builder-venv"
$builderPython = Join-Path $venvRoot "Scripts\python.exe"
$artifactName = "SecAI-Collector-Windows-x64.exe"
$artifactVersion = "0.1.0"

if (-not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) {
    New-Item -ItemType Directory -Path $runtimeRoot -Force | Out-Null
    & py install --target=$pythonRoot -y 3.14.6
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to install the exact CPython 3.14.6 builder runtime."
    }
}
$pythonVersion = (& $pythonPath -c "import platform; print(platform.python_version())").Trim()
if ($pythonVersion -ne "3.14.6") {
    throw "IMP-034 requires exact CPython 3.14.6, found $pythonVersion."
}
$builderHealthy = $false
if (Test-Path -LiteralPath $builderPython -PathType Leaf) {
    try {
        & $builderPython -c "import sys; assert sys.prefix" *> $null
        $builderHealthy = $LASTEXITCODE -eq 0
    } catch {
        $builderHealthy = $false
    }
}
if (-not $builderHealthy) {
    if (Test-Path -LiteralPath $venvRoot) {
        $resolvedRuntimeRoot = [System.IO.Path]::GetFullPath($runtimeRoot)
        $resolvedVenvRoot = [System.IO.Path]::GetFullPath($venvRoot)
        if (-not $resolvedVenvRoot.StartsWith(
            $resolvedRuntimeRoot + [System.IO.Path]::DirectorySeparatorChar,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
            throw "Refusing to recreate a builder environment outside runtime."
        }
        Remove-Item -LiteralPath $resolvedVenvRoot -Recurse -Force
    }
    & $pythonPath -m venv $venvRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to create the IMP-034 Windows builder environment."
    }
}
& $builderPython -m pip install `
    --disable-pip-version-check `
    --require-hashes `
    -r (Join-Path $projectRoot "requirements\lock\collector-build.lock")
if ($LASTEXITCODE -ne 0) {
    throw "Unable to install the hash-locked Collector build dependencies."
}
& $builderPython -m pip check
if ($LASTEXITCODE -ne 0) {
    throw "Collector build dependency consistency check failed."
}

$buildJson = (
    & $builderPython (Join-Path $PSScriptRoot "build_imp034_collector.py") |
        Select-Object -Last 1
)
if ($LASTEXITCODE -ne 0) {
    throw "Windows Collector native build failed."
}
$build = $buildJson | ConvertFrom-Json
$outputDirectory = [System.IO.Path]::GetFullPath([string]$build.output_directory)
$expectedOutputRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $runtimeRoot "imp034-artifacts")
)
if (-not $outputDirectory.StartsWith(
    $expectedOutputRoot + [System.IO.Path]::DirectorySeparatorChar,
    [System.StringComparison]::OrdinalIgnoreCase
)) {
    throw "Build output escaped the approved runtime directory."
}
$artifactPath = Join-Path $outputDirectory $artifactName
$artifactHash = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256).Hash.ToLowerInvariant()

$dockerCommon = @(
    "run",
    "--rm",
    "--network", "bridge",
    "--read-only",
    "--tmpfs", "/tmp:rw,size=512m",
    "-e", "HOME=/tmp/secai-home",
    "--entrypoint", "python",
    "-v", "${projectRoot}:/workspace:ro",
    "-v", "${outputDirectory}:/out:rw",
    "-w", "/workspace",
    "sec-ai-mvp/dev-tools:0.1.0",
    "-m", "pip_audit",
    "-r", "requirements/lock/collector-build.lock",
    "--no-deps",
    "--disable-pip",
    "--cache-dir", "/tmp/pip-audit",
    "--progress-spinner", "off"
)
$sbomName = "SecAI-Collector-Windows-x64-$artifactVersion.cdx.json"
& docker @dockerCommon `
    --format cyclonedx-json `
    --output "/out/$sbomName"
if ($LASTEXITCODE -ne 0) {
    throw "CycloneDX SBOM generation or dependency vulnerability lookup failed."
}
$vulnerabilityName = "SecAI-Collector-Windows-x64-$artifactVersion.vulnerability.json"
& docker @dockerCommon `
    --format json `
    --output "/out/$vulnerabilityName"
if ($LASTEXITCODE -ne 0) {
    throw "Known dependency vulnerability Gate failed."
}
$vulnerabilityPath = Join-Path $outputDirectory $vulnerabilityName
$vulnerability = Get-Content -LiteralPath $vulnerabilityPath -Raw -Encoding utf8 |
    ConvertFrom-Json
$vulnerability | Add-Member -NotePropertyName scanner -NotePropertyValue ([ordered]@{
    name = "pip-audit"
    version = "2.10.1"
    service = "PyPI"
}) -Force
[System.IO.File]::WriteAllText(
    $vulnerabilityPath,
    ($vulnerability | ConvertTo-Json -Depth 20) + "`n",
    [System.Text.UTF8Encoding]::new($false)
)

$clamOutput = & docker run `
    --rm `
    --network sec-ai-mvp-app `
    --read-only `
    --tmpfs /tmp:rw,size=256m `
    -e HOME=/tmp/secai-home `
    --entrypoint python `
    -v "${projectRoot}:/workspace:ro" `
    -v "${outputDirectory}:/artifact:ro" `
    -w /workspace `
    sec-ai-mvp/dev-tools:0.1.0 `
    tools/scan_clamd.py `
    "/artifact/$artifactName"
if ($LASTEXITCODE -ne 0) {
    throw "ClamAV detected the Collector or could not complete the scan."
}
$clamPath = Join-Path $outputDirectory (
    "SecAI-Collector-Windows-x64-$artifactVersion.clamav.json"
)
[System.IO.File]::WriteAllText(
    $clamPath,
    ($clamOutput | Select-Object -Last 1) + "`n",
    [System.Text.UTF8Encoding]::new($false)
)

$defenderStatus = Get-MpComputerStatus
if (
    -not $defenderStatus.AntivirusEnabled -or
    -not $defenderStatus.RealTimeProtectionEnabled
) {
    throw "Microsoft Defender is not active on the IMP-034 Windows builder."
}
$mpCmd = Join-Path $env:ProgramFiles "Windows Defender\MpCmdRun.exe"
if (-not (Test-Path -LiteralPath $mpCmd -PathType Leaf)) {
    throw "Microsoft Defender command-line scanner is unavailable."
}
& $mpCmd -Scan -ScanType 3 -File $artifactPath -DisableRemediation
$defenderExitCode = $LASTEXITCODE
$defenderReport = [ordered]@{
    scanner = "Microsoft Defender"
    engine_version = [string]$defenderStatus.AMProductVersion
    signature_version = [string]$defenderStatus.AntivirusSignatureVersion
    signature_updated_at = $defenderStatus.AntivirusSignatureLastUpdated.ToUniversalTime().ToString("o")
    artifact_name = $artifactName
    artifact_sha256 = $artifactHash
    status = $(if ($defenderExitCode -eq 0) { "CLEAN" } else { "DETECTED_OR_ERROR" })
    exit_code = $defenderExitCode
}
$defenderPath = Join-Path $outputDirectory (
    "SecAI-Collector-Windows-x64-$artifactVersion.defender.json"
)
[System.IO.File]::WriteAllText(
    $defenderPath,
    ($defenderReport | ConvertTo-Json -Depth 5) + "`n",
    [System.Text.UTF8Encoding]::new($false)
)
if ($defenderExitCode -ne 0) {
    throw "Microsoft Defender detected the Collector or could not complete the scan."
}

$signature = Get-AuthenticodeSignature -LiteralPath $artifactPath
$signatureStatus = $signature.Status.ToString()
$authenticodeReport = [ordered]@{
    scanner = "Get-AuthenticodeSignature"
    artifact_name = $artifactName
    artifact_sha256 = $artifactHash
    status = $(if ($signatureStatus -eq "NotSigned") { "NOT_SIGNED" } else { $signatureStatus.ToUpperInvariant() })
    expected = "NOT_SIGNED_UNTIL_IMP035"
    signer_certificate_present = $null -ne $signature.SignerCertificate
}
$authenticodePath = Join-Path $outputDirectory (
    "SecAI-Collector-Windows-x64-$artifactVersion.authenticode.json"
)
[System.IO.File]::WriteAllText(
    $authenticodePath,
    ($authenticodeReport | ConvertTo-Json -Depth 5) + "`n",
    [System.Text.UTF8Encoding]::new($false)
)
if ($signatureStatus -ne "NotSigned") {
    throw "IMP-034 expected an unsigned DEV artifact; signing belongs to IMP-035."
}

$previousPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = Join-Path $projectRoot "src"
    & $builderPython `
        (Join-Path $PSScriptRoot "finalize_imp034_collector.py") `
        $outputDirectory
    if ($LASTEXITCODE -ne 0) {
        throw "IMP-034 final acceptance failed."
    }
} finally {
    $env:PYTHONPATH = $previousPythonPath
}

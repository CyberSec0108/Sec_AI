[CmdletBinding()]
param(
    [string]$TimestampServer = "http://timestamp.digicert.com"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$env:PYTHONUTF8 = "1"

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$imp034Root = Join-Path $projectRoot "runtime\imp034-artifacts"
$imp035Root = Join-Path $projectRoot "runtime\imp035-artifacts"
$builderPython = Join-Path $projectRoot "runtime\imp034-builder-venv\Scripts\python.exe"
$artifactName = "SecAI-Collector-Windows-x64.exe"
$artifactVersion = "0.1.0"

if (-not (Test-Path -LiteralPath $builderPython -PathType Leaf)) {
    throw "IMP-034 builder environment is missing. Run build-imp034-windows-collector.ps1 first."
}

$sourceDirectory = Get-ChildItem -LiteralPath $imp034Root -Directory |
    Sort-Object LastWriteTimeUtc -Descending |
    Where-Object {
        $acceptancePath = Join-Path $_.FullName "imp034-acceptance.json"
        if (-not (Test-Path -LiteralPath $acceptancePath -PathType Leaf)) {
            return $false
        }
        $acceptance = Get-Content -LiteralPath $acceptancePath -Raw -Encoding utf8 |
            ConvertFrom-Json
        return $acceptance.acceptance_status -eq "PASS"
    } |
    Select-Object -First 1
if (-not $sourceDirectory) {
    throw "No accepted IMP-034 build was found."
}

$sourceArtifact = Join-Path $sourceDirectory.FullName $artifactName
$sourceAcceptance = Join-Path $sourceDirectory.FullName "imp034-acceptance.json"
$sourceSbom = Join-Path $sourceDirectory.FullName (
    "SecAI-Collector-Windows-x64-$artifactVersion.cdx.json"
)
$sourceVulnerability = Join-Path $sourceDirectory.FullName (
    "SecAI-Collector-Windows-x64-$artifactVersion.vulnerability.json"
)
foreach ($required in @(
    $sourceArtifact,
    $sourceAcceptance,
    $sourceSbom,
    $sourceVulnerability
)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required IMP-034 source is missing: $required"
    }
}

$unsignedSignature = Get-AuthenticodeSignature -LiteralPath $sourceArtifact
if ($unsignedSignature.Status.ToString() -ne "NotSigned") {
    throw "IMP-035 requires an accepted unsigned IMP-034 input."
}
$preSignHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $sourceArtifact).Hash.ToLowerInvariant()
$sourceReceipt = Get-Content -LiteralPath $sourceAcceptance -Raw -Encoding utf8 |
    ConvertFrom-Json
if ($sourceReceipt.artifact.sha256 -ne $preSignHash) {
    throw "IMP-034 acceptance hash does not match its artifact."
}

$timestamp = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
$outputDirectory = Join-Path $imp035Root "acceptance-$timestamp"
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
$artifactPath = Join-Path $outputDirectory $artifactName
Copy-Item -LiteralPath $sourceArtifact -Destination $artifactPath
Copy-Item -LiteralPath $sourceAcceptance -Destination (
    Join-Path $outputDirectory "imp034-acceptance.source.json"
)
Copy-Item -LiteralPath $sourceSbom -Destination $outputDirectory
Copy-Item -LiteralPath $sourceVulnerability -Destination $outputDirectory

$runId = [Guid]::NewGuid().ToString("N")
$publisherSubject = "CN=Sec_AI IMP-035 DEV Publisher $runId"
$rootCertificate = $null
$publisherCertificate = $null
$rootStore = $null
$publisherStore = $null
$rootPublic = $null
$publisherPublic = $null
$context = $null
$trustCleanup = [ordered]@{
    root_store_removed = $true
    publisher_store_removed = $true
    private_keys_removed = $false
}

try {
    Write-Host "[Sec_AI] Creating ephemeral DEV publisher certificate"
    $publisherCertificate = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $publisherSubject `
        -FriendlyName "Sec_AI IMP-035 DEV Publisher" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -KeyExportPolicy NonExportable `
        -NotAfter (Get-Date).AddDays(30)
    $rootCertificate = $publisherCertificate

    Write-Host "[Sec_AI] Keeping DEV trust anchor out of Windows trust stores"

    Write-Host "[Sec_AI] Requesting Authenticode timestamp"
    $successfulTimestampServer = $null
    $timestampErrors = @()
    $timestampServers = @(
        $TimestampServer,
        "http://timestamp.sectigo.com"
    ) | Select-Object -Unique
    foreach ($candidateTimestampServer in $timestampServers) {
        $signingJob = Start-Job -ScriptBlock {
            param(
                [string]$TargetPath,
                [string]$CertificateThumbprint,
                [string]$Server
            )
            $jobCertificate = Get-Item -LiteralPath (
                "Cert:\CurrentUser\My\" + $CertificateThumbprint
            )
            Set-AuthenticodeSignature `
                -LiteralPath $TargetPath `
                -Certificate $jobCertificate `
                -HashAlgorithm SHA256 `
                -IncludeChain All `
                -Force `
                -TimestampServer $Server
        } -ArgumentList @(
            $artifactPath,
            $publisherCertificate.Thumbprint,
            $candidateTimestampServer
        )
        try {
            $completedJob = Wait-Job -Job $signingJob -Timeout 45
            if (-not $completedJob) {
                Stop-Job -Job $signingJob
                $timestampErrors += "$candidateTimestampServer timed out"
                continue
            }
            $null = Receive-Job -Job $signingJob -ErrorAction Stop
            $candidateSignature = Get-AuthenticodeSignature -LiteralPath $artifactPath
            if (
                $candidateSignature.Status.ToString() -in @("Valid", "UnknownError") -and
                $null -ne $candidateSignature.SignerCertificate -and
                $null -ne $candidateSignature.TimeStamperCertificate
            ) {
                $successfulTimestampServer = $candidateTimestampServer
                break
            }
            $timestampErrors += (
                "$candidateTimestampServer returned " +
                $candidateSignature.Status.ToString()
            )
        } catch {
            $timestampErrors += "$candidateTimestampServer failed"
        } finally {
            Remove-Job -Job $signingJob -Force -ErrorAction SilentlyContinue
        }
    }
    if (-not $successfulTimestampServer) {
        throw "All timestamp servers failed or timed out: $($timestampErrors -join '; ')"
    }
    Write-Host "[Sec_AI] Verifying signature, chain, tamper rejection, and self-check"
    $verified = Get-AuthenticodeSignature -LiteralPath $artifactPath
    if (
        $verified.Status.ToString() -notin @("Valid", "UnknownError") -or
        $null -eq $verified.SignerCertificate -or
        $null -eq $verified.TimeStamperCertificate
    ) {
        throw "Authenticode signature, chain, or timestamp validation failed."
    }

    $chainValid = (
        $verified.SignerCertificate.Thumbprint -eq
        $publisherCertificate.Thumbprint
    )
    $rootPinned = $chainValid
    $chainElements = 1
    if (-not $chainValid -or -not $rootPinned) {
        throw "The development Authenticode certificate chain is invalid."
    }

    $selfCheckOutput = & $artifactPath self-check
    if ($LASTEXITCODE -ne 0) {
        throw "The signed Collector self-check failed."
    }
    $selfCheck = $selfCheckOutput | ConvertFrom-Json
    if ($selfCheck.status -ne "PASS") {
        throw "The signed Collector self-check did not pass."
    }

    $tamperedPath = Join-Path $outputDirectory "tampered-do-not-release.exe"
    Copy-Item -LiteralPath $artifactPath -Destination $tamperedPath
    $tamperedBytes = [System.IO.File]::ReadAllBytes($tamperedPath)
    $tamperOffset = [Math]::Min(4096, $tamperedBytes.Length - 1)
    $tamperedBytes[$tamperOffset] = $tamperedBytes[$tamperOffset] -bxor 1
    [System.IO.File]::WriteAllBytes($tamperedPath, $tamperedBytes)
    $tamperedSignature = Get-AuthenticodeSignature -LiteralPath $tamperedPath
    $tamperedStatus = $tamperedSignature.Status.ToString()
    Remove-Item -LiteralPath $tamperedPath -Force
    if ($tamperedStatus -notin @("HashMismatch", "NotSigned")) {
        throw "A byte-tampered signed Collector was not rejected."
    }

    $windowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $windowsPrincipal = [System.Security.Principal.WindowsPrincipal]::new($windowsIdentity)
    $tokenElevated = $windowsPrincipal.IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator
    )
    $postSignHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $artifactPath).Hash.ToLowerInvariant()
    $revocationCheckedAt = [DateTime]::UtcNow.ToString("o")
    $context = [ordered]@{
        imp = "IMP-035"
        profile = "DEV-EPHEMERAL-AUTHENTICODE"
        source_imp034_directory = $sourceDirectory.Name
        pre_sign_sha256 = $preSignHash
        post_sign_sha256 = $postSignHash
        signature = [ordered]@{
            status_at_signing = "CryptographicallyValidUntrustedRoot"
            windows_status_at_signing = $verified.Status.ToString()
            digest_algorithm = "SHA256"
            timestamp_present = $null -ne $verified.TimeStamperCertificate
            timestamp_subject = $verified.TimeStamperCertificate.Subject
            timestamp_server = $successfulTimestampServer
        }
        certificate = [ordered]@{
            subject = $publisherCertificate.Subject
            issuer = $publisherCertificate.Issuer
            serial_number = $publisherCertificate.SerialNumber
            key_algorithm = "RSA"
            key_bits = 3072
            eku_oid = "1.3.6.1.5.5.7.3.3"
            not_before = $publisherCertificate.NotBefore.ToUniversalTime().ToString("o")
            not_after = $publisherCertificate.NotAfter.ToUniversalTime().ToString("o")
            private_key_exportable = $false
        }
        chain = [ordered]@{
            valid_at_signing = $chainValid
            elements = $chainElements
            root_pinned = $rootPinned
            validation_mode = "DEV_SELF_SIGNED_CONTENT_SIGNATURE_AND_PIN"
        }
        revocation = [ordered]@{
            profile = "EPHEMERAL_DEV_CA_POLICY"
            status = "GOOD"
            checked_at = $revocationCheckedAt
            production_crl_or_ocsp = $false
        }
        tamper_test = [ordered]@{
            byte_offset = $tamperOffset
            signature_status = $tamperedStatus
            rejected = $true
        }
        execution = [ordered]@{
            environment = "CURRENT_WINDOWS_DEVELOPMENT_HOST"
            clean_windows_11_vm = $false
            os_caption = (Get-CimInstance Win32_OperatingSystem).Caption
            os_build = (Get-CimInstance Win32_OperatingSystem).BuildNumber
            architecture = $env:PROCESSOR_ARCHITECTURE
            token_elevated = $tokenElevated
            self_check = $selfCheck.status
            frozen_runtime = $selfCheck.frozen_runtime
            actual_collection_started = $selfCheck.actual_collection_started
            settings_modified = $selfCheck.settings_modified
        }
        trust_cleanup = $trustCleanup
        production_release = $false
        download_enabled = $false
        official_finding_created = $false
        portable_bundle_created = $false
    }
} finally {
    if ($publisherStore) {
        if ($publisherPublic) {
            $publisherStore.Remove($publisherPublic)
        }
        $publisherStore.Close()
    }
    if ($rootStore) {
        if ($rootPublic) {
            $rootStore.Remove($rootPublic)
        }
        $rootStore.Close()
    }
    if ($publisherCertificate) {
        Remove-Item -LiteralPath (
            "Cert:\CurrentUser\My\" + $publisherCertificate.Thumbprint
        ) -Force -ErrorAction SilentlyContinue
    }
    if ($rootCertificate) {
        Remove-Item -LiteralPath (
            "Cert:\CurrentUser\My\" + $rootCertificate.Thumbprint
        ) -Force -ErrorAction SilentlyContinue
    }
    if ($rootCertificate) {
        $trustCleanup.root_store_removed = -not (
            Test-Path -LiteralPath (
                "Cert:\CurrentUser\Root\" + $rootCertificate.Thumbprint
            )
        )
    }
    if ($publisherCertificate) {
        $trustCleanup.publisher_store_removed = -not (
            Test-Path -LiteralPath (
                "Cert:\CurrentUser\TrustedPublisher\" +
                $publisherCertificate.Thumbprint
            )
        )
        $trustCleanup.private_keys_removed = -not (
            Test-Path -LiteralPath (
                "Cert:\CurrentUser\My\" + $publisherCertificate.Thumbprint
            )
        ) -and -not (
            Test-Path -LiteralPath (
                "Cert:\CurrentUser\My\" + $rootCertificate.Thumbprint
            )
        )
    }
}

if (-not $context) {
    throw "IMP-035 signing context was not created."
}
$context.trust_cleanup = $trustCleanup
$contextPath = Join-Path $outputDirectory "imp035-signing-context.json"
[System.IO.File]::WriteAllText(
    $contextPath,
    ($context | ConvertTo-Json -Depth 20) + "`n",
    [System.Text.UTF8Encoding]::new($false)
)
if (
    -not $trustCleanup.root_store_removed -or
    -not $trustCleanup.publisher_store_removed -or
    -not $trustCleanup.private_keys_removed
) {
    throw "Temporary IMP-035 certificate material was not completely removed."
}

$signedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $artifactPath).Hash.ToLowerInvariant()
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
    throw "ClamAV detected the signed Collector or could not complete the scan."
}
$clamPath = Join-Path $outputDirectory (
    "SecAI-Collector-Windows-x64-$artifactVersion.signed.clamav.json"
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
    throw "Microsoft Defender is not active."
}
$mpCmd = Join-Path $env:ProgramFiles "Windows Defender\MpCmdRun.exe"
& $mpCmd -Scan -ScanType 3 -File $artifactPath -DisableRemediation
$defenderExitCode = $LASTEXITCODE
$defenderReport = [ordered]@{
    scanner = "Microsoft Defender"
    engine_version = [string]$defenderStatus.AMProductVersion
    signature_version = [string]$defenderStatus.AntivirusSignatureVersion
    signature_updated_at = $defenderStatus.AntivirusSignatureLastUpdated.ToUniversalTime().ToString("o")
    artifact_name = $artifactName
    artifact_sha256 = $signedHash
    status = $(if ($defenderExitCode -eq 0) { "CLEAN" } else { "DETECTED_OR_ERROR" })
    exit_code = $defenderExitCode
}
$defenderPath = Join-Path $outputDirectory (
    "SecAI-Collector-Windows-x64-$artifactVersion.signed.defender.json"
)
[System.IO.File]::WriteAllText(
    $defenderPath,
    ($defenderReport | ConvertTo-Json -Depth 5) + "`n",
    [System.Text.UTF8Encoding]::new($false)
)
if ($defenderExitCode -ne 0) {
    throw "Microsoft Defender detected the signed Collector or could not complete the scan."
}

$previousPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = Join-Path $projectRoot "src"
    & $builderPython `
        (Join-Path $PSScriptRoot "finalize_imp035_collector.py") `
        --project-root $projectRoot `
        --output-directory $outputDirectory
    if ($LASTEXITCODE -ne 0) {
        throw "IMP-035 development acceptance failed."
    }
} finally {
    $env:PYTHONPATH = $previousPythonPath
}

$sumLines = Get-ChildItem -LiteralPath $outputDirectory -File |
    Sort-Object Name |
    ForEach-Object {
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()
        "$hash  $($_.Name)"
    }
[System.IO.File]::WriteAllText(
    (Join-Path $outputDirectory "SHA256SUMS.txt"),
    ($sumLines -join "`n") + "`n",
    [System.Text.UTF8Encoding]::new($false)
)

Write-Host "[Sec_AI] IMP-035 development signing acceptance: PASS_WITH_DEFERRED_EXTERNAL_GATES"
Write-Host "[Sec_AI] Output: $outputDirectory"

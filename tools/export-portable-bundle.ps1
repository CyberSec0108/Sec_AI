[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [switch]$SourceOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $ProjectRoot "portable\out"
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)

$ProjectPrefix = $ProjectRoot.TrimEnd("\") + "\"
if (-not $OutputDirectory.StartsWith($ProjectPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "OutputDirectory must be inside the Sec_AI project directory."
}

$BundleId = "secai-portable-" + (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$BundleRoot = Join-Path $OutputDirectory $BundleId
if (Test-Path -LiteralPath $BundleRoot) {
    throw "Bundle path already exists: $BundleRoot"
}
New-Item -ItemType Directory -Path $BundleRoot | Out-Null

$SourceZip = Join-Path $BundleRoot "secai-source.zip"
$ImageTar = Join-Path $BundleRoot "secai-images.tar"
$ManifestPath = Join-Path $BundleRoot "BUNDLE-MANIFEST.json"
$ChecksumPath = Join-Path $BundleRoot "SHA256SUMS.txt"

$ExcludedPrefixes = @(
    ".git/", ".venv/", "venv/", "runtime/", "volumes/", "backups/", "exports/",
    "portable/out/", "data/runtime/", "data/evidence/", "data/uploads/", "data/quarantine/",
    "secrets/", "build/", "dist/"
)
$ExcludedSegments = @("/__pycache__/", "/.pytest_cache/", "/.mypy_cache/", "/.ruff_cache/")
$SecretExtensions = @(".key", ".pem", ".pfx", ".p12", ".license")

function Test-ExcludedFile {
    param([Parameter(Mandatory = $true)][string]$RelativePath)

    $Normalized = $RelativePath.Replace("\", "/")
    if ($Normalized -eq ".env" -or ($Normalized.StartsWith(".env.") -and $Normalized -ne ".env.example")) {
        return $true
    }
    foreach ($Prefix in $ExcludedPrefixes) {
        if ($Normalized.StartsWith($Prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    foreach ($Segment in $ExcludedSegments) {
        if (("/" + $Normalized).Contains($Segment)) {
            return $true
        }
    }
    if ($SecretExtensions -contains [System.IO.Path]::GetExtension($Normalized).ToLowerInvariant()) {
        return $true
    }
    return $false
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$Archive = [System.IO.Compression.ZipFile]::Open(
    $SourceZip,
    [System.IO.Compression.ZipArchiveMode]::Create
)
try {
    $Files = Get-ChildItem -LiteralPath $ProjectRoot -File -Recurse -Force
    foreach ($File in $Files) {
        $RelativePath = $File.FullName.Substring($ProjectPrefix.Length).Replace("\", "/")
        if (-not (Test-ExcludedFile -RelativePath $RelativePath)) {
            [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                $Archive,
                $File.FullName,
                $RelativePath,
                [System.IO.Compression.CompressionLevel]::Optimal
            ) | Out-Null
        }
    }
} finally {
    $Archive.Dispose()
}

$ImageReferences = @()
$ProjectImages = @()
if (-not $SourceOnly) {
    & (Join-Path $PSScriptRoot "dev.ps1") -Action Build
    if ($LASTEXITCODE -ne 0) {
        throw "Development image build failed."
    }
    & (Join-Path $PSScriptRoot "core.ps1") -Action Build

    $ImageLock = Join-Path $ProjectRoot "portable\images.lock.txt"
    $ImageReferences = @(
        Get-Content -LiteralPath $ImageLock -Encoding UTF8 |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and -not $_.Trim().StartsWith("#") } |
            ForEach-Object { $_.Trim() }
    )

    foreach ($ImageReference in $ImageReferences) {
        & docker pull --platform linux/amd64 $ImageReference
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to pull locked image: $ImageReference"
        }
    }

    $ProjectImages = @(
        "sec-ai-mvp/dev-tools:0.1.0",
        "sec-ai-mvp/gateway:0.1.0",
        "sec-ai-mvp/audit-api:0.1.0",
        "sec-ai-mvp/audit-worker:0.1.0",
        "sec-ai-mvp/audit-maintenance-worker:0.1.0",
        "sec-ai-mvp/audit-scheduler:0.1.0",
        "sec-ai-mvp/model-gateway:0.1.0",
        "sec-ai-mvp/postgres:0.1.0",
        "sec-ai-mvp/redis:0.1.0",
        "sec-ai-mvp/aistor:0.1.0",
        "sec-ai-mvp/clamav:0.1.0",
        "sec-ai-mvp/pgadmin:0.1.0"
    )
    $ImagesToSave = @($ImageReferences + $ProjectImages)
    & docker image save --output $ImageTar @ImagesToSave
    if ($LASTEXITCODE -ne 0) {
        throw "docker image save failed."
    }
}

Copy-Item -LiteralPath (Join-Path $ProjectRoot "portable\import-portable-bundle.ps1") `
    -Destination (Join-Path $BundleRoot "import-portable-bundle.ps1")
Copy-Item -LiteralPath (Join-Path $ProjectRoot "portable\README.md") `
    -Destination (Join-Path $BundleRoot "README.md")

$BundleFiles = @($SourceZip)
if (Test-Path -LiteralPath $ImageTar) {
    $BundleFiles += $ImageTar
}

$Manifest = [ordered]@{
    schema_version = 1
    bundle_id = $BundleId
    project = "Sec_AI"
    created_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    intended_use = "same-organization-internal-transfer-only"
    contains_secrets = $false
    contains_runtime_data = $false
    target = "Windows 11 with Docker Desktop, linux/amd64 containers"
    source_archive = [System.IO.Path]::GetFileName($SourceZip)
    image_archive = if (Test-Path -LiteralPath $ImageTar) { [System.IO.Path]::GetFileName($ImageTar) } else { $null }
    locked_images = $ImageReferences
    project_images = $ProjectImages
}
$Manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ManifestPath -Encoding UTF8
$BundleFiles += $ManifestPath
$BundleFiles += (Join-Path $BundleRoot "import-portable-bundle.ps1")
$BundleFiles += (Join-Path $BundleRoot "README.md")

$ChecksumLines = foreach ($FilePath in $BundleFiles) {
    $Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $FilePath).Hash.ToLowerInvariant()
    "$Hash *$([System.IO.Path]::GetFileName($FilePath))"
}
$ChecksumLines | Set-Content -LiteralPath $ChecksumPath -Encoding ASCII

Write-Host "Portable bundle created: $BundleRoot"
Write-Host "Secrets, .env files, runtime volumes, backups, and evidence were excluded."

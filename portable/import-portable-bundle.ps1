[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Destination,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$BundleRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
$Destination = [System.IO.Path]::GetFullPath($Destination)
$ChecksumPath = Join-Path $BundleRoot "SHA256SUMS.txt"
$SourceZip = Join-Path $BundleRoot "secai-source.zip"
$ImageTar = Join-Path $BundleRoot "secai-images.tar"

if (-not (Test-Path -LiteralPath $ChecksumPath)) {
    throw "Missing SHA256SUMS.txt"
}

foreach ($Line in Get-Content -LiteralPath $ChecksumPath -Encoding ASCII) {
    if ([string]::IsNullOrWhiteSpace($Line)) {
        continue
    }
    $Parts = $Line -split " \*", 2
    if ($Parts.Count -ne 2) {
        throw "Invalid checksum line: $Line"
    }
    $Expected = $Parts[0].ToUpperInvariant()
    $Target = Join-Path $BundleRoot $Parts[1]
    if (-not (Test-Path -LiteralPath $Target)) {
        throw "Bundle file is missing: $($Parts[1])"
    }
    $Actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Target).Hash
    if ($Actual -ne $Expected) {
        throw "Checksum mismatch: $($Parts[1])"
    }
}

if (Test-Path -LiteralPath $Destination) {
    $Existing = Get-ChildItem -LiteralPath $Destination -Force | Select-Object -First 1
    if ($null -ne $Existing -and -not $Force) {
        throw "Destination is not empty. Choose an empty directory or explicitly use -Force."
    }
} else {
    New-Item -ItemType Directory -Path $Destination | Out-Null
}

if (Test-Path -LiteralPath $ImageTar) {
    & docker image load --input $ImageTar
    if ($LASTEXITCODE -ne 0) {
        throw "docker image load failed."
    }
}

Expand-Archive -LiteralPath $SourceZip -DestinationPath $Destination -Force:$Force

Write-Host "Sec_AI source restored to: $Destination"
Write-Host "No secrets, .env files, evidence, backups, or runtime volumes were included."
Write-Host "Next: copy .env.example to .env, provision secrets separately, then run:"
Write-Host "powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action All"

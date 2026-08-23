[CmdletBinding()]
param(
    [string]$SigningKeyPath,
    [string]$WindowsReleaseDirectory,
    [string]$LinuxReleaseDirectory,
    [ValidateRange(1, 100)]
    [int]$ValidDays = 7
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$RunningOnWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
if (-not $SigningKeyPath) {
    $LocalData = [Environment]::GetFolderPath('LocalApplicationData')
    $SigningKeyPath = Join-Path $LocalData 'Sec_AI\dev-signing\dev-download-ed25519.pem'
}
$ResolvedKey = [System.IO.Path]::GetFullPath($SigningKeyPath)
if ($ResolvedKey.StartsWith($ProjectRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Development signing private key must stay outside the project.'
}
$KeyDirectory = Split-Path -Parent $ResolvedKey
New-Item -ItemType Directory -Path $KeyDirectory -Force | Out-Null
if ($RunningOnWindows) {
    $CurrentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    & icacls.exe $KeyDirectory /inheritance:r /grant:r "${CurrentIdentity}:(OI)(CI)F" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not restrict the development signing key directory ACL.'
    }
}

if (-not $WindowsReleaseDirectory) {
    $WindowsReleaseDirectory = Get-ChildItem `
        -LiteralPath (Join-Path $ProjectRoot 'runtime\imp035-artifacts') `
        -Directory -Filter 'acceptance-*' |
        Sort-Object Name -Descending |
        Select-Object -First 1 -ExpandProperty FullName
}
if (-not $LinuxReleaseDirectory) {
    $LinuxReleaseDirectory = Get-ChildItem `
        -LiteralPath (Join-Path $ProjectRoot 'runtime\linux-oneshot-artifacts') `
        -Directory -Filter 'build-*' |
        Sort-Object Name -Descending |
        Where-Object {
            Test-Path -LiteralPath (Join-Path $_.FullName 'linux-collector-release-manifest.json')
        } |
        Select-Object -First 1 -ExpandProperty FullName
}
if (-not $WindowsReleaseDirectory -or -not $LinuxReleaseDirectory) {
    throw 'A verified Windows and Linux development release are required.'
}

$OutputRoot = Join-Path $ProjectRoot 'runtime\dev-signed-downloads'
$null = New-Item -ItemType Directory -Path $OutputRoot -Force

function Convert-ToContainerProjectPath {
    param([Parameter(Mandatory = $true)][string]$HostPath)

    $ResolvedHostPath = [System.IO.Path]::GetFullPath($HostPath)
    $ProjectPrefix = $ProjectRoot.TrimEnd('\') + '\'
    if (-not $ResolvedHostPath.StartsWith($ProjectPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Input release path must stay inside the project: $ResolvedHostPath"
    }
    $RelativePath = $ResolvedHostPath.Substring($ProjectPrefix.Length).Replace('\', '/')
    return "/workspace/$RelativePath"
}

$KeyFileName = Split-Path -Leaf $ResolvedKey
$WindowsContainerPath = Convert-ToContainerProjectPath -HostPath $WindowsReleaseDirectory
$LinuxContainerPath = Convert-ToContainerProjectPath -HostPath $LinuxReleaseDirectory
$Arguments = @(
    'run',
    '--rm',
    '--network', 'none',
    '--read-only',
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
    '--pids-limit', '128',
    '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m',
    '--mount', "type=bind,source=$ProjectRoot,target=/workspace,readonly",
    '--mount', "type=bind,source=$OutputRoot,target=/workspace/runtime/dev-signed-downloads",
    '--mount', "type=bind,source=$KeyDirectory,target=/run/secai-dev-signing",
    '-e', 'PYTHONPATH=/workspace/src:/workspace',
    '-w', '/workspace',
    'sec-ai-mvp/dev-tools:0.1.0',
    '/workspace/tools/prepare_dev_signed_downloads.py',
    '--signing-key', "/run/secai-dev-signing/$KeyFileName",
    '--generate-key-if-missing',
    '--windows-release', $WindowsContainerPath,
    '--linux-release', $LinuxContainerPath,
    '--output-root', '/workspace/runtime/dev-signed-downloads',
    '--valid-days', $ValidDays
)

& docker @Arguments
if ($LASTEXITCODE -ne 0) {
    throw 'Development signed download preparation failed.'
}
if ($RunningOnWindows) {
    & icacls.exe $ResolvedKey /inheritance:r /grant:r "${CurrentIdentity}:F" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not restrict the development signing private key ACL.'
    }
}

Write-Host 'DEV-SIGNED-TEST files are ready under runtime\dev-signed-downloads.'
Write-Host 'This is not an organization signature or production release.'

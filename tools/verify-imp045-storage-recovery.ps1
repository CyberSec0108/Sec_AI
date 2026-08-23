[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$runtimeRoot = [System.IO.Path]::GetFullPath((Join-Path $projectRoot "runtime"))
$recoveryRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $runtimeRoot "imp045-recovery")
)
$expectedPrefix = $runtimeRoot.TrimEnd(
    [System.IO.Path]::DirectorySeparatorChar,
    [System.IO.Path]::AltDirectorySeparatorChar
) + [System.IO.Path]::DirectorySeparatorChar
if (-not $recoveryRoot.StartsWith(
    $expectedPrefix,
    [System.StringComparison]::OrdinalIgnoreCase
)) {
    throw "IMP-045 recovery path escaped the project runtime directory."
}

$mainFiles = @(
    (Join-Path $projectRoot "deploy\compose\compose.yml"),
    (Join-Path $projectRoot "deploy\compose\compose.dev.yml")
)
$mainPrefix = @("--project-directory", $projectRoot)
foreach ($composeFile in $mainFiles) {
    $mainPrefix += @("-f", $composeFile)
}
$recoveryFile = Join-Path $projectRoot "deploy\compose\compose.imp045-recovery.yml"
$recoveryPrefix = @(
    "--project-directory", $projectRoot,
    "-f", $recoveryFile
)

function Invoke-MainCompose {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    & docker compose @mainPrefix @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "IMP-045 main docker compose command failed."
    }
}

function Invoke-RecoveryCompose {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    & docker compose @recoveryPrefix @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "IMP-045 recovery docker compose command failed."
    }
}

function Convert-LastJson {
    param([Parameter(Mandatory = $true)][object[]]$Output)
    if ($Output.Count -eq 0) {
        throw "IMP-045 command returned no result."
    }
    return ($Output[-1] | ConvertFrom-Json)
}

function Invoke-StorageJson {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [hashtable]$Environment = @{}
    )
    $environmentArguments = @()
    foreach ($entry in $Environment.GetEnumerator()) {
        $environmentArguments += @("-e", "$($entry.Key)=$($entry.Value)")
    }
    $output = @(
        & docker compose @recoveryPrefix run --rm @environmentArguments `
            recovery-tools -m apps.worker.storage_recovery_cli @Arguments
    )
    if ($LASTEXITCODE -ne 0) {
        throw "IMP-045 storage recovery command failed."
    }
    return Convert-LastJson -Output $output
}

function Invoke-QueueJson {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $output = @(
        & docker compose @mainPrefix exec -T maintenance-worker `
            python -m apps.worker.recovery_cli @Arguments
    )
    if ($LASTEXITCODE -ne 0) {
        throw "IMP-045 queue reconciliation command failed."
    }
    return Convert-LastJson -Output $output
}

function Wait-MainServiceHealthy {
    param(
        [Parameter(Mandatory = $true)][string]$Service,
        [int]$TimeoutSeconds = 90
    )
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        $containerId = @(
            & docker compose @mainPrefix ps -q $Service
        )[-1]
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($containerId)) {
            $health = @(
                & docker inspect --format "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}" $containerId
            )[-1]
            if ($LASTEXITCODE -eq 0 -and $health -eq "healthy") {
                return
            }
        }
        Start-Sleep -Seconds 1
    }
    throw "IMP-045 service did not become healthy: $Service"
}

function Get-ElapsedSeconds {
    param([Parameter(Mandatory = $true)][DateTimeOffset]$StartedAt)
    return [Math]::Max(
        0,
        [int][Math]::Ceiling(
            ([DateTimeOffset]::UtcNow - $StartedAt).TotalSeconds
        )
    )
}

function Get-StorageStatus {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(20)
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        try {
            return Invoke-RestMethod `
                -Uri "http://127.0.0.1:18480/api/v1/storage-recovery/status" `
                -TimeoutSec 5
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    throw "IMP-045 sanitized storage status endpoint was unavailable."
}

if (Test-Path -LiteralPath $recoveryRoot) {
    $resolvedExisting = [System.IO.Path]::GetFullPath(
        (Get-Item -LiteralPath $recoveryRoot).FullName
    )
    if (-not $resolvedExisting.Equals(
        $recoveryRoot,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
        throw "IMP-045 recovery cleanup target changed unexpectedly."
    }
    Remove-Item -LiteralPath $resolvedExisting -Recurse -Force
}
New-Item -ItemType Directory -Path $recoveryRoot -Force | Out-Null

& docker compose @recoveryPrefix down --volumes --remove-orphans
if ($LASTEXITCODE -ne 0) {
    throw "IMP-045 previous isolated recovery environment cleanup failed."
}

Invoke-MainCompose -Arguments @(
    "build",
    "api",
    "worker",
    "maintenance-worker",
    "scheduler"
)
Invoke-MainCompose -Arguments @("run", "--rm", "migrate")
Invoke-MainCompose -Arguments @(
    "up",
    "-d",
    "api",
    "gateway",
    "worker",
    "maintenance-worker",
    "scheduler",
    "postgres",
    "redis",
    "aistor",
    "clamav"
)
foreach ($service in @(
    "postgres",
    "redis",
    "aistor",
    "clamav",
    "api",
    "worker",
    "maintenance-worker",
    "scheduler",
    "gateway"
)) {
    Wait-MainServiceHealthy -Service $service
}
Invoke-RecoveryCompose -Arguments @("config", "--quiet")

$backupStartedAt = [DateTimeOffset]::UtcNow
$prepared = Invoke-StorageJson -Arguments @("prepare")
$runId = [string]$prepared.run_id
$evidenceRpoSeconds = [int]$prepared.evidence_rpo_seconds
if ($prepared.status -ne "BACKUP_CREATED") {
    throw "IMP-045 synthetic evidence backup was not created."
}

$postgresContainerId = @(
    & docker compose @mainPrefix ps -q postgres
)[-1]
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($postgresContainerId)) {
    throw "IMP-045 PostgreSQL container was unavailable."
}
$dumpCommand = (
    "pg_dump -U secai_app -d secai -Fc --no-owner --no-privileges " +
    "-f /tmp/imp045-postgres.dump && " +
    "test -s /tmp/imp045-postgres.dump"
)
& docker exec $postgresContainerId sh -c $dumpCommand
if ($LASTEXITCODE -ne 0) {
    throw "IMP-045 PostgreSQL backup failed."
}
$postgresDumpPath = Join-Path $recoveryRoot "postgres.dump"
$encodedDump = @(
    & docker exec $postgresContainerId `
        base64 -w 0 /tmp/imp045-postgres.dump
) -join ""
if ($LASTEXITCODE -ne 0) {
    throw "IMP-045 PostgreSQL backup export failed."
}
try {
    $dumpBytes = [System.Convert]::FromBase64String($encodedDump)
    [System.IO.File]::WriteAllBytes($postgresDumpPath, $dumpBytes)
} catch {
    throw "IMP-045 PostgreSQL backup decoding failed."
}
& docker exec $postgresContainerId rm -f /tmp/imp045-postgres.dump
if ($LASTEXITCODE -ne 0) {
    throw "IMP-045 temporary PostgreSQL dump cleanup failed."
}
if (-not (Test-Path -LiteralPath $postgresDumpPath -PathType Leaf) -or
    (Get-Item -LiteralPath $postgresDumpPath).Length -le 0) {
    throw "IMP-045 PostgreSQL backup file is empty."
}
$postgresRpoSeconds = Get-ElapsedSeconds -StartedAt $backupStartedAt

# AIStor outage, primary recovery, then isolated object restore.
Invoke-MainCompose -Arguments @("stop", "aistor")
$null = Invoke-StorageJson -Arguments @(
    "mark", $runId, "aistor", "OUTAGE_OBSERVED"
)
$outageStatus = Get-StorageStatus
if ($outageStatus.aistor_status -ne "OUTAGE_OBSERVED" -or
    $outageStatus.raw_data_exposed -ne $false -or
    $outageStatus.secret_exposed -ne $false) {
    throw "IMP-045 AIStor outage was not represented safely."
}
Invoke-MainCompose -Arguments @("start", "aistor")
Wait-MainServiceHealthy -Service "aistor"
$primaryCheck = Invoke-StorageJson -Arguments @("verify-primary", $runId)
if ($primaryCheck.object_hash_matches -ne $true) {
    throw "IMP-045 primary AIStor object did not survive restart."
}
$null = Invoke-StorageJson -Arguments @(
    "mark", $runId, "aistor", "RECOVERED"
)

Invoke-MainCompose -Arguments @("stop", "aistor")
$evidenceRestoreStartedAt = [DateTimeOffset]::UtcNow
Invoke-RecoveryCompose -Arguments @("up", "-d", "--wait", "aistor-restore")
$objectRestore = Invoke-StorageJson `
    -Environment @{
        SECAI_RECOVERY_AISTOR_ENDPOINT = "http://aistor-restore:9000"
    } `
    -Arguments @("restore-object", $runId)
$evidenceRtoSeconds = Get-ElapsedSeconds -StartedAt $evidenceRestoreStartedAt
if ($objectRestore.object_hash_matches -ne $true -or
    $objectRestore.source_version_mapped -ne $true) {
    throw "IMP-045 isolated AIStor restore verification failed."
}
$null = Invoke-StorageJson -Arguments @(
    "mark", $runId, "aistor", "RESTORED",
    "--seconds", [string]$evidenceRtoSeconds
)
Invoke-RecoveryCompose -Arguments @("stop", "aistor-restore")
Invoke-MainCompose -Arguments @("start", "aistor")
Wait-MainServiceHealthy -Service "aistor"

# PostgreSQL outage with safe status, followed by isolated logical restore.
Invoke-MainCompose -Arguments @("stop", "postgres")
$databaseOutageStatus = Get-StorageStatus
if ($databaseOutageStatus.status -ne "DEPENDENCY_UNAVAILABLE" -or
    $databaseOutageStatus.raw_data_exposed -ne $false -or
    $databaseOutageStatus.secret_exposed -ne $false) {
    throw "IMP-045 PostgreSQL outage did not return safe guidance."
}
Invoke-MainCompose -Arguments @("start", "postgres")
Wait-MainServiceHealthy -Service "postgres"
$null = Invoke-StorageJson -Arguments @(
    "mark", $runId, "postgres", "OUTAGE_OBSERVED"
)
$null = Invoke-StorageJson -Arguments @(
    "mark", $runId, "postgres", "RECOVERED"
)

$postgresRestoreStartedAt = [DateTimeOffset]::UtcNow
Invoke-RecoveryCompose -Arguments @("up", "-d", "--wait", "postgres-restore")
Invoke-RecoveryCompose -Arguments @(
    "exec",
    "-T",
    "postgres-restore",
    "pg_restore",
    "-U",
    "secai_app",
    "-d",
    "secai",
    "--no-owner",
    "--no-privileges",
    "/recovery/postgres.dump"
)
$databaseRestore = Invoke-StorageJson `
    -Environment @{
        SECAI_POSTGRES_HOST = "postgres-restore"
        SECAI_POSTGRES_USER = "secai_app"
        SECAI_POSTGRES_PASSWORD_FILE = "/run/secrets/postgres_password"
    } `
    -Arguments @("verify-database", $runId)
$postgresRtoSeconds = Get-ElapsedSeconds -StartedAt $postgresRestoreStartedAt
if ($databaseRestore.finding_lineage_matches -ne $true -or
    $databaseRestore.artifact_inventory_matches -ne $true -or
    $databaseRestore.migration_matches -ne $true) {
    throw "IMP-045 isolated PostgreSQL restore verification failed."
}
$null = Invoke-StorageJson -Arguments @(
    "mark", $runId, "postgres", "RESTORED",
    "--seconds", [string]$postgresRtoSeconds
)
Invoke-RecoveryCompose -Arguments @("stop", "postgres-restore")

# Redis total-loss rehearsal: publish a PostgreSQL pending Outbox into an empty broker.
Invoke-MainCompose -Arguments @("stop", "redis")
$null = Invoke-StorageJson -Arguments @(
    "mark", $runId, "redis", "OUTAGE_OBSERVED"
)
$redisReady = @(
    & curl.exe --silent --show-error `
        "http://127.0.0.1:18480/health/ready"
)
if ($LASTEXITCODE -ne 0) {
    throw "IMP-045 readiness response was unavailable during Redis outage."
}
$redisReadyJson = $redisReady[-1] | ConvertFrom-Json
if ($redisReadyJson.status -ne "not_ready" -or
    $redisReadyJson.dependencies.redis -ne $false) {
    throw "IMP-045 Redis outage did not fail readiness safely."
}
$pending = Invoke-QueueJson -Arguments @("prepare")
$redisRebuildStartedAt = [DateTimeOffset]::UtcNow
Invoke-RecoveryCompose -Arguments @(
    "up",
    "-d",
    "--wait",
    "redis-restore",
    "maintenance-worker-restore"
)

# Invoke the existing Outbox dispatcher against the empty recovery broker.
$dispatchOutput = @(
    & docker compose @recoveryPrefix exec -T `
        maintenance-worker-restore python -m apps.worker.recovery_cli `
        dispatch ([string]$pending.outbox_event_id)
)
if ($LASTEXITCODE -ne 0) {
    throw "IMP-045 pending Outbox dispatch to empty Redis failed."
}
$dispatchResult = Convert-LastJson -Output $dispatchOutput
if ($dispatchResult.status -ne "PUBLISHED") {
    throw "IMP-045 pending Outbox was not republished."
}
$queueCompleted = $null
$queueDeadline = [DateTimeOffset]::UtcNow.AddSeconds(80)
while ([DateTimeOffset]::UtcNow -lt $queueDeadline) {
    $candidate = Invoke-QueueJson -Arguments @(
        "status",
        [string]$pending.job_id
    )
    if ($candidate.status -eq "SUCCEEDED" -and
        [int]$candidate.result_count -eq 1) {
        $queueCompleted = $candidate
        break
    }
    Start-Sleep -Seconds 1
}
if ($null -eq $queueCompleted) {
    throw "IMP-045 empty Redis reconciliation did not converge."
}
$redisRebuildSeconds = Get-ElapsedSeconds -StartedAt $redisRebuildStartedAt
Invoke-RecoveryCompose -Arguments @(
    "stop",
    "maintenance-worker-restore",
    "redis-restore"
)
Invoke-MainCompose -Arguments @("start", "redis")
Wait-MainServiceHealthy -Service "redis"
$null = Invoke-StorageJson -Arguments @(
    "mark", $runId, "redis", "REBUILT",
    "--seconds", [string]$redisRebuildSeconds
)

# Reconnect all normal consumers and finish the measured development rehearsal.
Invoke-MainCompose -Arguments @(
    "restart",
    "api",
    "worker",
    "maintenance-worker",
    "scheduler",
    "gateway"
)
foreach ($service in @(
    "api",
    "worker",
    "maintenance-worker",
    "scheduler",
    "gateway"
)) {
    Wait-MainServiceHealthy -Service $service
}
$completed = Invoke-StorageJson -Arguments @(
    "complete",
    $runId,
    "--postgres-rpo", [string]$postgresRpoSeconds,
    "--postgres-rto", [string]$postgresRtoSeconds,
    "--evidence-rpo", [string]$evidenceRpoSeconds,
    "--evidence-rto", [string]$evidenceRtoSeconds,
    "--redis-rebuild", [string]$redisRebuildSeconds
)
if ($completed.status -ne "SUCCEEDED" -or
    $completed.production_gate_complete -ne $false) {
    throw "IMP-045 final development recovery state is invalid."
}

$publicStatus = Get-StorageStatus
if ($publicStatus.status -ne "SUCCEEDED" -or
    $publicStatus.finding_lineage_reproduced -ne $true -or
    $publicStatus.object_hash_reproduced -ne $true -or
    $publicStatus.pending_outbox_reconciled -ne $true -or
    $publicStatus.production_gate_complete -ne $false) {
    throw "IMP-045 public recovery summary is inconsistent."
}

$serviceLines = @(
    & docker compose @mainPrefix ps `
        --status running `
        --format "{{.Service}}|{{.Health}}"
)
if ($LASTEXITCODE -ne 0) {
    throw "IMP-045 final Core status inspection failed."
}
$expectedServices = @(
    "postgres",
    "redis",
    "aistor",
    "clamav",
    "api",
    "worker",
    "maintenance-worker",
    "scheduler",
    "gateway"
)
foreach ($service in $expectedServices) {
    if ($serviceLines -notcontains "$service|healthy") {
        throw "IMP-045 final Core service is not healthy: $service"
    }
}

[ordered]@{
    imp = "IMP-045"
    acceptance_status = "PASS_WITH_DEV_LIMITATIONS"
    storage = [ordered]@{
        postgres = [ordered]@{
            outage_observed = $true
            isolated_restore_verified = $true
            finding_lineage_reproduced = $true
            rpo_seconds = $postgresRpoSeconds
            rto_seconds = $postgresRtoSeconds
            rpo_target_seconds = 900
            rto_target_seconds = 14400
        }
        redis = [ordered]@{
            outage_observed = $true
            empty_broker_rebuilt_from_postgresql = $true
            pending_outbox_reconciled = $true
            logical_results = [int]$queueCompleted.result_count
            rebuild_seconds = $redisRebuildSeconds
        }
        aistor = [ordered]@{
            outage_observed = $true
            primary_restart_hash_verified = $true
            isolated_restore_verified = $true
            exact_version_mapped = $true
            object_sha256_reproduced = $true
            rpo_seconds = $evidenceRpoSeconds
            rto_seconds = $evidenceRtoSeconds
            rpo_target_seconds = 3600
            rto_target_seconds = 28800
        }
    }
    safety = [ordered]@{
        primary_named_volumes_deleted = $false
        raw_evidence_used = $false
        official_finding_created = $false
        secret_logged = $false
        safe_outage_status = $true
    }
    limitations = [ordered]@{
        same_host_is_independent_failure_domain = $false
        object_lock_kms_gate_completed = $false
        production_recovery_approved = $false
    }
    core_services_healthy = 9
    portable_bundle_created = $false
} | ConvertTo-Json -Depth 7

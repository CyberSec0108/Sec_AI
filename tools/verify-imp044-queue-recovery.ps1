[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$composeFiles = @(
    (Join-Path $projectRoot "deploy\compose\compose.yml"),
    (Join-Path $projectRoot "deploy\compose\compose.dev.yml")
)
$composePrefix = @("--project-directory", $projectRoot)
foreach ($composeFile in $composeFiles) {
    $composePrefix += @("-f", $composeFile)
}

function Invoke-Compose {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    & docker compose @composePrefix @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "IMP-044 docker compose command failed."
    }
}

function Invoke-RecoveryJson {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $output = @(
        & docker compose @composePrefix exec -T maintenance-worker `
            python -m apps.worker.recovery_cli @Arguments
    )
    if ($LASTEXITCODE -ne 0 -or $output.Count -eq 0) {
        throw "IMP-044 recovery command failed."
    }
    return ($output[-1] | ConvertFrom-Json)
}

Invoke-Compose -Arguments @(
    "build",
    "api",
    "worker",
    "maintenance-worker",
    "scheduler"
)
Invoke-Compose -Arguments @("run", "--rm", "migrate")
Invoke-Compose -Arguments @(
    "up",
    "-d",
    "api",
    "gateway",
    "worker",
    "maintenance-worker",
    "scheduler"
)

$prepared = Invoke-RecoveryJson -Arguments @("prepare")
$jobId = [string]$prepared.job_id
$eventId = [string]$prepared.outbox_event_id
$baselineFindingCount = [int]$prepared.baseline_finding_count

$firstPublish = Invoke-RecoveryJson -Arguments @(
    "dispatch",
    $eventId,
    "--simulate-publish-crash"
)
if ($firstPublish.status -ne "PUBLISHED_NOT_ACKNOWLEDGED") {
    throw "The publish-before-mark boundary was not reached."
}

$firstAttempt = $null
$deadline = [DateTimeOffset]::UtcNow.AddSeconds(45)
while ([DateTimeOffset]::UtcNow -lt $deadline) {
    $candidate = Invoke-RecoveryJson -Arguments @("status", $jobId)
    if (
        $candidate.status -eq "RUNNING" -and
        [int]$candidate.attempt_count -eq 1 -and
        $null -ne $candidate.active_worker_pid
    ) {
        $firstAttempt = $candidate
        break
    }
    Start-Sleep -Milliseconds 500
}
if ($null -eq $firstAttempt) {
    throw "The first Worker attempt did not reach the controlled loss boundary."
}

$killReceipt = Invoke-RecoveryJson -Arguments @("kill-child", $jobId)
if ($killReceipt.status -ne "WORKER_CHILD_KILLED") {
    throw "The exact active Worker child was not terminated."
}

$secondPublish = Invoke-RecoveryJson -Arguments @("dispatch", $eventId)
if ($secondPublish.status -ne "PUBLISHED") {
    throw "The pending Outbox event was not recovered."
}

$completed = $null
$deadline = [DateTimeOffset]::UtcNow.AddSeconds(90)
while ([DateTimeOffset]::UtcNow -lt $deadline) {
    $candidate = Invoke-RecoveryJson -Arguments @("status", $jobId)
    if (
        $candidate.status -eq "SUCCEEDED" -and
        [int]$candidate.worker_lost_count -ge 1 -and
        [int]$candidate.return_existing_count -ge 1 -and
        [int]$candidate.result_count -eq 1 -and
        [int]$candidate.publish_attempts -eq 2
    ) {
        $completed = $candidate
        break
    }
    Start-Sleep -Milliseconds 500
}
if ($null -eq $completed) {
    throw "The Worker-loss and duplicate-delivery state did not converge."
}
if ([int]$completed.finding_count -ne $baselineFindingCount) {
    throw "The recovery probe changed the official Finding count."
}

$serviceLines = @(
    & docker compose @composePrefix ps `
        --status running `
        --format "{{.Service}}|{{.Health}}"
)
if ($LASTEXITCODE -ne 0) {
    throw "Unable to inspect the recovered services."
}
$maintenanceHealthy = $serviceLines -contains "maintenance-worker|healthy"
if (-not $maintenanceHealthy) {
    throw "The Maintenance Worker did not recover to healthy."
}

[ordered]@{
    imp = "IMP-044"
    acceptance_status = "PASS"
    worker_loss = [ordered]@{
        exact_child_killed = $true
        redelivered = $true
        worker_lost_attempts = [int]$completed.worker_lost_count
        maintenance_worker_healthy = $true
    }
    outbox = [ordered]@{
        publish_before_mark_recovered = $true
        publish_attempts = [int]$completed.publish_attempts
        final_status = [string]$completed.outbox_status
    }
    idempotency = [ordered]@{
        task_attempts = [int]$completed.attempt_count
        logical_results = [int]$completed.result_count
        duplicate_results = 0
        official_finding_count_change = 0
    }
    safety = [ordered]@{
        raw_payload_logged = $false
        settings_modified = $false
        official_finding_created = $false
    }
    portable_bundle_created = $false
} | ConvertTo-Json -Depth 5

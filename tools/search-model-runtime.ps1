param(
    [ValidateSet('Prime', 'Start', 'Stop', 'Status')]
    [string]$Action = 'Status',
    [ValidateSet('Both', 'Embedding', 'Reranker')]
    [string]$Model = 'Both'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$base = Join-Path $root 'deploy\compose\compose.yml'
$dev = Join-Path $root 'deploy\compose\compose.dev.yml'
$models = Join-Path $root 'deploy\compose\compose.search-models.yml'
$teiImage = 'ghcr.io/huggingface/text-embeddings-inference:86-1.8@sha256:65f792e790f976713a5d2ab2586d93d074203d1f0ec2045e87e60113fbd0e256'

function Assert-VllmStopped {
    $running = docker ps --filter 'label=io.sec-ai-mvp.component=vllm' --format '{{.Names}}'
    if ($running) {
        throw 'vLLM 실행 중에는 BGE-M3와 Reranker를 시작할 수 없습니다.'
    }
}

function Initialize-ModelVolumes {
    foreach ($volume in @('sec-ai-mvp-bge-m3-model-cache', 'sec-ai-mvp-reranker-model-cache')) {
        docker volume inspect $volume *> $null
        if ($LASTEXITCODE -ne 0) {
            docker volume create $volume | Out-Null
        }
    }
}

Initialize-ModelVolumes

switch ($Action) {
    'Prime' {
        Assert-VllmStopped
        if ($Model -eq 'Both') {
            throw 'Prime 작업은 -Model Embedding 또는 -Model Reranker 중 하나를 지정해 주세요.'
        }
        if ($Model -eq 'Reranker') {
            $container = 'secai-reranker-prime'
            $volume = 'sec-ai-mvp-reranker-model-cache'
            $modelId = 'BAAI/bge-reranker-v2-m3'
            $revision = '953dc6f6f85a1b2dbfca4c34a2796e7dde08d41e'
            $port = '18582'
        }
        else {
            $container = 'secai-bge-m3-prime'
            $volume = 'sec-ai-mvp-bge-m3-model-cache'
            $modelId = 'BAAI/bge-m3'
            $revision = '5617a9f61b028005a4858fdac845db406aefb181'
            $port = '18581'
        }
        $existing = docker ps -a --filter "name=^${container}$" --format '{{.Names}}'
        if ($existing) {
            throw "$container 컨테이너가 이미 있습니다. 상태를 확인하거나 먼저 중지해 주세요."
        }
        docker run --detach --rm --gpus all --name $container `
            --publish "127.0.0.1:${port}:80" `
            --volume "${volume}:/data" `
            --read-only --security-opt no-new-privileges --cap-drop ALL `
            --tmpfs /tmp:size=512m,mode=1777 `
            $teiImage --model-id $modelId --revision $revision --dtype float16 --port 80
        Write-Host "$Model 가중치를 전용 볼륨에 준비하고 있습니다. 준비 확인 포트: $port"
    }
    'Start' {
        Assert-VllmStopped
        if ($Model -eq 'Both') {
            docker compose --project-directory $root -f $base -f $dev -f $models --profile search-models up -d embedding-service reranker-service api
        }
        elseif ($Model -eq 'Reranker') {
            docker compose --project-directory $root -f $base -f $dev -f $models --profile search-models stop embedding-service
            docker compose --project-directory $root -f $base -f $dev -f $models --profile search-models up -d reranker-service api
        }
        else {
            docker compose --project-directory $root -f $base -f $dev -f $models --profile search-models stop reranker-service
            docker compose --project-directory $root -f $base -f $dev -f $models --profile search-models up -d embedding-service api
        }
        Write-Host "$Model 검색 모델 구성을 GPU에 올렸습니다. vLLM과는 동시에 실행하지 않습니다."
    }
    'Stop' {
        docker compose --project-directory $root -f $base -f $dev -f $models --profile search-models stop embedding-service reranker-service
    }
    'Status' {
        docker compose --project-directory $root -f $base -f $dev -f $models --profile search-models ps embedding-service reranker-service vllm
        nvidia-smi --query-gpu=name,memory.total,memory.used --format=csv,noheader
    }
}

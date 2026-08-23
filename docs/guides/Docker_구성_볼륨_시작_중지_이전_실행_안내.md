# Sec_AI Docker 구성·볼륨·시작·중지·이전 실행 안내

이 문서는 Docker가 익숙하지 않은 사용자도 Sec_AI 개발 환경을 안전하게 시작하고 중지하며,
같은 PC의 다른 폴더 또는 다른 Windows 11 PC로 옮길 수 있도록 현재 저장소의 실제 Compose와
PowerShell 도구를 기준으로 설명한다.

현재 구성은 `DEV-LOCAL` 환경이다. Windows·Linux·Aruba 점검, 통합 결과, 가이드 질의와 Windows 알려진 취약점 후보 비교가 개발 환경에서 연결되어 있다. 기본 Gateway는 이 PC의 `127.0.0.1:18480`에만 열리며,
프로덕션 공개·다중 사용자 운영·실제 TLS·조직 OIDC·운영 KMS·운영 Backup/Restore 승인을
완료한 배포 구성은 아니다.

기능 완료 상태와 다음 작업은 [`../../구현_현황.md`](../../구현_현황.md)를 우선한다. 이 문서는 Docker 구성과 데이터 이동만 설명하며, 서버 등록·조직 서명·Audit Pack 승인 상태를 대신하지 않는다.

## 1. 가장 먼저 알아둘 핵심

Docker 이전에서 다음 세 가지는 서로 다른 대상이다.

| 대상 | 쉬운 의미 | 이동 방법 |
|---|---|---|
| Source | 프로그램 설계도와 설정 파일 | portable source ZIP 또는 승인된 저장소 |
| Image | 프로그램 실행 재료를 묶은 읽기 전용 상자 | 대상 PC에서 다시 build/pull하거나 portable image TAR load |
| Volume·Secret | 실제 DB·증적·모델과 비밀번호 | 별도 Backup/Restore 또는 대상 PC에서 안전하게 재생성 |

`export-portable-bundle.ps1`은 Source와 선택적 Image만 옮긴다. PostgreSQL DB, AIStor 증적,
Redis 상태, Docker volume, 실제 `.env`, Secret, license, VM과 모델 가중치는 포함하지 않는다.
따라서 “프로그램을 다른 PC에서 새로 실행”하는 일과 “현재 데이터를 그대로 이전”하는 일은
반드시 별도 작업으로 계획해야 한다.

안전한 기본 원칙은 다음과 같다.

- 평상시 시작·중지는 `tools/core.ps1`을 사용한다.
- `Down`은 컨테이너를 내리지만 named volume은 지우지 않는다.
- `docker compose down -v`, `docker volume prune`, Docker Desktop 데이터 폴더 직접 복사는
  승인된 백업 없이 실행하지 않는다.
- 다른 PC로 상태를 옮길 때는 실행 중인 volume directory를 복사하지 않는다. PostgreSQL은
  논리 백업, AIStor는 제품 수준 객체 백업·복원처럼 저장소별 절차를 사용한다.
- Secret과 license는 Source·Image·DB 백업에 섞지 않고 별도 보안 경로로 취급한다.

## 2. Docker 구성요소를 쉽게 이해하기

```text
Compose YAML
  ├─ 어떤 Image를 쓸지 결정
  ├─ Image로 Container를 생성
  ├─ Container를 Network로 연결
  ├─ 계속 보존할 데이터는 Named volume에 기록
  ├─ 프로젝트 파일은 필요한 부분만 Bind mount
  └─ 비밀번호·token·license는 Secret file로 주입
```

### 2.1 Image

Image는 컨테이너를 만드는 읽기 전용 원본이다. API 코드, Python 실행 환경, PostgreSQL,
Redis 같은 실행 재료가 들어 있다. Image를 삭제해도 volume의 DB가 바로 삭제되지는 않지만,
같은 버전의 Image를 다시 구할 수 있어야 서비스를 재생성할 수 있다.

### 2.2 Container

Container는 Image를 실제로 실행한 인스턴스다. `Down` 후 다시 `Up`하면 컨테이너는 새로 만들어질
수 있지만 named volume을 다시 연결하므로 저장 데이터는 유지된다. 컨테이너 내부의 volume이나
bind mount가 아닌 위치에 직접 만든 파일은 재생성할 때 사라질 수 있으므로 정본으로 취급하지 않는다.

### 2.3 Network

Network는 컨테이너 사이의 통신 구간이다. Sec_AI는 외부에 모든 DB port를 열지 않고 필요한
서비스끼리만 내부 Network로 연결한다.

### 2.4 Named volume

Named volume은 Docker가 관리하는 영속 저장 공간이다. 프로젝트 폴더 밖에 있으므로 프로젝트
폴더를 삭제하거나 옮겨도 같은 Docker 엔진 안에서는 남아 있다. 반대로 다른 PC의 Docker
엔진에는 자동 복사되지 않는다.

### 2.5 Bind mount

Bind mount는 Windows 프로젝트 폴더의 실제 파일 또는 directory를 컨테이너에 연결하는 방식이다.
개발 중 Source 변경을 컨테이너에서 곧바로 보거나, 승인된 PDF·다운로드 파일을 읽기 전용으로
제공할 때 사용한다. 다른 PC에서는 같은 상대 경로의 파일을 다시 준비해야 한다.

### 2.6 tmpfs

`tmpfs`는 메모리에만 존재하는 임시 공간이다. 컨테이너가 사라지면 함께 사라진다. `/tmp`, 로그,
socket, 일시 cache처럼 보존하면 안 되는 자료에 사용한다.

### 2.7 Secret file

비밀번호·token·license를 YAML이나 Image에 넣지 않고 Windows의 `runtime/dev-secrets` 아래 파일에서
컨테이너의 `/run/secrets/...`로 읽어 들인다. 파일 내용은 문서·로그·채팅·화면 공유에 노출하지 않는다.

## 3. 현재 Compose 파일 역할

| 파일 | 역할 | 평상시 사용 여부 |
|---|---|---|
| `deploy/compose/compose.yml` | Core 서비스, Network, volume, Secret의 기본 계약 | 항상 사용 |
| `deploy/compose/compose.dev.yml` | 개발 Source bind mount, dev tool, pgAdmin 등 DEV 덮어쓰기 | `core.ps1`이 항상 함께 사용 |
| `deploy/compose/compose.search-models.yml` | BGE-M3 embedding과 reranker GPU 서비스 | 검색 모델 도구가 선택적으로 사용 |
| `deploy/compose/compose.imp045-recovery.yml` | 격리된 장애·복구 훈련 전용 | 일반 시작에 사용하지 않음 |

`tools/core.ps1`은 앞의 기본 파일 두 개를 항상 같은 순서로 병합한다. 직접 `docker compose` 명령을
조합하면 파일 누락이나 다른 project name으로 인해 별도 컨테이너가 생길 수 있으므로 일상 운영에서는
스크립트를 우선한다.

병합 후 Compose project name은 `sec-ai-mvp-dev`다. 다만 주요 Network와 volume은 아래처럼
`name:`이 명시되어 있어 프로젝트 폴더명과 무관하게 고정 이름을 사용한다.

## 4. 서비스 구조

```text
브라우저
  ↓ http://127.0.0.1:18480
Gateway ── frontend_net ── API
                             ├─ app_net ── PostgreSQL
                             │             Redis
                             │             AIStor
                             │             ClamAV
                             │             Worker / Maintenance Worker / Scheduler
                             └─ model_net ─ Model Gateway ─ 외부 승인 모델 또는 선택형 vLLM
```

| 서비스 | 역할 | Host 공개 |
|---|---|---|
| `gateway` | Web UI·API 단일 진입점, reverse proxy와 보안 header | 기본 `127.0.0.1:18480` |
| `api` | UI·JSON API·Health·업무 유스케이스 | 직접 공개하지 않음 |
| `worker` | 일반 비동기 작업 처리 | 없음 |
| `maintenance-worker` | 복구·유지보수 Queue 작업 처리 | 없음 |
| `scheduler` | 예약 작업 발행 | 없음 |
| `model-gateway` | API와 승인 모델 사이의 내부 경계 | 없음 |
| `postgres` | 업무 정본, 감사·결과·Guide 검색 projection | 없음 |
| `redis` | Celery Broker와 전달 상태 | 없음 |
| `aistor` | 원본 증적 Object Storage | 없음 |
| `clamav` | 업로드 자료 악성코드 검사 | 없음 |
| `migrate` | DB migration 실행 후 종료하는 도구 | 없음 |
| `pgadmin` | 선택형 개발 DB 관리 화면 | profile 사용 시 `127.0.0.1:18490` |
| `vllm` | 선택형 로컬 LLM 실행 골격 | 기본 중지·미승인 |
| `embedding-service`, `reranker-service` | 선택형 GPU Guide 검색 모델 | Host에 공개하지 않음 |

`app_net`과 `model_net`은 `internal: true`다. PostgreSQL, Redis, AIStor, ClamAV port를 Host에
공개하지 않는다. 다른 PC나 사내망에 Gateway를 공개하는 것은 단순 port 변경 작업이 아니며,
TLS·방화벽·인증·승인 범위를 별도로 설계해야 한다.

## 5. 볼륨과 저장 데이터

### 5.1 영속 named volume

| 실제 volume 이름 | 연결 서비스 | 저장 내용 | 이전 판단 |
|---|---|---|---|
| `sec-ai-mvp-postgres-data` | PostgreSQL | 업무 DB, 사용자·감사·점검 결과·Guide 검색 상태 | 가장 중요. 논리 Backup/Restore 필요 |
| `sec-ai-mvp-redis-data` | Redis | AOF와 Queue 전달 상태 | 정지 시점 일관성 필요. PostgreSQL Outbox 기준 재구축 전략 우선 검토 |
| `sec-ai-mvp-aistor-data` | AIStor | 원본 증적과 Object Storage 자료 | 가장 중요. AIStor 지원 Backup/Restore 필요 |
| `sec-ai-mvp-vllm-model-data` | vLLM | 로컬 LLM model 파일 | 현재 실행 Gate 미승인. license·hash 확인 후 별도 준비 |
| `sec-ai-mvp-pgadmin-data` | pgAdmin | pgAdmin 사용자 설정·연결 정보 | 개발 편의 자료. 보통 새 환경에서 재생성 가능 |
| `sec-ai-mvp-bge-m3-model-cache` | embedding service | 고정 revision BGE-M3 가중치 cache | 재다운로드 가능하나 offline 이전 시 별도 준비 |
| `sec-ai-mvp-reranker-model-cache` | reranker service | 고정 revision reranker 가중치 cache | 재다운로드 가능하나 offline 이전 시 별도 준비 |

마지막 두 검색 모델 volume은 `external: true`이므로 Compose가 자동 생성하지 않는다.
`tools/search-model-runtime.ps1`이 volume을 준비한다. 모델 cache는 업무 정본과 분리하며, 모델
revision·license·hash·GPU 호환성을 확인하지 않은 임의 가중치를 넣지 않는다.

### 5.2 Bind mount

| Host 경로 | Container 경로 | 목적 |
|---|---|---|
| `.runtime/vmware` | `/run/secai-vmware` | 고정 VM 개발 실행 자료, 읽기 전용 |
| `data/주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드.pdf` | `/run/secai-guides/kisa-2026.pdf` | KISA 원본, 읽기 전용 |
| `src` | `/app/src` | 개발 Python Source, 읽기 전용 |
| `apps/api` | `/app/apps/api` | API Source, 읽기 전용 |
| `apps/web` | `/app/apps/web` | Web template·JS·CSS, 읽기 전용 |
| `runtime/dev-signed-downloads` | `/run/secai-dev-downloads` | 개발 서명 다운로드 산출물, 읽기 전용 |
| `data/public_guides` | `/run/secai-public-guides` | 승인된 공공기관 Guide, 읽기 전용 |
| 프로젝트 루트 `.` | `/workspace` | `dev-tools`, `guide-ingest` 도구 실행용, 읽기 전용 |

프로젝트를 다른 위치로 옮길 때는 절대 경로를 유지할 필요는 없지만 프로젝트 내부의 상대 경로와
필수 파일은 유지해야 한다. `.runtime/vmware`처럼 빈 directory도 Compose 시작 전 만들어야 한다.

### 5.3 Secret

현재 Secret은 PostgreSQL 운영·runtime·DB 관리 계정, Redis password·ACL, 개발 로그인·두 번째
인증·CSRF·session index, AIStor 계정·license, LLM API key, Model Gateway 내부 token,
pgAdmin password를 포함한다.

- 일반 DEV Secret은 `core.ps1 -Action Init`으로 대상 PC에서 새로 생성한다.
- AIStor license와 승인 LLM 설정은 별도 승인된 보안 전송으로 반입한다.
- 기존 PC의 `runtime/dev-secrets` 폴더 전체를 portable bundle에 넣지 않는다.
- 상태 데이터를 이전할 때 암호화 키·계정 Secret의 호환이 필요한지는 복원 시험에서 별도로 검토한다.

## 6. 처음 시작하기

### 6.1 준비물

- Windows 11과 Windows PowerShell
- Docker Desktop, Linux container mode, Docker Compose v2
- `linux/amd64` Image를 실행할 수 있는 환경
- Source·Image·volume을 둘 충분한 디스크
- 프로젝트 루트에서 실행할 권한
- 전체 구성이라면 같은 조직에서 적법하게 발급받은 AIStor license

Host에 Python, Node.js, PostgreSQL, Redis, AIStor를 따로 설치할 필요는 없다.

### 6.2 환경 파일과 빈 경로 준비

프로젝트 루트에서 다음을 실행한다.

```powershell
Copy-Item .env.example .env
New-Item -ItemType Directory -Force -Path .runtime\vmware | Out-Null
```

`.env`에는 공개 가능한 실행 선택만 둔다. password, API key, token, license와 private key를 직접
기록하지 않는다.

### 6.3 DEV Secret 생성

AIStor 없이 시작할 때:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action Init
```

승인된 AIStor license를 함께 반입할 때:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 `
  -Action Init `
  -AIStorLicensePath D:\secure-transfer\minio.license
```

예시 경로는 조직의 승인된 보안 반입 위치로 바꾼다. license 값은 출력하거나 Source에 복사하지 않는다.

### 6.4 Compose 계약 확인

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action Config
```

이 명령은 YAML 병합, 변수 참조, 서비스 관계를 확인한다. Secret 내용의 유효성이나 실제 서비스
Health까지 증명하지는 않는다.

### 6.5 AIStor 없이 Core 시작

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action UpWithoutAIStor
```

이 작업은 다음 순서로 진행된다.

1. 필요한 DEV Secret 존재 확인
2. PostgreSQL 시작
3. DB migration 실행
4. 개발 인증 bootstrap 실행
5. PostgreSQL, Redis, ClamAV, API, 일반·유지보수 Worker, Scheduler, Gateway 시작

AIStor와 Model Gateway는 이 경로에서 시작하지 않는다. `/health/live`는 `200`이어야 하지만
AIStor가 없으므로 `/health/ready`가 `503 not_ready`인 것은 예상된 fail-closed 상태다.

### 6.6 전체 Core 시작

AIStor license와 필요한 설정을 준비했다면 다음을 실행한다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action Up
```

`Up`은 PostgreSQL 시작, migration, 인증 bootstrap을 먼저 수행하고 Core Image를 `--build`한 뒤
전체 기본 서비스를 올린다.

### 6.7 상태와 Health 확인

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action Status

powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action Health
```

- `Status`: 종료된 컨테이너까지 포함해 상태를 보여 준다.
- `Health`: Gateway의 `/health/live`와 `/health/ready` 응답을 보여 준다.
- 전체 Core라면 두 Health 모두 정상이어야 한다.
- 현재 스크립트는 `live` 요청에는 실패 exit를 적용하지만 `ready`는 응답 본문을 출력하는 방식이다.
  따라서 명령 종료 여부만 보지 말고 `ready` 응답의 HTTP 상태와 본문도 확인한다.

브라우저 진입점은 [http://127.0.0.1:18480](http://127.0.0.1:18480)이다.

## 7. 평상시 올리고 내리기

### 7.1 현재 상태 확인

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action Status
```

문제가 있으면 먼저 상태를 보고, 그다음 로그를 확인한다.

### 7.2 최근 로그 확인

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action Logs
```

기본적으로 서비스별 최근 200줄을 보여 준다. 로그를 공유할 때 token, 사용자 정보, 실제 Evidence가
포함되지 않았는지 확인한다.

### 7.3 재시작

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action Restart
```

`Restart`는 기존 컨테이너를 재시작할 뿐 Image를 다시 build하거나 migration을 실행하지 않는다.
Dockerfile, Python dependency, Compose 설정, DB Schema가 바뀌었다면 `Restart` 대신 변경에 맞는
검증 후 `Up`을 사용한다.

### 7.4 안전하게 중지

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action Down
```

현재 `Down`은 내부적으로 `docker compose down --remove-orphans`를 실행한다.

- Core 컨테이너와 Compose Network 연결은 내려간다.
- named volume은 삭제되지 않으므로 다음 `Up`에서 기존 DB와 저장 데이터를 다시 사용한다.
- 같은 Compose project로 별도 실행한 검색 모델 컨테이너는 orphan으로 판단되어 제거될 수 있다.
  검색 모델을 사용 중이면 먼저 아래 전용 `Stop`으로 정상 중지한다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\search-model-runtime.ps1 -Action Stop
```

검색 모델 컨테이너가 제거되어도 두 모델 cache volume은 남지만, 작업 중인 요청이 없는지 먼저
확인하고 중지해야 한다.

### 7.5 절대 혼동하면 안 되는 명령

| 명령 종류 | 결과 |
|---|---|
| `docker compose stop` | 컨테이너만 멈추고 그대로 둠 |
| 프로젝트의 `core.ps1 -Action Down` | 컨테이너를 제거하지만 named volume 유지 |
| `docker compose down -v` | 컨테이너와 named volume까지 삭제할 수 있음 |
| `docker volume prune` | 다른 프로젝트를 포함한 미사용 volume을 삭제할 수 있음 |

마지막 두 명령은 데이터 손실 가능성이 있으므로 이 가이드의 일상 절차에 포함하지 않는다.

## 8. 코드와 설정 변경을 반영하는 방법

| 변경 내용 | 권장 반영 |
|---|---|
| `src`, `apps/api`, `apps/web`의 개발 Source | bind mount와 reload 범위를 확인하고 관련 시험 후 필요 시 `Restart` |
| Dockerfile·기반 Image | `core.ps1 -Action Build` 또는 `Up` |
| Compose YAML·환경 변수 | `Config`로 병합 확인 후 `Up` |
| DB migration | 관련 시험 후 `Up`의 migration 단계 사용 |
| Secret 값 | 안전하게 파일 갱신 후 영향 서비스 재생성·Health 확인 |
| 검색 모델 | `search-model-runtime.ps1`의 `Prime`, `Start`, `Stop`, `Status` 사용 |

Source가 bind mount되어 있어도 모든 변경이 자동 반영되는 것은 아니다. 실행 process가 reload를
지원하지 않는 파일, dependency, Image 안에 복사된 파일은 다시 build하거나 컨테이너를 재생성해야 한다.

## 9. 다른 위치로 옮기는 세 가지 전략

### 전략 A. 새 환경으로 재현 — 기본 권장

대상 PC에서 빈 DB와 빈 증적 저장소로 새로 시작하는 방식이다. 개발·검증 환경 복제에는 이 방법이
가장 단순하고 위험이 낮다.

```text
원본 PC: Source + 선택적 Image bundle 생성
  → 승인된 전송수단으로 이동
대상 PC: hash 검증 + Image load + Source 해제
  → 새 DEV Secret 생성
  → Config / 표준 시험 / Up
  → Health와 기능 확인
```

장점은 오래된 상태·Secret·Queue를 함께 복제하지 않는 것이다. 단점은 기존 사용자, 결과, 증적,
Guide 적재 상태가 따라오지 않는 것이다.

### 전략 B. 같은 PC에서 프로젝트 폴더만 이동

Source를 새 빈 폴더로 가져온 뒤 실행한다. 주요 volume 이름이 고정되어 있으므로 같은 Docker Desktop
엔진을 사용하면 기존 `sec-ai-mvp-*` volume을 다시 연결한다.

주의할 점은 다음과 같다.

1. 실행 중인 Core를 먼저 정상 중지한다.
2. portable import는 내용 있는 대상 폴더를 기본 거부하므로 새 폴더를 사용한다.
3. `.env`, Secret, license, `.runtime/vmware`는 portable bundle에 포함되지 않는다.
4. 같은 PC에서 기존 Secret을 재사용할지 새로 만들지는 저장 데이터의 암호화·계정 호환성을 검토해
   결정한다. 무조건 `Init`으로 덮어쓰지 않는다.
5. 새 Source version이 기존 DB보다 최신이면 `Up` 과정에서 migration이 실행된다. rollback 가능성과
   backup을 먼저 확인한다.
6. 새 위치의 Source·bind mount 파일이 모두 준비됐는지 `Config`로 확인한다.

폴더를 두 개 남겨 둔 채 양쪽에서 동시에 `Up`하지 않는다. 고정 Network·volume 이름을 공유하므로
컨테이너 충돌이나 같은 DB에 서로 다른 Source version이 접속할 수 있다.

### 전략 C. 다른 PC로 현재 상태까지 이전

Source·Image 이전에 더해 DB·증적·필요한 설정 상태를 Backup/Restore하는 운영 작업이다. 현재
저장소에는 실제 운영 데이터를 한 번에 내보내고 복원하는 승인된 통합 자동화가 없다. 따라서 아래
절차는 전략과 Gate이며, 조직 책임자·RPO/RTO·보관·암호화·복원 시험이 승인되기 전에는 실제 데이터
이전을 완료로 판단하지 않는다.

```text
1. 범위 확정
   Source/Image만인지, PostgreSQL·AIStor까지인지 결정
2. 버전 기록
   Source revision, Image digest, DB migration head, 저장소 version 기록
3. 쓰기 동결
   사용자 요청·Worker·Scheduler를 멈추고 일관된 시점 확보
4. 저장소별 백업
   PostgreSQL 논리 백업 + AIStor 객체/version 백업 + 필요한 운영 metadata
5. 무결성·보안
   hash, 암호화, 접근자, 보관기한, Secret 분리 확인
6. 대상 기반 설치
   portable bundle import, Docker/디스크/시간/GPU 사전 점검
7. Secret·license 준비
   별도 보안 경로로 반입하거나 대상에서 rotation·재발급
8. 격리 복원
   외부 공개 전 PostgreSQL과 AIStor 복원, Redis 재구축/정합성 확인
9. 검증
   migration, Health, 로그인, 결과·증적 조회, Queue, AI/Guide 기능 시험
10. 전환과 rollback 대기
    원본을 즉시 폐기하지 않고 승인된 기간 동안 읽기 금지 상태로 보존
```

## 10. 상태 데이터별 이전 판단

| 자료 | 권장 이전 방법 | 이유·주의점 |
|---|---|---|
| PostgreSQL | 호환되는 PostgreSQL 도구의 논리 Backup/Restore | 실행 중 data directory 복사는 일관성과 version 호환을 보장하지 못함 |
| AIStor | AIStor가 지원하는 객체·version 단위 Backup/Restore | DB row와 실제 Evidence object의 연결·hash를 함께 검증해야 함 |
| Redis | 가능한 경우 PostgreSQL Outbox 기준 재구축 | 전달 중 작업을 복제하면 중복 실행 가능. 단순 volume 복사 금지 |
| pgAdmin | 새 환경에서 재생성 | 업무 정본이 아니라 관리 UI 설정임 |
| BGE-M3·Reranker cache | 고정 revision을 다시 `Prime`하거나 승인된 cache 이전 | 업무 데이터와 분리, 모델 hash·license 확인 |
| vLLM model | 별도 승인된 model 반입 | 현재 로컬 추론 Gate가 열리지 않았으며 대용량·license·GPU 호환 필요 |
| `.env` | `.env.example`에서 새로 생성 후 공개 설정만 재적용 | Secret 저장소가 아님 |
| `runtime/dev-secrets` | 대상에서 재생성 또는 승인된 Secret 이전·rotation | Source/Image/bundle에 포함 금지 |
| AIStor license | 조직 이용조건에 맞는 별도 보안 전송 | Image나 문서에 포함 금지 |
| Linux VM·SSH key·인증서 private key | 자산별 별도 승인 절차 | portable bundle에 포함되지 않으며 권한·신원 경계가 다름 |

DB와 AIStor는 서로 연결된 기록을 가질 수 있다. 둘 중 하나만 다른 시점으로 복원하면 DB에는 객체가
있다고 나오지만 실제 증적이 없거나, 반대로 고아 객체가 생길 수 있다. 동일한 쓰기 동결 시점과
manifest를 사용해 상호 참조·hash를 검증해야 한다.

## 11. Portable bundle로 다른 PC에서 새로 실행하기

### 11.1 원본 PC에서 내보내기

Docker Desktop을 실행한 뒤 프로젝트 루트에서 Source와 Image 묶음을 만든다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\export-portable-bundle.ps1
```

온라인 대상 PC에서 Image를 다시 받을 수 있어 Source만 필요하면 다음을 사용한다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\export-portable-bundle.ps1 -SourceOnly
```

결과 directory에는 Source ZIP, 선택적 Image TAR, manifest, SHA-256 목록, import 도구와 안내가
들어간다. 묶음 전체를 승인된 이동식 저장장치나 내부 전송수단으로 옮긴다.

### 11.2 대상 PC에서 가져오기

묶음 directory에서 빈 대상 경로를 지정한다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\import-portable-bundle.ps1 `
  -Destination D:\Sec_AI

Set-Location D:\Sec_AI
Copy-Item .env.example .env
New-Item -ItemType Directory -Force -Path .runtime\vmware | Out-Null
```

import 도구는 manifest와 모든 SHA-256을 먼저 확인하고, Image TAR이 있으면 Docker에 load한 뒤
Source를 해제한다. ZIP hash는 전송 중 손상을 검출하지만 생산자 신원·조직 배포 승인을 대신하지 않는다.

### 11.3 대상 PC 초기화·검증·시작

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\dev.ps1 -Action All

powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action Init

powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action Config

powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action UpWithoutAIStor

powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action Status

powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\core.ps1 -Action Health
```

AIStor와 기존 상태가 필요하면 빈 환경 시작 절차를 그대로 완료 처리하지 말고, 승인된 license와
Backup/Restore Gate를 추가한다.

## 12. 이전 전후 확인 목록

### 12.1 원본 PC

- [ ] 이동 범위가 Source/Image인지, 실제 상태 데이터까지인지 문서로 정했다.
- [ ] Source revision, Image digest, migration head를 기록했다.
- [ ] 실제 `.env`, Secret, license, private key, Evidence가 portable bundle에서 제외됐다.
- [ ] 상태 이전이면 쓰기 동결과 Worker·Scheduler 중지 순서를 승인했다.
- [ ] PostgreSQL과 AIStor를 같은 논리 시점으로 백업했다.
- [ ] Backup hash, 암호화, 접근자, 보관 위치와 복원 책임자를 기록했다.
- [ ] 원본 환경을 즉시 삭제하지 않는 rollback 기간을 정했다.

### 12.2 대상 PC

- [ ] Docker Desktop이 Linux container mode로 정상 실행된다.
- [ ] Source, Image, volume을 위한 디스크 여유가 있다.
- [ ] 시간·시간대와 인증서 검증 시간이 맞다.
- [ ] portable manifest와 모든 SHA-256이 일치한다.
- [ ] `.env`는 `.env.example`에서 만들고 Secret을 넣지 않았다.
- [ ] DEV Secret ACL 또는 조직 Secret 관리 절차를 적용했다.
- [ ] `Config`가 통과했다.
- [ ] PostgreSQL·AIStor 복원 후 상호 참조와 Evidence hash를 확인했다.
- [ ] `Status`, live, ready 결과를 기록했다.
- [ ] 로그인·권한·점검 결과·증적·Queue·Guide 검색을 실제로 확인했다.
- [ ] 전환 승인 전에는 외부 접속을 열지 않았다.

## 13. 자주 생기는 문제

| 증상 | 먼저 확인할 것 | 안전한 대응 |
|---|---|---|
| Docker 명령이 실행되지 않음 | Docker Desktop 실행, Linux container mode, Compose v2 | Docker Desktop 상태를 정상화한 뒤 `Config` 재실행 |
| `Missing development secret files` | `runtime/dev-secrets` 존재와 빈 파일 여부 | `Init` 실행. 기존 DB 복원 환경이면 Secret 호환성 검토 후 진행 |
| AIStor license 오류 | license 존재·이용조건·반입 경로 | license 없으면 `UpWithoutAIStor`; 임의 license 사용 금지 |
| `18480` port 충돌 | 다른 process 또는 이전 Gateway | 기존 상태 확인 후 승인된 port 선택. 전사 공개 bind로 바꾸지 않음 |
| live `200`, ready `503` | AIStor 없이 시작했는지, DB·Redis·ClamAV 상태 | `UpWithoutAIStor`면 예상 상태. 전체 Core면 `Status`·`Logs` 확인 |
| 새 폴더인데 예전 DB가 보임 | 고정 named volume을 같은 Docker 엔진에서 재사용했는지 | 정상 가능. 두 Source version 동시 실행을 멈추고 migration 호환 확인 |
| 다른 PC에 DB가 없음 | portable bundle에 volume이 포함된다고 오해했는지 | 승인된 PostgreSQL·AIStor Backup/Restore 별도 수행 |
| 검색 모델이 시작되지 않음 | NVIDIA GPU, vLLM 동시 실행, external model volume | 전용 검색 모델 도구의 `Status`와 고정 revision 준비 상태 확인 |
| Source 수정이 반영되지 않음 | bind mount 대상인지, reload 지원 여부 | 관련 시험 후 `Restart`, Image 변경이면 `Build` 또는 `Up` |
| `Down` 뒤 데이터가 남음 | named volume 보존 정책 | 정상 동작. 삭제가 필요해도 먼저 Backup과 exact volume 승인 필요 |

## 14. 권장 운영 습관

1. 시작 전 `Status`, 변경 후 `Config`, 시작 후 `Health`를 확인한다.
2. 일상 중지에는 프로젝트 `Down`만 사용하고 `-v`를 붙이지 않는다.
3. Source/Image bundle과 실제 데이터 Backup을 다른 산출물로 관리한다.
4. Backup 성공이 아니라 격리 환경 Restore 성공을 기준으로 복구 가능성을 판단한다.
5. Secret·license는 Source, Image, volume archive, 문서와 분리한다.
6. 다른 PC 전환 후 원본은 승인된 rollback 기간 동안 변경 금지 상태로 보존한다.
7. 프로덕션 이전에는 TLS·인증·KMS·Object Lock·RPO/RTO·담당자·감사 기록을 별도 승인한다.

## 15. 관련 문서와 정본

- [다른 PC 설치·이전 안내](다른_PC_설치_및_이전_안내.md)
- [이동용 묶음 README](../../portable/README.md)
- [Core Compose README](../../deploy/README.md)
- [루트 실행 안내](../../README.md)
- [현재 구현 상태](../../구현_현황.md)

실제 서비스·volume·Network·Secret 이름의 코드 정본은
`deploy/compose/compose.yml`, `deploy/compose/compose.dev.yml`,
`deploy/compose/compose.search-models.yml`이다. 일상 동작의 정본은 `tools/core.ps1`, 이동 묶음의
정본은 `tools/export-portable-bundle.ps1`과 `portable/import-portable-bundle.ps1`이다.

# Sec_AI (AI 자동 보안 점검 도구)

[![Sec_AI 시연 영상](https://img.youtube.com/vi/1PsSlsWfYuk/maxresdefault.jpg)](https://youtu.be/1PsSlsWfYuk)
                                   <유튜브로 연결됩니다>

Sec_AI는 인프라 및 자산에 대해 **"KISA 보안 기준을 1:1로 정밀 대조하는 확정적 판정 엔진"**을 실행하고, 복잡한 취약점 결과를 투영(Projection) 기반 비식별화를 거쳐 **AI(대형언어모델)가 안전하고 쉽게 해설해 주는 오픈소스 플랫폼**입니다.

Windows, Linux, 그리고 Aruba Switch(AOS-CX) 등 다양한 플랫폼의 규정 준수 여부를 자동화된 파이프라인으로 점검할 수 있습니다. 

> **판정 권한 원칙**: PASS·FAIL·ERROR·REVIEW 공식 판정은 규칙 엔진만 결정합니다. AI는 이미 확정된 판정을 설명하고 조치를 권고할 뿐이며 판정을 바꾸지 않습니다.

---

## 🛠 1. 필수 요구 사항 (Prerequisites)

모든 구성 요소를 Docker 기반으로 자체 빌드하므로 로컬에 Python이나 DB를 설치할 필요가 없습니다.

### 기본 환경

* **운영체제**: Windows 10/11 (PowerShell) 또는 Linux/macOS (`pwsh` 설치 필요)
* **필수 소프트웨어**: Docker Desktop (또는 Docker Engine + Compose v2 이상), Git
* **권장 디스크 용량**
  * 기본 구동(외부 API 사용): 약 **5GB ~ 10GB**
  * *(선택)* BGE-M3 검색 모델 사용 시: 추가 **10GB 내외** + NVIDIA GPU
  * *(선택)* 로컬 LLM(vLLM) 구동 시: 모델 크기에 따라 추가 **10GB ~ 수백 GB** + NVIDIA GPU

---

## 🚀 2. 설치 (Installation)

### Step 2.1: 저장소 복제와 필수 디렉터리 생성

```powershell
git clone <저장소 주소> Sec_AI
cd Sec_AI

# Compose가 bind mount 하는 디렉터리는 비어 있어도 미리 있어야 합니다.
New-Item -ItemType Directory -Force .runtime\vmware, .runtime\linux-asset-keys | Out-Null
```

### Step 2.2: 환경 변수 파일 준비

`.env`는 자동 생성되지 않습니다. 예시 파일을 복사해서 시작합니다.

```powershell
Copy-Item .env.example .env
```

`.env`가 없어도 Compose 기본값으로 기동은 되지만, 포트·LLM 설정을 바꾸려면 이 파일을 사용합니다.

### Step 2.3: 개발용 시크릿 생성

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Init
```

`runtime/dev-secrets/` 아래에 DB 비밀번호, 세션 키, 개발 계정 비밀번호·인증 코드 등이 생성되고 디렉터리 ACL이 현재 사용자로 제한됩니다. 이 폴더는 `.gitignore`로 보호됩니다.

> **⚠️ 이 명령이 만들지 않는 시크릿이 3개 있습니다.** Compose가 파일 기반 secret으로 요구하므로, 아래를 준비하지 않으면 해당 컨테이너가 생성되지 않습니다.

| 파일 | 사용 서비스 | 준비 방법 |
| :--- | :--- | :--- |
| `runtime/dev-secrets/llm_api_key` | model-gateway | 외부 LLM API 키를 **평문 한 줄**로 저장 |
| `runtime/dev-secrets/model_gateway_token` | model-gateway | 임의의 긴 난수 문자열 한 줄 (내부 인증용) |
| `runtime/dev-secrets/minio.license` | aistor | AIStor 라이선스 파일. **없으면 Step 2.4의 AIStor 제외 기동을 사용하세요.** |

앞의 두 개를 직접 만들려면:

```powershell
Set-Content -NoNewline -Encoding utf8 runtime\dev-secrets\llm_api_key "sk-여기에-API-키"
$bytes = [byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
Set-Content -NoNewline -Encoding utf8 runtime\dev-secrets\model_gateway_token ([Convert]::ToBase64String($bytes))
```

`.env` 형식의 외부 설정 파일이 이미 있다면 `tools\import-llm-settings.ps1 -SourceEnvironmentFile <경로>`로 `.env`와 위 두 파일을 한 번에 만들 수 있습니다(원본에 `DEEPSEEK_API_BASE`, `DEEPSEEK_API_KEY`, `MODEL_NAME` 키가 있어야 합니다).

### Step 2.4: 필수 자료 배치 (API 기동 전제)

Compose가 KISA 상세가이드 PDF를 **정확한 파일명 그대로** bind mount 합니다. 파일이 없거나 이름이 다르면 API 컨테이너가 기동에 실패하거나 가이드 기능이 동작하지 않습니다. 자세한 출처는 9장을 참고하세요.

```text
data/주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드.pdf
```

### Step 2.5: 빌드 및 기동

```powershell
# AIStor 라이선스가 있는 경우 — 전체 9개 서비스
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Up

# 라이선스가 없는 경우 — 핵심 8개 서비스만 (권장 시작점)
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action UpWithoutAIStor
```

두 명령 모두 다음을 순서대로 수행합니다.

1. 베이스 이미지 다운로드 후 `sec-ai-mvp/*` 이미지 빌드
2. PostgreSQL 기동 → DB 마이그레이션(`migrate`) 실행
3. 초기 관리자 계정 bootstrap (`apps.api.auth_bootstrap`)
4. 서비스 기동

#### 기동되는 컨테이너

| 구분 | 서비스 | 역할 |
| :--- | :--- | :--- |
| 핵심 | `gateway` | NGINX 리버스 프록시 (외부 노출 지점, 기본 18480) |
| 핵심 | `api` | FastAPI 백엔드 · 웹 UI |
| 핵심 | `worker` | Celery 비동기 점검 워커 |
| 핵심 | `maintenance-worker` | 보존·정리 등 유지보수 큐 |
| 핵심 | `scheduler` | Celery beat 스케줄러 |
| 핵심 | `postgres` | pgvector 포함 DB (Row Level Security 적용) |
| 핵심 | `redis` | 브로커 · 캐시 (ACL 사용자 분리) |
| 핵심 | `clamav` | 업로드·증적 악성코드 검사 |
| 선택 | `model-gateway` | 외부/로컬 AI 모델 통신 경계 |
| 선택 | `aistor` | 증적 오브젝트 스토리지 (라이선스 필요) |
| 프로파일 | `pgadmin` | DB 관리 UI (`admin-tools` 프로파일) |
| 프로파일 | `migrate`, `guide-ingest`, `dev-tools` | 일회성 도구 (`tools` 프로파일) |
| 프로파일 | `embedding-service`, `reranker-service` | BGE-M3 검색 모델 (`search-models` 프로파일) |
| 프로파일 | `vllm` | 로컬 GPU 추론 (`local-vllm` 프로파일, 기본 비활성) |

#### 상태 확인

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Status
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Health
```

---

## 🔑 3. 로그인

### Step 3.1: 계정 정보 확인

초기 관리자 계정은 Step 2.5에서 이미 만들어집니다. 별도로 다시 만들려면:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\bootstrap-dev-auth.ps1
```

**비밀번호는 터미널에 출력되지 않습니다.** 계정 정보는 다음 위치에 있습니다.

| 항목 | 값 / 위치 |
| :--- | :--- |
| 사용자 이름 | `local-owner` |
| 비밀번호 | `runtime/dev-secrets/auth_dev_password` |
| 인증 코드(6자리) | `runtime/dev-secrets/auth_dev_mfa_code` |

```powershell
Get-Content .\runtime\dev-secrets\auth_dev_password
Get-Content .\runtime\dev-secrets\auth_dev_mfa_code
```

> 이 값은 로컬 개발 전용입니다. 화면 공유·이슈·로그에 붙여넣지 마세요.

### Step 3.2: 웹 UI 접속

* 주소: **`http://localhost:18480/auth/login`** (HTTPS 아님, DEV-LOCAL 프로파일)
* 로그인은 **2단계**입니다. 사용자 이름 + 비밀번호를 입력한 뒤, 이어지는 화면에서 6자리 인증 코드를 입력합니다.
* 포트는 `.env`의 `SECAI_GATEWAY_PORT`(기본 18480)로 변경합니다.
* 로그인 후 비밀번호는 `계정정보 → 비밀번호 변경`에서 바꿀 수 있습니다.

---

## 🤖 4. LLM (AI 모델) 연동

Sec_AI의 해설 기능은 OpenAI 호환 API를 사용합니다. 기본값은 OpenRouter이며, `.env`에서 두 줄만 바꾸면 다른 상용 API나 로컬 모델로 전환됩니다.

### 외부 API 사용 시

```env
SECAI_LLM_API_BASE=https://openrouter.ai/api/v1   # 또는 https://api.openai.com/v1
SECAI_LLM_MODEL=openai/gpt-oss-120b               # 사용할 모델명
```

API 키는 `.env`가 아니라 `runtime/dev-secrets/llm_api_key` 파일에 평문 한 줄로 저장합니다(Step 2.3).

### 로컬 vLLM 사용 시

로컬 vLLM은 **이미지 준비 상태(`PREPARED_NOT_ACTIVE`)이며 기본 기동 대상이 아닙니다.** `local-vllm` 프로파일로만 켤 수 있고, 실제 구동에는 (1) CUDA 13 요구를 만족하는 NVIDIA 드라이버, (2) `vllm_model_data` 볼륨에 배치한 승인 모델, (3) `.env`의 경로 설정이 모두 필요합니다.

```env
SECAI_LLM_API_BASE=http://vllm:8000/v1
SECAI_LLM_MODEL=<approved-served-model-name>
SECAI_VLLM_MODEL_PATH=/models/<approved-model-directory>
SECAI_VLLM_SERVED_MODEL=<approved-served-model-name>
```

변경 후 적용:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Restart
```

---

## 📚 5. AI 해설(RAG) 활성화 — 가이드 적재

PDF를 폴더에 두는 것만으로는 검색이 동작하지 않습니다. **적재(ingest)를 한 번 실행해야** 벡터 검색 인덱스가 만들어집니다.

### 5.1 KISA 상세가이드 (필수)

```powershell
$compose = "--project-directory", ".", "-f", "deploy\compose\compose.yml", "-f", "deploy\compose\compose.dev.yml"
docker compose @compose --profile tools run --rm guide-ingest
```

### 5.2 공공기관 보완 가이드 (선택)

9장의 PDF를 배치한 뒤, 배치가 정확한지 먼저 검증하고 적재합니다.

```powershell
# 파일명·SHA-256이 manifest와 일치하는지 확인
docker compose @compose --profile tools run --rm guide-ingest tools/verify-public-guides.py

# 적재
docker compose @compose --profile tools run --rm guide-ingest tools/ingest-public-guides.py

# 검색 품질 확인
docker compose @compose --profile tools run --rm guide-ingest tools/verify-public-guide-retrieval.py
```

### 5.3 BGE-M3 검색 모델 (선택, GPU 필요)

기본 검색 모드는 `LEGACY_LOCAL`이라 모델 서비스 없이도 동작합니다. 고품질 검색을 쓰려면 아래로 모델 서비스를 띄우세요(이때 `SECAI_GUIDE_SEARCH_MODE`가 `BGE_M3_WITH_LEGACY_FALLBACK`으로 적용됩니다). **vLLM과 동시에 실행할 수 없습니다.**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\search-model-runtime.ps1 -Action Prime   # 가중치 내려받기
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\search-model-runtime.ps1 -Action Start
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\search-model-runtime.ps1 -Action Status
```

---

## 💻 6. 점검 대상(타겟) 연동

본 프로젝트는 **점검 도구(서버)** 이므로 점검 대상 장비는 사용자가 직접 준비합니다. **대상 장비의 계정·비밀번호를 소스코드에 하드코딩하거나 Git에 커밋하지 마세요.**

### 6.1 Windows PC 자가 점검 / Linux 원샷 자가 점검

대상 장비에서 수집 프로그램을 한 번 실행하고 결과 패키지를 웹 UI로 제출하는 방식입니다. SSH 등록이 필요 없습니다.

다운로드 화면(`/ui/dev-downloads`)이 동작하려면 **개발 서명 카탈로그를 먼저 만들어야 합니다.** 만들지 않거나 유효기간(기본 7일, 최대 100일)이 지나면 화면이 503으로 표시됩니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\prepare-dev-signed-downloads.ps1 -ValidDays 30
```

> 이 서명은 **개발시험 전용(DEV-SIGNED-TEST)** 이며 조직의 운영 서명이 아닙니다. 격리된 개발 PC와 시험 VM에서만 사용하세요.

#### Windows PC

두 가지 방식을 지원합니다. 대상 PC에 **열어야 할 포트는 어느 쪽도 없습니다.**

**동일 PC 방식** — 서버와 점검 대상이 같은 PC일 때

프로그램을 실행하면 브라우저가 열리고 그 화면에서 점검을 시작합니다. 프로그램과 브라우저가 `127.0.0.1`로만 통신합니다.

**원격 방식** — 서버가 다른 장비에 있을 때

서버 쪽 `.env` 설정은 아래 Linux 절과 동일합니다. 대상 PC에서는 이렇게 합니다.

1. 브라우저에서 `http://<서버IP>:18480`에 로그인합니다.
2. 다운로드 화면에서 **[다운로드(실행 파일 + 설정 파일)]** 를 누릅니다. 실행 파일과 설정 파일(`*.secai-scan.json`)이 연달아 내려옵니다.
3. 두 파일을 **같은 폴더**에 두고 실행합니다.

   ```powershell
   .\SecAI-Collector-Windows-x64.exe remote-scan
   ```

4. 브라우저에 뜬 승인 화면에서 **점검 대상 장비 이름을 확인**하고 [점검 승인]을 누릅니다.
5. 18개 항목을 수집한 뒤 결과가 서버로 자동 전송됩니다.

설정 파일이 없으면 프로그램은 위의 동일 PC 방식으로 넘어갑니다. 일회용 코드를 입력하지 않으며, 토큰은 **24시간 동안 최대 3회 실행**에 쓸 수 있습니다.

> **증적 보증 수준이 Linux 원샷과 다릅니다.** Windows 원격은 결과 JSON을 서버로 보내고, 서버가 결과 구조와 안전 필드(원본값 미저장·설정 미변경·18개 항목)를 검증합니다. Linux 원샷의 **패키지 서명·증적 해시 체인·증적 악성코드 검사는 적용되지 않습니다.** 자가 점검 결과는 어느 쪽이든 참고용이며 공식 판정이 아닙니다.

> 현재 Windows 실행 파일은 자체 서명(신뢰되지 않은 루트)이라, 빌드하지 않은 다른 PC에서 실행하면 SmartScreen 경고가 표시됩니다. "추가 정보 → 실행"으로 진행하거나, 배포하려면 정식 코드 서명 인증서가 별도로 필요합니다.

#### Linux 서버 (원격 지원)

서버를 다른 장비에 두고, 점검 대상 Linux 서버에서 프로그램만 실행하는 방식입니다. 대상 서버에 **열어야 할 포트가 없습니다**(통신 방향이 대상 → 서버).

**서버 쪽 설정** — `.env`에 다음을 지정하고 재기동합니다.

```env
SECAI_GATEWAY_BIND=0.0.0.0
SECAI_PUBLIC_ORIGIN=http://<서버IP>:18480
SECAI_AUTH_CANONICAL_ORIGIN=http://<서버IP>:18480
```

##### 사용자 절차

1. 브라우저에서 `http://<서버IP>:18480`에 로그인합니다.
2. 다운로드 화면에서 **[다운로드(실행 파일 + 설정 파일)]** 를 누릅니다. 실행 파일과 설정 파일(`*.secai-scan.json`)이 연달아 내려옵니다.
3. 두 파일을 대상 서버의 **같은 폴더**에 두고 실행합니다.

   ```bash
   chmod +x secai-linux-check-x86_64
   ./secai-linux-check-x86_64
   ```

4. 화면에 뜬 승인 페이지에서 **점검 대상 장비 이름을 확인**하고 [점검 승인]을 누릅니다.
   추가 권한(계정 정책·SSH·파일 권한 등 39개 항목)이 필요하면 같은 화면의 체크박스로 동의합니다.
5. 점검이 끝나면 결과가 서버로 자동 제출됩니다.

**일회용 코드를 입력하지 않습니다.** 설정 파일의 토큰은 **24시간 동안 최대 3회 실행**에 쓸 수 있고, 승인 요청은 10분 뒤 만료됩니다.

> 설정 파일에는 서버 주소와 실행 토큰만 들어갑니다. 서명된 실행 파일 자체는 모든 사용자에게 동일하므로 다운로드 화면의 SHA-256 검증이 그대로 유지됩니다. 설정 파일이 없으면 프로그램은 기존의 수동 코드 입력 방식으로 동작합니다.
>
> **설정 파일은 서버가 Ed25519로 서명합니다.** 실행 파일에는 빌드 시점에 그 서버의 공개 키가 들어갑니다. 누군가 `server_origin`을 자기 서버로 바꿔 배포해도, 서명이 맞지 않아 프로그램이 실행을 멈추고 점검 결과가 나가지 않습니다. 서명 키(seed)는 `runtime/dev-secrets/scan_sidecar_signing_key`에 있으며 `tools\init-dev-secrets.ps1`이 없을 때만 새로 만듭니다. **이 파일을 잃어버리거나 바꾸면 이미 배포한 실행 파일이 설정 파일을 거부하므로, 백업해 두고 교체 시에는 수집기를 다시 빌드해 배포하세요.**
>
> ⚠️ DEV-LOCAL 프로파일은 평문 HTTP라 세션 쿠키가 네트워크에 노출됩니다. 격리망 시험용이며, 그 밖의 환경에서는 게이트웨이 앞에 TLS를 두고 canonical origin을 `https://`로 바꾸세요.

### 6.2 등록된 Linux 서버 SSH 점검

등록 대상은 환경 변수로 지정하고, 접속에는 **SSH 키**를 사용합니다(비밀번호 로그인 아님).

| 항목 | 기본값 / 위치 |
| :--- | :--- |
| 대상 A 주소 | `.env`의 `SECAI_LINUX_UBUNTU_HOST` (기본 `192.168.110.146`) |
| 대상 B 주소 | `.env`의 `SECAI_LINUX_ROCKY_HOST` (기본 `192.168.110.148`) |
| SSH 사용자 | `.env`의 `SECAI_LINUX_SSH_USER` (기본 `secai-lab`) |
| 개인키 | `.runtime/vmware/secai-ubuntu-lab-ed25519`, `.runtime/vmware/secai-rocky-lab-ed25519` |
| known_hosts | `.runtime/vmware/known_hosts` (`StrictHostKeyChecking=yes` 강제) |

준비 절차:

```powershell
ssh-keygen -t ed25519 -f .runtime\vmware\secai-ubuntu-lab-ed25519 -N '""'
# 공개키를 대상 서버의 ~/.ssh/authorized_keys에 등록하고, 해당 계정에 NOPASSWD sudo 권한 부여
ssh-keyscan -H 192.168.110.146 >> .runtime\vmware\known_hosts
```

점검 명령은 고정된 읽기 전용 allowlist만 실행하며, root 권한이 필요한 명령은 `sudo -n -- <고정 argv>` 형태로만 수행됩니다.

### 6.3 Aruba AOS-CX 스위치 점검

* 실제 장비 또는 **AOS-CX Simulator OVA**가 필요합니다. [HPE Networking (Aruba) Support Portal](https://asp.arubanetworks.com/)에서 내려받아 VMware 등에 올립니다.
* 대상 주소: `.env`의 `SECAI_ARUBA_AOS_CX_HOST` (기본 `192.168.11.10`)
* **인증서 핀닝**: `.runtime/vmware/aruba_https_certificate.sha256`에 장비 HTTPS 인증서의 SHA-256 해시를 등록해야만 REST 연결이 승인됩니다(MITM 차단).
* REST 계정과 비밀번호는 점검 시작 화면에서 입력하며, DB·로그·결과에 저장되지 않습니다.

### 6.4 실습 자격증명 보관 파일 (선택)

여러 실습 VM을 반복 사용한다면 `runtime/dev-secrets/lab_vm_credentials.json`에 모아둘 수 있습니다. 이 파일은 `.gitignore`로 보호되며 평문 비밀번호를 담으므로 외부에 복사하지 마세요.

```jsonc
{
  "schema_version": "1.2",
  "environment": "DEV-LOCAL",
  "linux": {
    "common_credential": {
      "username": "secai-lab",
      "password": "<로컬 실습용 비밀번호>",
      "password_login_enabled": true
    },
    "targets": {
      "ubuntu_24_04_lts": {
        "support_status": "SUPPORTED",
        "authentication_type": "ssh_key_and_password",
        "private_key_file": ".runtime/vmware/secai-ubuntu-lab-ed25519"
      }
    }
  }
}
```

등록된 Linux VM에 이 비밀번호를 일괄 적용·검증하려면 `tools\set-lab-linux-password.ps1`, Aruba 계정 회전은 `tools\rotate-aruba-lab-passwords.ps1`을 사용합니다.

---

## 🧪 7. 개발 · 검증 명령

```powershell
# 전체 품질 게이트 (설정 검증 → 테스트 → 스키마 → lint → 타입)
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action All

# 개별 실행
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action Test
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action Lint
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action Type

# DB 관리 UI (http://localhost:18490)
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\open-database-admin.ps1 -Action Start

# 로그 확인 / 종료
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Logs
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Down
```

---

## 📁 8. 주요 디렉터리 구조

| 경로 | 내용 |
| :--- | :--- |
| `apps/` | FastAPI 백엔드, 웹 템플릿·정적 파일, 워커 진입점 |
| `src/security_audit/` | 점검 비즈니스 로직, KISA 규칙 엔진, AI 해설 매핑 |
| `audit_packs/` | 대상별(PC·Linux·스위치) 확정적 검사 규칙 팩 |
| `collectors/` | Windows·Linux 원샷 수집기 소스와 계약 파일 |
| `deploy/` | Dockerfile, Compose 정의, 이미지 잠금·검증 기록 |
| `database/` | Alembic 마이그레이션, JSON Schema, 검증 스크립트 |
| `guides/` | 가이드 카탈로그·페이지 맵·매니페스트 (PDF 원본 제외) |
| `tools/` | 설치·빌드·검증 자동화 스크립트 |
| `tests/` | 단위·계약 테스트 |
| `data/` | 가이드 PDF 보관 구역 **(PDF는 업로드 차단)** |
| `runtime/`, `.runtime/` | 시크릿·산출물·VM 자산 **(전체 업로드 차단)** |

Docker 데이터(PostgreSQL, Redis, 오브젝트 스토리지)는 프로젝트 폴더가 아니라 **Docker named volume**에 보존됩니다.

---

## 📥 9. KISA · NCSC 보안 가이드라인 (PDF) 다운로드

RAG 기반 AI 보안 해설을 사용하려면 정부 기관이 배포하는 공식 PDF가 필요합니다. 저작권·재배포 금지 정책에 따라 저장소에 포함되지 않으므로 직접 내려받아 배치해야 합니다.

| 발행 기관 | 문서명 | 폴더 경로 | 출처 |
| :--- | :--- | :--- | :--- |
| **KISA** | 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 | `data/` | KISA 자료실 |
| **KISA** | 제로트러스트 가이드라인 2.0 | `data/public_guides/kisa_zero_trust_2_0/` | [KISA 자료실](https://www.kisa.or.kr/2060204/form?postSeq=18) |
| **KISA** | SW 공급망 보안 가이드라인 1.0 | `data/public_guides/kisa_sw_supply_chain_1_0/` | [KISA 자료실](https://www.kisa.or.kr/2060204/form?postSeq=15) |
| **KISA** | 인공지능(AI) 보안 안내서 (정오 수정본) | `data/public_guides/kisa_ai_security_guide_2026_errata/` | [KISA 자료실](https://www.kisa.or.kr/2060204/form?postSeq=19) |
| **KISA** | AI 보안 위협 대응 매뉴얼 | `data/public_guides/kisa_ai_threat_response_2026/` | [KISA 보도자료](https://www.kisa.or.kr/401/form?postSeq=3712) |
| **KISA** | AI 보안 레드티밍 가이드 | `data/public_guides/kisa_ai_red_teaming_2026/` | [KISA 보도자료](https://www.kisa.or.kr/401/form?postSeq=3713) |
| **국정원(NCSC)** | 국가 망 보안체계(N2SF) 보안가이드라인 1.0 및 해설서 | `data/public_guides/ncsc_n2sf_1_0/` | [국가사이버안보센터](https://www.ncsc.go.kr/) |

> 📌 **파일명까지 정확해야 합니다.**
>
> * KISA 상세가이드는 `data/주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드.pdf` 경로 그대로 Compose에 mount 됩니다. 이름이 다르면 API가 기동하지 않습니다.
> * 공개 가이드의 정확한 파일명과 SHA-256은 [`guides/public_guides_manifest.json`](guides/public_guides_manifest.json)의 `source_path`에 정의되어 있습니다. 배치 후 `tools/verify-public-guides.py`(5.2절)로 일치 여부를 확인하세요.
> * 원본을 그대로 받아 내용을 변경하지 않아야 해시 검증을 통과합니다.

---

## 🧭 10. 자주 막히는 지점

| 증상 | 원인 · 해결 |
| :--- | :--- |
| `Up` 실행 중 secret 관련 오류 | `llm_api_key`, `model_gateway_token`, `minio.license` 누락 → Step 2.3 참고. 라이선스가 없으면 `-Action UpWithoutAIStor` 사용 |
| api 컨테이너가 계속 재시작 | KISA 상세가이드 PDF 파일명 불일치 → Step 2.4 |
| 로그인 후 코드 입력 화면에서 진행 불가 | 인증 코드는 `runtime/dev-secrets/auth_dev_mfa_code` |
| 다운로드 화면 503 | 개발 서명 카탈로그 미생성 또는 만료 → 6.1절 재실행 |
| AI 해설에 근거가 안 붙음 | 가이드 적재 미실행 → 5장 |
| Linux SSH 점검이 권한 오류 | 대상 계정의 NOPASSWD sudo 미설정 또는 known_hosts 미등록 → 6.2절 |
| 원격 실행인데 코드를 물어봄 | 설정 파일(`*.secai-scan.json`)이 실행 파일과 다른 폴더에 있음 → 6.1절 |
| `설정 파일을 신뢰할 수 없어 중단합니다` | 설정 파일이 편집되었거나 다른 서버에서 받은 것 → 다운로드 화면에서 다시 받으세요 |
| `신뢰 키 파일이 없어…` | 서명 seed 없이 빌드된 실행 파일 → `tools\init-dev-secrets.ps1` 실행 후 수집기 재빌드 |
| 승인 화면이 "기존 점검을 취소하라"고 함 | 제출을 기다리는 자가 점검이 남아 있음. 해당 점검을 취소한 뒤 다시 실행 |
| 승인 요청이 만료됨 | 승인 유효시간은 10분입니다. 프로그램을 다시 실행하면 새 요청이 만들어집니다 |
| Windows 원격인데 로컬 화면이 열림 | 더블클릭은 동일 PC 방식입니다. 원격은 `remote-scan` 인자를 붙여 실행하세요 → 6.1절 |
| Windows 결과 제출이 `SCAN_ASSET_UNAVAILABLE` | 승인한 계정에 Windows 자산이 정확히 1개 배정돼 있어야 합니다 |
| 다른 PC에서 서버에 접속 불가 | `SECAI_GATEWAY_BIND=0.0.0.0` 설정과 서버 PC의 방화벽 인바운드(기본 18480) 허용을 확인하세요 |

---

## 📜 11. 라이선스 및 저작권

* **Sec_AI Core**: `GNU AGPL v3.0`
* RAG 참조용으로 내려받은 **공공기관 지침 문서(PDF)** 는 해당 기관의 이용 허락 규정(공공누리 등)을 따르며 무단 외부 재배포를 금지합니다.
* 오브젝트 스토리지는 상용 AIStor(MinIO) Free Tier를 사용하며, 엔터프라이즈 라이선스를 추가하면 Object Lock·KMS 기능으로 확장할 수 있는 구조입니다.

> **[라이선스 고지 및 심사위원 재현성 평가 안내]**
> 본 프로젝트(Sec_AI)는 PyMuPDF(AGPL-3.0)를 포함함에 따라 **GNU AGPL v3.0 라이선스**로 제공됩니다. AGPL 제13조(네트워크 이용자에 대한 소스코드 제공 의무)를 준수하기 위해 본 프로젝트의 모든 소스코드는 `https://github.com/CyberSec0108/Sec_AI` 에 공개되어 있습니다.
> 
> 시스템 인프라 중 오브젝트 스토리지(MinIO AIStor)는 상용 EULA 기반의 무료 티어 이미지를 사용하여 이미지 직접 재배포가 불가능합니다. AIStor 상용 라이선스 파일(`minio.license`)이 없는 심사/평가 환경에서는 아래 명령어를 통해 우회 기동해 주시기 바랍니다.
> 
> **[AIStor 라이선스 없는 환경에서의 평가 기동 방법]**
> ```powershell
> # 1. AIStor를 제외한 핵심 8개 서비스(DB, API, 스케줄러 등) 기동 (점검·판정·결과 조회 가능)
> powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action UpWithoutAIStor
> 
> # 2. AI 해설 기능까지 평가하기 위해 model-gateway 추가 기동
> docker-compose up -d model-gateway
> ```
> *(참고: AI 해설 기능을 확인하시려면 사전에 `.env` 파일에 `llm_api_key`가 설정되어 있어야 합니다. 증적 오브젝트 스토리지 복구 기능만 AIStor 부재로 인해 제한되며 나머지 핵심 기능은 모두 정상 평가가 가능합니다.)*   

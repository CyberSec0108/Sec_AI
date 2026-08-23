# Sec_AI (AI 자동 보안 점검 도구)

Sec_AI는 인프라 및 자산에 대해 **"KISA 보안 기준을 1:1로 정밀 대조하는 확정적 판정 엔진"**을 실행하고, 복잡한 취약점 결과를 투영(Projection) 기반 비식별화를 거쳐 **AI(대형언어모델)가 안전하고 쉽게 해설해 주는 오픈소스 플랫폼**입니다. 

Windows, Linux, 그리고 Aruba Switch(AOS-CX) 등 다양한 플랫폼의 규정 준수 여부를 자동화된 파이프라인으로 점검할 수 있습니다.

---

## 🛠 1. 필수 요구 사항 (Prerequisites)
본 프로젝트는 시스템 파편화를 막고 독립적인 구동을 보장하기 위해 **모든 구성 요소를 Docker 기반으로 자체 빌드**합니다. 따라서 로컬 PC에 복잡한 파이썬 라이브러리나 DB를 직접 설치할 필요가 전혀 없으며, 도커만 설치되어 있다면 스크립트 명령어 하나로 모든 이미지가 자동 다운로드 및 설치됩니다.

### 기본 환경
*   **운영체제**: Windows 10/11 (Windows 기본 PowerShell 호환) 또는 Linux/Mac (`pwsh` 설치 필요)
*   **필수 소프트웨어**: Docker Desktop (또는 Docker Engine & Docker Compose v2 이상), Git
*   **권장 디스크 용량**: 
    *   **기본 구동 (OpenRouter API 사용 시)**: 약 **5GB ~ 10GB** 여유 공간 (PostgreSQL, Redis, ClamAV DB 및 자체 빌드되는 컨테이너 이미지 용량)
    *   *(선택)* 로컬 LLM(vLLM) 구동 시: 모델 크기에 따라 추가 **10GB ~ 수백 GB**의 대용량 스토리지 및 NVIDIA GPU (CUDA 환경) 필요

---

## 🚀 2. 설치 및 빌드 (Installation & Build)

### Step 2.1: 저장소 복제 및 개발용 시크릿 초기화
프로젝트를 내려받은 후, 가장 먼저 DB 패스워드, JWT 서명 키, TLS 인증서 등 **시스템 구동에 필요한 모든 보안 키를 자동 생성**해야 합니다.

1.  **Windows 시작 메뉴**에서 `PowerShell`을 검색하여 실행합니다. (또는 터미널을 엽니다.)
2.  아래 명령어를 복사하여 순서대로 붙여넣고 엔터를 누르세요.

```powershell
# 저장소 복제
git clone https://github.com/YourID/Sec_AI.git
cd Sec_AI

# (윈도우 환경 보안 정책 우회) 로컬 개발용 시크릿 자동 생성
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\init-dev-secrets.ps1
```
> **💡 중요**: 이 과정을 거치면 `runtime/dev-secrets/` 폴더 하위에 보안 설정 파일들이 세팅됩니다. 이 폴더는 `.gitignore`로 보호되어 실수로 GitHub에 업로드되지 않습니다.

### Step 2.2: 도커 이미지 자동 빌드 및 코어 서비스 구동
사용자가 일일이 도커 이미지를 찾아 다운로드할 필요 없이, 아래 명령어 한 줄만 입력하면 시스템 구동에 필요한 모든 환경이 **완전 자동으로 설치**됩니다.

```powershell
# 코어 서비스 전체 빌드 및 실행 (무료 오픈소스 AIStor 포함)
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Up
```
> **💡 동작 원리**: 이 명령어를 치면 백그라운드에서 다음 과정이 자동으로 진행됩니다.
> 1. **자동 다운로드**: 운영체제, Python, NGINX, PostgreSQL 등 뼈대가 되는 공식 베이스 이미지를 알아서 다운로드합니다.
> 2. **자동 설치(Build)**: 다운로드한 베이스 이미지 위에 프로젝트의 소스코드와 라이브러리(`requirements.txt`)를 엮어, `sec-ai-mvp/*`라는 Sec_AI 맞춤형 도커 이미지들을 구워냅니다.
> 3. **초기 세팅**: 데이터베이스 테이블 생성 및 구조 세팅(Migration)을 완료합니다.
> 4. **실행**: 최종적으로 7개의 핵심 컨테이너가 묶여서 켜집니다.

**📦 구동되는 도커 컨테이너 목록:**
*   `sec-ai-mvp/gateway`: NGINX 리버스 프록시 (웹 트래픽 라우팅 및 SSL 처리)
*   `sec-ai-mvp/audit-api`: FastAPI 기반 핵심 백엔드 서버
*   `sec-ai-mvp/audit-worker`: Celery 비동기 분산 처리 워커 (실제 점검 로직 수행)
*   `sec-ai-mvp/postgres`: 데이터베이스 (보안 설정 및 Row Level Security 적용)
*   `sec-ai-mvp/redis`: 인메모리 데이터 저장소 및 워커 메시지 브로커
*   `sec-ai-mvp/clamav`: 첨부파일 및 시스템 악성코드 검사 엔진
*   `sec-ai-mvp/model-gateway`: 외부/로컬 AI 모델 통신을 통제하는 보안 게이트웨이

*(처음 실행 시 베이스 이미지를 다운로드하고 빌드하므로 몇 분 정도 소요됩니다.)*

---

## 🔑 3. 초기 설정 및 사용 방법

### Step 3.1: 초기 관리자 계정 발급
시스템이 정상 구동 중이면(`powershell -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Status`로 확인 가능), 데이터베이스에 초기 관리자 권한을 부여해야 합니다.

```powershell
# 초기 관리자 계정 생성 및 DB 적용
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\bootstrap-dev-auth.ps1
```
*   명령어 실행 결과로 터미널에 **임시 관리자 이메일(ID)과 무작위 비밀번호**가 출력됩니다. 

### Step 3.2: 웹 UI 접속
*   브라우저를 열고 `https://localhost:18480` (기본 포트)에 접속한 뒤, 발급받은 계정으로 로그인합니다.
*   기본 포트는 `.env` 파일의 `SECAI_GATEWAY_PORT`에서 변경 가능합니다.

---

## 🤖 4. LLM (AI 모델) 연동 및 `.env` 환경 변수 설정
Sec_AI의 해설 기능은 OpenAI 호환 API 규격을 따르는 LLM(대형언어모델)을 사용합니다. **기본값은 OpenRouter API로 설정되어 있으나, 자신의 환경에 맞게 로컬 vLLM 또는 다른 상용 API로 손쉽게 변경할 수 있습니다.**

### 외부 API (OpenRouter, OpenAI 등) 사용 시
1.  `tools\init-dev-secrets.ps1` 스크립트를 실행한 뒤, 프로젝트 루트에 생성된 `.env` 파일을 엽니다.
2.  아래 환경 변수들을 사용하고자 하는 모델과 API 주소로 변경합니다.
    ```env
    SECAI_LLM_API_BASE=https://openrouter.ai/api/v1  # 또는 https://api.openai.com/v1 등
    SECAI_LLM_MODEL=openai/gpt-oss-120b              # 사용할 모델명으로 변경
    ```
3.  **API 키 설정**: 외부 API 통신을 위한 실제 API 키는 보안을 위해 `runtime/dev-secrets/llm_api_key` 파일 안에 평문으로 한 줄만 입력하여 저장합니다. (이 파일 역시 `.gitignore`에 의해 보호됩니다.)

### 로컬 모델 (vLLM 등) 직접 구동 시
폐쇄망이나 온프레미스 환경을 위해 로컬에 자체 GPU 모델을 띄운 경우, 외부로 데이터를 보내지 않고 내부에서 처리하도록 설정할 수 있습니다.
1.  `.env` 파일에서 API 주소를 로컬 호스트(예: `http://vllm:8000/v1`)로 변경합니다.
    ```env
    SECAI_LLM_API_BASE=http://vllm:8000/v1
    SECAI_LLM_MODEL=my-approved-local-model
    ```
2.  이후 `powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Restart` 명령어를 실행하여 변경된 환경 변수를 적용합니다.

---

## 💻 5. 가상머신(VM) 및 타겟 장비 연동 가이드 (매우 중요)

이 도구는 실제 대상 서버 및 스위치 네트워크를 원격 또는 로컬로 점검합니다. **타겟 장비의 접속 계정과 비밀번호는 절대 소스코드 내부에 하드코딩하거나 Git에 커밋해서는 안 됩니다.**

### 5.1 타겟 장비(VM) 준비 방법
본 프로젝트는 **점검 도구(서버)** 이므로, 해킹 및 보안 점검의 대상이 될 타겟 장비(VM)는 사용자가 직접 준비해야 합니다.
*   **Windows / Linux**: 사용자가 점검을 원하는 PC나 서버를 자유롭게 준비하여 연동할 수 있습니다.
*   **Aruba Switch (AOS-CX)**: 네트워크 스위치 점검 기능을 테스트하려면 실제 물리 장비가 있거나 가상 어플라이언스(OVA)가 필요합니다. 
    *   *다운로드 방법*: [HPE Networking (Aruba) Support Portal](https://asp.arubanetworks.com/)에 회원가입 후, **AOS-CX Simulator OVA** 파일을 다운로드 받아 VMware Workstation 등에 가상머신으로 올려서 테스트할 수 있습니다.

### 5.2 장비 연동 및 보안 통신 설정
1. **자격 증명 맵핑 파일 생성**
   *   점검할 타겟 장비의 로그인 정보는 `runtime/dev-secrets/lab_vm_credentials.json` 파일을 수동으로 생성하여 관리합니다. 백엔드 워커는 이 JSON 파일을 읽어 SSH/REST 통신을 수행합니다.
2. **Aruba Switch 인증서 핀닝 (Certificate Pinning)**
   *   AOS-CX 스위치 장비와 HTTPS REST 통신을 수행할 때, 중간자 공격(MITM)을 막기 위해 `.runtime/vmware/aruba_https_certificate.sha256` 파일에 장비의 정확한 인증서 해시값을 등록해야만 연결이 승인됩니다.
3. **Linux / Windows 자가 점검**
   *   Windows 점검이나 Linux One-shot 스크립트는 중앙 API를 통해 결과를 암호화하여 안전하게 반환합니다.

> 📝 **참고사항 (AIStor / MinIO 활용에 대하여)**
> 본 프로젝트는 보안 점검 결과와 대용량 증적 파일을 보존하기 위해 **오픈소스(AGPLv3) 기반의 `AIStor (MinIO)` 스토리지**를 기본 탑재하고 있습니다. 
> *   명령어(`-Action Up`) 실행 시 100% 무료로 스토리지가 자동 구축되며, 향후 엔터프라이즈 라이선스를 추가할 경우 법적 불변성 보존(Object Lock) 및 KMS 암호화 기능으로 즉시 확장 가능하도록 설계된 하이브리드 아키텍처입니다.

---

## 📁 6. 주요 디렉터리 구조 및 보호 구역
*   `apps/` : FastAPI, 웹 프론트엔드 템플릿, 워커(Worker) 진입점 소스
*   `src/security_audit/` : 보안 점검 비즈니스 로직, KISA 규칙 엔진 및 AI 해설 맵핑 코드
*   `audit_packs/` : 대상별(PC, Linux, 스위치) 확정적 검사 규칙(Ruleset) 팩
*   `volumes/` : PostgreSQL, Redis 등의 실제 데이터가 영구 보존되는 도커 볼륨 구역 **(업로드 차단됨)**
*   `data/` : RAG 검색용 KISA/NCSC 보안 가이드 PDF 보관 구역 **(업로드 차단됨)**

---

## 📥 7. KISA 및 NCSC 보안 가이드라인 (PDF) 필수 다운로드
Sec_AI의 가장 강력한 기능인 **RAG(검색 증강 생성) 기반 AI 보안 해설**을 사용하려면, 정부 기관에서 배포하는 공식 보안 가이드라인 PDF 파일들이 필요합니다. 

이 파일들은 저작권 및 무단 재배포 금지 정책에 따라 **GitHub에 업로드되지 않으므로(완벽히 배제됨)**, 프로젝트 다운로드 후 아래 지정된 위치에 직접 원본 PDF를 다운로드하여 배치해야 합니다.

### 다운로드 경로 및 파일 배치 가이드
| 발행 기관 | 문서명 | 폴더 경로 (프로젝트 루트 기준) | 다운로드 출처 |
| :--- | :--- | :--- | :--- |
| **KISA** | 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 | `data/` | KISA 자료실 |
| **KISA** | 제로트러스트 가이드라인 2.0 | `data/public_guides/kisa_zero_trust_2_0/` | [KISA 자료실](https://www.kisa.or.kr/2060204/form?postSeq=18) |
| **KISA** | SW 공급망 보안 가이드라인 1.0 전체본 최종 수정본 | `data/public_guides/kisa_sw_supply_chain_1_0/` | [KISA 자료실](https://www.kisa.or.kr/2060204/form?postSeq=15) |
| **KISA** | 인공지능(AI) 보안 안내서 정오 수정본 | `data/public_guides/kisa_ai_security_guide_2026_errata/` | [KISA 자료실](https://www.kisa.or.kr/2060204/form?postSeq=19) |
| **KISA** | AI 보안 위협 대응 매뉴얼 | `data/public_guides/kisa_ai_threat_response_2026/` | [KISA 보도자료](https://www.kisa.or.kr/401/form?postSeq=3712) |
| **KISA** | AI 보안 레드티밍 가이드 | `data/public_guides/kisa_ai_red_teaming_2026/` | [KISA 보도자료](https://www.kisa.or.kr/401/form?postSeq=3713) |
| **국정원(NCSC)** | 국가 망 보안체계(N2SF) 보안가이드라인 1.0 (및 해설서) | `data/public_guides/ncsc_n2sf_1_0/` | [국가사이버안보센터](https://www.ncsc.go.kr/) |

> 📌 **주의사항**: 위 파일들은 프로젝트 내 `guides/public_guides_manifest.json`에 정의된 메타데이터 해시(SHA-256)를 참조하므로, 공식 사이트에서 원본을 그대로 받아 내용 변경 없이 배치해야 AI가 정상적으로 인식합니다.

---

## 📜 8. 라이선스 및 저작권
*   **Sec_AI Core**: `GNU AGPL v3.0` (오픈소스 릴리스 적용)
*   내부에 RAG(검색 증강 생성) 참조용으로 다운로드한 **공공기관 지침 문서(PDF)** 등은 해당 기관의 이용 허락 규정(공공누리 등)을 따르며, 무단 외부 재배포를 금지합니다.

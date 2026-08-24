# Sec_AI Core Compose

이 디렉터리는 2단계 Core 서비스 실행 구성을 보관한다. 실행 이미지는 모두 `sec-ai-mvp/<component>:0.1.0`으로 표시한다. 외부 제품은 동작을 바꾸지 않는 얇은 프로젝트 래퍼로 감싸며, 승인된 원본 공급자 이름과 `linux/amd64` digest는 Dockerfile·라벨·잠금표에 유지한다.

## 서비스

| 서비스 | 이미지 | 현재 책임 |
|---|---|---|
| Gateway | `sec-ai-mvp/gateway:0.1.0` | `127.0.0.1:18480` 단일 DEV 진입점, API reverse proxy·보안 헤더 |
| API | `sec-ai-mvp/audit-api:0.1.0` | Health, 사용자 UI·JSON API와 PostgreSQL 업무 상태 조회 |
| Worker | `sec-ai-mvp/audit-worker:0.1.0` | 일반 Celery Core Queue 소비자 |
| Maintenance Worker | `sec-ai-mvp/audit-maintenance-worker:0.1.0` | `maintenance` Queue 전용, Outbox·Worker 손실 복구 작업 |
| Scheduler | `sec-ai-mvp/audit-scheduler:0.1.0` | Celery Beat 골격, 아직 정기 업무 없음 |
| PostgreSQL+pgvector | `sec-ai-mvp/postgres:0.1.0` | PostgreSQL 18.4·pgvector 0.8.2, migration chain `0001~0035`(Guide 검색은 `0008`에서 도입), 업무 정본과 격리된 Guide 검색 projection |
| pgAdmin | `sec-ai-mvp/pgadmin:0.1.0` | 관리자 선택 기동, `127.0.0.1:18490`, Guide DB 조회·수정·SQL 관리 |
| Redis | `sec-ai-mvp/redis:0.1.0` | 잠긴 공식 Redis 기반, named ACL user를 사용하는 Celery Broker |
| AIStor | `sec-ai-mvp/aistor:0.1.0` | 잠긴 공식 AIStor 기반, 라이선스가 있을 때만 전체 기동 가능한 원본 저장소 골격 |
| ClamAV | `sec-ai-mvp/clamav:0.1.0` | 잠긴 정의 파일을 사용하는 non-root daemon |
| Model Gateway | `sec-ai-mvp/model-gateway:0.1.0` | API와 외부 시험 모델·향후 로컬 vLLM 사이의 OpenAI 호환 내부 경계 |
| vLLM | `sec-ai-mvp/vllm-openai-gpu:0.23.0` | `local-vllm` profile 전용 준비 이미지, 승인 모델·GPU·취약점 Gate 전에는 실행 차단 |

`migrate`, `dev-tools`, `guide-ingest`는 상시 서비스가 아니라 필요한 작업에서만 실행하는 도구성 container입니다. pgAdmin과 vLLM도 각각 명시적 profile을 선택한 경우에만 기동합니다.

## 디렉터리 구조

```text
deploy/
├─ compose/         Core·개발 override·복구훈련·모델 검색 Compose
├─ docker/          프로젝트 service와 잠긴 외부 제품 wrapper Dockerfile
├─ gateway/         Nginx reverse proxy와 보안 header 설정
├─ locks/           외부 image·검색 모델의 exact tag/digest 잠금
├─ model-search/    별도 검색 모델 실행용 비밀정보 없는 예제 설정
├─ patches/         공급자 수정 반영 전 제한적 보안 patch
├─ pgadmin/         사전 등록 서버의 비밀정보 없는 정의
├─ security/        image/구성요소 취약점 판정 보조 자료
├─ verification/    단계별 실행·시험·SBOM·취약점 검증 기록
└─ vmware/          Ubuntu/Rocky 시험 VM 생성 template·도구
```

`deploy/verification`은 실행 산출물의 정본 위치가 아니라, 어떤 코드·image·DB·VM 조건에서 무엇을 검증했는지 남기는 감사 기록입니다. 실제 secret, 원본 Evidence, DB dump와 private key를 넣지 않습니다.

## 네트워크와 공개 범위

```text
Windows host 127.0.0.1:18480
  → Gateway(frontend_net)
  → API(app_net)
  ├→ PostgreSQL / Redis / AIStor / ClamAV
  └→ Model Gateway(model_net)
       ├→ 승인된 외부 시험 provider
       └→ local-vllm profile(기본 중지)
```

- 기본 Gateway는 `127.0.0.1:18480`에만 bind합니다.
- PostgreSQL, Redis, AIStor와 ClamAV port는 host에 publish하지 않습니다.
- pgAdmin은 `admin-tools` profile과 `127.0.0.1:18490`에서만 엽니다.
- VM 또는 다른 PC가 Gateway에 직접 접속하게 하려면 bind·방화벽·TLS·인증 범위를 별도 승인해야 합니다. 개발용 SSH reverse tunnel은 운영 공개 설정이 아닙니다.
- 모델 provider token과 내부 Gateway token은 Compose YAML이나 `.env` 값으로 기록하지 않고 secret file로 주입합니다.

## 파일 변경 기준

| 변경 대상 | 함께 확인할 내용 |
|---|---|
| `compose/*.yml` | `dev.ps1 -Action Config`, network·port·secret·healthcheck, 기존 volume 보존 |
| `docker/*.Dockerfile` | base digest, non-root, lock hash 설치, SBOM·CVE·악성코드 검사 |
| `gateway/nginx.conf` | route allowlist, timeout, streaming buffer, CSP·보안 header |
| `locks/*` | 공급자·platform·exact digest·license와 재현성 |
| `patches/*` | 공식 수정 출처, 적용 대상 exact version, 제거 조건 |
| `vmware/*` | template에 secret 없음, snapshot 이름·네트워크·읽기 전용 시험 |
| `verification/*` | 실행 명령, 입력 기준, PASS/FAIL, 미검증 Gate, 민감정보 제외 |

Docker, 네트워크, secret, 인증과 배포 설정은 영향이 큰 변경입니다. 사용자가 요청한 범위 안에서 최소 변경하고, Compose 병합 결과와 관련 service image를 즉시 검증합니다.

## 기본 검증

```powershell
# Compose 병합·환경 변수 참조 검사
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action Config

# service 상태와 Gateway Health
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Status
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Health
```

변경 service만 먼저 재빌드한 뒤 실제 route·DB·Worker·streaming 경계를 집중 검증합니다. 전체 개발 품질 Gate는 [`../tools/README.md`](../tools/README.md)를 따릅니다.

## 실행

개발 Secret을 먼저 만든다. 값은 화면에 출력되지 않고 `runtime/dev-secrets`에 저장되며 Git과 이동 묶음에서 제외된다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Init
```

AIStor Free 라이선스 파일을 이미 발급받았다면 다음처럼 별도로 반입한다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 `
  -Action Init `
  -AIStorLicensePath D:\secure-transfer\minio.license
```

라이선스가 아직 없으면 AIStor를 제외한 8개 서비스와 API fail-closed Readiness를 먼저 시험할 수 있다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action UpWithoutAIStor
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Status
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Health
```

이 상태에서 `/health/live`는 `200`이고 `/health/ready`는 AIStor가 없으므로 `503 not_ready`여야 정상이다. 라이선스 반입 뒤 전체 9개 서비스는 `-Action Up`으로 실행한다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Up
```

2026-07-22 DEV 환경은 발급된 라이선스를 `runtime/dev-secrets/minio.license`로 반입했고 당시 8개 서비스 기동·재시작과 `/health/ready` HTTP `200`을 확인했다. 2026-07-24 IMP-044에서 Maintenance Worker를 추가했고, IMP-045에서 AIStor·PostgreSQL 격리 복원과 빈 Redis Outbox 재구축을 통과했다. 현재 9개 서비스가 healthy다. 라이선스 값은 로그·문서·이미지에 기록하지 않는다.

기동 과정은 migration 뒤 `local-owner` DEV named account를 idempotent하게 준비한다. 비밀번호와 개발용 두 번째 인증코드는 `runtime/dev-secrets/auth_dev_password`, `runtime/dev-secrets/auth_dev_mfa_code`에서 이 PC 사용자만 확인하며 화면공유·로그·문서에 복사하지 않는다.

기동 후 [http://localhost:18480](http://localhost:18480)에서 로그인한다. `18480`은 Sec_AI DEV HTTP 규칙의 기본 포트이며 실제 Docker·Windows listener 조사에서 사용 중인 `8080`, `18000`, `18080`과 충돌하지 않도록 선택했다. `18443`은 향후 DEV TLS용으로 예약만 하고 현재 publish하지 않는다.

일반 제품 화면과 DB 관리 화면은 분리한다. 관리자 DB 화면은 다음 스크립트로 선택 기동하며 브라우저에서 [http://127.0.0.1:18490](http://127.0.0.1:18490)을 연다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\open-database-admin.ps1 -Action Start
```

로그인 ID는 `admin@secai.dev`다. pgAdmin 로그인 비밀번호는 `runtime/dev-secrets/pgadmin_default_password`, 사전 등록된 `Sec_AI PostgreSQL + pgvector` 서버의 DB 비밀번호는 `runtime/dev-secrets/postgres_db_admin_password`에서 이 PC 사용자만 확인한다. 값을 문서·채팅·화면공유에 복사하지 않는다.

`18490`은 `18x9x` 관리자 도구 규칙으로 선택했고 loopback에만 bind한다. PostgreSQL `5432`는 host에 publish하지 않는다. DB 계정 `secai_db_admin`은 슈퍼유저·DB/Role 생성·복제 권한이 없고, 현재 DEV 조직 범위의 Guide table 조회·추가·수정·삭제와 상태 관찰만 허용된다. DB 제약조건·RLS·append-only trigger는 pgAdmin에서도 그대로 적용된다.

pgAdmin wrapper image는 공식 9.16 digest를 기준으로 하되, 2026-07-24 검사에서 확인된 수정 가능 패키지를 hash·버전 고정 갱신하고 CPython 3.14의 `CVE-2026-15308` 공식 수정 commit을 backport했다. 개발 관리자 전용 구성이다. 운영·Pilot 전에는 최신 공식 base로 교체하고 다시 이미지 취약점 검사를 통과해야 한다.

IMP-020 전체 시연은 다음 한 명령으로 재현한다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\demo.ps1
```

IMP-045 합성 저장소 장애·복구훈련은 다음 명령으로 재현한다. 기본 named volume은 삭제하지 않고 `sec-ai-mvp-imp045-*` 전용 복구 volume을 사용한다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\verify-imp045-storage-recovery.ps1
```

IMP-046 로그인·권한·Web 보안 실제 HTTP 흐름은 다음 명령으로 재현한다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\tools\verify-imp046-auth-rbac-web-security.ps1
```

중지는 volume을 삭제하지 않는다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Down
```

## 현재 제한

- Gateway의 host `18480`은 loopback DEV-LOCAL 로그인·합성 UI·Health 전용 HTTP다. 운영 업무 API를 열기 전에 실제 TLS·WebAuthn·조직 OIDC를 구현한다.
- AIStor Console, PostgreSQL, Redis와 ClamAV port는 host에 publish하지 않는다. pgAdmin은 별도 `admin-tools` profile에서만 `127.0.0.1:18490`으로 연다.
- AIStor license, 비밀번호와 이후 TLS·KMS key는 source, image, `.env`, 이동 묶음에 넣지 않는다.
- 합성 UI/API는 `SECAI_DEV_DEMO_ENABLED=true`, DEV-LOCAL 로그인과 fixed synthetic case allowlist에 한정된다. 실제 원본 download·운영 권한 surface가 아니다.
- 합성 object의 versioning·exact version 격리 복원은 통과했지만, 장기 보존 bucket·Object Lock·KMS와 다른 failure domain의 독립 백업은 아직 없다.


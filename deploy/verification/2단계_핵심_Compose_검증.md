# 2단계 Core Compose 검증 기록

| 항목 | 결과 |
|---|---|
| 프로젝트 | Sec_AI |
| Release | `R0-WALKING-SKELETON` |
| 검증일 | 2026-07-22 |
| 상태 | `PASS` — AIStor를 포함한 8개 서비스 기동·Health·재시작 PASS |
| 실제 증적 사용 | 없음. 합성 DEV Health 시험만 수행 |

> 이 문서는 2단계 당시의 `127.0.0.1:8080` 실행 증적을 보존한다. IMP-019부터 현재 DEV host port는 충돌 회피 규칙에 따라 `127.0.0.1:18480`이며, 최신 기준은 `IMP019_응용_웹_종단간_검증.md`다.

## 1. 구현 범위

Gateway, FastAPI API, Celery Worker, Celery Scheduler, PostgreSQL, Redis, AIStor, ClamAV의 Compose 정의를 작성했다.

AIStor Free 라이선스를 `tools/core.ps1 -Action Init -AIStorLicensePath <경로>`로 `runtime/dev-secrets/minio.license`에 반입했다. 값은 출력하지 않았고, 빈 파일이나 임의 문자열로 우회하지 않았다. 잠긴 AIStor 이미지를 포함한 8개 서비스를 실제로 기동했다.

## 2. 자동 품질 Gate

| 검사 | 결과 |
|---|---|
| Python | CPython `3.14.6` |
| Unit·Contract test | 15건 PASS |
| JSON Schema | 8종 자체 검사 PASS |
| Schema example | 14건 PASS |
| Ruff | PASS |
| mypy | 35개 source file PASS |
| Compose config | PASS |
| Gitleaks source scan | 0 leak |

FastAPI TestClient 실행에서 잠긴 Starlette가 향후 `httpx2` 전환을 안내하는 deprecation warning 1건을 출력했다. 현재 테스트 실패는 아니며 dependency lock을 임의 변경하지 않았다.

## 3. 실제 컨테이너 검증

| 서비스 | 결과 | 비고 |
|---|---|---|
| Gateway | healthy | `127.0.0.1:8080`만 publish |
| API | healthy | non-root `10001:10001`, read-only, capability 전체 제거 |
| Worker | healthy | non-root `10001:10001`, Redis named ACL 연결 |
| Scheduler | healthy | non-root `10001:10001`, Redis named ACL 연결 |
| PostgreSQL | healthy | host port 미공개, server process UID `999` |
| Redis | healthy | host port 미공개, server process UID `999`, default user 비활성 |
| ClamAV | healthy | non-root `100:101`, read-only, capability 전체 제거 |
| AIStor | healthy | host port 미공개, read-only root filesystem, capability 전체 제거, license read-only secret mount |

Redis에 인증 없이 `PING`했을 때 `NOAUTH Authentication required`를 확인했다. Gateway 이외 서비스는 host port binding이 없으며 PostgreSQL·Redis·ClamAV·AIStor는 `internal` application network에만 둔다.

## 4. Health 결과

`GET /health/live`:

```json
{"status":"ok","service":"audit-api","version":"0.1.0"}
```

`GET /health/ready`:

```json
{
  "status": "ready",
  "service": "audit-api",
  "version": "0.1.0",
  "dependencies": {
    "postgres": true,
    "redis": true,
    "aistor": true,
    "clamav": true
  }
}
```

Readiness HTTP status는 `200`이며 PostgreSQL·Redis·AIStor·ClamAV가 모두 `true`다. 인증된 S3 API로 임시 합성 bucket과 object를 생성하고 PUT·GET·STAT 후 삭제하는 smoke test도 통과했다.

## 5. 재시작 시험

8개 서비스를 동시에 재시작한 뒤 Compose `--wait`로 PostgreSQL·Redis·AIStor·ClamAV·API·Worker·Scheduler·Gateway가 다시 healthy가 되고 Health 응답이 복구되는 것을 확인했다. PostgreSQL·Redis·AIStor named volume은 유지됐다.

## 6. 프로젝트 이미지 식별

PostgreSQL·Redis·AIStor에도 동작을 변경하지 않는 얇은 Sec_AI 래퍼를 적용했다. 실행 이미지는 모두 `sec-ai-mvp/*:0.1.0`으로 표시하며, 각 래퍼의 라벨에는 승인된 공식 원본 repository·version·digest를 기록한다.

| 이미지 | 실행 사용자 |
|---|---|
| `sec-ai-mvp/dev-tools:0.1.0` | `10001:10001` |
| `sec-ai-mvp/gateway:0.1.0` | `101:101` |
| `sec-ai-mvp/audit-api:0.1.0` | `10001:10001` |
| `sec-ai-mvp/audit-worker:0.1.0` | `10001:10001` |
| `sec-ai-mvp/audit-scheduler:0.1.0` | `10001:10001` |
| `sec-ai-mvp/postgres:0.1.0` | `999:999` |
| `sec-ai-mvp/redis:0.1.0` | `999:999` |
| `sec-ai-mvp/aistor:0.1.0` | upstream 기본 사용자 `root`; read-only rootfs·capability drop·no-new-privileges 적용 |
| `sec-ai-mvp/clamav:0.1.0` | `100:101` |

모든 프로젝트 이미지에서 `io.sec-ai-mvp.project=Sec_AI`와 component label을 확인한다. PostgreSQL·Redis·AIStor 래퍼는 원본 repository·version·digest 라벨도 함께 확인한다. 로컬 BuildKit manifest ID는 rebuild provenance에 따라 바뀔 수 있으므로 Release 공급망 digest로 승인하지 않는다. SBOM·취약점 scan·서명 후 별도 잠금해야 한다.

## 7. 이동 묶음 검증

최종 묶음은 `portable/out/secai-portable-<UTC>` 형식의 가장 최근 directory다. exact ID와 SHA-256은 해당 묶음의 `BUNDLE-MANIFEST.json`과 `SHA256SUMS.txt`를 따른다.

| 항목 | 결과 |
|---|---|
| Source ZIP | SHA-256 일치 |
| Image TAR | SHA-256 일치, 약 `0.70 GiB` |
| 공식 기반 잠금 이미지 | 6개 기록 |
| 프로젝트 실행 이미지 | 기존 묶음 6개, 신규 묶음은 프로젝트 종료·명시적 요청 시 생성 |
| Source ZIP entry | 134개 |
| 금지 경로·확장자 | 0개 |
| 복원 source Gitleaks | 0 leak |

실제 `.env`, `runtime`, Secret, AIStor license, 실제 증적, backup과 Docker volume은 포함하지 않았다. PostgreSQL·Redis·AIStor 래퍼가 반영된 신규 이동 묶음은 프로젝트 종료 시점 또는 사용자의 명시적 요청이 있을 때만 생성한다. 그 전에는 기존 `secai-portable-20260722T033002Z`를 최신 배포 묶음으로 사용하지 않는다.

## 8. AIStor 라이선스·기동 Gate 결과

다음 항목을 완료했다.

1. 발급받은 AIStor Free license file의 존재·비어 있지 않음을 확인했다.
2. DEV secret 영역에 값 노출 없이 반입하고 directory ACL을 제한했다.
3. 잠긴 `sec-ai-mvp/aistor:0.1.0` image로 전체 8개 서비스를 실행했다.
4. AIStor `healthy`, 전체 readiness HTTP `200 ready`를 확인했다.
5. AIStor host port가 없고 internal application network에만 연결됨을 확인했다.
6. license는 read-only bind secret이며 `.gitignore`·`.dockerignore`·이동 묶음 제외 규칙에 포함됨을 확인했다.
7. 인증된 S3 합성 object PUT·GET·STAT·DELETE를 확인했다.
8. SPDX 2.3 SBOM을 생성했다. Docker Scout CVE 조회는 Docker ID 로그인이 없어 실행되지 않았으므로 취약점 Gate는 미완료다.

장기 보존 Bucket 생성, Object Lock, KMS, service account 최소권한, backup·restore와 실제 증적 반입은 이 Health 골격 검증의 완료를 의미하지 않는다. 해당 항목은 증적 저장 정책의 별도 Gate로 남으며, 통과 전에는 합성 자료만 사용한다.

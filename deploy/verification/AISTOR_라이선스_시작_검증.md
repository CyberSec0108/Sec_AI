# AIStor Free 라이선스 반입·기동 검증

| 항목 | 결과 |
|---|---|
| 검증일 | 2026-07-22 |
| 환경 | DEV, Docker Desktop, `linux/amd64` |
| 프로젝트 이미지 | `sec-ai-mvp/aistor:0.1.0` |
| 잠긴 upstream | `quay.io/minio/aistor/minio:RELEASE.2026-06-06T02-44-06Z@sha256:5dbb753c0dbe6a987dd30ce564f66c0042e291e464d10e792443451d4fec2120` |
| 결과 | `PASS-WITH-REMAINING-GATES` |

## 완료한 검증

- 라이선스 파일의 존재·일반 파일·비어 있지 않음만 확인하고 값은 출력하지 않았다.
- `tools/core.ps1 -Action Init -AIStorLicensePath <경로>`로 `runtime/dev-secrets/minio.license`에 byte 그대로 반입했다.
- runtime secret directory ACL은 현재 Windows 사용자, SYSTEM, Administrators로 제한했다.
- 라이선스는 container `/run/secrets/minio.license`에 read-only로 mount되며 image layer에 포함되지 않는다.
- AIStor는 `sec-ai-mvp-app` internal network에만 연결되고 host port binding이 없다.
- container는 read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`로 실행된다.
- AIStor와 나머지 Core 서비스 8개가 기동·재시작 후 모두 `healthy`다.
- `/health/ready`가 PostgreSQL·Redis·AIStor·ClamAV 전체 `true`, HTTP `200`을 반환한다.
- root credential을 화면에 출력하지 않고 인증된 S3 임시 합성 bucket을 만들었다. 합성 object의 PUT·GET·STAT과 byte 일치를 확인한 뒤 object와 bucket을 즉시 삭제했다.
- 이동 묶음은 생성하거나 갱신하지 않았다.

## 공급망 자료

- SPDX version: `SPDX-2.3`
- SPDX package entry: 416개
- SBOM SHA-256: `23db193e10cd43a2cd6b8f1643c95e9fbdec8855bc5caf778cb977823c20deb3`
- SBOM: `deploy/verification/aistor/sec-ai-mvp-aistor-0.1.0.sbom.spdx.json`

Docker Scout로 SBOM 생성은 성공했다. CVE 조회는 실행 환경에 Docker ID 로그인이 없어 중단됐으며 PASS로 기록하지 않는다. Docker 로그인 또는 승인된 offline scanner를 준비한 뒤 같은 exact image에 대해 다시 실행해야 한다.

## 보안상 남은 Gate

- 제공된 upstream image는 기본 사용자 `root`로 server를 실행한다. capability 전체 제거·read-only rootfs·외부 port 차단을 적용했지만, non-root 지원 여부는 제조사 지원 구성으로 별도 검증한다.
- `secai-original`, `secai-evidence-quarantine`, derived·audit bucket과 versioning은 단계 F의 `object-init` 구현 때 생성한다.
- COMPLIANCE/GOVERNANCE 1,095일 Object Lock, KMS/OpenBao, service account별 최소권한, audit webhook은 아직 적용하지 않았다.
- 독립 backup과 RPO 1시간·RTO 8시간 복구시험은 아직 수행하지 않았다.
- 위 Gate 전에는 실제 기관 증적을 저장하지 않고 합성 data만 사용한다.
- 프로젝트 루트에 제공됐던 원본은 `runtime/license-archive/minio.license`로 이동하고 현재 Windows 사용자·SYSTEM·Administrators만 접근하도록 ACL을 제한했다. 활성 `runtime/dev-secrets/minio.license`와 SHA-256이 같음을 값 노출 없이 확인했다. 보존 또는 삭제는 추후 Secret 관리 책임자가 결정한다.

## 다음 작업

현재 구현 순서에서는 `IMP-009` package archive 보안 계약을 먼저 완료한다. AIStor 영구 bucket·Object Lock·KMS 초기화는 PC-07 pure core 이후 Persistence·Queue·API 최소 E2E 단계에서 수행한다.

# SWITCH-UI-03 PDF·결과 화면 구성 통합 검증

| 항목 | 내용 |
|---|---|
| 검증일 | 2026-08-07 |
| 범위 | Aruba AOS-CX N-01~N-38 결과의 사용자용·기술 검증용 PDF와 Linux형 결과 패널 구성 |
| 상태 | 개발 source·합성 결과 집중시험 PASS, 실제 장비·배포 image 브라우저 E2E는 미실행 |
| 판정 경계 | `0.4.0-DRAFT`, 공식 Finding·승인 Pack으로 승격하지 않음 |

## 1. 구현 결과

- Switch 결과 화면에 `결과 보고서(PDF) 받기` 패널을 추가했다.
- 일반 사용자는 사용자용 PDF를 받을 수 있다.
- 기술 검증용 PDF는 `EVIDENCE_DOWNLOAD` 권한이 있는 역할만 받을 수 있다.
- 사용자용 PDF에는 실제 확인값, 개발용 판정, 판정 이유, 다음 행동과 KISA 쪽 근거를 담고
  내부 판정 코드·기술 위치·증적 hash는 제외한다.
- 기술 검증용 PDF에는 내부 판정 코드, REST 확인 방법·출처·기술 위치, 수집 상태, 원문·정규화
  SHA-256과 비식별 처리 여부를 추가한다.
- 결과 hash·기준 hash, DRAFT 상태와 조직 보완 판정이 장비 REST 수집값이 아니라는 설명을
  두 보고서에 유지한다.
- Linux 결과 화면과 같은 위치에 보고서·무결성·재점검 패널을 배치했다.

## 2. 보안·정합성 경계

- 보고서 API는 organization과 owner scope에서 무결성이 확인된 완료 결과만 사용한다.
- 기술 검증용 다운로드는 기존 중앙 RBAC의 `Permission.EVIDENCE_DOWNLOAD`를 재사용한다.
- 응답은 `Cache-Control: no-store`와 attachment filename을 사용한다.
- 비밀번호·session cookie·REST 원문을 보고서에 넣지 않는다.
- 사용자용 PDF에는 raw output hash와 기술 locator를 넣지 않는다.
- AI 설명은 공식 판정을 변경하지 않으며 이번 PDF는 저장된 결정론 결과를 정본으로 사용한다.

## 3. TDD와 검증 결과

첫 시험은 `build_switch_report_document`가 없어 import 단계에서 실패하는 것을 확인했다.

```text
ImportError: cannot import name 'build_switch_report_document'
```

구현 후 실행한 집중시험:

```powershell
docker compose --project-directory . `
  -f deploy\compose\compose.yml `
  -f deploy\compose\compose.dev.yml `
  run --rm dev-tools -m pytest `
  tests/unit/test_switch_product_flow.py `
  tests/unit/test_linux_product_flow.py -q
```

결과:

```text
37 passed, 1 warning
```

Ruff:

```powershell
docker compose --project-directory . `
  -f deploy\compose\compose.yml `
  -f deploy\compose\compose.dev.yml `
  run --rm dev-tools -m ruff check `
  src/security_audit/application/device_report.py `
  apps/api/switch_audit.py `
  tests/unit/test_switch_product_flow.py
```

결과: `All checks passed!`

mypy strict 집중검사:

```powershell
docker compose --project-directory . `
  -f deploy\compose\compose.yml `
  -f deploy\compose\compose.dev.yml `
  run --rm dev-tools -m mypy `
  src/security_audit/application/device_report.py `
  apps/api/switch_audit.py `
  tests/unit/test_switch_product_flow.py
```

결과: `Success: no issues found in 3 source files`

기존 `httpx` TestClient deprecation warning 1건과 작업 범위 밖 orphan container 경고는 기능 실패가
아니며 이번 변경에서 의존성이나 container를 수정·삭제하지 않았다.

## 4. 미실행 Gate

- 현재 실행 중인 API image 재빌드와 실제 로그인 브라우저 클릭
- 실제 AOS-CX 재점검 뒤 PDF 육안 검수
- 조직 `SECURITY_OFFICER` 계정의 기술 PDF 실제 다운로드
- 운영 Publisher·승인 Pack·공식 Finding과 결합한 보고서

따라서 이 기록은 개발용 DRAFT PDF 구현을 증명하며 운영 공식 보고서 승인을 뜻하지 않는다.

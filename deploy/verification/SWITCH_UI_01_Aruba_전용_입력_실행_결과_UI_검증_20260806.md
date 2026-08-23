# SWITCH-UI-01 Aruba 전용 입력·실행·결과 UI 검증

| 항목 | 결과 |
|---|---|
| 기준일 | 2026-08-06 |
| 대상 | Aruba AOS-CX 10.13.1170 개발 시험 VM |
| 범위 | 등록 장비 선택 → REST 자격증명 입력 → 읽기 전용 SW-01~06 실행 → 사용자별 결과 저장·표시 |
| 기능 상태 | 개발 환경 `LIVE`, 결과 기준은 `0.1.0-DRAFT` |
| 공식 Finding | 생성하지 않음 |
| 운영 승인 | 아님 — 공식 Pack·PDF·AI·Cisco 교차 회귀 대기 |

## 1. 구현 결과

- 홈의 `네트워크 스위치 점검`을 실제 `/ui/switch-scan` 경로에 연결했다.
- 사용자는 서버에 등록된 `aruba-aos-cx-10.13.1170-lab`만 선택할 수 있다. 임의 host·port·인증서 지문은 요청 Schema와 화면에 없다.
- 사용자 이름과 비밀번호를 입력하면 인증서 고정 AOS-CX REST 세션으로 고정 `GET` allowlist만 실행한다.
- 브라우저는 비밀번호를 요청 직후 입력칸과 요청 객체에서 지우며 local/session storage에 기록하지 않는다.
- 실행 상태 API를 polling하고 완료 시 `/ui/switch-results?run_id=...`로 이동한다.
- 결과 화면은 SW-01~06의 상태·안전 기준·비식별 확인값·다음 행동·정규화 SHA-256을 표시한다.
- REST 원문, 전체 running-config, password, cookie, token은 결과에 넣지 않는다.
- AOS-CX 10.13.1170 내장 `admin`은 REST `current_user` 응답에서 `user_group`을 생략한다. 정확한 `admin` 로그인과 group 필드 생략이 함께 확인된 경우만 내장 관리자 호환 경계로 처리하고, 명시된 비관리자 group과 다른 계정은 계속 `INSUFFICIENT_PRIVILEGE`로 거부한다.

## 2. 인증·권한·저장 경계

| 경계 | 적용 내용 |
|---|---|
| Web 인증 | DEV-LOCAL password + 두 번째 인증 뒤 접근 |
| CSRF | session-bound token과 same-origin 검사 |
| 중앙 RBAC | `USER`, `SECURITY_OFFICER`, `ADMIN` 허용; 승인 전용 `APPROVER` 거부 |
| 대상 제한 | 서버 등록 asset key 하나, Pydantic `extra=forbid` |
| 장비 신원 | 서버 보관 SHA-256 인증서 pin과 exact AOS-CX REST `v10.13` |
| 저장 | PostgreSQL migration `0025_switch_audit_ui` |
| 격리 | organization + owner user RLS, `FORCE ROW LEVEL SECURITY` |
| 동시 실행 | 조직·asset별 `QUEUED/RUNNING` unique index |
| 무결성 | canonical result SHA-256을 저장하고 화면 렌더 전 재검증 |
| 비밀정보 | 요청 메모리에서만 사용; DB column·result·event payload에 저장하지 않음 |

## 3. TDD·정적 검증

첫 Red 단계는 `apps.api.switch_audit`가 없어 테스트 collection에서 실패하는 것을 확인했다. 구현 뒤 다음 검증을 통과했다.

```powershell
docker compose --project-directory . `
  -f deploy\compose\compose.yml `
  -f deploy\compose\compose.dev.yml `
  run --rm dev-tools -m pytest `
  tests/unit/test_switch_product_flow.py `
  tests/unit/test_aruba_aoscx_rest.py `
  tests/unit/test_multiplatform_foundation.py -q
```

- 최종 집중 Pytest: `27 passed`
- Ruff: 변경 Python 파일 전체 PASS
- mypy strict: Switch UI/API/service/repository/Aruba Adapter 시험 PASS
- JavaScript syntax: `node --check apps/web/static/app/switch-scan.js` PASS
- IMP-040 product launcher acceptance: `PASS`, 현재 registry `LIVE 12 / PREVIEW 1 / BLOCKED 0`
- 기존 `test_imp040_product_ui.py` 병합 실행에서 새 Switch 관련 회귀는 통과했다. 별도 기존 실패 1건은 현재 작업과 무관한 header help-link 기대값 불일치다.

## 4. 실제 DB·장비·HTTP E2E

### 4.1 DB migration

- Alembic: `0024_linux_oneshot_active → 0025_switch_audit_ui`
- 실제 개발 DB head: `0025_switch_audit_ui`
- `switch_audit_runs`, `switch_audit_events`: RLS와 FORCE RLS 모두 `true`

### 4.2 실제 AOS-CX와 저장 서비스

DPAPI로 보호된 비밀번호를 표준입력으로만 전달해 API container에서 실제 점검을 실행했다.

- 결과: `COMPLETED`
- Control: `6`, 모두 `PASS`
- 저장 결과 무결성 재검증: `PASS`
- 이때 생성된 결과 SHA-256 예시: `9f68186b5b7acf26a7e5493604b6bedc1ba4dec248fd11024ecb99ef98799e7f`
- 비식별 projection SHA-256은 기존 안전 snapshot 검증값 `11848e85d916d7d13607911b4486b31025842c0ff77d0e975aeaa5fa9f0baa9a`와 일치했다.

### 4.3 실제 브라우저 HTTP 흐름

보호된 개발 로그인·MFA·스위치 비밀번호를 출력하지 않고 메모리에서만 사용해 Gateway를 통과했다.

```text
로그인 화면 200
→ MFA 완료·/ui/switch-scan 200
→ POST /api/v1/switch/audits 202
→ 상태 COMPLETED
→ /ui/switch-results 200
→ 결과 카드 6개
```

- 결과 HTML 민감 필드 검사: `false`
- 최신 DB 결과: `COMPLETED | controls 6 | 민감 키 없음 true | hash 길이 64`
- 자격증명성 DB column 수: `0`
- RLS 실측: `owner_visible=true | other_visible=false`

### 4.4 실행 이미지

- API image/container: `sha256:b41baeba873d33eb9c7e2fa9625db40d64515fbca8f22d2a6da7bdc95e5ad448`
- API health: `healthy`
- 비로그인 `/ui/switch-scan`: `/auth/login?next=/ui/switch-scan`으로 `303`
- 정적 `/static/app/switch-scan.js`: `200`

## 5. 완료·미완료 경계

이번 변경으로 `SWITCH-05` 중 다음만 개발 구현했다.

- 등록 장비 선택
- credential 입력과 즉시 비저장 처리
- 실행 상태·오류 코드 표시
- 실제 SW-01~06 결과·비식별 증적·hash UI
- 인증·CSRF·RBAC·RLS·결과 무결성

다음은 계속 미완료다.

- Cisco IOS XE 실제 구조화 API 세로 기능과 두 벤더 교차 회귀
- KISA·Aruba 공식 기준 Source Mapping과 승인·서명 Audit Pack
- 운영 공식 Finding
- Switch 사용자/기술 PDF
- 근거가 연결된 Switch AI 설명·후속 질문
- OpenBao 등 운영 secret store와 단기 credential

따라서 화면 기능의 `LIVE`는 **현재 개발 환경에서 실제로 동작한다**는 뜻이며, 운영 승인·공식 판정 완료를 뜻하지 않는다.

# Windows 결과 정합성·기본 기준·재점검 UI 검증 (2026-08-05)

## 1. 목적

- PC-01~18 카드의 공식 DRAFT 판정 개수와 AI 종합 설명의 개수를 항상 일치시킨다.
- 조직 Profile이 없더라도 제품이 안전하게 판단할 수 있는 보조 기본 기준을 제공한다.
- 일반 권한·관리자 권한 항목을 빠짐없이 재점검할 수 있게 하고, 작은 화면에서도 버튼과 상태 표시가 겹치지 않게 한다.
- AI 설명은 PC-01부터 PC-18까지 순차 표시하며 완료 안내 문구는 남기지 않는다.

공식 판정 권한은 기존과 같이 규칙 엔진에만 있다. 아래 제품 기본값은 KISA의 공식 수치나 조직 승인을 대신하지 않으며 `2026-DRAFT` 개발 판정에만 사용한다.

## 2. 원인과 수정

### 2.1 AI 요약 개수 불일치

- 원인 1: 종합 설명 모델이 양호·취약·확인 필요 개수를 자유 문장으로 다시 계산해 실제 18개 판정과 다른 수를 출력할 수 있었다.
- 원인 2: 관리자 항목 일부만 재점검하면 브라우저 카드에는 이전 다섯 결과가 남지만 AI 전달용 관리자 결과는 선택한 일부 결과로 교체됐다.
- 수정: 종합 설명의 `전체 상태`는 모델 문장을 사용하지 않고 정렬된 규칙 엔진 입력에서 `PASS/FAIL/ERROR/REVIEW/NOT_APPLICABLE`을 계산해 삽입한다.
- 수정: 일부 관리자 재점검 결과는 같은 표준 점검 결과 ID의 이전 관리자 결과와 Control ID별로 병합하고, 최신 결과만 같은 항목을 교체한다.

### 2.2 제품 기본 기준

기존 기본 기준에 다음 보조 기준을 추가했다.

| 항목 | 제품 기본값 | 의미 |
|---|---:|---|
| PC-09 | `true` | 현재 로그인 사용자의 WinINet 범위를 판정에 사용 |
| PC-13 | `24시간` | 백신 서명이 마지막으로 갱신된 뒤 허용하는 최대 경과 시간 |
| PC-16 | `true` | 현재 로그인 사용자의 화면 잠금 범위를 판정에 사용 |
| PC-17 | `true` | 모든 드라이브·비볼륨 장치 자동 실행 차단 요구 |
| PC-18 | `true` | 요청·제공 원격 지원의 명시적 차단 요구 |

값과 출처는 API, 브라우저 기준 편집 화면, Windows Collector exact contract, 실행 시점 기준 snapshot/hash에 동일하게 포함한다. 범위를 사용자가 명시적으로 해제하면 기존처럼 `REVIEW`로 남긴다. 필수 증적 수집 실패는 `FAIL`로 바꾸지 않고 `ERROR`를 유지한다.

### 2.3 카드·재점검·반응형 UI

- 카드 왼쪽 테두리는 `기준 확인 필요(REVIEW)` 파란색, `양호(PASS)` 초록색, `취약(FAIL)` 빨간색, `수집 오류(ERROR)` 오류색으로 분리했다.
- 재점검 영역은 기본 닫힘 `<details>`로 바꾸고 PC-01~18을 모두 표시한다.
- 일반 권한 13개는 기존 안전 경계에 따라 한 번에 다시 수집하고, 관리자 권한 5개는 필요한 항목만 선택해 별도 동의·UAC 뒤 다시 수집한다.
- 작은 화면에서는 상단 보기 전환, 보고서·재점검 버튼, 재점검 항목을 3열→2열→1열로 줄이고 줄바꿈을 허용한다.

### 2.4 AI 설명 순서와 완료 문구

- 결과 카드를 중요도 순서가 아니라 PC 번호 순서로 렌더링해 서버의 PC-01→18 스트림과 화면 순서를 일치시켰다.
- 항목 생성 완료 뒤 상태 문구와 중지 버튼을 숨긴다.
- `설명 생성 완료` 및 같은 의미의 완료 안내 문구를 Windows 결과 화면 코드에서 제거했다.

## 3. 변경 파일

- `src/security_audit/application/result_ai_token_stream.py`: 규칙 엔진 기준 상태 집계·종합 설명 고정
- `apps/api/result_ai_explanation.py`: 종합 시작 이벤트에 확정 상태 개수 전달
- `src/security_audit/application/assessment_criteria.py`: PC-09·13·16·17·18 제품 기본 기준
- `src/security_audit/collector/criteria_contract.py`: Collector exact 기준 계약 확장
- `src/security_audit/application/current_host_regression.py`: 새 기본값을 사용하는 결정론적 판정
- `apps/api/assessment_criteria.py`: 개인·조직 기준 API 확장
- `apps/api/product.py`: PC-01~18 재점검 목록 제공
- `apps/web/templates/components/criteria_form.html`: 기본 기준 편집 화면
- `apps/web/templates/pages/product_results.html`: 기본 닫힘 재점검 표와 전체 18개 항목
- `apps/web/static/app/product-results.js`: 관리자 부분 결과 병합·재점검 패널 동작
- `apps/web/static/app/product-results-integrated.js`: PC 번호순 카드·완료 문구 제거
- `apps/web/static/app/result-ai-analysis.js`: 순차 진행 표시·완료 문구 제거
- `apps/web/static/app/app.css`: 상태별 왼쪽 테두리·반응형 배치
- `tests/unit/test_product_ai_token_stream.py`, `tests/unit/test_assessment_criteria_profiles.py`, `tests/unit/test_product_result_consistency_ui.py`: 회귀 시험
- `src/security_audit/application/result_report.py`: UI형 PDF 렌더러·한글 글꼴 호환성·기술 증적 행
- `apps/api/result_reports.py`: 별도 모델 명세 다운로드 API 제거
- `apps/web/templates/pages/product_results.html`, `apps/web/static/app/product-results.js`: 모델 명세 다운로드 버튼·동작 제거
- `tests/unit/test_product_ai_08_result_reports.py`: PDF 디자인·증적·글꼴·모델 명세 제거 회귀 시험

## 4. 검증 결과

### 통과

- 요구사항·Windows 수집·관리자 흐름 집중 Pytest: `62 passed`
- 추가 UI·AI·기준 집중 Pytest: `49 passed`
- 변경 Python Ruff: `All checks passed`
- 변경 Python mypy strict: `Success: no issues found in 7 source files`
- JavaScript syntax: `product-results.js`, `product-results-integrated.js`, `result-ai-analysis.js` 모두 PASS
- Windows 완료 문구 검색: `설명 생성 완료` 잔존 0건
- Core Health: API `ok`, PostgreSQL·Redis·AIStor·ClamAV 의존성 `ready`, API·Gateway `healthy`
- API image/container: `sha256:5e14089bcf579f4bb8caf9722da104088e9d0292f33dd2157b09e8ee066088f7`

집중 Pytest 범위는 다음 파일을 포함한다.

- `test_product_ai_token_stream.py`
- `test_assessment_criteria_profiles.py`
- `test_product_result_consistency_ui.py`
- `test_imp043_administrator_consent.py`
- `test_windows_administrator_complete_flow.py`
- `test_imp037_windows_collection.py`
- `test_imp037_windows_collection_ui.py`
- `test_imp038_current_host_regression.py`

### Windows 실행 파일

- 위치: `runtime/imp034-artifacts/build-20260805T120037Z/SecAI-Collector-Windows-x64.exe`
- 크기: `12,708,491 bytes`
- SHA-256: `d88924c5c6aea25013eccf8b7fea89618f385ad2ca04b9736db51b50addd9e6d`
- IMP-034 인수: `10/10 PASS`
- 잠긴 의존성: 24개, 알려진 취약점: 0건
- ClamAV·Microsoft Defender: `CLEAN`
- 채널: `DEV-UNSIGNED`, 운영 배포물 아님

### 전체 Gate에서 확인한 작업 범위 밖 불일치

`powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action All` 결과는 `691 passed, 11 failed`였다. 실패는 이번 변경 파일의 새 계약이 아니라 기존 화면 문구 기대값, 시험 secret 미제공, DB table 기대값, Schema catalog 25개 기대값과 현재 26개 등록의 불일치다. 요청 범위 밖의 오래된 기대값을 임의 수정하거나 시험을 약화하지 않았다.

## 5. 결과 영역 클릭 시 위치 유지 Hotfix

- 증상: AI 설명·출처·접기/펼치기 등 결과 패널 안을 클릭하면 패널 맨 위로 이동했다.
- 원인: 결과 패널과 상태 요약 버튼이 모두 `data-result-status`를 사용했는데, 이벤트 등록 선택자가 패널까지 포함했다. 패널 내부의 모든 click이 버블링되어 상태 필터와 `scrollIntoView()`를 실행했다.
- 수정: 이벤트와 활성 상태 변경 대상을 `button[data-result-status]`로 제한하고, 상태 필터의 자동 스크롤을 제거했다.
- TDD: 수정 전 새 회귀시험 `1 failed, 3 passed`, 수정 후 `4 passed`.
- JavaScript syntax: `product-results-integrated.js` PASS.
- Runtime: 최종 API image/container ID 일치, API `ok`, 모든 Core 의존성 `ready`.

## 6. 결과 보기 버튼 한 줄 반응형 Hotfix

- 증상: `통합 보기`, `점검 결과만`, `AI 설명만` 중 세 번째 버튼이 다음 줄로 내려가 2칸+1칸으로 표시됐다.
- 원인: 각 버튼이 최소 `8rem`을 요구하는 flex-wrap 배치여서 컨테이너의 계산 폭에 따라 임의로 줄바꿈됐다.
- 수정: 버튼 그룹을 항상 동일 폭 3칸 Grid로 배치하고, 컨테이너는 최대 `24rem`·모바일 `100%`로 조정했다.
- 좁은 화면에서는 버튼 자체가 겹치지 않도록 글자 크기와 좌우 여백을 `clamp()`로 축소하고 버튼 안에서만 안전하게 줄바꿈한다.
- TDD: 수정 전 `1 failed, 3 passed`, 수정 후 `4 passed`.
- Runtime: 최종 API image/container ID 일치, API `ok`, 모든 Core 의존성 `ready`.

## 7. Windows 카드 기술 증적 UI 제거

- 사용자 요청에 따라 Windows 통합 결과 카드의 `확인 방법과 기술 증적` 접기 영역을 제거했다.
- 카드 생성 코드에서 해당 UI 함수와 호출만 제거했으며, 실제 확인값·KISA 기준·판정 이유·AI 설명·출처와 백엔드 수집 데이터는 유지한다.
- Linux의 별도 증적 표시와 기술 검증용 PDF 계약은 변경하지 않았다.
- TDD: 수정 전 `1 failed, 4 passed`, 수정 후 `5 passed`.
- JavaScript syntax와 실행 Gateway 제공 스크립트 확인 PASS.
- Runtime: 최종 API image/container ID 일치, API `ok`, 모든 Core 의존성 `ready`.

## 8. AI 완료 화면 보존·명시적 재생성

- 최초 AI 생성 완료 시 종합 설명·PC-01~18 항목별 원문·허용 출처를 결과 ID·버전·관리자 결과 조합별로 현재 브라우저 탭의 `sessionStorage`에 저장한다.
- 결과 화면 새로고침 또는 같은 탭에서 다른 화면 방문 후 복귀 시 저장 결과를 복원하고 token stream API를 다시 호출하지 않는다.
- 완료 화면에는 `AI 설명 재생성` 버튼을 표시하며, 이 버튼을 사용자가 직접 누른 경우에만 새 생성을 시작한다.
- HTML을 저장하지 않는다. 최대 길이를 제한한 AI 원문과 출처만 저장하고, 복원할 때 현재 PC-01~18과 정확히 일치하는지 확인한 뒤 제한형 Markdown 렌더러로 다시 검증한다.
- 새 점검 결과 ID·버전에는 기존 설명을 재사용하지 않고 최초 생성을 수행한다.
- 사용자가 후속 요청에서 멈춤 버튼 변경을 제외했으므로 기존 생성 중지 동작은 이번 범위에서 변경하지 않았다.
- TDD: 수정 전 `1 failed, 5 passed`, 수정 후 관련 token stream 포함 `15 passed`.
- JavaScript syntax와 실행 Gateway 제공 스크립트 확인 PASS.
- Runtime: 최종 API image/container ID 일치, API `ok`, 모든 Core 의존성 `ready`.

## 9. 사용자·기술 검증 PDF 보완

### 사용자용 PDF 디자인

- 기존 좌표식 단순 텍스트 출력을 UI와 같은 A4 보고서 레이아웃으로 교체했다.
- 한글 고딕 CID 글꼴과 `FontDescriptor`를 명시해 Chrome뿐 아니라 MuPDF 계열에서도 한글이 깨지지 않게 했다.
- 상단 제목·용도 배지, 판정 성격 메타데이터, 5칸 상태 요약 표, 상태색 왼쪽 테두리와 배지가 있는 PC-01~18 카드, 라벨/값 표, 출처 영역, 페이지 번호를 적용했다.
- ASCII 문자별 폭을 보정해 기존 PDF의 `S e c _ A I`, `F i n d i n g` 같은 과도한 자간을 제거했다.

### 기술 검증용 PDF 실제 증적

- 각 항목에 실제 수집 결과에서 만들어진 비식별 `normalized_facts`를 `정규화 증적`으로 표시한다.
- Probe ID·수집 상태·수집 시각·사용자 출처 라벨·정규화 레코드 SHA-256을 `실제 증적 추적` 행으로 표시한다.
- Collector·Probe·Adapter 버전, 확인 방법과 기술 위치, 내부 결과 코드, 설명 입력·규칙 결과 hash, KISA 문서·원문 hash·mapping 상태를 함께 제공한다.
- 원본 증적과 민감 식별자는 ADR 15 안전 경계에 따라 PDF에 넣지 않고, `원본 증적 포함: 아니요`와 비식별 실제값·정규화 hash 제공 사실을 명시한다.

### AI 모델 활용 명세 다운로드 제거

- 결과 화면의 `AI 모델 활용 명세 받기` 버튼과 전용 다운로드 API·응답 URL·JavaScript 처리를 제거했다.
- 내부 감사에 필요한 모델 계보와 라이선스 정보는 기술 검증용 PDF의 무결성 명세에만 남겼다.

### 검증

- 집중 Pytest: `21 passed`
- Ruff: `All checks passed`
- mypy: `Success: no issues found in 2 source files`
- JavaScript syntax: `product-results.js` PASS
- 제거 문자열 검색: 실행 코드의 모델 명세 다운로드 UI·URL 0건
- 합성 PDF 렌더링: 사용자용 8쪽·기술 검증용 16쪽, MuPDF 글꼴 오류 0건
- 시각 확인: 사용자용 요약 표·카드·출처 표, 기술용 정규화 증적·수집 추적·SHA-256 표시 PASS
- Core Health: API `ok`, PostgreSQL·Redis·AIStor·ClamAV 의존성 `ready`, API `healthy`
- API image/container: `sha256:7b4f7c75f907800ee288913f608e3f6073e342e0b6384d9e180a9107c2260ac3`

## 10. 안전 경계와 남은 인수

- 제품 기본값은 조직이 등록한 기준이 있으면 그 기준과 Profile 병합 규칙을 따른다.
- KISA 공식 결과·공식 Audit Pack 승인·운영 Finding으로 승격하지 않는다.
- Collector는 읽기 전용이며 설정 변경, 자동 권한 상승, raw evidence 저장, 공식 Finding 생성을 하지 않는다.
- 실제 좁은 브라우저 폭의 시각 회귀와 clean Windows 11 VM 재점검은 `IMP-055~062` Release Gate에서 다시 확인한다.

## 11. 사용자 PDF 관리자 결과·세부 레이아웃 후속 보완

### 관리자 점검 결과 누락 원인과 수정

- 결과 화면은 관리자 PC-02·04·06·08·10 결과를 일반 점검 카드에 병합했지만, PDF 생성 요청은 최초 일반 점검의 `ai_explanation_inputs`만 전달했다. 따라서 관리자 실측과 판정이 있어도 PDF에는 이전 `ERROR`와 “관리자 자료를 확인하지 못함”이 표시됐다.
- PDF 요청에 같은 표준 결과 ID의 `administrator_results`를 함께 전달한다.
- 서버는 관리자 허용 Control 5개, 필수 필드, Probe ID, 수집·판정 상태를 검증하고 실제값·기준·판정·제약을 반영한 뒤 규칙 결과 hash와 설명 입력 hash를 다시 계산한다.
- 관리자 병합 전 AI 설명은 입력 hash가 달라질 수 있으므로 PDF에 재사용하지 않는다. 공식 규칙 결과와 KISA 근거는 그대로 제공한다.

### 기존 PDF 보존과 재생성

- 잘못 생성된 기존 PDF와 snapshot은 수정·삭제하지 않는다.
- migration `0022_report_snapshots`는 같은 결과 ID·버전에서도 `snapshot_sha256`이 다른 수정 입력을 별도 append-only snapshot으로 보존한다.
- 보고서 버전은 snapshot별로 다시 1부터 시작하지 않고 동일 사용자·결과 ID·결과 버전·보고서 종류 전체에서 연속 배정한다.
- 실제 PostgreSQL 트랜잭션에서 서로 다른 snapshot 2개와 사용자 보고서 버전 `[1, 2]`를 확인한 뒤 전체를 rollback했다.

### 문단·표·출처 레이아웃

- 큰 상단 시험 판정 경고 배너는 제거하고 `판정 성격`을 메타데이터 상자에 넣었다.
- `점검 요약`, `AI 종합 설명`, `항목별 점검 결과`는 번호 배지와 제목 위·아래 여백을 두어 앞 표·문단과 붙지 않게 했다.
- AI 상태/종합 판단은 별도 정보 패널로 분리했다.
- 항목 본문은 라벨 셀과 값 셀을 구분하고 `다음 행동`은 연한 색으로만 구분했다.
- 카드가 페이지 하단에서 제목만 남지 않도록 제목과 확인값·기준·판정 이유 4개 핵심 행을 새 페이지로 함께 이동한다.
- 출처는 본문 표 밖의 얇은 구분선 아래에 본문보다 2pt 작은 회색 글씨로 `[출처]`, `[1] …`, `[2] …` 순서로 표시한다. 출처 배경색·표 테두리·강한 파란색 강조는 사용하지 않는다.

### 검증 결과

- 관리자·AI 설명·PDF 집중 Pytest: `35 passed` (기존 Starlette deprecation warning 1건)
- PDF 단독 회귀: `10 passed`
- Ruff: `All checks passed`
- mypy strict: `Success: no issues found in 6 source files`
- JavaScript syntax: `product-results.js` PASS
- migration: `0022_report_snapshots`, 고유키 `organization_id, owner_user_id, result_id, result_version, snapshot_sha256` 확인
- 실제 PostgreSQL rollback 검증: `distinct_snapshot_ids=true`, `variant_count=2`, `report_versions=[1,2]`, `rolled_back=true`
- MuPDF 시각 검증: 사용자 PDF 7쪽, 섹션 여백·AI 패널·무테두리 소형 출처·PC-02 관리자 실측값 표시 PASS
- Core Health: API `ok`, 모든 의존성 `ready`, API container `healthy`
- API image/container: `sha256:e2337a440edcfaa0441d0f3a504348acc0e6fab174a54567a445ce9cb0d3bc8d`

전체 Gate·clean Windows 11 VM 회귀는 기존 계획대로 `IMP-055~062` Release Gate에서 수행한다.

## 12. 기술 검증용 PDF 버튼 권한 복구

### 원인

- 결과 화면은 `/api/v1/result-reports/capabilities`의 `technical_report_allowed`가 `true`일 때만 기술 검증용 PDF 버튼을 활성화한다.
- 기술 PDF에는 비식별 정규화 증적과 수집 계보가 포함되므로 중앙 RBAC의 `EVIDENCE_DOWNLOAD` 권한을 요구하며, 이 권한은 `SECURITY_OFFICER` 역할에만 있다.
- 개발용 `local-owner`는 `ADMIN·USER`만 부여되어 있어 API가 정상적으로 `false`를 반환했고 버튼이 비활성화됐다.

### 수정

- 전역 RBAC와 일반 사용자 권한은 변경하지 않았다.
- `DEV-LOCAL` 전용 bootstrap이 `local-owner`에 `SECURITY_OFFICER` 역할을 함께 부여하며, 기존 할당이 없으면 추가하고 폐기된 할당이면 복원한다.
- 역할 변경 시 `role_assignment_version`을 증가시켜 기존 세션을 안전하게 무효화한다.
- 실제 제품 검증 스크립트는 canonical Host를 명시하고 로그인·MFA·capability·사용자 PDF·기술 PDF 생성과 attachment 다운로드를 검사한다.

### 검증

- 수정 전 TDD: DEV-LOCAL 보안 검증 담당자 역할 시험 `1 failed`
- 수정 후 집중 Pytest: 기술 PDF 시험과 deny-by-default RBAC 시험 `12 passed`
- Ruff: `All checks passed`
- mypy strict: `Success: no issues found in 10 source files`
- 실제 DB 역할: `ADMIN`, `SECURITY_OFFICER`, `USER`
- 실제 E2E: `technical_report_allowed=true`, 기술 PDF 생성 `201`, `secai-result-technical.pdf` attachment 다운로드 PASS
- CSRF 거부·IDOR 404·append-only 보고서 버전도 함께 PASS
- Core Health: 모든 의존성 `ready`, API container `healthy`
- API image/container: `sha256:66ea61ecd1463154e9af883a514c4e0fc827373db789ed0e8ebcd82d61684026`

역할 버전이 변경됐으므로 기존 브라우저 세션은 다시 로그인해야 한다. 이후 결과 화면을 새로 열면 기술 검증용 PDF 버튼이 활성화된다.

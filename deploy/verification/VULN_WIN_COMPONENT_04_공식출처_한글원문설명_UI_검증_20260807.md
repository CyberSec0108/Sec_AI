# Windows 취약점 공식 출처·한글 원문 설명 UI 검증

## 1. 검증 범위

- Windows 알려진 취약점 후보 카드의 출처 표시와 공식 원문 링크
- 공식 공개 원문을 사실 추가·삭제 없이 한국어로 옮기는 별도 모델 계약
- 기존 공통 안내인 `이 결과의 의미`, `다음 확인`, `확인된 대상`,
  `공개 자료 중요도`, `자료 제공` 제거
- 인증, Browser CSRF, 외부 입력 검증, 공식 Finding 불변
- 항목을 닫았다 다시 열 때 같은 DOM에서 번역 재호출 방지

## 2. 구현 결과

- 접힘 영역 이름을 `출처와 공식 취약점 설명`으로 변경했다.
- 펼친 영역에는 `자료 출처`, 원문 식별번호와 allowlist된 HTTPS 링크,
  `공식 취약점 설명(한글)`만 핵심 정보로 표시한다.
- NVD 자료는 `NIST NVD · CVE-...`, OSV 자료는 `OSV.dev · source record ID`로
  표시한다. NVD의 기존 `Microsoft Corporation` 표시는 자료 제공처와 제조사를 혼동하므로
  `NIST NVD`로 바로잡았다.
- 영문 원문 번역은 새 인증 API
  `POST /api/v1/vulnerability-check/official-description-ko`가 담당한다.
- 모델은 원문을 요약·해석하거나 조치 방법을 추가하지 않고
  `description_ko` 한 필드만 반환한다. 출력은 strict JSON, 길이, 한국어 포함 여부를
  검증한 뒤 Browser `textContent`로만 표시한다.
- 번역문은 원기관이 제공한 공식 한국어 번역이 아니라, 원기관의 공식 영문 자료를 SecAI가
  한국어로 옮긴 내용이라고 화면에 명시한다.
- 기존 `AI로 쉽게 설명`은 영향·공격 조건·조치·한계를 설명하는 별도 선택 기능으로 유지한다.

## 3. 실제 공개 예시 확인

OSV.dev `PYSEC-2026-163`의 공개 설명을 내부 모델 게이트웨이에 전달한 결과는 다음과 같다.

```text
Microsoft Semantic Kernel Python SDK에서 원격 코드 실행(RCE) 취약점이 확인되었습니다.
특히 InMemoryVectorStore 필터 기능 내에서 발생합니다.
이 문제는 python-1.39.4에서 수정되었습니다.
```

반환 계약은 `SOURCE_GROUNDED_KOREAN_TRANSLATION`,
`source_translation_official=false`, `official_finding_changed=false`였다.

## 4. 검증 결과

```text
pytest tests/unit/test_known_vulnerability_check.py \
       tests/unit/test_windows_component_vulnerability_check.py -q

26 passed
```

```text
ruff check apps/api/vulnerability_check.py \
  src/security_audit/application/vulnerability_ai_explanation.py \
  src/security_audit/application/known_vulnerability_check.py \
  tests/unit/test_known_vulnerability_check.py \
  tests/unit/test_windows_component_vulnerability_check.py

All checks passed!
```

```text
mypy --strict apps/api/vulnerability_check.py \
  src/security_audit/application/vulnerability_ai_explanation.py \
  src/security_audit/application/known_vulnerability_check.py

Success: no issues found in 3 source files
```

```text
node --check apps/web/static/app/vulnerability-check.js

PASS
```

```text
GET http://localhost:18480/static/app/vulnerability-check.js

HTTP 200
출처와 공식 취약점 설명=True
공식 취약점 설명(한글)=True
/api/v1/vulnerability-check/official-description-ko=True
```

```text
GET http://localhost:18480/health/ready

HTTP 200
status=ready
postgres=true, redis=true, aistor=true, clamav=true
```

## 5. 남은 경계

- 한국어 문장은 원기관의 공식 번역문이 아니며 모델이 만든 출처 기반 번역이다.
- 모델 연결이 끊기면 원문 출처와 링크는 남지만 새 한국어 번역은 생성되지 않는다.
- 현재 재호출 방지는 같은 화면에 렌더링된 카드 수명 동안만 적용된다. Browser 새로고침 뒤
  재사용하는 영구 번역 cache는 아직 없다.
- 공급자 확정 적용성, VEX, 검증된 수정 버전 계산과 공식 Finding 생성은 이 변경 범위가 아니다.
- 로그인된 전체 후보 화면에서 키보드·모바일·주야간 육안 Browser E2E는 별도 확인이 필요하다.

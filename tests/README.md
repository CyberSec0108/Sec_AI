# 테스트 구성 안내

이 폴더는 Sec_AI의 순수 로직, JSON 계약, 실제 서비스 연결과 브라우저 보안 동작을 검증합니다. 시험 자료는 합성 데이터만 사용하며 실제 사용자·조직·서버 정보나 secret을 넣지 않습니다.

## 폴더별 역할

| 위치 | 무엇을 확인하나요? | 외부 서비스 |
|---|---|---|
| `unit/` | 함수·서비스·repository 계약의 빠른 회귀 | 기본적으로 없음 또는 격리된 fake |
| `contract/` | Audit Pack, Fixture, Manifest와 JSON 계약 | 없음 |
| `fixtures/` | Package·Linux·Switch의 비식별 합성 입력 | 없음 |
| `browser/` | 제한 Markdown, DOM allowlist, XSS, 키보드·화면 동작 | Node 또는 실제 브라우저 |
| `integration/` | 여러 구성요소와 실제 인프라 연결 | 현재 공용 시험 파일 없음 |
| `e2e/` | 사용자 시작부터 결과까지 종단 흐름 | 현재 공용 시험 파일 없음 |

실제 PostgreSQL, Redis, API, Gateway 또는 VM이 필요한 시험은 `database/verification`, `tools/verify-*.ps1`과 `deploy/verification`의 단계별 절차로 관리합니다. `integration/`과 `e2e/`가 비어 있다는 이유로 실제 통합시험이 없는 것은 아닙니다.

## 기본 실행

잠긴 개발 container에서 단위·계약 시험을 실행합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action Test
```

이 명령은 현재 `tests/unit`과 `tests/contract`를 실행합니다. 전체 표준 Gate는 Schema, Ruff, mypy strict까지 포함합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action All
```

특정 파일만 빠르게 확인할 때는 잠긴 `dev-tools` container 안에서 pytest 경로를 지정하는 기존 검증 wrapper를 우선 사용합니다. 호스트 Python에 우연히 설치된 package를 기준으로 완료 판단하지 않습니다.

## 브라우저 시험

제한 Markdown의 Node 계약 시험은 Node 내장 모듈만 사용합니다.

```powershell
node .\tests\browser\restricted_markdown.node.test.cjs
```

`restricted_markdown.browser.html`과 `restricted_markdown.browser.test.js`는 실제 DOM, CSP/Trusted Types, XSS, 링크·출처 버튼과 키보드 동작을 확인하는 브라우저 자료입니다. 실제 Chrome 실행 절차와 결과는 [`../deploy/verification/MARKDOWN_01_03_제한형_렌더러_검증_20260802.md`](../deploy/verification/MARKDOWN_01_03_제한형_렌더러_검증_20260802.md)를 따릅니다.

## 시험 작성 원칙

- 하나의 시험은 하나의 명확한 동작을 검증합니다.
- 이름만 읽어도 입력 조건과 기대 결과를 알 수 있게 작성합니다.
- 로직 변경은 가능한 한 실패하는 회귀시험을 먼저 추가합니다.
- 시간, random, 네트워크, 파일 시스템과 외부 모델은 고정하거나 격리합니다.
- 실제 운영 서비스, 외부 AI, 인터넷 상태에 따라 흔들리는 시험을 기본 단위시험에 넣지 않습니다.
- 테스트를 통과시키기 위해 `skip`, `only`, 주석 처리 또는 약한 존재 검사로 바꾸지 않습니다.
- 이번 변경과 무관한 기존 실패를 숨기지 않고 별도로 기록합니다.

## Fixture 작성 원칙

- 실제 이름, 조직, IP, hostname, volume label, token, cookie와 파일 경로를 사용하지 않습니다.
- UUID, 시간, hash, 서명과 canonical JSON 조건을 실제 계약에 맞춥니다.
- 정상 사례만 만들지 않고 변조, replay, 권한 부족, timeout, 미지원, 경계 크기를 포함합니다.
- 수집 실패는 `FAIL`이 아니라 `ERROR` 또는 확인 필요 경계로 유지합니다.
- 공격 Fixture는 검증 실패 뒤 저장·정규화·Rule·Finding이 0건인지 확인합니다.
- Pack의 입력 Fixture와 기대 결과는 [`../audit_packs/README.md`](../audit_packs/README.md)의 버전 규칙을 따릅니다.

## 변경 유형별 필요한 시험

| 변경 | 최소 확인 |
|---|---|
| 순수 함수·표시 변환 | 관련 `unit/` |
| Schema·Pack·Manifest | `contract/` + Schema valid/invalid |
| Finding·멱등성 | canonical hash, 100회 결정론, 충돌 replay |
| DB migration·repository | 단위시험 + 실제 PostgreSQL verification |
| 인증·RBAC·CSRF·IDOR | 단위시험 + actual HTTP 통합시험 |
| Queue·Outbox | Worker kill·redelivery·중복 결과 0 |
| Collector·Probe | allowlist, timeout, 권한 분리, 설정 diff 0 |
| AI·SSE·Markdown | 계약, 중단·재시도, XSS, 근거·판정 불변 |
| Docker·환경 변수 | Compose config, image rebuild, Health |

## 관련 위치

- 전체 검증 진입점: [`../tools/README.md`](../tools/README.md)
- Schema validator: [`../database/README.md`](../database/README.md)
- 실행·배포 증적: [`../deploy/verification/`](../deploy/verification/)
- 프로젝트 품질 설정: [`../pyproject.toml`](../pyproject.toml)
- 현재 최신 검증 상태: [`../구현_현황.md`](../구현_현황.md)

## 완료 보고에 남길 내용

시험을 실행한 명령, 통과·실패 개수, 실행하지 못한 범위와 이유를 기록합니다. 실제 DB·VM·외부 모델처럼 환경이 필요한 시험은 “미실행”을 “통과”로 표시하지 않습니다.

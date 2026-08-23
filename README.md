# Sec_AI

Windows 11 PC·Linux 서버와 개발용 Aruba AOS-CX 시험 스위치의 보안 점검 자료를 읽기 전용으로 수집하고, 승인된 점검 기준 묶음(Audit Pack)으로 결과를 판정하며 AI가 근거와 조치를 설명하는 Sec_AI 프로젝트다.

| 항목           | 현재 기준                                                                                                                         |
| -------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| 프로젝트 루트  | 이 파일이 있는 디렉터리                                                                                                           |
| 현재 개발 대상 | Windows 11 PC-01~18·알려진 취약점 후보 점검, Ubuntu 24.04/Rocky 9 U-01~U-67, Aruba AOS-CX N-01~N-38 DRAFT, 전체 분류 가이드 질의 |
| 현재 단계      | Windows 제품 흐름 완료 후 Linux·복수 기준·BGE-M3/Reranker와 Aruba 실제 REST·전용 UI를 개발 환경에 부분 구현. 운영·Pilot·공식 Switch Pack 인수는 미완료 |
| 첫 구현 항목   | PC-07 세로 기능 조각                                                                                                              |
| 공식 판정 주체 | 승인된 점검 기준 묶음을 실행하는 규칙 엔진                                                                                        |
| 기준일         | 2026-08-07                                                                                                                        |

> 이 저장소에는 PC-01~18 개발 규칙과 Windows native Probe 20개가 있다. Windows x64 Collector의 빌드와 개발용 Authenticode 서명 기술시험은 통과했다. 그러나 현재 서명은 조직 인증서가 아닌 self-signed 개발 Publisher이므로 일반 PC가 신뢰하는 배포 서명이 아니다. 점검 기준 묶음과 제품 Adapter Catalog도 `DRAFT`이므로 운영 배포·Web 다운로드·공식 판정에는 사용할 수 없다.

> 현재 완료 상태와 잔여 Gate는 [`구현_현황.md`](구현_현황.md)를 정본으로 사용한다. Windows 계획은 [`다음_I_J_단계_계획.md`](docs/plans/다음_I_J_단계_계획.md), 전체 가이드 검색은 [`대화_RAG_제품_계획.md`](docs/plans/대화_RAG_제품_계획.md), 다중 장비·안전한 표시·승인형 조치는 부분 구현 ADR 19와 [`플랫폼_확장_및_보조_조치_계획.md`](docs/plans/플랫폼_확장_및_보조_조치_계획.md), 복수 기준은 부분 구현 ADR 20과 [`사용자_정의_점검기준_안내.md`](docs/guides/사용자_정의_점검기준_안내.md)를 따른다. OpenRouter 시험 대역과 최종 로컬 vLLM 경계는 ADR 17, 결과 중심 AI는 ADR 18을 따른다. 다른 Codex 세션은 루트 [`AGENTS.md`](AGENTS.md)를 먼저 적용한다.

> 사용자용 첫 화면은 [`http://localhost:18480`](http://localhost:18480)이다. 현재는 로그인과 개발용 두 번째 인증을 통과해야 화면을 볼 수 있다. Windows 개발 실행 파일은 일반 권한 점검을 한 번의 확인으로 시작하지만 아직 운영 서명·다운로드 대상이 아니다. 이 PC는 깨끗한 시험용 VM이 아니며, 결과는 개발 검증일 뿐 운영 배포나 공식 보안 판정이 아니다.

> 현재 Windows EXE는 설치 프로그램이 아니므로 브라우저가 자동으로 찾아 실행할 수 없다. 결과 화면에서 Launcher가 연결되지 않으면 `점검 프로그램 다운로드`, `다운로드한 파일 여는 방법`, `연결 다시 확인`, `원클릭 점검으로 돌아가기`를 제공한다. EXE가 연 새 탭의 token handoff는 기존 결과 탭에도 2분 제한으로 전달하지만 점검 동의가 만료됐으면 자동 실행하지 않고 동의를 다시 확인한다. 이 보완은 설치형 전환이 아니며 상단 제목줄에 다운로드 텍스트 메뉴를 추가하지 않는다. 상세는 [`Windows Launcher 미연결 복구 UI 검증`](deploy/verification/WINDOWS_LAUNCHER_미연결_복구_UI_검증_20260807.md)을 따른다.

> 홈의 `알려진 취약점 점검`은 Windows를 먼저 지원한다. 최신 Windows 실행 파일은 OS·KB·registry 프로그램·AppX·Python·Node.js·Java 구성요소의 비식별 이름·버전을 고정 read-only 원천에서 수집한다. 선택한 requirements/lock 파일은 Browser가 로컬에서 이름·버전만 추출한다. 중앙 서버는 Windows exact CPE를 NVD와, PyPI/npm/Maven exact version을 OSV와 비교한다. 결과는 영향 가능 구성요소 수와 공개 취약점 참고자료 수를 분리하고, 같은 라이브러리 후보를 한 카드로 묶어 Windows·Python·Node.js·Java 필터와 검색으로 확인한다. 각 후보의 `공식 자료 기반 한글 설명`은 AI 없이 열 수 있으며 AI는 선택형 보충 설명이다. AI 연결 실패·시간 초과는 한국어 안내와 재시도로 처리하고 기존 후보·판정을 바꾸지 않는다. 이 한글 설명은 공식 번역이나 제조사 확정 판정이 아니다. CVE/GHSA/PYSEC alias는 확인 가능한 범위에서 대표 CVE와 다른 식별번호로 정리하며 자동 비교 제외는 제품 매핑·Windows 업데이트 증적·자료 오류 사유로 나눈다. 후보 0건도 `안전`을 뜻하지 않는다. 외부 통신 장애 때는 마지막 정상 DB snapshot을 현재/오래됨/만료로 구분해 재사용한다. 일반 프로그램의 검토된 CPE, Microsoft 권고 확정 판정, 생태계별 수정 버전 계산, 서명 Offline Feed Bundle, Linux·Switch 확대는 아직 남아 있다.

> 2026-08-02 `MARKDOWN-01~03`에서 제목·문단·목록·표·강조·inline code·안전한 링크만 허용하는 제한형 AST renderer를 적용했다. 2026-08-05 현재 `secai.result-knowledge.v2`의 AI 설명 직접 출처는 `[1] 실제 확인값`, `[2] KISA 근거`, `[3] AI 일반 보안지식` 순서이며 인용은 관련 문장의 뒤에 붙인다. 공식 규칙은 결과 판정 권한으로 별도 표시하고 AI 설명과 AI 출처에서는 제외한다. 항목 설명은 `1. 왜 중요한가요?`부터 `4. 용어 간단 설명`까지 번호형으로 구성하며 완료·취소·실패 뒤 생성 커서를 제거한다. 전체 출처 등급 E1/R1/G1/G2/G3/A1은 내부 지식 계약에 보존되지만 현재 AI 설명에 직접 노출하는 것은 E1/G1/A1 세 종류다. renderer는 실패하거나 100KB를 넘으면 일반 텍스트로 안전하게 전환하고 raw HTML·image·실행 코드와 위험 URL은 DOM으로 만들지 않는다. 과거 v1 기준 검증은 [`KNOWLEDGE_01_03_지식_출처_분리_검증_20260802.md`](deploy/verification/KNOWLEDGE_01_03_지식_출처_분리_검증_20260802.md), 현재 화면 정합성은 [`Linux_Windows_결과_AI_정합성_검증_20260805.md`](deploy/verification/Linux_Windows_결과_AI_정합성_검증_20260805.md)를 따른다.

> 2026-08-07부터 완료된 Windows 결과·공식 표시 설명·AI 입력은 비식별 append-only PostgreSQL snapshot으로 저장하고, 늦게 도착하는 관리자 결과와 AI 완성 화면은 별도 presentation version으로 추가한다. Linux·Switch 새 결과도 공식 설명·AI 입력을 결과 hash에 고정하며 기존 owner-scoped AI output cache와 함께 상단 `점검 결과`에서 복원한다. API와 PostgreSQL RLS가 organization·owner user를 함께 고정하므로 같은 조직이어도 다른 로그인 아이디의 결과는 볼 수 없다. 보존 정책은 새 version만 추가하며 기본 365일·Backup 필수·`HOLD`다. 운영 Backup·복구 승인·보존 만료 tombstone 실행은 아직 별도 Gate이며 화면이나 API에서 물리 삭제하지 않는다. 사용법과 경계는 [`통합 점검 이력·보존 안내`](docs/guides/통합_점검_이력_보존_안내.md)를 따른다.

> 최신 검색은 기존 32차원 `secai-ko-lexical-hash-v1` generation을 rollback 경로로 보존하면서 BGE-M3 1024차원 embedding과 `bge-reranker-v2-m3`를 `BGE_M3_WITH_LEGACY_FALLBACK` mode로 사용한다. 모델은 전용 Docker volume에 cache되며 PostgreSQL+pgvector에 두 세대를 병렬 보존한다. 정식 recall·MRR·인용 정확도·p95 승인은 아직 남아 있다. 2026-08-03 기반 상태는 [`현재_상태_문서_동기화_20260803.md`](deploy/verification/현재_상태_문서_동기화_20260803.md), 2026-08-05 Linux·Windows UI/AI와 Linux 시작 오류 보정은 [`Linux_Windows_결과_AI_정합성_검증_20260805.md`](deploy/verification/Linux_Windows_결과_AI_정합성_검증_20260805.md), Windows 실제 수집·판정·AI 최신 상태는 [`WINDOWS_관리자_5개_수집_판정_AI_가이드_출처_정합성_20260805.md`](deploy/verification/WINDOWS_관리자_5개_수집_판정_AI_가이드_출처_정합성_20260805.md)를 따른다.

> Linux 개발 화면은 Ubuntu 24.04와 Rocky Linux 9에서 U-01~U-67 진행 항목을 Windows와 같은 방식으로 보여주고, 결과 카드 안에 실제 확인값·KISA 기준·판정 이유·다음 행동·AI 설명·출처를 통합한다. KISA·SecAI 안전 기본값은 비어 있지 않게 적용되며 사용자는 숫자·승인 계정·허용 포트·승인 SUID 경로만 수정하거나 초기화할 수 있다. 실행 시점 기준 snapshot과 SHA-256을 결과에 남기며 raw command·정규식·스크립트 입력은 받지 않는다. 내부 `REVIEW`는 보존하되 사용자 화면에서는 `확인 필요`에 합쳐 별도 `기준 확인 필요` 분류를 만들지 않는다. `/etc/os-release` 사전 확인은 일시 수집 실패를 실제 배포판 불일치와 구분하고 최대 2회 시도하며, 실패 뒤 새로고침 없이 다시 시작할 수 있다.

> Aruba 개발 화면은 서버에 등록된 AOS-CX 10.13.1170 시험 장비만 선택하고 REST 사용자 이름·비밀번호로 KISA 네트워크 N-01~N-38을 실행한다. 인증서가 고정된 18개 GET으로 구조화 설정과 system status·사용자·hot patch·event log를 읽고, 구조화 API에서 빠진 배너는 running-config를 실행 중 메모리에서만 확인한다. 비밀번호·cookie·배너/구성 원문·전체 running-config는 결과에 저장하지 않으며 비식별 사실만 projection에 남긴다. 안전 기본 판정 기준 26개와 장비 밖 증적인 N-12 권고 검토 이력·N-17 SNMP 업무 승인 2개를 닫힌 선택지로 수정·초기화하고 실행 snapshot/hash에 고정한다. 결과 카드는 Windows·Linux와 같은 네 필드와 AI 상세 설명·출처 순서를 사용하며 사용자용·권한 제한 기술 검증용 DRAFT PDF를 제공한다. AI는 사용자 버튼 승인 뒤에만 비식별 문맥을 모델 게이트웨이로 보내며 `[1] 실제 확인값`, `[2] KISA 2026 원문·개발용 AOS-CX 판정 매핑`, `[3] AI 일반 보안지식`을 구분한다. `/ui/switch-scan`의 `LIVE`는 DEV-LOCAL 실제 기능을 뜻하며 현재 결과는 `0.4.0-DRAFT`다. 공식 Finding·서명 Pack·실제 외부 모델 AI E2E·Cisco 교차 인수는 미완료다.

## 1. 먼저 읽을 문서

개발 경험이 없거나 기술 용어가 익숙하지 않다면 먼저 [`초보자_사용_안내.md`](docs/guides/초보자_사용_안내.md)를 읽는다. 보안검진센터 비유, 전체 처리 흐름, 자주 묻는 질문과 용어 사전으로 프로젝트를 설명한다.

처음 참여하는 개발자는 다음 순서로 읽는다.

1. [`구현_현황.md`](구현_현황.md): 현재 완료 상태, 다음 작업과 전체 잔여 체크리스트
2. 이 `README.md`: 현재 저장소 구성과 사용 기준
3. [`docs/README.md`](docs/README.md): 모든 Markdown 문서를 역할별로 찾는 통합 목차
4. [`docs/guides/초보자_사용_안내.md`](docs/guides/초보자_사용_안내.md): 비개발자용 쉬운 프로젝트 설명
5. [`docs/adr/README.md`](docs/adr/README.md): 의사결정 문서 목록, 우선순위와 SHA-256 기준선
6. [`docs/plans/README.md`](docs/plans/README.md): 현재·후속 제품 계획과 제출 준비
7. [`docs/maintenance/유지보수_가이드.md`](docs/maintenance/유지보수_가이드.md): 변경 유형별 파일·보안 경계·검증·장애 대응
8. [`docs/maintenance/프로젝트_구조_및_파일_기능_카탈로그.md`](docs/maintenance/프로젝트_구조_및_파일_기능_카탈로그.md): 폴더·파일별 기능과 주요 정의
9. 담당 작업과 직접 관련된 ADR·계획·검증 문서

문서가 충돌하면 승인된 번호 문서의 구체적인 결정을 우선한다. 단, `승인 대기` 문서는 승인 전까지 기준안이며 자동으로 상위 기획 문서를 대체하지 않는다.

## 2. 현재 폴더 구조

```text
<project-root>\
├─ AGENTS.md
├─ 구현_현황.md
├─ README.md
├─ 보안_정책.md
├─ apps\                    # API·Web·Worker·Scheduler·Model Gateway
├─ audit_packs\             # Windows·UNIX DRAFT Pack·Fixture·Catalog
├─ collectors\one_shot\    # Windows 읽기 전용 one-shot Collector
├─ data\                    # 승인된 KISA 가이드 원문
├─ database\
│  ├─ alembic\              # 순차 migration; 기존 revision 수정 금지
│  ├─ schemas\              # JSON Schema·valid/invalid 예제
│  └─ verification\         # DB·계약 검증 도구
├─ deploy\
│  ├─ compose\              # Core·DEV·검색·복구 Compose
│  ├─ docker\               # 구성요소별 잠긴 Dockerfile
│  ├─ locks\                # 공급망 digest 기준선
│  ├─ verification\         # IMP·PRODUCT-AI 실행·검증 이력
│  └─ vmware\               # Linux 시험 VM 자동화
├─ docs\
│  ├─ README.md
│  ├─ adr\                 # ADR 1~20과 승인·hash index
│  ├─ guides\              # 사용자·설치·내부망 운영 안내
│  ├─ maintenance\         # 유지보수 절차와 파일 기능 카탈로그
│  └─ plans\               # 현재·후속·확장·제출 계획
├─ guides\                  # 검색용 Catalog·page/control mapping
├─ portable\                # source/image 이전·무결성 검증
├─ requirements\            # 직접 의존성·플랫폼별 hash lock
├─ src\security_audit\      # 도메인·application·분석·플랫폼 Core
├─ tests\                   # unit·contract·integration·e2e·browser
└─ tools\                   # 개발·검증·build·이전 자동화
```

이 트리는 유지보수 책임을 보여주는 요약입니다. 전체 폴더와 파일별 기능·주요 class/function·변경 주의는 자동 생성된 [`프로젝트 구조·파일 기능 카탈로그`](docs/maintenance/프로젝트_구조_및_파일_기능_카탈로그.md)를 사용합니다. Runtime·VM·secret·cache는 카탈로그에서 의도적으로 제외합니다.

## 3. 루트 파일

| 파일               | 용도                                                                        |
| ------------------ | --------------------------------------------------------------------------- |
| `README.md`      | 프로젝트 진입점. 현재 구조, 문서 탐색 순서와 파일 관리 원칙을 설명한다.     |
| `AGENTS.md`      | 코드 에이전트가 작업 전에 지켜야 할 규칙과 필수 읽기 순서다.                |
| `구현_현황.md`   | 현재 완료 상태와 다음 실행 작업의 단일 인계 지점이다.                       |
| `보안_정책.md`   | 취약점 신고, 비밀정보·실제 증적 취급과 지원 기준을 설명한다.               |
| `docs/README.md` | ADR·계획·사용자 안내·검증 기록·구성요소 README를 찾는 통합 문서 목차다. |
| `pyproject.toml` | Python package metadata와 pytest·Ruff·mypy·coverage 품질 기준이다.       |
| `.env.example`   | 비밀값 없이 환경변수 이름과 안전한 DEV 기본값만 제공한다.                   |

루트에는 프로젝트 전체에서 가장 먼저 읽어야 하는 문서만 둔다. 나머지 사람이 읽는 설계·계획·안내 문서는 `docs/`에서 찾고, 구성요소 README와 검증 기록은 코드·증적과 함께 해당 디렉터리에 둔다.

## 4. `docs/adr/`: 1차 개발 의사결정 기준선

ADR은 **Architecture Decision Record**의 약자로, 중요한 기술·보안 결정을 선택 이유, 대안, 영향과 승인 기록과 함께 남기는 문서다.

|  번호 | 파일                                         | 구성 용도                                                                                                                              |
| ----: | -------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
|     1 | `1.MVP_범위.md`                            | 첫 OS, PC-01~PC-18, MVP 포함·제외 범위를 고정한다.                                                                                    |
|     2 | `2.MVP_점검항목_매트릭스.md`               | 항목별 원문 위치, 중요도, 적용성, 자동화 유형, 권한과 증적 요구사항을 연결한다.                                                        |
|     3 | `3.ADR_Python_실행환경.md`                 | 서비스·Collector의 Python Runtime과 지원 플랫폼 원칙을 결정한다.                                                                      |
|     4 | `4.컨테이너_이미지_잠금.md`                | 외부·자체 build container image의 tag, digest, 검증 및 반입 Gate를 정의한다.                                                          |
|     5 | `5.ADR_수집기.md`                          | Windows One-shot Collector, Probe allowlist, 권한·서명·제출 경계를 정의한다.                                                         |
|     6 | `6.ADR_웹_UI.md`                           | FastAPI Static/Jinja2와 로컬 HTMX 기반 UI 및 Browser 보안 기준을 정한다.                                                               |
|     7 | `7.ADR_대기열.md`                          | Celery·Redis, Outbox, 멱등성, 재시도와 Queue 신뢰 경계를 정한다.                                                                      |
|     8 | `8.데이터베이스_스키마.md`                 | JSON Schema 데이터 계약, version, canonicalization과 검증 Gate를 설명한다.                                                             |
|     9 | `9.증적_저장_보존_정책.md`                 | AIStor 원본 증적의 저장, 잠금, 보존, 파기, backup·restore 정책을 정의한다.                                                            |
|    10 | `10.ADR_공식_판정_권한.md`                 | AI가 아닌 Audit Pack 규칙 엔진만 공식 판정을 생성하도록 권한 경계를 고정한다.                                                          |
|    11 | `11.RBAC_권한_매트릭스.md`                 | 사용자·보안담당자·승인자·관리자와 service identity의 권한 및 업무분리를 정의한다.                                                   |
|    12 | `12.ADR_인증.md`                           | 초기 Local 계정, MFA/WebAuthn, session·CSRF와 향후 OIDC 전환 기준을 정의한다.                                                         |
|    13 | `13.MVP_구현_시작_계획.md`                 | R0~R5 구현 순서, PC-07 세로 기능과 완료 Gate를 정의한다.                                                                               |
|    14 | `14.ADR_보안_시험.md`                      | 보안시험 종류, 결과 해석, 영역별 공격시험과 Release 승인 기준을 정의한다.                                                              |
|    15 | `15.ADR_확장형_증적_점검팩_AI_거버넌스.md` | Windows 우선 canonical fact·Adapter/Mapping registry, Guide/Audit Pack 승인 분리, LLM DRAFT 작성 보조와 다중 OS 후속 경계를 정의한다. |
| Index | `README.md`                                | 문서 탐색, 기준 우선순위, 변경관리와 번호 문서 SHA-256을 제공한다.                                                                     |

### 문서 상태 해석

- `승인 대기`: 설계 초안은 완성됐지만 책임자의 승인 기록이 필요한 상태
- `승인`: 구현 기준선으로 사용할 수 있는 상태
- 승인 후 의미 변경: 관련 ADR version 증가, 영향 분석과 재승인 필요
- Runtime, 인증, 공식 판정, 증적 보존 정책 변경: 연관 문서를 함께 검토

## 5. `database/schemas/`: 기계 판독 데이터 계약

Collector, API, 검증·정규화 Worker, Audit Pack 규칙 엔진, AI 설명기와 UI 사이에서 교환하는 JSON의 형식과 의미를 고정한다. PostgreSQL DDL이나 migration을 보관하는 위치는 아니다.

| 파일 또는 폴더                      | 생산자 → 소비자 / 용도                                                                               |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `README.md`                       | Draft 2020-12, RFC 8785 JCS, version·서명·상태 경계와 검증 방법을 설명한다.                         |
| `schema-catalog.json`             | 허용된 8개 Schema 파일과`$id`를 등록한다. Runtime의 임의 remote `$ref` 사용을 막는 기준 목록이다. |
| `common.schema.json`              | 모든 문서가 공유하는 ID, 시간, hash, 상태와 오류 vocabulary를 제공한다.                               |
| `collector_manifest.schema.json`  | API → Collector 실행 허가, 대상, Probe allowlist와 제출 profile이다.                                 |
| `audit_package.schema.json`       | Collector → API/검증 Worker archive descriptor, file inventory와 원시 수집 record다.                 |
| `normalized_evidence.schema.json` | 정규화 Worker → 규칙 엔진의 검증 완료 공통 증적이다.                                                 |
| `finding.schema.json`             | 규칙 엔진 → API/UI/AI의 공식`PASS/FAIL/REVIEW/ERROR/N/A` 판정 결과다.                              |
| `audit_pack.schema.json`          | 승인된 규칙 build → 규칙 엔진의 항목·증적·규칙·근거 정의다.                                       |
| `ai_explanation.schema.json`      | AI Worker → API/UI의 선택적 설명이다. 공식 Finding을 변경할 수 없다.                                 |
| `remediation_plan.schema.json`    | 승인 workflow → API/UI의`PLAN_ONLY` 조치 초안이다. 1차 MVP에서는 실행할 수 없다.                   |
| `examples/valid/`                 | 각 주요 Schema가 반드시 받아들여야 하는 정상 example이다.                                             |
| `examples/invalid/`               | 각 주요 Schema가 반드시 거부해야 하는 오류·공격 example이다.                                         |
| `examples/index.json`             | example과 대상 Schema, 예상 검증 결과를 연결한다.                                                     |
| `validate_examples.py`            | Schema 자체 검사, valid 통과, invalid 거부와 일부 교차 field 규칙을 검사한다.                         |

데이터 흐름은 다음과 같다.

```text
collector_manifest
  → Windows Collector
  → audit_package + payload.zip
  → 무결성·인증·archive 검증
  → normalized_evidence
  → 승인된 audit_pack 규칙 평가
  → finding
  ├─→ ai_explanation       선택 사항, 판정 변경 금지
  └─→ remediation_plan     1차 MVP는 PLAN_ONLY
```

향후 확장은 현재 Windows 계약을 먼저 안정화한 뒤 다음 방향으로 진행한다.

```text
Windows 원본 Probe·제품 Adapter
→ versioned Evidence Mapping
→ canonical security fact
→ exact Audit Pack rule
→ finding

Guide Catalog APPROVED
→ 검색·인용 가능
→ Control Source Mapping DRAFT
→ Fixture·결정론·서명·별도 승인
→ Audit Pack APPROVED
```

Guide Catalog 승인은 공식 Audit Pack 승인이 아니다. LLM은 mapping·rule·Fixture의 내부 `DRAFT` 제안을 만들 수 있지만, 공식 Finding 생성·Pack 승인·서명·활성화 권한을 갖지 않는다. 다중 OS는 현재 단계에서 구현하지 않고 Pilot 이후 별도 ADR 승인 후 진행한다.

Schema example 검증은 프로젝트 루트에서 다음과 같이 실행한다.

```powershell
.\tools\dev.ps1 -Action Schema
```

Schema 통과만으로 증적을 신뢰하지 않는다. 인증, nonce 재사용, manifest 만료·scope, archive/file hash, 서명과 Audit Pack 승인 상태는 application integration 계층에서 별도로 확인해야 한다.

## 6. `requirements/`: Python 의존성 입력과 해시 잠금

사람이 관리하는 직접 의존성 입력과 `pip-tools`로 생성한 플랫폼별 해시 잠금파일을 분리한다.

### 직접 의존성 입력

| 파일                   | 용도                                                                |
| ---------------------- | ------------------------------------------------------------------- |
| `base.in`            | 여러 Python 서비스가 공유하는 공통 직접 의존성                      |
| `constraints.in`     | 서비스 간 공통 package version 제약                                 |
| `api.in`             | FastAPI API와 Server-rendered UI 의존성                             |
| `worker.in`          | Celery Worker/Beat와 LangGraph workflow 의존성                      |
| `ingestion.in`       | 가이드 문서 parsing·ingestion과 후속 vector 적재 의존성            |
| `collector.in`       | Windows Collector Runtime 의존성                                    |
| `collector-build.in` | PyInstaller 기반 Collector build 의존성                             |
| `dev.in`             | pytest, Ruff, mypy, pip-audit 등 개발·CI 도구                      |
| `build-tools.in`     | pip, setuptools, wheel과 pip-tools build 도구                       |
| `remediation.in`     | 후속 자동조치 기능의 자리만 예약한다. 승인 전 lock을 만들지 않는다. |

### 잠금·검증 파일

| 파일 또는 폴더                    | 용도                                                                                       |
| --------------------------------- | ------------------------------------------------------------------------------------------ |
| `lock/api.lock`                 | Linux amd64 API/UI 설치용 해시 잠금                                                        |
| `lock/worker.lock`              | Linux amd64 Worker/Beat 설치용 해시 잠금                                                   |
| `lock/ingestion.lock`           | Linux amd64 ingestion 설치용 해시 잠금                                                     |
| `lock/collector.lock`           | Windows amd64 Collector Runtime 설치용 해시 잠금                                           |
| `lock/collector-build.lock`     | Windows amd64 PyInstaller build 환경 잠금                                                  |
| `lock/dev.lock`                 | Linux amd64 개발·CI 환경 잠금                                                             |
| `lock/build-tools-linux.lock`   | Linux dependency-builder 도구 잠금                                                         |
| `lock/build-tools-windows.lock` | Windows Collector builder 도구 잠금                                                        |
| `잠금_메타데이터.md`            | Python·resolver version, 생성 환경·명령, 주요 version, 검증 결과와 보류 범위를 기록한다. |
| `LOCK-SHA256SUMS.txt`           | lock 산출물 자체의 SHA-256 기준선이다.                                                     |
| `verification/*.json`           | clean install, import와 공통 version 확인 결과를 기계 판독 형태로 기록한다.                |
| `README.md`                     | lock 생성·설치·변경 규칙을 설명한다.                                                     |

운영·build 설치에는 `*.in`이 아니라 해당 플랫폼의 `lock/*.lock`만 사용한다. 다음 명령은 host에서 직접 실행하는 개발 절차가 아니라 Dockerfile·잠긴 builder 내부 설치 기준이다.

```powershell
python -m pip install --require-hashes --no-compile -r requirements\lock\<target>.lock
python -m pip check
```

Lock 파일의 version이나 hash를 직접 수정하지 않는다. `*.in` 또는 `constraints.in`을 변경하고 동일 Runtime·플랫폼의 승인된 builder에서 전체 lock을 다시 생성한다.

## 7. `deploy/locks/`: Container 공급망 기준선

`deploy/locks/container-images.lock.yml`은 container를 mutable tag가 아니라 `linux/amd64` platform digest로 배포하기 위한 기계 판독 잠금표다.

현재 다음 범주를 구분한다.

- `LOCKED`: Python base, Nginx gateway, PostgreSQL 18.4+pgvector 0.8.2, ClamAV
- `LOCKED-RSALV2-INTERNAL`: Redis 8은 RSALv2로 조직 내부 Celery Broker에만 사용
- `LOCKED-MVP-FREE`: MinIO AIStor Free 최신 Stable 단일 node MVP 구성. Free license 수락, SBOM·취약점·출처·Object Lock·backup/restore Gate 필요
- `PENDING-BUILD`: `audit-api`, `audit-worker`, `audit-scheduler` 자체 image는 source와 Dockerfile이 생긴 후 build·scan·digest 잠금
- `NOT_SELECTED`: Milvus·PyMilvus·Attu·Milvus용 etcd/object store는 PostgreSQL+pgvector로 대체
- `PREPARED-NOT-ACTIVE`: NVIDIA GPU용 vLLM image와 host port 없는 중지 container는 준비했지만 취약점 Gate·GPU·승인 모델 부재로 추론은 차단
- `DEFERRED`: Neo4j, Wazuh, 자동조치와 관측 제품은 1차 Core MVP 범위 밖

`latest` tag나 tag-only 참조를 Compose·Dockerfile·배포 manifest에 사용하지 않는다. 제품 또는 image version을 변경하면 호환성 시험, license·SBOM·취약점 검토와 digest 재승인이 필요하다.

## 8. 현재 준비 상태와 아직 없는 구성

### 준비된 항목

- Windows 11 PC-01~PC-18 MVP 범위와 Control Matrix
- Python Runtime, Collector, Web UI와 Queue ADR
- 공식 판정 권한, RBAC와 인증 설계
- 원본 증적 저장·보존 정책
- JSON Schema 8종과 valid/invalid example
- Python service·플랫폼별 hash lock
- 외부 container image platform digest 잠금표
- PC-07부터 시작하는 단계별 구현 Backlog

### 1단계에서 생성된 구현 골격

```text
apps\                    API·Worker·Scheduler package 경계
src\security_audit\      domain·application·분석·보안·PostgreSQL persistence 경계
audit_packs\             PC별 규칙·Fixture·승인 build 위치
deploy\docker\           잠긴 Docker 개발 image
deploy\compose\          이동 가능한 Docker Compose 개발환경
tests\                    unit·contract·integration·E2E 경계
tools\                    Docker 품질검사와 이동 묶음 생성도구
portable\                 다른 PC 가져오기 도구와 image 목록
```

이 단계의 `__init__.py`와 `.gitkeep`은 책임 경계를 고정하기 위한 최소 뼈대다. 실제 업무 코드는 PC-07 Schema Gate·Audit Pack·Fixture 순서로 추가한다. 경로를 변경하면 이 README와 실행계획서를 함께 갱신한다.

### IMP-018 PostgreSQL Finding 저장 계약

Alembic `0001_imp018`은 최소 organization·asset·job scope, append-only `finding_versions`, 별도 `finding_current` projection을 생성한다. `rule_result.input_sha256` named unique constraint와 `INSERT ... ON CONFLICT DO NOTHING`으로 Worker race의 최종 중복 방지를 PostgreSQL에 위임한다. 동일 fingerprint는 기존 Finding을 반환하고 다른 output/ID는 거부한다. 상세 검증은 [`deploy/verification/IMP018_PostgreSQL_판정결과_영속성_검증.md`](deploy/verification/IMP018_PostgreSQL_판정결과_영속성_검증.md)를 따른다.

### IMP-019 localhost Web application E2E

DEV Compose를 실행하면 [http://localhost:18480](http://localhost:18480)에서 PC-07 합성 PASS·FAIL·Probe ERROR Package 실행 결과와 저장된 Finding 상세를 확인할 수 있다. UI와 JSON API는 같은 application service를 사용하며 동일 입력 재실행은 새 row 대신 `RETURN_EXISTING`을 반환한다. 외부 공개는 `127.0.0.1:18480` 하나로 제한하고 PostgreSQL·Redis·AIStor·ClamAV는 host에 publish하지 않는다. `18443`은 향후 DEV TLS용 예약 포트이며 현재 listener를 열지 않는다. 상세 검증은 [`deploy/verification/IMP019_응용_웹_종단간_검증.md`](deploy/verification/IMP019_응용_웹_종단간_검증.md)를 따른다.

화면의 주 표기는 KISA 가이드의 `PC-07 파일 시스템이 NTFS 포맷으로 설정`과 `양호·취약·확인 필요`를 사용한다. `PASS`, `FAIL`, `ERROR`, 결과 코드와 SHA-256 같은 기술값은 괄호 안의 작은 보조표기 또는 접힌 기술 정보 영역에 둔다.

### IMP-020 시연 안정화·Gap Review

`tools/demo.ps1` 한 명령으로 PASS·FAIL·Probe ERROR, archive hash 변조 거부, 동일 Package replay, 실DB row 수와 상세 근거를 검증한다. Gateway는 Docker runtime DNS를 사용하므로 API 컨테이너만 교체해도 Gateway 재시작 없이 자동 복구한다. 단계 G는 테스트 데이터로 기능을 확대할 수 있지만 실제 PC 자료 수집과 운영 적용은 아직 금지한다. 상세 결과는 [`deploy/verification/IMP020_시연_차이점_검토.md`](deploy/verification/IMP020_시연_차이점_검토.md)를 따른다.

### IMP-021 계정·비밀번호 설정 테스트

PC-01 비밀번호 변경 주기, PC-02 안전한 비밀번호 사용 기준과 PC-03 복구 기능의 자동 관리자 로그인 차단 규칙은 보존한다. 과거 독립 시연 화면은 2026-08-06 제거했으며, 현재 재검증은 규칙·Fixture 시험과 `deploy/verification/IMP021_계정_정책_검증.md`를 사용한다.

테스트 사례는 양호 3개, 취약 3개, 설정 수집 실패 3개와 조직 기준 미등록 1개로 구성된다. 실제 PC·사용자·조직 자료는 사용하지 않는다. 자세한 결과는 [`deploy/verification/IMP021_계정_정책_검증.md`](deploy/verification/IMP021_계정_정책_검증.md)를 따른다.

### IMP-022 서비스와 사용 환경 설정 테스트

PC-04 공유 권한, PC-05 불필요 서비스, PC-06 금지 메신저, PC-08 여러 운영체제와 PC-09 IE 계열 임시 파일 설정 규칙은 보존한다. 과거 독립 시연 화면은 제거했으며, 현재 재검증은 규칙·Fixture 시험과 `deploy/verification/IMP022_서비스_관리_검증.md`를 사용한다.

신규 합성 사례는 20개다. PC-04~06은 PC 상태와 조직의 허용·금지 기준을 함께 비교하며 기준이 없으면 `REVIEW`다. PC-08은 복구·진단·가상화 항목을 멀티부팅 OS 수에서 제외한다. PC-09는 IE 데스크톱·IE 모드·WinINet 사용 범위를 확인하고, 모두 사용하지 않는다는 범위 확인이 있어야만 `N/A`다. 자세한 결과는 [`deploy/verification/IMP022_서비스_관리_검증.md`](deploy/verification/IMP022_서비스_관리_검증.md)를 따른다.

### IMP-023 패치와 Windows 지원 수명 테스트

PC-10 보안 패치와 PC-11 Windows 지원 수명 규칙 및 개인정보가 없는 합성 사례 12개는 보존한다. 과거 독립 시연 화면은 제거했으며, 현재 재검증은 `deploy/verification/IMP023_패치_수명주기_검증.md`를 사용한다.

PC-10은 `Get-HotFix` 목록 하나만으로 양호 판정하지 않고 승인 패치 기준·운영체제 Build·자동 업데이트·최근 점검·재시작 대기·내부 관리 절차를 함께 본다. PC-11은 같은 23H2라도 Home/Pro와 Enterprise/Education의 지원 종료일이 다름을 구분한다. 일부 장비에만 필요한 선택적 긴급 업데이트는 모든 PC의 일반 필수 패치로 확대하지 않는다. 자세한 결과는 [`deploy/verification/IMP023_패치_수명주기_검증.md`](deploy/verification/IMP023_패치_수명주기_검증.md)를 따른다.

### IMP-024 로그인·백신·방화벽 테스트

PC-12 자동 로그인, PC-13 백신 설치·업데이트, PC-14 실시간 감시와 PC-15 방화벽 보호 규칙 및 합성 사례 18개는 보존한다. 과거 독립 시연 화면은 제거했으며, 현재 재검증은 `deploy/verification/IMP024_단말_보호_검증.md`를 사용한다.

PC-12는 Winlogon의 자동 로그인 상태와 암호값의 존재 여부만 확인하며 암호 내용은 수집하지 않는다. PC-13~15는 정확한 Adapter ID·version과 필드 범위가 일치할 때만 자동 판정한다. Defender 수동 모드, 미지원 타사 제품과 기관 최신성 기준 누락은 추측하지 않고 `REVIEW`다. PC-15는 `ActiveStore`의 Domain·Private·Public 유효 정책을 확인하며 타사 방화벽 PASS 사례는 합성 분기시험일 뿐 운영 제품 지원을 뜻하지 않는다. 자세한 결과는 [`deploy/verification/IMP024_단말_보호_검증.md`](deploy/verification/IMP024_단말_보호_검증.md)를 따른다.

### IMP-025 사용자·이동식 미디어·원격지원 테스트

PC-16 화면보호기 잠금, PC-17 이동식 미디어 자동실행과 관리 절차, PC-18 Windows Remote Assistance 차단 규칙 및 합성 사례 15개는 보존한다. 과거 독립 시연 화면은 제거했으며, 현재 재검증은 `deploy/verification/IMP025_사용자_미디어_원격지원_검증.md`를 사용한다.

### IMP-026 PC-01~18 전체 Pack 통합 회귀

과거 PC-01~18 전체 목록 시연 화면은 제거했지만 최종 `0.6.0 DRAFT` Pack, Fixture와 회귀시험은 보존한다. Pack에 18개 Control이 정확히 한 번씩 포함됐는지, 합성 사례 92개와 기대값이 일치하는지, 100회 canonical SHA-256이 하나인지 계속 검사할 수 있다. 이 통과 결과는 개발 규칙의 안정성을 뜻하며 운영 승인이나 실제 PC의 공식 Finding을 뜻하지 않는다.

### IMP-027 단계 G 시연·Gap review

단계 G Web 시연 스크립트는 제거했다. 단계 G 인수·Gap review와 규칙 회귀시험은 보존했으며, 비-PASS oracle 64건 중 PASS로 바뀐 사례, 필수 상태 분기가 없는 Control과 상태가 충돌하는 결과 코드가 모두 0건인지 시험으로 다시 확인할 수 있다.

단계 G를 막는 결함은 없지만 실제 Windows 수집기, 권한 분리, 실제 제품 Adapter·조직 기준, 온라인/오프라인 제출·서명과 Audit Pack 운영 승인은 아직 남아 있다. 따라서 인수 상태는 `PASS_WITH_DEFERRED_GAPS`이며 운영 준비 완료를 뜻하지 않는다. 자세한 결과는 [`deploy/verification/IMP027_G단계_시연_차이점_검토.md`](deploy/verification/IMP027_G단계_시연_차이점_검토.md)를 따른다.

### IMP-028 Mock Collector·Manifest verifier

과거 Collector Job 시연 화면은 제거했지만 Manifest 계약, PC-07 세 Probe allowlist, 모의 실행과 차단 시험은 보존한다. Manifest는 엄격한 JSON Schema·RFC 8785 content hash·외부 서명 proof·유효 시간·Job/Asset/endpoint/nonce·Collector version·Probe 제한을 모두 통과해야 좁은 실행 계획이 된다.

이번 단계는 protocol test double이다. `win.storage.disks`, `win.storage.partitions`, `win.storage.volumes`의 고정 합성 결과만 만들며 Registry, CIM, PowerShell과 실제 디스크를 읽지 않는다. 실제 공개키 서명 adapter, Windows context와 PC-07 읽기 전용 Probe는 후속 단계에서 연결한다. 자세한 결과는 [`deploy/verification/IMP028_모의_수집기_명세_검증.md`](deploy/verification/IMP028_모의_수집기_명세_검증.md)를 따른다.

### IMP-029 Windows context·PC-07 읽기 전용 Probe

과거 Windows context 시연 화면은 제거했다. 비식별 Windows context, PC-07 세 Probe와 읽기 전용 안전 경계의 실제 재검증은 Windows 호스트의 `tools/verify-imp029-windows.ps1`로 수행한다. 이 파일은 잠긴 Collector dependency를 `runtime` 전용 환경에 준비하고, hash가 고정된 PowerShell source로 현재 OS·Build·관리자 토큰 여부·SID 형식과 디스크·파티션·볼륨 속성만 읽는다.

현재 Windows 11 x64에서 세 Probe가 각각 4개 record를 읽었고 자동 권한 상승, 설정 변경과 공식 Finding 생성은 없었다. 실제 SID와 원시 결과는 저장하지 않았다. 자세한 결과는 [`deploy/verification/IMP029_Windows_PC07_읽기전용_검증.md`](deploy/verification/IMP029_Windows_PC07_읽기전용_검증.md)를 따른다.

### IMP-030 권한 분리·Probe 안전성

일반/관리자 Probe 분리, 자동 UAC 금지, 실행 상한과 설정 차이 0건은 Windows 호스트의 `tools/verify-imp030-windows-safety.ps1`로 재검증한다. 관련 과거 시연 화면은 제거했다.

현재 PC-07 세 Probe는 모두 일반 권한이라 관리자 process를 시작하지 않는다. 향후 관리자 Probe는 항목과 이유를 먼저 알리고 명시적 동의를 받은 뒤 별도 process로 실행한다. 각 Probe는 최대 30초, stdout·stderr 각각 65,536 bytes로 제한되며 초과 시 그 process tree를 종료한다. 실행 전후 5개 설정 표면의 Snapshot을 비교해 현재 Windows에서 차이 0건을 확인했다. 이 결과는 읽기 작업의 무변경 확인이며 PC가 안전하다는 공식 PASS는 아니다. 자세한 결과는 [`deploy/verification/IMP030_권한_점검_안전성_검증.md`](deploy/verification/IMP030_권한_점검_안전성_검증.md)를 따른다.

### IMP-031 PC-01~18 Probe·Adapter Coverage

PC-01~18 각각의 native Probe, 권한, Adapter와 기관 기준 필요 여부는 Coverage 계약과 `tools/verify-imp031-windows-coverage.ps1`로 재검증한다. 과거 Coverage 시연 화면은 제거했다. host Probe는 20개이며 일반 권한 15개와 관리자 권한 5개로 분리된다.

제품 Adapter는 DRAFT catalog의 Microsoft Defender와 Windows Firewall만 host 실행을 허용한다. 합성 타사 방화벽과 catalog에 없는 제품은 자동 PASS가 되지 않는다. 패치·Windows 수명 reference와 기관 정책도 host가 임의로 만들지 않는다. 직접 재검증은 `tools/verify-imp031-windows-coverage.ps1`, 상세 결과는 [`deploy/verification/IMP031_PC01_PC18_점검_어댑터_범위.md`](deploy/verification/IMP031_PC01_PC18_점검_어댑터_범위.md)를 따른다.

### IMP-032 Online 인증 제출

단기 Job credential, Asset·Job·Manifest·nonce 결합과 재사용 차단 흐름은 `tools/verify-imp032-online-submission.ps1`과 단위시험으로 재검증한다. 과거 제출 시연 화면은 제거했다. credential은 기본 60분·최대 2시간이며 전체 Package 검증이 성공한 뒤 한 번만 사용 완료 처리한다.

현재 화면과 API는 비식별 합성 ZIP 인수 결과만 보여준다. 사람 인증과 Asset RBAC가 아직 없으므로 실제 credential 발급·업로드 POST endpoint는 열지 않았고 원본 증적도 저장하지 않았다. 직접 재검증은 `tools/verify-imp032-online-submission.ps1`, 상세 결과는 [`deploy/verification/IMP032_온라인_인증_제출.md`](deploy/verification/IMP032_온라인_인증_제출.md)를 따른다.

### IMP-033 Offline Package 제출

두 오프라인 제출 방식의 차이와 차단 계약은 `tools/verify-imp033-offline-submission.ps1`과 단위시험으로 재검증한다. 과거 제출 시연 화면은 제거했다. 조직 인증서로 서명한 `OFFLINE-SIGNED`는 조직 루트·전용 용도·PC 식별자·폐기 상태·서명을 확인해 `MEDIUM`으로 접수한다.

두 방식은 같은 Organization·Asset·Job·nonce를 공유하므로 제출 방식을 바꿔 재전송해도 거부한다. 현재는 시험 중 메모리에서 만든 인증서와 비식별 합성 ZIP만 사용하며 실제 개인키·인증서·원본 증적을 저장하지 않는다. 운영 업로드 POST와 공식 Finding도 비활성이다. 직접 재검증은 `tools/verify-imp033-offline-submission.ps1`, 상세 결과는 [`deploy/verification/IMP033_오프라인_패키지_제출.md`](deploy/verification/IMP033_오프라인_패키지_제출.md)를 따른다.

### IMP-034 Windows x64 native 개발 빌드

`tools/build-imp034-windows-collector.ps1` 한 명령이 프로젝트 전용 CPython 3.14.6 환경을 준비하고, 해시로 잠긴 24개 부품을 설치한 뒤 `SecAI-Collector-Windows-x64.exe`를 만든다. 이어서 별도 Python 없는 self-check, PE32+ AMD64 형식, 포함 자료 99개의 해시, CycloneDX SBOM, pip-audit, ClamAV와 Microsoft Defender를 검사한다.

현재 최종 unsigned 개발 파일은 12,750,154 bytes이며 SHA-256은 `47f34a7988824524ebce137c6e3ee7f89473f43e7a1b35045e41a352352dcb91`이다. 의존성 알려진 취약점 0건이고 두 악성코드 검사는 `CLEAN`이다. `runtime/imp034-artifacts/build-20260806T144530Z`에 Windows 구성요소 취약점 인벤토리를 포함해 보관한다. 개발용 Authenticode 서명 결과 SHA-256은 `b9c9a3c8509046ff219ffbf109d1a3ceb9f85bace86652eebfcff731aebd2362`이며 임시 다운로드 Catalog는 `runtime/dev-signed-downloads/release-20260806T144647Z`다. 모두 `DEV-SIGNED-TEST` 개발 시험물이며 조직 서명·운영 배포 승인을 대신하지 않는다. OS 최소 기능은 [`VULN-01 검증`](deploy/verification/VULN_01_Windows_알려진_취약점_점검_검증_20260806.md), 현재 구성요소 UI는 [`Windows 구성요소 검증`](deploy/verification/VULN_WIN_COMPONENT_01_Windows_구성요소_한국어_AI_검증_20260806.md), AI 비의존 한글 설명과 오류 UX는 [`한글 설명·AI 오류 UX 검증`](deploy/verification/VULN_WIN_COMPONENT_03_한글설명_AI오류_UX_검증_20260807.md)을 따른다.

### IMP-035 개발용 Authenticode 서명

`tools/sign-imp035-windows-collector.ps1`은 최신 IMP-034 PASS 파일만 선택해 개발용 non-exportable RSA 3072 코드서명 키를 만들고 SHA-256 Authenticode와 timestamp를 적용한다. 서명 전·후 hash, Code Signing EKU, 변조 거부, self-check와 서명 후 ClamAV·Defender 검사를 확인한 뒤 임시 인증서와 private key를 제거한다.

현재 개발 서명 파일은 `runtime/imp035-artifacts/acceptance-20260723T080809Z`에 있으며 SHA-256은 `4a41267022faff84c5aa4a16a5dcb51356c8678a3eecd144c16755c057858a5c`다. 구현시험 12개는 통과했지만 조직 코드서명 인증서, 운영 CRL/OCSP, clean Windows 11 VM·SmartScreen 인수는 남아 있다. 과거 서명 확인 시연 화면은 제거했으며, 자세한 결과는 [`deploy/verification/IMP035_Authenticode_수집기_인수.md`](deploy/verification/IMP035_Authenticode_수집기_인수.md)를 따른다.

### IMP-043 관리자 추가 점검

[결과 화면](http://localhost:18480/ui/results#administrator-scan)에서 PC-02·04·06·08·10 중 필요한 항목만 선택하고 별도 동의한 뒤 관리자 점검을 요청할 수 있다. 각 항목이 왜 관리자 권한을 요구하고 무엇을 확인하는지 먼저 설명하며, 실행 버튼을 눌러도 Windows UAC에서 사용자가 허용해야 별도 관리자 프로세스가 시작된다.

UAC를 취소하거나 일부 항목을 읽지 못해도 앞서 완료한 일반 점검 결과는 유지된다. 완료된 관리자 결과는 결과 화면 상단의 `관리자 점검 결과`에 자료 수집 상태·실제 확인값·판정 기준·시험 PASS/FAIL/ERROR/REVIEW와 함께 표시되며, `관리자 점검 다시 하기`로 항목을 다시 선택할 수 있다. 관리자 동의는 읽기 권한 허용이며 곧바로 양호 판정을 뜻하지 않는다. Windows 값은 읽었지만 조직 기준이 더 필요하면 `기준 확인 필요(REVIEW)`, 자료를 읽지 못했으면 실제 실패 이유와 `정보 수집 오류(ERROR)`로 구분한다. 선택하지 않은 항목은 읽지 않고, PC 설정·원본 값·공식 Finding을 저장하거나 만들지 않는다. 실제 실행 기능은 최신 `DEV-UNSIGNED` EXE에 들어 있으므로 운영 배포가 아닌 현재 개발 PC 시험에만 사용한다. 최신 보정은 [`deploy/verification/PRODUCT_AI_관리자_결과_보정_20260726.md`](deploy/verification/PRODUCT_AI_관리자_결과_보정_20260726.md)를 따른다.

### Worker·Queue·Outbox 복구

[작업 복구 상태](http://localhost:18480/ui/queue-recovery)는 백그라운드 작업을 처리하던 Worker가 갑자기 꺼져도 작업이 다시 전달되고 결과가 중복 저장되지 않았는지 쉬운 용어로 보여주는 개발용 읽기 전용 화면이다. PostgreSQL이 Job·단계·Outbox·시도·최종 결과의 정본이며 Redis는 다시 만들 수 있는 전달 통로다.

실제 유지보수 Worker 자식 프로세스를 강제 종료한 시험에서 작업은 재전달됐다. 총 3번의 처리 시도가 있었지만 논리 결과는 1건, 중복 결과와 공식 Finding 증가는 0건이었다. 공개 화면과 API에는 Job ID·Worker PID·원본 message·비밀값을 표시하지 않는다. 재현 방법과 상세 결과는 [`deploy/verification/IMP044_작업자_대기열_아웃박스_복구_검증.md`](deploy/verification/IMP044_작업자_대기열_아웃박스_복구_검증.md)를 따른다.

### IMP-046 로그인·역할·Web 보안

[로그인 화면](http://localhost:18480/auth/login)에서 개발용 개인 계정으로 로그인한 뒤 두 번째 인증을 완료해야 Sec_AI 화면을 사용할 수 있다. 개발 사용자 이름은 `local-owner`이며 비밀번호와 두 번째 인증코드는 `runtime/dev-secrets/`의 보호 파일로만 관리한다. 이 값은 source·문서·image에 포함하지 않는다.

서버는 화면의 숨겨진 버튼을 믿지 않고 full page, HTMX 화면 조각, JSON API, SSE 연결과 download마다 역할·조직·할당된 PC를 다시 확인한다. 다른 조직·PC ID 접근, cross-site CSRF, logout한 세션 재사용을 차단했다. 실제 브라우저의 자동 favicon 요청이 로그인 쿠키를 바꾸던 결함도 수정했으며 DEV-LOCAL의 브라우저 검증 `same-origin` 요청을 안전하게 처리한다. HTTP 흐름 17/17과 전체 Pytest 417개가 통과했다. 자세한 결과와 재실행 방법은 [`deploy/verification/IMP046_인증_RBAC_웹_보안_검증.md`](deploy/verification/IMP046_인증_RBAC_웹_보안_검증.md)를 따른다.

현재 두 번째 인증은 `DEV-LOCAL` 전용 시험 기능이다. 실제 hostname·TLS·WebAuthn·조직 OIDC와 원본 증적 download는 Pilot 전까지 계속 비활성이다.

로그인 화면의 `계정 생성 요청`은 즉시 로그인 가능한 공개 회원가입이 아니다. 요청 계정은 Argon2id password hash만 가진 `PENDING_APPROVAL` 상태로 저장되고 역할·session이 없다. 같은 조직의 `ADMIN`이 계정정보 아래 관리자 계정 관리에서 승인해야 `ACTIVE`와 기본 `USER` 역할을 받는다. 사용자는 계정정보에서 자신의 표시 이름·password를 변경할 수 있고, password 변경 시 기존 session이 폐기된다.

관리자는 개발용 두 번째 인증 코드를 재발급할 수 있지만 원문은 결과 화면에서 한 번만 복사하고 DB에는 keyed digest와 만료 시각만 저장한다. 이 기능은 관리자가 코드 원문을 알 수 있는 DEV-LOCAL 시험 수단이므로 Pilot MFA가 아니다. Pilot에서는 사용자가 최초 접속 때 자신의 WebAuthn 또는 TOTP를 직접 등록해야 한다. 현재 계약과 집중시험 6 PASS는 [`deploy/verification/개발_로컬_계정_승인_관리_20260801.md`](deploy/verification/개발_로컬_계정_승인_관리_20260801.md)를 따른다.

### IMP-047 믿을 수 있는 KISA 원문 준비

사용자가 제공한 KISA PDF를 [`guides/catalog.json`](guides/catalog.json)에 등록하고, exact SHA-256·873쪽·PDF 형식·이용 조건과 조회 범위를 고정했다. PC 장은 PDF 552~592쪽의 연속 41쪽이며 PC-01~18 본문은 555~592쪽이다. 각 페이지의 전체 문장을 복제하지 않고 정규화 글자 수와 text SHA-256만 보관해 원문 변경을 탐지한다.

[`guides/mappings/kisa_2026_pc_control_sources.json`](guides/mappings/kisa_2026_pc_control_sources.json)은 PC-01~18의 페이지 범위를 기존 `0.6.0 DRAFT` Audit Pack 인용과 대조한다. Guide 등록, Control 출처 연결과 Audit Pack 승인은 서로 다른 Gate다. IMP-048에서 프로젝트 내부 검색과 파생 text·chunk·embedding 저장을 승인해 Guide Catalog만 `APPROVED`로 바꾸고 PC 41쪽을 실제 적재했다. Mapping과 Audit Pack은 계속 `DRAFT`, 규칙 활성화는 `false`이며 원문 외부 재배포도 금지한다.

[가이드 검색 저장소](http://localhost:18480/ui/guide-store)는 로그인 후 PostgreSQL·pgvector 버전, 실제 문서 1건·검색 문단 41건·벡터 41건과 원문 쪽 연결을 안전하게 보여준다. raw vector와 DB 비밀번호는 노출하지 않는다. 개발 관리자는 `tools/open-database-admin.ps1`로 별도 pgAdmin을 열어 `127.0.0.1:18490`에서 제한 계정으로 Guide 데이터를 관리한다. PostgreSQL `5432`는 host에 열지 않는다.

관리자 image는 공식 pgAdmin 9.16 digest에 수정 가능 패키지 갱신과 CPython 3.14 `CVE-2026-15308` 공식 backport를 적용했다. `admin-tools` profile과 loopback에서만 사용하는 개발 도구이며, 운영·Pilot 전 최신 공식 base 재검증이 필요하다.

직접 검증은 `tools/verify-imp047-guide-source.ps1`로 실행한다. 원문 hash·페이지 지문·Control 인용이 바뀌거나 미검토 라이선스를 느슨하게 하면 실패한다. PDF 원문은 `data/`에만 두고 Docker image·source·이동 묶음에 넣지 않는다. 상세 결과는 [`deploy/verification/IMP047_신뢰_KISA_원문_검증.md`](deploy/verification/IMP047_신뢰_KISA_원문_검증.md)를 따른다.

### IMP-049 KISA 질문별 근거·인용 검증

실제 PostgreSQL+pgvector 저장소를 대상으로 PC-01~18 대표 질문 18개를 검사했다. 정답 Control의 첫 검색 결과, 원문 페이지·절, 답변에 사용할 문단과 그 문단의 SHA-256이 모두 18/18 일치했다. 관련 없는 질문 4개는 `근거 없음`, 승인 문서가 서로 다른 내용을 말하는 경우 3개는 `문서 충돌`로 구분했고 다른 조직·가이드 범위의 결과 누출은 0건이었다.

검색 결과는 문서 ID·버전·원문 hash·페이지·절·문단 순번·문단 hash를 함께 고정한다. 이 정보가 하나라도 바뀌거나 질문 핵심어가 인용 문단에 없으면 답변 근거로 사용하지 않는다. 상세 결과와 재실행 방법은 [`deploy/verification/IMP049_KISA_질문_근거화_검증.md`](deploy/verification/IMP049_KISA_질문_근거화_검증.md)를 따른다.

### IMP-050 OpenRouter 시험 대역·향후 로컬 vLLM 연결 계약

`sec-ai-mvp/model-gateway:0.1.0` 내부 container를 추가했다. 현재는
OpenRouter를 `VLLM_COMPATIBILITY_TEST_DOUBLE`로 사용해
`openai/gpt-oss-120b`의 모델 목록과 비식별 생성을 실제 확인한다. API key는
image·Compose 환경값·API container·문서·로그에 넣지 않는다.

```text
현재: Sec_AI API → model-gateway → OpenRouter
향후: Sec_AI API → model-gateway → local vLLM
```

향후에는 `SECAI_LLM_API_BASE`와 `SECAI_LLM_MODEL`을 로컬 endpoint와 served model로 바꾼다. 현재 실행 중인 model-gateway image는
연결 전용이며 vLLM package·CUDA·모델 weight가 없다. 별도로 NVIDIA GPU vLLM image와 자동 시작되지 않는 container를 준비했지만 취약점 Gate·GPU·승인 모델 부재로 `PREPARED_NOT_ACTIVE` 상태다. OpenRouter 시험은 외부
전송임을 `/ui/model-runtime`에서 알리고, local vLLM이 아직 실행되지 않았음도
분명히 표시한다. 자동 모델 fallback은 없고 AI가 중단돼도 PC 점검과 공식
Finding은 계속 동작한다.

OpenRouter는 vLLM 자체나 운영 모델이 아니다. 합성 또는 승인된 비식별 최소
입력으로 OpenAI 호환 API·SSE·오류 계약만 확인한다. 실제 점검 결과 설명·후속
질문·보고서의 최종 제품은 `LOCAL_VLLM_FULL_CONTEXT`에서 외부 egress 0,
model/revision/license·weight/image 공급망과 성능 Gate를 통과해야 한다.

실제 KISA 질문답변 화면은 `IMP-053`에서 `LIVE`로 전환했다. 현재 화면은
로컬 PostgreSQL+pgvector에서 근거를 찾은 뒤, 사용자가 승인한 질문·검색 문단만
OpenRouter `VLLM_COMPATIBILITY_TEST_DOUBLE`에 전송해 설명을 생성한다. 향후
주소와 모델을 local vLLM으로 바꾸되 같은 Completion·SSE 계약을 유지한다. 상세
보안·image·SBOM·실제 연결 결과는
[`deploy/verification/IMP050_OpenAI_호환_모델_게이트웨이_검증.md`](deploy/verification/IMP050_OpenAI_호환_모델_게이트웨이_검증.md)를
따른다.

### PRODUCT-AI 점검 결과 실제 token stream

점검 결과 AI 설명은 일반 가이드 질의와 전송 경계가 다르다. 사용자가 승인한 현재 시험 환경에서는 비식별·정규화한 결과와 해당 Control에 검색된 KISA 근거만 OpenRouter `VLLM_COMPATIBILITY_TEST_DOUBLE`로 보낼 수 있다. 원본 증적·사용자/조직/Asset 식별자·내부 판정 이유 코드·명령 전문은 보내지 않는다.

```text
원클릭 점검
→ 일반 수집과 선택한 관리자 결과 수신
→ /ui/ai-analysis
→ PC-01~18 항목별 OpenRouter token delta 즉시 표시
→ 마지막 AI 종합 설명 token delta 표시
→ 기존 상세 점검 결과·PDF·후속 질문
```

기본 화면은 `POST /api/v1/result-explanations/from-scan/token-stream`을 사용한다. 각 Control은 완성된 답변을 기다렸다가 한 번에 출력하지 않고 model-gateway가 받은 OpenAI 호환 SSE `delta`를 즉시 표시한다. 기존 최대 6개 validated batch endpoint는 호환용으로 유지한다. LLM은 공식 `PASS/FAIL/ERROR/REVIEW/N/A`를 바꾸지 않으며 AI 장애가 공식 결과를 차단하지 않는다. 구현·검증 결과는 [`deploy/verification/PRODUCT_AI_실제_토큰_스트림_검증_20260801.md`](deploy/verification/PRODUCT_AI_실제_토큰_스트림_검증_20260801.md)를 따른다.

### IMP-051 대화 기록·중단·재시도 계약

대화방·메시지·인용과 생성 시도의 PostgreSQL 정본을 추가했다. 질문을
편집하거나 답변을 다시 요청해도 기존 메시지 본문을 덮어쓰지 않고 새
버전·분기로 추가한다. 같은 요청을 100회 보내도 메시지와 생성 시도는 각각
1건만 생성되며, 중단된 생성은 늦게 도착한 완료 요청으로 바뀌지 않는다.

PostgreSQL 강제 행 수준 보안은 조직과 대화 소유자가 모두 일치할 때만
조회·저장을 허용한다. 인용은 가이드 ID·버전·검색 범위·chunk·PDF 쪽·절·문단
hash를 함께 보존한다. 보존기간은 아직 승인되지 않아 물리 삭제 대신
`TOMBSTONED` 삭제 표시만 허용한다.

기본 설정은 `SECAI_CHAT_LIVE_ENABLED=false`로 fail-closed를 유지한다.
개발 Compose만 인증·CSRF·RLS·근거 답변 검증을 통과한 API에 이 값을
`true`로 주며 `/ui/guide-chat`에서 실제 사용자 소유 대화를 저장한다.
상세 결과는
[`deploy/verification/IMP051_대화_계약_검증.md`](deploy/verification/IMP051_대화_계약_검증.md)를
따른다.

### IMP-052 KISA Q&A·점검 결과 쉬운 설명

`GUIDE_QA`와 `FINDING_EXPLAIN`이 로컬 임베딩과 PostgreSQL+pgvector 검색
결과를 사용한다. 대표 질문 18개는 정확한 Control·페이지·절·문단을 인용했고,
범위 밖 질문 4개는 모델을 호출하지 않고 `근거 없음`으로 처리했다.

사용자 질문과 검색 문서는 불신 입력으로 격리한다. prompt injection과 실행형
모델 출력, 승인되지 않은 원격 자료 전송은 모델 호출 또는 응답 공개 전에
차단한다. 모델 장애가 발생해도 PC 점검은 계속되며 AI 처리 전후 공식 Finding과
Audit Pack canonical hash는 동일해야 한다. 실제 OpenRouter에는 이번 검증의
KISA 원문·질문을 보내지 않았고, local 결정론적 모델 대역으로 결합 계약을
검증했다. 자세한 결과는
[`deploy/verification/IMP052_근거기반_AI_안전성_검증.md`](deploy/verification/IMP052_근거기반_AI_안전성_검증.md)를
따른다.

### IMP-053 실제 KISA 질문답변 챗 화면

로그인 후 [`http://localhost:18480/ui/guide-chat`](http://localhost:18480/ui/guide-chat)에서
새 대화, 최근 대화, 질문 전송, 생성 상태, 중단, 질문 수정, 다시 답변,
분기, 출처와 기술 추적정보를 실제 API로 사용한다. 답변은 승인된 KISA
PostgreSQL+pgvector 근거를 사용하며, 현재 시험 환경에서는 사용자가 승인한
질문·검색 문단만 OpenRouter로 전송한다. 원본 PDF·원본 증적·계정·조직·자산
식별자와 비밀값은 전송하지 않는다.

완료 답변에는 모델 식별자와 prompt/input/output SHA-256, 외부 전송 여부가
원자적으로 저장된다. 답변은 PC 설정과 공식 Finding·Audit Pack을 변경하지
않는다. 실제 DB·로그인 UI 검증 결과는
[`deploy/verification/IMP053_실시간_가이드_대화_검증.md`](deploy/verification/IMP053_실시간_가이드_대화_검증.md)를
따른다.

2026-08-02 후속 UI는 대화 목록 inline 관리, 크기 조절, 긴 답변 내부 스크롤,
사용자 스크롤 우선 auto-follow, 실제 model delta와 제한 Markdown·한글 출처를
연결했다. 현재 검색 구현과 BGE-M3 전환 경계까지 포함한 최신 기준선은
[`deploy/verification/가이드_대화_UI_스트리밍_검색_기준선_20260802.md`](deploy/verification/가이드_대화_UI_스트리밍_검색_기준선_20260802.md)를
따른다.

PC-16은 평가 사용자별 화면보호기 활성, 1~600초 대기와 재개 시 암호 보호를 요구한다. 현재 사용자가 양호해도 평가해야 할 다른 사용자가 남으면 `REVIEW`다. PC-17은 모든 드라이브 자동실행 차단과 승인된 내부 절차가 함께 있어야 PASS다. PC-18은 요청형·제공형 Windows Remote Assistance를 모두 명시적으로 꺼야 하며 Quick Assist와 원격 데스크톱은 다른 기능이므로 범위에서 제외한다. 자세한 결과는 [`deploy/verification/IMP025_사용자_미디어_원격지원_검증.md`](deploy/verification/IMP025_사용자_미디어_원격지원_검증.md)를 따른다.

### 2단계에서 추가된 실행 골격

```text
Gateway → FastAPI Health
             ├─ PostgreSQL readiness
             ├─ Redis ACL readiness
             ├─ AIStor readiness
             └─ ClamAV readiness

Redis ← Celery Worker·Scheduler 연결 골격
```

AIStor Free 라이선스를 DEV secret 영역에 반입한 뒤 최초 8개 서비스가 실제 Docker 기동·Health·재시작 시험을 통과했다. IMP-044에서 전용 Maintenance Worker가 추가되어 현재는 9개 서비스가 모두 healthy다. API `/health/ready`는 PostgreSQL·Redis·AIStor·ClamAV를 모두 확인해 HTTP `200 ready`를 반환한다. 인증된 S3 합성 객체의 생성·조회·삭제 시험도 통과했다. 최초 시험은 [`deploy/verification/2단계_핵심_Compose_검증.md`](deploy/verification/2단계_핵심_Compose_검증.md), 현재 Queue 복구 시험은 [`deploy/verification/IMP044_작업자_대기열_아웃박스_복구_검증.md`](deploy/verification/IMP044_작업자_대기열_아웃박스_복구_검증.md)를 따른다.

## 9. 구현 착수 순서

첫 구현은 전체 PC 항목을 한꺼번에 작성하지 않고 PC-07 하나를 다음 끝단까지 연결한다.

```text
문서 승인·기준선 동결
→ Repository와 Core Compose 골격
→ JSON Schema 자동 검증 Gate
→ PC-07 Audit Pack·PASS/FAIL/ERROR Fixture
→ Pure deterministic 규칙 엔진
→ PostgreSQL·AIStor·Celery·FastAPI 최소 E2E
→ PC-01~PC-18 확대
→ Windows Collector
→ 현재 OS 실측·제출 보안시험
→ PowerShell·Docker 명령 없는 1~2클릭 점검·결과·재점검
→ 향후 AI 기능을 명확한 미리 보기로 포함한 제품 UI 골격
→ Core 복구·권한시험
→ 믿을 수 있는 KISA 원문 준비
→ 질문에 필요한 KISA 페이지 찾기와 출처 정확도 검증
→ 로컬 AI·대화 기록·중단·재시도로 KISA 질문답변 완성
→ 검증된 KISA 질문답변을 미리 보기에서 실제 챗 기능으로 전환
→ 깨끗한 Windows 11 VM 회귀·조직 서명·Pilot 인수
```

PostgreSQL+pgvector·Embedding·Reranker는 사용자가 별도로 실행하는 기능이 아니라 질문과 관련된 KISA 페이지를 찾아주는 내부 검색도구다. 별도 Milvus 운영 구성은 사용하지 않는다. 사용자 중심 단계명과 `IMP-047~054`의 쉬운 설명은 [`대화_RAG_제품_계획.md`](docs/plans/대화_RAG_제품_계획.md)와 [`다음_I_J_단계_계획.md`](docs/plans/다음_I_J_단계_계획.md)를 따른다.

UI의 향후 기능은 `LIVE/PREVIEW/BLOCKED/HIDDEN` 상태로 구분한다. `PREVIEW`는 비식별 고정 예시만 사용하고 실제 수집·저장·제출·판정을 호출하지 않는다. 실제 API·권한검사·감사·자동시험이 연결된 기능만 `LIVE`로 표시한다.

PC-07을 첫 항목으로 선택한 이유와 세부 완료 조건은 `docs/adr/2.MVP_점검항목_매트릭스.md`와 `docs/adr/13.MVP_구현_시작_계획.md`를 따른다.

## 10. 저장소 관리 원칙

- 운영 credential, token, cookie, private key, 실제 `.env`, 원본 증적과 DB backup을 Git 또는 문서 디렉터리에 저장하지 않는다.
- Collector나 AI가 공식 `PASS/FAIL/REVIEW/ERROR/N/A` 결과를 임의 생성·변경하지 않는다.
- 자동 수집 가능 여부와 자동 판정 가능 여부를 분리한다. 권한 부족·수집 오류를 취약 판정인 `FAIL`로 변환하지 않는다.
- 승인된 Audit Pack의 exact version·hash·서명과 사용된 증적 hash를 Finding에 연결한다.
- JSON Schema, dependency lock과 container digest 변경은 각각의 검증·승인 절차를 통과한다.
- 문서와 구현이 다르면 구현 편의를 이유로 차이를 숨기지 않고 ADR 개정 또는 예외 결정을 남긴다.
- 생성물, cache, runtime data와 test artifact는 source·정책 문서와 분리하고 향후 `.gitignore`에서 관리한다.

## 11. 현재 주요 승인 Gate

구현과 병행하거나 Pilot 전에 완료해야 할 대표 항목이다. 상세 조건은 각 ADR과 실행계획서를 따른다.

| Gate                                                              | 관련 위치                                             |
| ----------------------------------------------------------------- | ----------------------------------------------------- |
| 번호 문서의 조직 책임자 실제 성명·서명                           | `docs/adr/`                                         |
| Redis 8 SBOM·취약점·ACL·Outbox 복구시험                        | `deploy/locks/container-images.lock.yml`, Queue ADR |
| AIStor Free SBOM·취약점·Object Lock·1시간 backup/8시간 restore | container 잠금표, 증적 보존 정책                      |
| Audit Pack 승인·서명·폐기 절차                                  | 공식 판정 ADR, Schema 계약                            |
| Collector code signing·Probe allowlist·관리자 권한 승인         | Collector ADR                                         |
| Local MFA/WebAuthn 운영 hostname·TLS·복구 절차                  | 인증 ADR                                              |
| 실제 Secret 담당자와 OpenBao 복구훈련                             | 실행계획서 및 인증·저장 정책                         |

## 12. Docker 우선 개발과 다른 PC 이동

Sec_AI 개발자는 host에 Python·Node·PostgreSQL·Redis·AIStor와 품질도구를 개별 설치하지 않는다. 승인된 dependency lock을 설치한 `sec-ai-mvp/dev-tools:0.1.0` image에서 다음 명령을 실행한다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action Build
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action All
```

Sec_AI가 실행하는 Docker 이미지는 모두 `sec-ai-mvp/<component>:<version>` 형식을 사용한다. API·Worker·Scheduler뿐 아니라 PostgreSQL·Redis·AIStor도 얇은 프로젝트 래퍼 이미지인 `sec-ai-mvp/postgres:0.1.0`, `sec-ai-mvp/redis:0.1.0`, `sec-ai-mvp/aistor:0.1.0`으로 실행한다. 따라서 Docker Desktop의 컨테이너 목록에서도 Sec_AI 프로젝트를 한 묶음으로 바로 구분할 수 있다. 래퍼는 제품을 수정하거나 재구현하지 않으며, 승인된 공식 이미지를 정확한 `tag@digest`로 상속한다. 원본 공급자·버전·digest는 Dockerfile, 이미지 라벨과 잠금표에 보존한다.

`All`은 Python version, unit·contract test, JSON Schema example, Ruff와 mypy를 순서대로 검사한다. `PRODUCT-AI-04~08`에서는 변경 기능의 집중시험만 실행하고, 이 전체 명령과 변경 서비스 Docker 재빌드는 `PRODUCT-AI-09`에서 한 번 수행한다. API·DB·인증·판정 불변성·외부 AI 전송·Docker 경계를 바꾸는 단계는 관련 위험 영역을 즉시 확대 검증한다. 상세 기준은 [`PRODUCT_AI_시험_전략_20260726.md`](deploy/verification/PRODUCT_AI_시험_전략_20260726.md)를 따른다. 개발 container는 source를 read-only로 연결하고 network, Linux capability와 root filesystem 쓰기를 차단한다.

이동 묶음은 일반 개발·검증 단계마다 만들지 않는다. 프로젝트 종료 시점 또는 사용자의 명시적 요청이 있을 때만 다음 명령으로 source ZIP, 잠긴 Docker image TAR, manifest와 SHA-256을 한 directory에 만든다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\export-portable-bundle.ps1
```

`-ExecutionPolicy Bypass`는 이 명령으로 시작한 PowerShell 프로세스에만 적용되며 PC의 전역 실행 정책을 변경하지 않는다.

Core 서비스는 다음 명령으로 관리한다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Init
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action UpWithoutAIStor
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Status
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\core.ps1 -Action Health
```

AIStor를 포함한 전체 9개 서비스를 실행할 때는 라이선스를 `runtime/dev-secrets`로 반입한 뒤 `-Action Up`을 사용한다. 현재 DEV 환경은 이 절차를 완료했다. 실행 기준과 현재 제한은 [`deploy/README.md`](deploy/README.md)를 따른다.

상세 설치·검증은 [`다른 PC 설치·이전 안내`](docs/guides/다른_PC_설치_및_이전_안내.md), 묶음 형식은 [`portable/README.md`](portable/README.md)를 따른다. 이동 묶음은 실제 `.env`, password, private key, AIStor license, 원본 증적, database backup, VM과 Docker volume을 자동 제외한다. 이 민감정보와 Runtime 자료는 승인된 Secret·Backup/Restore·VM 절차로 별도 이전한다.

## 13. 제출 준비와 사용자 정의 점검기준

현재 제출 평가 대응의 가장 큰 차단 항목은 프로젝트 자체 OSI 라이선스 선택, 공개 저장소 URL, 전체 Software 통합 SBOM·제3자 고지, 모델·RAG 데이터 명세와 시연 URL이다. 현재 `pyproject.toml`은 `LicenseRef-Proprietary`이며 `LICENSE`와 공개 저장소가 없으므로, 프로젝트 책임자의 라이선스·공개 범위 결정 전에는 임의로 바꾸지 않는다.

점검기준 확장은 KISA 규칙을 사용자가 직접 덮어쓰는 방식으로 구현하지 않는다. 일반 사용자는 쉬운 Template과 문장형 Wizard로 `개인 참고 기준`을 만들고 자신의 장비에서 비교할 수 있다. 조직 공통 기준은 관리자·보안 검토를 거치며, 공식 결과를 만드는 기준은 Fixture·결정론·서명·승인 Gate를 통과한 Audit Pack만 허용한다. 같은 실제값을 KISA 기준과 사용자 기준으로 나란히 평가하되 어느 기준의 결과인지 항상 표시한다.

상세 제출 대응은 [`제출_평가_정합성_및_제품_로드맵.md`](docs/plans/제출_평가_정합성_및_제품_로드맵.md), 무코드 작성·승격·rollback 계약은 [`사용자_정의_점검기준_안내.md`](docs/guides/사용자_정의_점검기준_안내.md)와 ADR 20을 따른다.

## 14. README 갱신 기준

다음 중 하나가 발생하면 이 문서를 같은 변경 묶음에서 갱신한다.

- 루트 또는 주요 디렉터리 추가·삭제·이름 변경
- 공식 판정 흐름이나 서비스 책임 변경
- Runtime, database, queue, object storage 또는 인증 방식 변경
- 신규 lock·Schema·Audit Pack 종류 추가
- 1차 MVP 범위나 첫 구현 순서 변경
- `승인 대기` 문서가 승인·대체·폐기됨

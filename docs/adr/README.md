# Sec_AI 아키텍처 결정 기록

| 항목 | 내용 |
|---|---|
| 문서 집합 | 초기 MVP 결정과 이후 다중 플랫폼·RAG·AI·점검기준 결정 |
| 위치 | 프로젝트 루트의 `docs/adr/` |
| 상위 문서 목차 | [`../README.md`](../README.md) |
| 기준일 | 2026-08-07 전체 ADR 현재 상태 검토 |
| 문서 수 | 번호 문서 20개 + 이 Index |
| 현재 상태 정본 | [`../../구현_현황.md`](../../구현_현황.md) |

## 1. 목적

이 directory는 Sec_AI의 범위, 데이터 계약, Runtime, Collector, UI, Queue, 증적, 판정, 권한과 인증 결정을 보존한다. 초기 MVP 문서는 현재 기능 설명서가 아니라 당시 결정과 승인 이력이다.

번호 문서와 구현 착수 계획은 사용자 승인 기록을 기준으로 구현 기준선이 됐다. 현재 코드와 다를 때는 source·Schema·실행 가능한 시험을 실제 동작으로 판단하고 차이를 새 ADR 또는 검증 기록으로 남긴다. 과거 ADR 본문을 현재 설명에 맞추려고 조용히 다시 쓰지 않는다.

## 2. 문서 목록

| 번호 | 파일 | 결정 범위 |
|---:|---|---|
| 1 | `1.MVP_범위.md` | Windows 11, PC-01~PC-18과 1차 MVP 포함·제외 범위 |
| 2 | `2.MVP_점검항목_매트릭스.md` | 원문 위치·중요도, Win11 지원 범위, 자산·기능 적용성, 판정 선행조건, 자동화 유형, 권한·증적과 첫 PC-07 선정 |
| 3 | `3.ADR_Python_실행환경.md` | CPython 3.14.6 Runtime과 플랫폼 잠금 |
| 4 | `4.컨테이너_이미지_잠금.md` | **승인** — Core container tag·digest, Redis RSALv2 내부 사용, AIStor Free 내부 단일 노드와 기술 반입 Gate |
| 5 | `5.ADR_수집기.md` | Windows One-shot Collector·Probe·서명·권한 경계 |
| 6 | `6.ADR_웹_UI.md` | FastAPI/Jinja2·정적 JavaScript·SSE UI와 Browser 보안 |
| 7 | `7.ADR_대기열.md` | **승인** — Celery·Redis 8 RSALv2 내부 사용, Outbox, 멱등성·재시도·Queue 경계 |
| 8 | `8.데이터베이스_스키마.md` | JSON Schema 계약·상태·canonicalization·검증 Gate |
| 9 | `9.증적_저장_보존_정책.md` | **승인** — 원본 증적 1,095일 정책과 AIStor·암호화·잠금·파기·backup. 현재 결과 이력 365일 개발 기본값과는 별도 범위 |
| 10 | `10.ADR_공식_판정_권한.md` | **승인** — Audit Pack 규칙 엔진의 유일한 공식 판정 권한, append-only Finding, Ed25519/JCS 서명 |
| 11 | `11.RBAC_권한_매트릭스.md` | **승인** — 네 사람 역할, 실제 증적 3인 분리, 관리자 원본 제한, DEV-LOCAL 계정 생성 승인, `evaluation-worker(rule-engine producer)` 경계 |
| 12 | `12.ADR_인증.md` | **승인** — Local MFA, DEV-LOCAL `PENDING_APPROVAL` 계정, password·개발 인증 코드 관리, WebAuthn, 역할별 session, CSRF, OIDC 전환 경계 |
| 13 | `13.MVP_구현_시작_계획.md` | **과거 승인 계획** — 초기 구현 착수 순서. 현재 backlog 정본으로 사용하지 않음 |
| 14 | `14.ADR_보안_시험.md` | **승인 대기** — 보안시험의 의미·종류·결과 상태·영역별 필수시험·Release 승인 Gate |
| 15 | `15.ADR_확장형_증적_점검팩_AI_거버넌스.md` | **승인** — 사용자 중심 KISA Q&A 단계명, Windows 우선 확장, Guide/Audit Pack 승인 분리, LLM DRAFT 보조와 시험/최종 Runtime 경계 |
| 16 | `16.ADR_PostgreSQL_pgvector_가이드_검색.md` | **승인** — PostgreSQL 정본·pgvector, 32차원 rollback과 BGE-M3 1024차원·Reranker 병렬 generation, Milvus 미도입 |
| 17 | `17.ADR_vLLM_호환_모델_게이트웨이.md` | **승인** — OpenRouter `VLLM_COMPATIBILITY_TEST_DOUBLE`과 최종 `LOCAL_VLLM_FULL_CONTEXT`, 출처 등급·모델 일반지식의 판정 불변 경계를 분리하는 내부 모델 connector·보안·공급망 Gate |
| 18 | `18.ADR_결과_중심_AI_PC_보안_도우미.md` | **승인·확장 구현** — Windows·Linux·Switch 결과 AI stream·cache·후속 질문, 직접 근거·일반지식 분리와 판정 불변 |
| 19 | `19.ADR_다중_플랫폼_점검_마크다운_보조_조치.md` | **사용자 범위 승인·부분 구현** — Linux 6종 Catalog, Aruba N-01~N-38, Windows NVD/OSV 후보·공식 출처 한글 번역; 공급자 확정·Offline Bundle·Cisco·공식 Pack·Agent/MCP 대기 |
| 20 | `20.ADR_점검기준_목록_프로필_무코드_작성기.md` | **사용자 범위 승인·부분 구현** — Windows Profile, Linux 기준과 Switch 26개 안전 기준·N-12/N-17 조직 보완 판정 편집/초기화·실행 snapshot 구현, 조직 승인·공식 Pack v2 Gate 대기 |

기존 8번 파일명에 포함돼 있던 zero-width 문자는 정리 과정에서 제거하고 `8.데이터베이스_스키마.md`로 정규화했다. 실제 기계 판독 Schema는 프로젝트 루트의 `database/schemas/`에 유지한다.

## 3. 기준 우선순위

1. 현재 사용자 요구와 실제 source·Schema·migration·실행 가능한 시험
2. [`../../구현_현황.md`](../../구현_현황.md)와 최신 검증 기록
3. 승인된 번호 문서의 보안·권한·데이터 결정
4. 초기 기획 문서와 구현 편의에 따른 임시 선택

예를 들어 초기 계획의 Python 3.12 권고와 현재 잠긴 Runtime·3번 ADR의 CPython 3.14.6이 충돌하면 현재 잠긴 Runtime과 3번 ADR을 따른다. 반대로 현재 source가 승인 ADR의 보안 경계를 어기면 source를 조용히 정당화하지 않고 구현을 고치거나 새 결정과 재승인을 기록한다.

경로를 표시할 때 별도 설명이 없으면 `requirements/`, `database/`, `deploy/` 같은 경로는 이 저장소의 프로젝트 루트를 기준으로 해석한다. 특정 PC의 drive letter는 기준이 아니다.

## 4. 변경관리

- 승인 전 변경은 해당 번호 문서의 승인 기록과 검토 이력에 반영한다.
- 승인 후 의미가 바뀌는 변경은 version 증가, 영향 분석과 재승인을 요구한다.
- 승인된 file을 날짜가 붙은 복사본으로 무분별하게 늘리지 않는다.
- Runtime, image digest, authentication, 공식 판정과 retention 변경은 관련 문서를 함께 검토한다.
- Evidence 의미·Adapter/Mapping registry·Guide/Audit Pack 승인·LLM 작성 권한 변경은 15번 ADR을 함께 검토한다.
- 가이드 검색 저장소·vector generation·검색 권한 변경은 16번 ADR을 함께 검토한다.
- 모델 공급자·주소·모델·vLLM image·CPU/GPU·fallback 변경은 17번 ADR을 함께 검토한다.
- 점검 결과 설명 입력·내부 판정 이유 코드 노출·AI 출력·결과 화면·대화 정보구조·PDF 보고서 변경은 18번 ADR을 함께 검토한다.
- Linux·Switch 지원, Markdown 렌더링, 모델 일반지식 등급화나 Agent/MCP 조치 실행 변경은 19번 ADR을 함께 검토한다.
- 점검기준 출처·Catalog·Profile·사용자 무코드 Builder·개인/조직/공식 승격·Audit Pack v2 변경은 20번 ADR을 함께 검토한다.
- 구현이 문서와 다르면 code를 조용히 정당화하지 않고 ADR을 개정하거나 예외 결정을 기록한다.
- 원본 증적, credential, private key, 실제 운영 `.env`와 DB backup은 이 directory에 저장하지 않는다.

## 5. SHA-256 기준선

현재 `docs/adr/` 정리와 내부 경로 동기화를 반영한 번호 문서 content hash다. 파일을 이동하면서 본문 경로 표기도 갱신했으므로 실제 content를 다시 계산한 기준선이다.

| 파일 | SHA-256 |
|---|---|
| `1.MVP_범위.md` | `935522736C5FDFBF365982DA1FCDDF933AD81F0F0D924FA9C363CE221619262C` |
| `2.MVP_점검항목_매트릭스.md` | `A77E9FC57FEE5AACE2AE79842ED9558101A03107D352C104419DB37255E35127` |
| `3.ADR_Python_실행환경.md` | `7A4E6402E0A970707B05FE219D1A98A5AECAE562FA045587B92E83A7FE34675C` |
| `4.컨테이너_이미지_잠금.md` | `46EF18D07C9E8BCEDADD02C2B21D5C2A3C11CCD41990B61C44E695BB4C2B8AAA` |
| `5.ADR_수집기.md` | `581A7FC13475C246C02F44029AE747E3CEB573036FFAA8E7746F1686F411238F` |
| `6.ADR_웹_UI.md` | `CA6E0E96856EAF7B34941EDE3BEDA306BFC014C5B1CDBD3843C91F0AC910C0C4` |
| `7.ADR_대기열.md` | `EF44BA6179E8AFDE1B04A7F72090D1D4E0C2B5E6AAAAF6777CA20873272DAD89` |
| `8.데이터베이스_스키마.md` | `46F8AD655B316462ED5FADD977C6B36CE66A2F023BCF76575F15D6D6404DB1EB` |
| `9.증적_저장_보존_정책.md` | `96FD30FF34DDD1E484D4E601E56423C2FF2692CF581D67C572C21E6A80D06BF7` |
| `10.ADR_공식_판정_권한.md` | `61F3F467B5912D1A56E95FEEE7448DA548CB94B048CFC0FA0CB7B05D81CD4F1E` |
| `11.RBAC_권한_매트릭스.md` | `E76F2585B5B15692EDCF4C052D02709BB77CEFCE97448254C4357239D6A27F74` |
| `12.ADR_인증.md` | `38DF0D14288FB20E3CB45BC10EB03C5BA8BB092BD4E8C6ED3BC1EC855734B7DC` |
| `13.MVP_구현_시작_계획.md` | `18E83AD1F438B62489D2084C8CA6B7733F320F27B9BCF69F103C8EB11752C185` |
| `14.ADR_보안_시험.md` | `692486504218F9C17D6FDAF5D553E50C8B77210A307DBB8C9B9454DF289E5992` |
| `15.ADR_확장형_증적_점검팩_AI_거버넌스.md` | `361C4094D9A2A1C039C75176D16FC5AB9A36410B03FCD5D3BDD7A73EDA477B2C` |
| `16.ADR_PostgreSQL_pgvector_가이드_검색.md` | `55D2859C583388C2625286F8CA5891DB6F353FB1865F1003FD11D5E9F844F292` |
| `17.ADR_vLLM_호환_모델_게이트웨이.md` | `AE50E370B3E2C0A99766C5EE76656B14BA794E3FA65AB62C4972CC7D8DC91770` |
| `18.ADR_결과_중심_AI_PC_보안_도우미.md` | `C005E8D54276BCFB83ED2F564ADAD9F9E08C7B06D228A9A43AE725BF97E1AEA2` |
| `19.ADR_다중_플랫폼_점검_마크다운_보조_조치.md` | `0DCCF4928BD6062ADA1D8D6B44CC0E0181EBF6EEB8B63FC1B6808B2E8C5C1002` |
| `20.ADR_점검기준_목록_프로필_무코드_작성기.md` | `FD2E42461FD5650565AB21C7D04B20D9EAC1F524312282C37A8003015C35354F` |

## 6. 현재 적용 방법

- 현재 기능과 다음 작업은 [`../../구현_현황.md`](../../구현_현황.md)를 따른다.
- 구현 계획은 [`../plans/README.md`](../plans/README.md)에서 관리한다.
- 실제 시험 결과는 [`../../deploy/verification/`](../../deploy/verification/)의 날짜별 기록을 따른다.
- ADR의 `승인`, `부분 구현`, `승인 대기` 상태는 운영 승인과 같은 뜻이 아니다. 조직 서명·KMS·실장비 인수·공식 Audit Pack Gate는 별도로 통과해야 한다.

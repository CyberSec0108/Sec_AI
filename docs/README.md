# Sec_AI 문서 안내

이 폴더의 문서는 현재 제품 사용법, 운영 방법, 유지보수 기준과 향후 계획을 역할별로 나눠 관리합니다. 현재 완료 상태와 정확한 다음 작업의 정본은 [`../구현_현황.md`](../구현_현황.md)입니다.

2026-08-07에 `adr/`, `guides/`, `maintenance/`, `plans/`의 모든 Markdown을 현재 source·Schema·migration·검증 기록과 대조했습니다. ADR 원문과 검증 기록은 이력으로 보존하고 현재 상태 주석을 추가했으며, 사용자 안내와 계획은 현재 기능·잔여 Gate 중심으로 정리했습니다. `docs/AGENTS.md`는 제품 설명서가 아닌 작업 규칙이고 파일 카탈로그는 생성 문서이므로 각각 별도 관리합니다.

## 현재 제공하는 기능

| 기능 | 현재 범위 | 상태 |
|---|---|---|
| Windows 점검 | Windows 10·11 x64 자동 식별, PC-01~PC-18 읽기 전용 점검, 관리자 동의형 5개 추가 점검, 결과·PDF·AI 설명 | 개발 환경 `LIVE`, DRAFT 판정 |
| Linux 중앙 점검 | 관리자가 등록한 서버에 SSH 공개키로 접속, OS 자동 식별, U-01~U-67 점검, 결과·PDF·AI 설명 | Ubuntu 22.04·24.04, Debian 12, Rocky·AlmaLinux 9 지원, RHEL 9 Pilot |
| Linux 원샷 점검 | 공용 x86_64 실행파일이 배포판을 자동 식별하고 온라인 제출 또는 오프라인 업로드 | 개발용 임시 서명·다운로드 제공, 조직 서명 대기 |
| 스위치 점검 | 등록한 Aruba AOS-CX 10.13 장비를 인증서 고정 REST GET으로 읽기 전용 점검, N-01~N-38 결과·PDF·AI 설명 | 개발 환경 `LIVE`, `DRAFT` |
| 점검 결과 | Windows·Linux·Switch 이력, 사용자·조직 범위 조회, 저장된 AI 설명 복원 | append-only 저장·RLS 적용 |
| 가이드 질의 | 승인된 KISA 직접 근거와 공공기관 보완 문서를 통합 검색한 LLM 스트리밍 답변·출처 표시 | 통합 검색 8종, 품질 benchmark 대기 |
| 알려진 취약점 점검 | Windows 인벤토리와 NVD·OSV 공개 자료 비교, 구성요소 묶음·필터·검색·공식 출처 기반 한글 번역 | 후보 비교 기능이며 제조사 확정 판정 아님 |
| 관리자 운영 | 계정 승인, Linux 서버 등록·키 발급·host key 확인, 조직 기본 기준, 복구 상태와 AI 연결 상태 확인 | 개발 환경 `LIVE` |

`LIVE`는 현재 개발 환경에서 UI·API·권한·시험이 연결됐다는 뜻입니다. 운영 승인, 조직 서명 또는 공식 Finding까지 완료됐다는 뜻은 아닙니다.

## 사용자 문서

- [`guides/초보자_사용_안내.md`](guides/초보자_사용_안내.md) — 로그인부터 점검 결과 확인까지 가장 쉬운 안내
- [`guides/Windows_Linux_Switch_통합_점검_초보자_안내.md`](guides/Windows_Linux_Switch_통합_점검_초보자_안내.md) — 플랫폼별 준비·실행·결과·재점검
- [`guides/Windows_알려진_취약점_점검_안내.md`](guides/Windows_알려진_취약점_점검_안내.md) — 자동 비교 완료·제외 사유와 공식 출처 한글 설명 읽는 법
- [`guides/통합_점검_이력_보존_안내.md`](guides/통합_점검_이력_보존_안내.md) — 과거 결과와 AI 설명 복원 범위
- [`guides/사용자_정의_점검기준_안내.md`](guides/사용자_정의_점검기준_안내.md) — 현재 수정 가능한 기준과 아직 제공하지 않는 Builder 구분

## Linux·다운로드·운영 문서

- [`guides/회사_내부망_Linux_SSH_점검_UI_배포_운영_안내.md`](guides/회사_내부망_Linux_SSH_점검_UI_배포_운영_안내.md) — 관리자 서버 등록과 중앙 SSH 점검
- [`guides/KISA_2026_UNIX_Linux_점검_안내.md`](guides/KISA_2026_UNIX_Linux_점검_안내.md) — U-01~U-67 수집·판정 구조
- [`guides/Linux_원샷_VM_시험_안내.md`](guides/Linux_원샷_VM_시험_안내.md) — Ubuntu·Rocky VM 반복시험
- [`guides/Windows_Linux_임시서명_다운로드_점검_안내.md`](guides/Windows_Linux_임시서명_다운로드_점검_안내.md) — 개발용 일회용 다운로드 코드 사용법
- [`guides/다른_PC_설치_및_이전_안내.md`](guides/다른_PC_설치_및_이전_안내.md) — 다른 개발 PC로 안전하게 이전
- [`guides/Docker_구성_볼륨_시작_중지_이전_실행_안내.md`](guides/Docker_구성_볼륨_시작_중지_이전_실행_안내.md) — 서비스·볼륨·시작·중지·이전

전체 사용자 문서 목록은 [`guides/README.md`](guides/README.md)에서 확인합니다.

## 개발·설계 문서

- [`maintenance/README.md`](maintenance/README.md) — 변경 유형별 유지보수 문서
- [`maintenance/유지보수_가이드.md`](maintenance/유지보수_가이드.md) — 작업 시작·검증·장애 대응
- [`maintenance/수집기_구조_판정_기준_유지보수_상세가이드.md`](maintenance/수집기_구조_판정_기준_유지보수_상세가이드.md) — 플랫폼 수집기와 판정 유지보수
- [`maintenance/프로젝트_구조_및_파일_기능_카탈로그.md`](maintenance/프로젝트_구조_및_파일_기능_카탈로그.md) — 생성 도구로 관리하는 파일 카탈로그
- [`adr/README.md`](adr/README.md) — 승인·부분 승인된 아키텍처 결정과 과거 기준선
- [`plans/README.md`](plans/README.md) — 현재 남은 구현·운영 전환 계획

## 대회 제출 문서

- [`submission/README.md`](submission/README.md) — 오픈소스 개발대회 제출 문서 목차
- [`submission/오픈소스_개발대회_결과보고서_SBOM_AI모델_명세.md`](submission/오픈소스_개발대회_결과보고서_SBOM_AI모델_명세.md) — 심사표에 맞춘 결과보고서, SBOM, AI 모델·데이터·라이선스 명세와 제출 전 체크리스트

대회 문서는 현재 상태를 과장하지 않는 제출 초안입니다. 팀 정보·공개 URL은 참가팀이 입력하고,
프로젝트 자체 라이선스와 PyMuPDF·Redis·AIStor·공공기관 PDF 재배포 Gate를 해소한 뒤 최종본으로
사용해야 합니다.

## 문서의 우선순위

내용이 서로 다르면 다음 순서로 판단합니다.

1. 최신 사용자 요청
2. 실제 source·Schema·migration·실행 가능한 시험
3. [`../구현_현황.md`](../구현_현황.md)와 최신 [`../deploy/verification/`](../deploy/verification/) 기록
4. 승인된 ADR
5. 계획 문서

계획에 적혀 있다는 이유만으로 기능을 완료로 보지 않습니다. AI 설명은 공식 판정을 바꾸지 않으며, Windows·Linux·Switch의 현재 결과는 승인된 운영 Finding이 아닌 개발용 판정입니다.

## 폴더 역할

| 폴더 | 역할 | 수정 원칙 |
|---|---|---|
| [`guides/`](guides/README.md) | 사용자·관리자 실행 안내 | 현재 화면과 실제 절차만 설명 |
| [`plans/`](plans/README.md) | 미완료 작업과 운영 전환 계획 | 완료된 작업은 현황 요약으로 축소 |
| [`adr/`](adr/README.md) | 의사결정·보안 경계 | 과거 승인 이력을 임의로 삭제하지 않음 |
| [`maintenance/`](maintenance/README.md) | 개발·검증·구조 설명 | 생성 카탈로그는 도구로만 갱신 |
| [`submission/`](submission/README.md) | 대회 결과보고서·SBOM·AI 명세 | 공개 release의 실제 URL·license·SBOM·시험 근거로 제출 직전 갱신 |
| [`../deploy/verification/`](../deploy/verification/) | 실행 당시 검증 증거 | 과거 기록을 현재 설명으로 덮어쓰지 않음 |

## 문서 작성 시 지킬 사항

- 실제 비밀번호, token, cookie, private key, 사용자·조직 식별정보와 원본 증적을 넣지 않습니다.
- 명령어는 프로젝트 루트를 기준으로 작성합니다.
- 기능 상태는 `LIVE`, `PREVIEW`, `BLOCKED`, `HIDDEN`으로 표시합니다.
- 검증하지 않은 기능을 `LIVE` 또는 완료로 쓰지 않습니다.
- 새 장기 문서는 해당 하위 README에 연결하고 상대 링크를 검사합니다.
- 현재 상태를 여러 문서에 길게 복제하지 않고 [`../구현_현황.md`](../구현_현황.md)를 연결합니다.

# 알려진 취약점 점검·후속 조치 발전 계획

## 현재 구현

Windows 최근 점검 인벤토리를 NVD·OSV 공개 Feed와 비교하는 개발 기능이 동작합니다.

- Windows OS·build·KB·설치 프로그램·AppX 수집
- Python·Node.js·Java 설치/lock file/local cache 구성요소 수집
- NVD·OSV 후보와 append-only PostgreSQL cache
- 구성요소별 후보 묶음, ecosystem·높음 이상 필터와 검색
- CVE alias 정리와 GHSA·PYSEC 원식별번호 보존
- 자동 비교 완료와 제외 사유 분리
- 공식 출처·원문 링크·원문 사실 보존 한국어 번역
- 선택형 AI 쉬운 설명과 공식 자료 번역 분리
- offline cache의 기준 시각·오래됨 표시

이 결과는 영향 가능성 후보이며 제조사 확정, 공식 Finding 또는 수정 완료 판정이 아닙니다.

## 다음 단계

### VULN-05 Windows 정확도

- 일반 프로그램의 검토된 공급자·제품·CPE mapping
- Microsoft KB와 OS build의 적용성 계약
- 설치 경로·실행 여부·제품 architecture를 사용한 후보 축소
- 제조사 advisory와 수정 버전 검증
- VEX `affected/not_affected/fixed/under_investigation` 분리
- Feed가 없거나 오래됐을 때 false safe 방지 benchmark

### VULN-06 Offline Feed Bundle

- NVD·OSV·KEV·vendor 자료의 허용 목록
- 생성 시각·만료·source hash·Schema version
- 조직 Ed25519 서명과 이동식 매체 반입 검사
- 이전 세대 rollback과 폐기 목록
- 온라인·오프라인 동일 후보 결과 회귀

### VULN-07 Linux

- dpkg/rpm 패키지와 distribution advisory 식별
- Ubuntu USN, Red Hat 계열 advisory 등 공급자 자료 연결
- backport version 비교와 distro epoch 처리
- container·language package 범위 분리

### VULN-08 Switch

- 제조사·model·NOS·firmware exact 식별
- Aruba/Cisco 공식 advisory 연결
- 장비 수집 결과와 외부 advisory 근거 분리

### VULN-09 승인형 후속 조치

처음에는 `PLAN_ONLY`로 조치 계획만 만듭니다. 실제 변경은 대상·명령·영향·backup·rollback·승인·재점검 계약이 모두 있을 때 별도 기능으로 추가합니다. AI 또는 Agent가 임의 shell·패치·재부팅을 실행하지 않습니다.

## 완료 기준

- 후보, 공급자 확정, KEV, VEX와 조직 Finding이 화면·DB에서 구분됩니다.
- Feed 장애·오래됨·자료 부재가 `안전`으로 표시되지 않습니다.
- 원문·번역·AI 설명이 각각 식별됩니다.
- 타 조직 인벤토리와 후보 결과가 노출되지 않습니다.
- 조치는 사람 승인과 rollback·재점검 없이는 실행되지 않습니다.

사용법은 [`../guides/Windows_알려진_취약점_점검_안내.md`](../guides/Windows_알려진_취약점_점검_안내.md)를 확인합니다.

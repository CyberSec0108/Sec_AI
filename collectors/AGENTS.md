# `collectors` 영역 코딩 에이전트 지침

적용 범위는 배포 가능한 one-shot 진입점·Probe·계약이다. 루트 지침과
[`README.md`](README.md),
[`수집기 상세 가이드`](../docs/maintenance/수집기_구조_판정_기준_유지보수_상세가이드.md)를
먼저 읽는다.

## 1. 현재 범위

- Windows: Windows 10·11 x64 PC-01~18, 일반 권한 15개와 사용자 동의 관리자 권한 5개 Probe. Server/DC는 별도 기준이 없어 차단
- Linux one-shot: Ubuntu 22.04·24.04, Debian 12, Rocky·RHEL·AlmaLinux 9 x64 자동 식별과 고정 42개 Probe
- Switch: 이 폴더가 아니라 `src/security_audit/platforms/aruba_rest.py`가 수집한다.

`collectors/one_shot`은 배포 진입점과 정적 계약을 두고, 실행·검증 핵심 로직은
`src/security_audit/collector`와 `src/security_audit/supply_chain`에 둔다.

## 2. 변경 순서

1. Control이 요구하는 최소 사실과 권한을 정의한다.
2. Probe ID·version·exact argv·허용 출력과 timeout을 계약에 추가한다.
3. 실패·권한 부족·timeout·초과 출력 Fixture를 먼저 작성한다.
4. parser와 redaction을 구현한다.
5. Package/Manifest Schema와 canonical hash 영향을 확인한다.
6. 관련 DRAFT rule과 결과 표시를 연결한다.
7. 일반/관리자 또는 online/offline 경계를 각각 검증한다.
8. build·SBOM·서명·악성코드 검사는 Release 단계에서 별도로 수행한다.

## 3. 안전 규칙

- 읽기 전용 command만 허용한다. 설정 변경·remediation을 Collector에 넣지 않는다.
- 사용자 입력 command, raw shell fragment, 임의 경로, wildcard를 실행하지 않는다.
- PowerShell은 고정 script와 검증된 인수만 사용한다.
- Linux command는 manifest의 exact argv만 실행한다.
- 관리자/UAC/sudo를 자동으로 올리지 않는다.
- timeout, stdout/stderr 상한, process tree 종료를 유지한다.
- 원본 command 출력은 최소 fact로 정규화하고 secret·계정명·host 식별자를 redaction한다.
- Probe 실패를 보안 취약 `FAIL`로 바꾸지 않는다.
- 동일 입력 Package의 canonical hash와 결과가 결정적이어야 한다.

## 4. 계약 파일

`one_shot/contracts`의 파일은 과거 IMP와 현재 Launcher·AI 입력 경계를 고정한다. 파일명이
오래됐다는 이유로 삭제하거나 의미를 바꾸지 않는다. 새 version이 필요하면 소비자, Fixture,
검증 기록과 build를 함께 갱신한다.

Windows PowerShell Probe는 `one_shot/probes/windows/powershell`, Linux 공용 진입점은
`linux_entrypoint.py`에서 찾는다. `linux_ubuntu24_entrypoint.py`와
`linux_rocky9_entrypoint.py`는 이전 산출물 호환 진입점이므로 임의로 제거하지 않는다.

## 5. 검증

- Manifest/allowlist/Package 관련 unit·contract 시험
- 잘못된 argv, timeout, 큰 출력, encoding, 권한 부족, 부분 수집 시험
- Windows 일반/관리자 분리와 사용자 동의 시험
- Linux 6개 배포판 exact support detection과 online/offline 제출 시험
- 실제 호스트/VM 시험은 비식별 snapshot과 설정 diff 0을 기록
- build 변경은 exact lock, SBOM, 취약점, ClamAV·Defender, 서명 상태 확인

실제 secret이나 VM credential 없이 수행할 수 없는 시험은 합성시험으로 대체했다고 명확히
기록하고 실제 Gate를 완료로 표시하지 않는다.

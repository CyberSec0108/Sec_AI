# Linux 원샷 점검 프로그램 현황·체크리스트

## 현재 결과

`LIN-ONESHOT-01~09`의 개발 기능은 구현됐습니다. 공용 `secai-linux-check-x86_64`가 로컬 OS를 자동 식별하고, 고정 읽기 전용 Probe를 실행한 뒤 online 제출 또는 Evidence ZIP+descriptor JSON을 만듭니다.

현재 개발용 다운로드는 Ed25519 Catalog·파일 SHA-256·만료·10분 1회용 코드로 보호됩니다. `DEV-SIGNED-TEST`이며 조직 운영 서명은 아닙니다.

## 단계별 상태

| 단계 | 내용 | 상태 |
|---|---|---|
| LIN-ONESHOT-01 | Manifest·Evidence·Package Schema | 완료 |
| LIN-ONESHOT-02 | 일반 권한 최소 Probe | 완료 |
| LIN-ONESHOT-03 | 추가 권한 목록·사용자 동의·sudo 분리 | 완료 |
| LIN-ONESHOT-04 | Ubuntu/RHEL 계열 고정 allowlist Adapter | 완료 |
| LIN-ONESHOT-05 | canonicalize·hash·Package 검증 | 완료 |
| LIN-ONESHOT-06 | 일회용 code exchange·online 제출 | 완료 |
| LIN-ONESHOT-07 | offline ZIP+descriptor 업로드 | 완료 |
| LIN-ONESHOT-08 | 공용 launcher 자동 식별·지원 Catalog | 완료 |
| LIN-ONESHOT-09 | 임시 서명·다운로드·기본 공격시험 | 완료 |
| LIN-ONESHOT-10 | 실제 VM·조직 서명·취소/장애 Release Gate | 부분 완료 |

## LIN-ONESHOT-10 남은 일

- Ubuntu·Rocky 정상/취약 snapshot 전체 U-01~U-67 2회 반복
- Ubuntu 22.04·Debian 12·AlmaLinux 9 실제 VM 인수 완료; RHEL 9 공식 구독 image 인수
- 권한 부족·중단·재시도·timeout·대용량 출력
- online 중단 후 offline 전환과 중복 제출 멱등성
- Package·descriptor·binary 변조, 만료·재사용 코드 차단
- 조직 Publisher 서명·timestamp·폐기·회전
- 최신 취약점 DB와 악성코드 검사 결과를 Release Manifest에 고정
- KMS/HSM, 운영 다운로드 TLS·감사·속도 제한

## 유지할 안전 경계

- 사용자 입력 command를 실행하지 않습니다.
- `sudo` 비밀번호를 읽거나 저장하지 않습니다.
- 부분 증적으로 `PASS`를 만들지 않습니다.
- Package 검증 실패 자료를 정규화·판정으로 넘기지 않습니다.
- offline 결과의 장치 보증 수준을 `LOW`로 표시합니다.
- 미지원·충돌 플랫폼은 자동 fallback하지 않습니다.

VM 실행법은 [`../guides/Linux_원샷_VM_시험_안내.md`](../guides/Linux_원샷_VM_시험_안내.md)를 확인합니다.

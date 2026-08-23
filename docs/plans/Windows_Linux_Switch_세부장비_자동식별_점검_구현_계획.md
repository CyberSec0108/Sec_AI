# Windows·Linux·Switch 자동 식별 확장 계획

## 제품 원칙

사용자는 `Windows`, `Linux`, `스위치`의 큰 종류만 선택합니다. 세부 OS·배포판·제조사·NOS·version·architecture는 읽기 전용 사전 확인값으로 시스템이 결정합니다.

```text
최소 fingerprint 수집
→ 정규화
→ 서명·version이 있는 Support Catalog exact 비교
→ SUPPORTED/PARTIAL/PILOT/BLOCKED 결정
→ 허용 Adapter와 Audit Pack 선택
→ 실행
```

미지원·불완전·충돌·다중 후보는 비슷한 플랫폼으로 추정하지 않고 차단합니다.

## 현재 Catalog

| 플랫폼 | 대상 | 현재 상태 |
|---|---|---|
| Windows | Windows 11 x64 | `SUPPORTED` 개발 경로 |
| Windows | Windows 10 x64 | 공통 Probe를 쓰는 `SUPPORTED`; clean VM E2E 대기 |
| Windows | Windows Server·Domain Controller | 별도 기준이 없어 `BLOCKED` |
| Linux | Ubuntu 22.04·24.04, Debian 12, Rocky·AlmaLinux 9 x64 | 실제 VM 근거가 있는 `SUPPORTED` |
| Linux | RHEL 9 x64 | 공식 구독 image 인수 전 `PILOT` |
| Switch | 등록된 Aruba AOS-CX 10.13 | exact 개발 지원 |
| Switch | Cisco와 다른 NOS | 미지원 |

Linux 중앙 화면과 one-shot에서 배포판 선택 UI를 제거했습니다. Windows/Linux Manifest·Package Schema와 DB CHECK도 Catalog 값에 맞춰 확장했습니다.

## 다음 단계

### AUTO-SELECT-03 실제 플랫폼 인수

- Windows 10·11 clean/취약/관리자 권한 회귀
- 지원 Linux 5종 정상·취약·권한 부족 VM 확대와 RHEL 9 공식 image 인수
- Aruba 실제 장비/OVA 반복 실행
- locale·version suffix·architecture 변형 fixture

### AUTO-SELECT-04 Catalog 운영

- Catalog Schema와 서명·version·폐기 상태
- Adapter·Pack·artifact compatibility matrix
- Pilot→Supported 승격 승인과 rollback
- 화면에 식별 근거와 차단 이유 표시

### AUTO-SELECT-05 추가 플랫폼

1. 실제 장비/VM과 공식 자료 확보
2. 최소 fingerprint·지원 범위 정의
3. 읽기 전용 Adapter와 strict fixture
4. false PASS·권한·timeout 공격시험
5. DRAFT Pack과 결과/PDF/AI 계약
6. 조직 승인 뒤 Catalog 게시

Cisco라는 이름만 보고 Aruba Adapter를 재사용하거나, RHEL 계열이라는 이유로 OS 식별 충돌을 무시하지 않습니다.

## 완료 기준

- 사용자가 세부 종류를 선택하지 않아도 정확한 Adapter가 선택됩니다.
- 미지원·충돌 입력은 실행 전에 차단됩니다.
- fingerprint와 선택 Catalog version/hash가 결과에 남습니다.
- Catalog 변경이 과거 결과를 바꾸지 않습니다.
- 실제 플랫폼별 정상·취약·오류 반복시험을 통과합니다.

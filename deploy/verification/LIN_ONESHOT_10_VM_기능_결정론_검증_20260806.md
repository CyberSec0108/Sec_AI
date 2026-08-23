# LIN-ONESHOT-10 VM 기능·결정론 검증

| 항목 | 내용 |
|---|---|
| 검증일 | 2026-08-06 |
| 대상 | Ubuntu Server 24.04, Rocky Linux 9.8 VMware 정상·취약 스냅샷 |
| 중앙 경로 | DEV-LOCAL 로그인 → 일회용 code → VM 원샷 수집 → 온라인 제출 → PostgreSQL 결과 |
| 결과 성격 | KISA UNIX U-01~U-67 `DRAFT`, 공식 인증·운영 Finding 아님 |
| 종합 결과 | 정상·취약 핵심 반복 Gate PASS, 조직 서명과 LIN-ONESHOT-10 장애·취소 세부 경로는 보류 |

## 1. 공급망 선행 Gate

### 빌드 이미지 최소화

- compiler stage: `quay.io/pypa/manylinux_2_34_x86_64` exact digest
- final builder stage: `registry.access.redhat.com/ubi9-minimal` exact digest
- final stage에서 빌드 후 불필요한 `curl-minimal`, `libcurl-minimal`, `microdnf` 제거
- CPython `3.14.6` 공식 source SHA-256 확인
- CPython 3.14 branch 공식 patch와 patch SHA-256 확인 뒤 다음 세 항목 backport
  - `CVE-2026-11940`
  - `CVE-2026-11972`
  - `CVE-2026-15308`
- backport 뒤 `test_tarfile`, `test_htmlparser` 실행 PASS

최종 build image digest:

```text
sha256:f537f942f7e9ad151cc9f6c0af348963bf8a3efec1ad7169cd9e3b7a97d891c9
```

### 최신 취약점 DB 검사

| 항목 | 값 |
|---|---|
| Grype image | `anchore/grype:latest@sha256:1e71065c0a4cff3e6bd3b8add525ffac4343eb4971694eb90a31cf6d4d3e85db` |
| DB schema | `v6.1.9` |
| DB built | `2026-08-05T07:04:14Z` |
| DB status | `valid` |
| 검사 방식 | Docker socket 미노출, `docker save` 읽기 전용 TAR 검사 |
| VEX 반영 | 실제 backport 3건만 `fixed`로 제외 |
| 결과 | `Critical 0`, `High 0`, `Medium 71`, VEX ignored 3 |

최신 DB의 최초 재검사에서는 UBI의 불필요한 curl RPM에서 High 12건이 새로 확인됐다.
해당 패키지와 package manager를 final builder에서 제거한 뒤 정확한 최종 digest를 다시
검사했다. Medium 71건은 존재하므로 별도 위험 검토 대상이며 High Gate 통과가 전체
취약점 0을 의미하지 않는다.

### 최종 개발 산출물

산출물 위치:

```text
runtime/linux-oneshot-artifacts/build-20260806T021722Z
```

| 파일 | SHA-256 | ClamAV |
|---|---|---|
| `secai-linux-check-ubuntu24-x86_64` | `42413e0d49d96c97b6fe1e1c08bf9ebb84b7e35499ddd24d6c79819400214443` | CLEAN |
| `secai-linux-check-rocky9-x86_64` | `08a716a2ed343ff20f76a56b27dafe5b1de0ba7ec7fb869878e8ab8833d04dfd` | CLEAN |

ClamAV는 `1.4.5/28058/Sun Jul 12 06:25:26 2026`이었다. Rocky Linux 9 최소
container에서는 system Python 없이 `--help`가 실행됐다. Ubuntu 24.04 container도
독립 실행을 통과했지만 해당 base image에는 system Python 3이 존재해 “Python 없음”으로
표시하지 않는다.

release manifest에는 SBOM, 제3자 고지와 OpenVEX exact hash를 묶었다. 실제 조직
private key가 없으므로 최종 산출물은 계속 `DEV-UNSIGNED`, `download_allowed=false`다.
`SIGNED-PILOT`을 key path와 key ID 없이 요청하면 빌드 전에 거부됨을 확인했다.

## 2. VM·스냅샷

| OS | 스냅샷 | 의미 |
|---|---|---|
| Ubuntu 24.04 | `secai-initial-vulnerable` | 의도적으로 `PASS_MAX_DAYS 99999`인 취약 기준 |
| Ubuntu 24.04 | `secai-normal` | 계정 수명·UMASK·세션·SSH 안전 기본값 적용 |
| Rocky 9.8 | `secai-initial-vulnerable` | firewalld·DNF cache가 없는 최소 취약 기준 |
| Rocky 9.8 | `secai-normal` | firewalld·SSH 허용·DNF cache·안전 기본값 적용 |
| Rocky 9.8 | `secai-normal-patched` | normal + `U-64` 대기 판정 55개를 보안 갱신해 대기 0 확인 |

VMware 공유 폴더는 사용하지 않았다. Windows에서 OS별 산출물을 `scp`로 전송한 뒤
VM에서 SHA-256이 release manifest와 같은지 확인했다. 중앙 개발 HTTP는 VM에 직접
노출하지 않고 일시적인 SSH reverse tunnel을 사용했다. 실제 운영 HTTPS에서는 이
tunnel이 필요 없다.

## 3. 실제 반복 결과

결과 hash는 run ID, asset ID와 수집 시각을 제외하고 Control ID·상태·result code·확인
요약·Evidence normalized SHA-256을 canonical JSON으로 만든 논리 hash다.

| 환경 | Run 1 / Run 2 | 판정 집계 | 반복 논리 hash | 설정 diff |
|---|---|---|---|---|
| Ubuntu 취약 | `8ec158c6-58bd-42b5-8da1-6ee4390056c8` / `f94bcc2e-a9fd-418c-8db2-e51dcf85df3a` | FAIL 9, N/A 18, PASS 34, REVIEW 6 | `611b98e6682fd99b6c2e870ece0b1d22cbef0731721547e3b1abf0aa32f5b666` 두 번 일치 | `c3ff66b18a192dccca246394ec9374d9a3d65febda00b7b48562022cd126ad0b` 전후 일치 |
| Ubuntu 정상 | `049bc949-87b5-4384-9bd6-b0681e6bb084` / `8cd46980-23f7-48f2-94ec-5b4eb1f4aa32` | FAIL 8, N/A 18, PASS 35, REVIEW 6 | `e4926451ee370d523fa033f74da4c3c71c3c6ca48dd3feb9eb8c6fa5a183f0ac` 두 번 일치 | `bbef5dd69b36552b16959ecd83950d593e7896d3f2394e0c4bbfab7379dafcb1` 전후 일치 |
| Rocky 취약 | `f9f3e6d3-e90f-4c1b-903f-ebdbdb6cdd7b` / `127fda40-a7f6-42ba-92b3-d3a54ae70da0` | ERROR 4, FAIL 9, N/A 16, PASS 32, REVIEW 6 | `f4737ea67036aeb5d7d5450eeeb366659c476aee183b9b370813604e5a85bda8` 두 번 일치 | `76aa706109017454033877255d4e3b665fb8c9a4a42c254d954e8c22255b2142` 전후 일치 |
| Rocky patched 정상 | `d839adb8-1493-4b45-a8e9-9757fbc526bd` / `854d5c29-3c10-413a-b329-55cdc77ceee8` | FAIL 8, N/A 18, PASS 35, REVIEW 6 | `5087c1bcc9c3875ed97910268a59704b2c1c5a84fe68bb1fcdcdc32d2d6d74f5` 두 번 일치 | `33d92cb9ef197d37b0b94a09958bb374fdb7081876477e8fd94ab507234fddea` 전후 일치 |

Ubuntu는 네 실행 모두 `42/42 COLLECTED`였다. Rocky 취약은 firewalld executable과
DNF security cache 부재로 `39 COLLECTED + 3 ERROR`였고 그 결과 U-28·45·49·64가
ERROR였다. 이를 숨기지 않고 원인을 triage했다. Rocky normal과 patched normal은
`42/42 COLLECTED`였다.

상태 변화:

- Ubuntu normal: `U-30 FAIL → PASS`
- Rocky normal: `U-28 ERROR → PASS`, `U-45·49 ERROR → N/A`, `U-64 ERROR → FAIL`
- Rocky 보안 업데이트 뒤: `U-64 FAIL → PASS`

Collector는 모든 성공 실행에서 `ONLINE-AUTHENTICATED`, 보증 수준 `MEDIUM`으로
PostgreSQL에 한 번만 commit됐다. 공식 Finding write는 계속 금지됐다.

## 4. 코드 회귀

```text
Linux one-shot contract/unit/API focused Pytest: 36 PASS
linux release TDD: VEX 미지원 상태에서 5개 예상 실패 확인 후 구현, 5 PASS
Ruff changed files: PASS
mypy --strict changed source 2 files: PASS
linux-self-scan.js node --check: PASS
```

기존 `LIN-ONESHOT-01~09` 집중 기준선 62 PASS는 유지한다. 이번 추가 변경은 release
manifest의 VEX hash binding과 빌더 최소화에 집중했으며 전체 저장소의 기존 불일치까지
완료로 재표시하지 않는다.

## 5. 보류·다음 Gate

- 실제 조직 Ed25519 private key·승인 key ID·공개키 배포·폐기 정보가 없어 조직 서명
  적용은 차단됐다. 테스트 key를 조직 key로 위장하지 않았다.
- 일반 사용자 취소, 추가 권한 거부, sudo 실패, 실제 timeout·출력 상한, 강제 종료,
  네트워크 중단 오프라인 저장, 제출 중 서버 재시작은 LIN-ONESHOT-10의 남은 세부 Gate다.
- 브라우저 IDOR·CSRF·중복 제출·DB replay 공격은 LIN-ONESHOT-11 범위다.
- 운영 HTTPS, 제한 사용자 Pilot과 운영 Pack 승인은 LIN-ONESHOT-12 범위다.

따라서 `LIN-ONESHOT-10` 전체를 완료로 표시하지 않는다. 정상·취약 실제 VM 반복과
결정론·설정 diff 핵심 Gate만 PASS이며, 조직 서명 전까지 UI 운영 다운로드는 계속
차단한다.

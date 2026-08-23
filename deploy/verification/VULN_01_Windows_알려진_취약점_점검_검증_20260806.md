# VULN-01 Windows 알려진 취약점 점검 검증

| 항목 | 결과 |
|---|---|
| 기준일 | 2026-08-06 |
| 상태 | **PASS — DEV-LOCAL Windows OS 후보 점검** |
| 사용자 이름 | `알려진 취약점 점검` |
| 지원 범위 | Windows 11 OS release·build·UBR·architecture |
| 제외 범위 | 공식 Finding, 제조사 확정, 설치 프로그램·KB·AppX, 이동식 서명 Offline Feed Bundle, Linux·Switch |

## 1. 구현 결과

- 홈의 `에이전트 활용` 카드를 제거하고 실제 `/ui/vulnerability-check` 기능으로 교체했다.
- Windows Collector/Launcher가 OS 이름·표시 version·build·UBR·architecture만 비식별
  `vulnerability_inventory`로 반환한다.
- Browser와 Collector는 외부 Feed를 직접 호출하지 않는다. 인증·CSRF를 통과한 중앙 API만
  고정 NVD CVE API endpoint에 exact CPE를 전송한다.
- NVD 응답은 CVE ID·요약·CVSS·게시/수정 시각·CISA KEV 표시로 제한해 정규화한다.
- migration `0029_vulnerability_feed`의 `vulnerability_feed_snapshots`는 공용 Feed snapshot을
  append-only로 저장한다. Runtime role은 `SELECT·INSERT`만 가지며 `UPDATE·DELETE`는 없다.
- 자료 나이는 72시간까지 `CURRENT`, 7일까지 `STALE`, 이후 `EXPIRED`다. 유효 자료가 없거나
  만료된 경우 0건이나 안전으로 표시하지 않는다.
- 결과는 알려진 취약점 **후보**이며 공식 Finding을 생성하거나 기존 KISA 판정을 바꾸지 않는다.
- 결과 hash는 RFC 8785 canonical JSON SHA-256으로 고정한다.

## 2. 실제 온라인·오프라인 장애 폴백

개발 기준선 Windows 11 25H2, build `26200.8894`, x86_64로 중앙 서버 NVD 동기화를 수행했다.

```text
provider: NVD
product_key: MICROSOFT_WINDOWS_11_25H2_10_0_26200_8894_X64
record_count: 1
candidate: CVE-2026-45585
official_finding_created: false
```

이후 외부 조회를 강제로 실패시켜 DB snapshot만 사용했으며 `LOCAL_CACHE_FALLBACK`·`CURRENT`로
같은 후보 1건을 복원했다. 이는 제품이 해당 CVE에 확정 영향받는다는 뜻이 아니며 Microsoft
공급자 권고와 fixed build 대조가 남아 있다.

현재 오프라인 기능은 **중앙 서버가 이미 보유한 DB cache를 재사용하는 네트워크 장애 폴백**이다.
완전 폐쇄망이나 다른 서버로 이동하는 서명 Feed Bundle은 구현하지 않았다.

## 3. 자동 검증

### 실패 시험

구현 전 신규 시험은 다음 이유로 실패했다.

```text
ModuleNotFoundError: security_audit.application.known_vulnerability_check
```

### 집중 Pytest

```powershell
docker compose --project-directory C:\Users\Hala\Desktop\Sec_AI -f deploy\compose\compose.yml -f deploy\compose\compose.dev.yml run --rm -e SECAI_DEMO_CSRF_TOKEN=vuln-test-csrf dev-tools -m pytest tests/unit/test_known_vulnerability_check.py tests/unit/test_imp041_scan_lifecycle.py tests/unit/test_imp040_product_launcher.py::test_feature_registry_has_one_live_scan_and_hides_internal_draft tests/unit/test_imp040_product_ui.py::test_product_home_leads_with_one_click_scan_and_clear_feature_states tests/unit/test_imp040_product_ui.py::test_product_home_maintenance_markers_and_dev_web_mount tests/unit/test_imp040_product_ui.py::test_product_download_cta_is_above_larger_feature_cards -q
```

결과: `20 passed, 1 warning`.

검증 내용은 exact CPE, 임의 필드/URL 거부, 고정 NVD endpoint, cache 폴백, stale/expired,
false safe 방지, 100회 결정론, 민감 필드 부재, 인증·CSRF API, 쉬운 화면 이름, migration 권한,
Windows Launcher 인벤토리를 포함한다.

### 정적 검사

```text
Ruff: All checks passed
mypy --strict: Success, no issues in 6 source files
node --check apps/web/static/app/vulnerability-check.js: PASS
```

한 번의 앞선 확대 Launcher 회귀에서 기존 port 반환 타이밍 시험 1건이
`previous Launcher did not release its port in time`으로 실패했다. 이번 기능의 집중 시험은
잠긴 개발 도구에서 20건 모두 통과했으며 포트 시험 자체를 약화하거나 건너뛰지 않았다. 전체 표준 Gate는 별도
제품 인수 단계에서 다시 실행한다.

## 4. DB·서비스 확인

```text
database revision: 0029_vulnerability_feed
runtime SELECT: true
runtime INSERT: true
runtime UPDATE: false
runtime DELETE: false
API/Gateway: healthy
```

## 5. Windows 실행 파일

| 산출물 | 결과 |
|---|---|
| unsigned build | `runtime/imp034-artifacts/build-20260806T135410Z` |
| bytes | `12,721,871` |
| SHA-256 | `f3d402448a0e5b5d3ad09cd4f9aa10f695c7631ef91900fb91f072c54a233051` |
| 공급망 | 24개 hash-lock, 의존성 알려진 취약점 0건, embedded resource 109개 |
| 악성코드 검사 | ClamAV `CLEAN`, Microsoft Defender `CLEAN` |
| 개발 서명 | `runtime/imp035-artifacts/acceptance-20260806T135507Z` |
| 서명 후 SHA-256 | `4b9a87b4e8222634d06611756006ea9fbd16a25ad019fc0f1577d6028b9cbfa9` |
| 임시 Catalog | `runtime/dev-signed-downloads/release-20260806T135544Z` |
| 서명 상태 | `DEV-SIGNED-TEST`; 조직 Publisher·운영 CRL/OCSP·clean Windows 11 Gate 미완료 |

## 6. 남은 Gate

- Microsoft 보안 권고·KB/build 기반 공급자 우선 확정/수정 판정
- 설치 프로그램·AppX·선택 library 인벤토리와 SBOM
- Ed25519 서명 Offline Feed Bundle, anti-rollback, atomic import
- 완전 폐쇄망 동일 hash E2E와 오래됨·만료·변조 Matrix
- 사용자/기술 PDF와 occurrence 계보
- Linux·Switch Adapter
- 조직 코드서명·clean Windows 11·SmartScreen 운영 인수

# IMP-027 단계 G PC-01~18 시연·Gap review

| 항목 | 결과 |
|---|---|
| 검증일 | 2026-07-23 |
| 범위 | PC-01~18 DRAFT Pack 시연·누락 Control·false PASS·전체 탐색 |
| 인수 상태 | `PASS_WITH_DEFERRED_GAPS` |
| Audit Pack | `0.6.0` `DRAFT` |
| 자동 인수 검사 | 8개 PASS |
| 비-PASS oracle | 64건 |
| false PASS | 0건 |
| 필수 PASS·FAIL·ERROR 분기 누락 | 0개 Control |
| 상태가 충돌하는 result code | 0개 |
| N/A 범위 | PC-09 한정 |
| 단계 G 차단 결함 | 0건 |
| 보류 Gap | 5건 |
| 전체 Pytest | 221 passed, 기존 Starlette warning 1건 |
| JSON Schema | 8 schemas·14 examples PASS |
| Ruff | PASS |
| mypy strict | 106 source files PASS |
| 실제 시연 | `demo-stage-g.ps1` PASS, PC-01~18·5개 상태 필터 HTTP 200 |
| Core 컨테이너 | 8개 모두 `healthy`, readiness 의존성 4개 PASS |
| 결과 지문 | `be23d63042dd70513910427a253372febcd886569a5cdf47e2fdfdbdc075f7e6` |
| API 이미지 digest | `sec-ai-mvp/audit-api@sha256:24d8b15ffa5acde02097a1f2a5806fa548e74def7c908b71de1b8cefc7026aec` |
| 시각 확인 | 앱 내 브라우저 탭 미제공으로 스크린샷 생략; 실제 HTTP 시연·UI 자동시험으로 확인 |

## 1. 시연 결과

`tools/demo-stage-g.ps1`은 실행 중인 Core에서 다음을 한 번에 확인한다.

1. API readiness와 PostgreSQL·Redis·AIStor·ClamAV 의존성
2. `IMP-027` 단계 G 인수 API와 `PASS_WITH_DEFERRED_GAPS`
3. PC-01~18 Control Coverage 18개
4. 합성 Fixture Coverage 92개
5. 비-PASS oracle 64건 중 false PASS 0건
6. 100회 전체 결과 지문 1개
7. Pack 승인 상태가 계속 `DRAFT`
8. PC-01~18 각각의 탐색 필터 HTTP 200과 화면 노출
9. PASS·FAIL·ERROR·REVIEW·N/A 상태 필터 HTTP 200

화면은 [http://localhost:18480/ui/full-audit](http://localhost:18480/ui/full-audit), 인수 JSON은 [http://localhost:18480/api/v1/demo/stage-g-review](http://localhost:18480/api/v1/demo/stage-g-review)에서 확인한다.

## 2. false PASS review

| 검사 | 결과 |
|---|---|
| 각 Control의 기본 방어 분기 | PC-01~18 모두 PASS·FAIL·ERROR 사례 보유 |
| 비-PASS 보존 | FAIL 26·ERROR 21·REVIEW 16·N/A 1, 합계 64건 모두 상태 유지 |
| 결과 코드 상태 충돌 | 같은 result code가 둘 이상의 상태를 만드는 사례 0건 |
| 적용 제외 | N/A는 조직 범위가 확인된 PC-09 WinINet 미사용 사례 1건뿐 |
| DRAFT 경계 | Pack과 합성시험 화면을 운영 공식 판정으로 표시하지 않음 |

이 검사는 현재 합성 사례 범위의 회귀를 방어한다. 실제 PC와 실제 조직 기준이 없는 상태에서 모든 현실 상황의 false PASS 가능성이 제거됐다는 뜻은 아니다.

## 3. 보류 Gap

| ID | 보류 내용 | 위험 | 목표 |
|---|---|---|---|
| `STAGEG-G01` | 실제 Windows 자료 수집기 없음 | 실제 PC 보안 상태를 주장할 수 없음 | `IMP-028~031` |
| `STAGEG-G02` | 권한 분리·Probe 무변경 안전성 미인수 | 관리자 수집의 영향을 아직 검증하지 않음 | `IMP-030` |
| `STAGEG-G03` | 실제 제품 Adapter·조직 정책 신뢰 연결 없음 | 미지원 제품·미승인 기준을 자동 PASS로 만들 수 없음 | `IMP-031` |
| `STAGEG-G04` | 온라인·오프라인 제출·서명 검증 없음 | 실제 Package 출처·재전송·변조 방어 미인수 | `IMP-032~035` |
| `STAGEG-G05` | Audit Pack 운영 승인·서명 없음 | DRAFT 결과는 공식 Finding으로 사용 불가 | 운영 Pack release Gate |

위 항목은 단계 G의 “합성 데이터 기반 PC-01~18 규칙 확대” 완료를 막지는 않지만 실제 운영을 차단한다.

## 4. Fail-closed 경계

- 8개 인수 검사 중 하나라도 실패하면 인수 API를 정상 결과로 만들지 않는다.
- Control 누락·중복, Fixture 참조·oracle 불일치는 IMP-026 통합 Gate에서 먼저 거부한다.
- 비-PASS 상태를 사용자 편의를 위해 PASS로 합치지 않는다.
- N/A를 PC-09 외 Control에 확대하지 않는다.
- DRAFT를 APPROVED나 운영 준비 완료로 표시하지 않는다.
- 보류 Gap을 완료된 기능으로 표시하지 않는다.
- 실제 Windows 자료와 개인정보는 시연에 사용하지 않는다.

## 5. 재실행

전체 품질 Gate:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\dev.ps1 -Action All
```

실행 중인 Core 시연:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\demo-stage-g.ps1
```

## 6. 다음 단계

다음은 `IMP-028` Mock Collector·Manifest verifier다. IMP-027에서는 실제 Windows Probe, 권한 상승, 제출 credential, 서명, 자동 설정 변경과 IMP-028 코드를 구현하지 않는다.

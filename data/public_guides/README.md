# 공공기관 보안 가이드 원본

이 폴더에는 공식 공공기관 사이트에서 내려받은 원본 PDF만 보관합니다.

- 원본 파일명과 내용을 변경하지 않습니다.
- 정확한 출처·해시·페이지 수·검색 역할은 `guides/public_guides_manifest.json`에서 확인합니다.
- 추출 text·chunk·embedding은 이 폴더에 만들지 않습니다.
- 이 프로젝트 내부 검색·설명에만 사용하며 원본 PDF를 외부에 재배포하지 않습니다.
- 공식 점검 판정은 이 폴더의 문서가 아니라 승인된 Audit Pack 규칙 엔진이 수행합니다.
- 승인된 개발용 원격 LLM을 사용하는 경우 질문과 검색된 공개 문서 일부 문단만 기존 모델 게이트웨이로 전달할 수 있습니다. 원본 PDF 전체·사용자 증적·Finding·자산 식별자는 전달하지 않습니다.

구현 계획은 `docs/plans/공공기관_가이드_임베딩_활용_계획.md`를 따릅니다.

## 현재 보관 현황

| 하위 폴더 | 원본 PDF |
|---|---|
| `ncsc_n2sf_1_0/` | N2SF 보안가이드라인 1.0, 보안통제 항목 해설서 |
| `kisa_zero_trust_2_0/` | 제로트러스트 가이드라인 2.0 |
| `kisa_sw_supply_chain_1_0/` | SW 공급망 보안 가이드라인 1.0 |
| `kisa_ai_security_guide_2026_errata/` | 인공지능(AI) 보안 안내서 정오 수정본 |
| `kisa_ai_threat_response_2026/` | AI 보안 위협 대응 매뉴얼 |
| `kisa_ai_red_teaming_2026/` | AI 보안 레드티밍 가이드 |

합계는 PDF 7개, 56,815,470 bytes, 997쪽입니다. 전체 파일의 exact SHA-256은
`guides/public_guides_manifest.json`에 기록되어 있습니다.

# PRODUCT-AI 로컬 vLLM·적극적 AI 활용 정합성 보완 기록

검토일: 2026-07-25

## 1. 사용자 목표

최종 제품 흐름을 다음과 같이 고정한다.

```text
내 PC 점검
→ 읽기 전용 수집
→ 승인 규칙의 공식 판정
→ 결과별 KISA 근거 검색
→ 로컬 vLLM의 종합·항목별 설명
→ 결과 문맥 후속 질문
→ 재점검 변화 설명
→ 사용자/기술 검증 PDF와 AI 모델 활용 명세
```

LLM은 공식 판정을 만들거나 바꾸지 않는다. 대신 실제 확인값과 근거를 바탕으로 전체 상태, 결과 간 관련 위험, 공식 판정과 구분된 AI 권장 우선순위, 사용자/관리자 조치, 불확실성, 재점검 변화와 후속 질문을 적극적으로 설명한다.

## 2. 모델 Runtime 결정

| profile | 의미 | 허용 범위 | 완료 의미 |
|---|---|---|---|
| `VLLM_COMPATIBILITY_TEST_DOUBLE` | 현재 OpenRouter를 vLLM 호환 API의 시험 대역으로 사용 | 합성 입력 또는 사용자가 승인한 현재 시험 환경의 비식별·정규화 점검 결과로 `/models`·`/chat/completions`·SSE·오류·모델 설정 전환과 결과 설명 흐름 확인 | 시험 환경의 OpenAI 호환 connector·결과 설명만 통과 |
| `LOCAL_VLLM_FULL_CONTEXT` | 최종 제품의 승인된 로컬 vLLM | 실제 점검 결과 설명·후속 질문·보고서 설명 | 로컬 endpoint·성능·공급망·license·외부 egress 0까지 통과 |

OpenRouter는 vLLM 자체가 아니며 개인정보 보호, 폐쇄망, 로컬 성능, 모델 파일 hash·license·악성 파일 검사와 vLLM image 공급망 Gate를 대신하지 않는다. 최종 local profile에서 OpenRouter로 자동 fallback하지 않는다.

## 3. PRODUCT-AI 반영

- `PRODUCT-AI-03`: 항목 설명에 전체 종합·관련 위험·AI 권장 우선순위·사용자/관리자 조치·불확실성 Schema와 `runtime_profile` 계보를 추가한다. 현재 OpenRouter는 비식별 호환성 시험만 수행한다.
- `PRODUCT-AI-04`: 완료 — 실제 시험 결과를 pgvector KISA 근거와 연결하고 `규칙 엔진의 공식 판정`, `KISA 근거`, `AI 해석·권장`을 시각적으로 구분한다.
- `PRODUCT-AI-05`: 선택 결과를 문맥으로 위험 시나리오·조치 주의점·우선순위 이유를 질문할 수 있게 한다.
- `PRODUCT-AI-06`: 재점검 시 개선·악화·미변경 항목과 남은 위험을 설명할 입력을 보존한다.
- `PRODUCT-AI-08`: 사용자용 PDF·기술 검증용 PDF와 AI 모델 활용·라이선스 기술 명세를 생성한다.
- `PRODUCT-AI-09`: `LOCAL_VLLM_FULL_CONTEXT`, 외부 egress 0, model/revision/license·weight/image 공급망과 초보 사용자 과업을 최종 인수한다.

## 4. AI 모델 활용·라이선스 명세

기술 검증용 PDF 부록과 별도 내려받기 문서에 다음을 기록한다.

- 활용 유형과 Runtime profile
- provider·base model·served model·revision·license·공식 저장소
- vLLM image version·digest·SBOM
- model weight hash·출처·악성 파일 검사
- 추가 학습 여부와 데이터셋·전처리·가중치 배포 방식
- 제품에서 AI가 수행하는 설명·종합·관련 위험·우선순위·후속 질문·보고서 범위
- AI가 수행하지 않는 공식 판정·설정 변경·Finding/Pack write
- 입력 데이터 종류·비식별화·배치 위치·외부 전송 여부
- prompt·retrieval·model·input/output hash
- 개발 과정의 AI 코딩 보조 사용 범위와 Runtime AI 사용 범위의 구분

현재 OpenRouter 사용은 운영 적용 모델이 아니라 호환성 시험으로 기록한다. 최종 명세는 실제 로컬 vLLM의 exact model·revision·license·weight·image가 승인된 뒤 확정한다.

## 5. 동기화 문서

| 문서 | 반영 내용 |
|---|---|
| `docs/adr/17.ADR_vLLM_호환_모델_게이트웨이.md` | OpenRouter 시험 대역과 최종 로컬 vLLM Gate 분리 |
| `docs/adr/18.ADR_결과_중심_AI_PC_보안_도우미.md` | 적극적 AI 역할·Runtime 경계·PDF/모델 명세·최종 인수 |
| `docs/adr/13.MVP_구현_시작_계획.md` | 단계 I 흐름·Gate와 승인 기록 개정 |
| `다음_I_J_단계_계획.md` | `PRODUCT-AI-03~09` 산출물·완료 기준 개정 |
| `대화_RAG_제품_계획.md` | 결과 중심 AI 설명·후속 질문·완료 기준 개정 |
| `구현_현황.md` | 현재 상태·다음 작업·미완료 체크리스트 동기화 |
| `README.md`·`docs/adr/README.md` | 현재 단계·ADR 인덱스·기준선 동기화 |

## 6. 변경·검증 범위

이번 작업은 ADR·계획·상태 문서 정합성 보완이다. application code, database schema/data, Docker image/container와 runtime secret은 변경하지 않는다. 따라서 code test·image rebuild·deploy는 수행하지 않는다.

검증 대상:

- `VLLM_COMPATIBILITY_TEST_DOUBLE`과 `LOCAL_VLLM_FULL_CONTEXT` 용어가 관련 문서에서 같은 의미인지
- `PRODUCT-AI-03~09`의 적극적 AI 역할·PDF·모델 명세·로컬 인수 조건이 일치하는지
- OpenRouter 시험 통과를 로컬 vLLM 완료로 오표시한 문구가 없는지
- ADR 13·17·18의 SHA-256과 ADR 인덱스 기준선이 일치하는지
- 상대 Markdown link 대상이 존재하는지

## 7. 문서 검증 결과

- 변경 대상 10개 문서 존재: `PASS`
- ADR 18·단계 계획·제품 계획·상태 문서에 `PRODUCT-AI-01~09` 모두 존재: `PASS`
- 핵심 문서에 `VLLM_COMPATIBILITY_TEST_DOUBLE`과 `LOCAL_VLLM_FULL_CONTEXT` 의미 일치: `PASS`
- 시험 대역과 최종 Runtime을 구분하지 않던 모호한 표현 제거: `PASS`
- 변경 문서의 상대 Markdown link 대상 존재: `PASS`
- ADR 인덱스 SHA-256 일치: `PASS`

| ADR | SHA-256 |
|---|---|
| `13.MVP_구현_시작_계획.md` | `2C645B2E5DF5C4F27F849D0EAB2D8420F67AE21CEB06D323128CEC18D4119778` |
| `15.ADR_확장형_증적_점검팩_AI_거버넌스.md` | `3E4429DAEE2437B2391E673FFD8A806EC2D4A332843FEE28A71481D7A0C94D4E` |
| `17.ADR_vLLM_호환_모델_게이트웨이.md` | `99EAABC0AD0E08C9F16D57A99F0DBE3A572D4A1326584685244C5B5B956EC2BE` |
| `18.ADR_결과_중심_AI_PC_보안_도우미.md` | `EC15FBA67655777058A39FEED12BDC515D15821DEB248ADF87E19E4B51566B04` |

application code·database·Docker image/container 변경은 없으며 문서 전용 작업이므로 code test·image rebuild·deploy는 수행하지 않았다.

## 8. 2026-07-26 PRODUCT-AI-04 승인 범위 보완

사용자는 현재 OpenRouter를 로컬 vLLM 호환 시험 대역으로 간주하고 현재 시험
환경의 결과를 보내는 것을 승인했다. 이에 따라 합성 입력만이 아니라 원시 증적과
식별정보를 제거한 정규화 점검 결과, 규칙 상태, 해당 결과에 검색된 KISA 관련
문단까지 시험 입력으로 허용한다.

이 보완은 운영 PC 원본 증적, 사용자·조직·Asset 식별자, 전체 registry dump 또는
전체 KISA 원문의 외부 전송 승인이 아니다. 최종 제품 Runtime과 외부 egress 0
Gate는 계속 `LOCAL_VLLM_FULL_CONTEXT`에서만 완료한다.

제7절의 ADR SHA-256은 2026-07-25 당시 문서 기준선이며, 2026-07-26 개정본 hash와
코드·image/container 검증은
[`PRODUCT_AI_04_결과_설명_UI_검증.md`](PRODUCT_AI_04_결과_설명_UI_검증.md)를
따른다.

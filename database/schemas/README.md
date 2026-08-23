# Sec_AI JSON Schema 계약

| 항목 | 내용 |
|---|---|
| 산출물 | `database/schemas` |
| 프로젝트 | Sec_AI |
| 문서 상태 | 승인 대기 |
| 기준일 | 2026-07-24 |
| Schema dialect | JSON Schema Draft 2020-12 |
| 계약 version | `1.0.0` |
| 문자 encoding | UTF-8, BOM 없음 |
| 시간 | RFC 3339 UTC, `Z` suffix |
| Hash | SHA-256, lowercase hexadecimal |
| JSON canonicalization | RFC 8785 JCS |

## 1. 범위

이 directory는 Collector, API, 정규화기, Audit Pack 규칙 엔진, AI 설명기와 UI 사이에서 교환하는 JSON document 계약이다. PostgreSQL table DDL이나 migration은 이 directory의 범위가 아니다.

| Schema | 생산자 | 소비자 | 역할 |
|---|---|---|---|
| `collector_manifest.schema.json` | API | Collector·API | 실행 허가, 대상, Probe allowlist와 제출 profile |
| `audit_package.schema.json` | Collector | API·검증 Worker | 분리된 archive descriptor, file inventory와 원시 수집 record |
| `normalized_evidence.schema.json` | 정규화 Worker | 규칙 엔진 | 무결성 검증을 통과한 공통 증적 |
| `finding.schema.json` | Audit Pack 규칙 엔진 | API·UI·AI | 공식 `PASS/FAIL/REVIEW/ERROR/N/A` 결과 |
| `audit_pack.schema.json` | 승인된 Audit Pack build | 규칙 엔진 | PC-01~PC-18 적용성·증적·규칙·근거 정의 |
| `ai_explanation.schema.json` | AI Worker | API·UI | Finding을 변경하지 않는 선택적 설명 |
| `remediation_plan.schema.json` | 승인 workflow | API·UI | MVP에서는 실행 불가능한 `PLAN_ONLY` 조치 초안 |
| `common.schema.json` | Schema maintainers | 모든 Schema | 공통 ID, 시간, hash, 상태와 오류 vocabulary |
| `offline_signature_envelope.schema.json` | Offline Collector | API 검증 경계 | 조직 인증서 기반 detached Package 서명, 12개 exact binding |
| `queue_task_message.schema.json` | API·Outbox Dispatcher | 등록된 Celery Worker | 원본 증적·비밀값 없이 Job 단계 재조회에 필요한 식별자 전용 message |
| `storage_recovery_manifest.schema.json` | 복구 도구 | 복구 검증기·운영 검토자 | 합성자료 exact version·hash, DB inventory와 RPO/RTO를 연결하는 복구 Manifest |
| `guide_catalog.schema.json` | Guide 관리자 | 적재 승인·검색 경계 | 원문 파일의 exact hash·판본·이용 조건과 검색 범위 |
| `guide_page_map.schema.json` | 원문 검증 도구 | 적재기·인용 검증기 | PDF 실제 페이지·표시 페이지·비내용 지문과 PC 항목 연결 |
| `control_source_mapping.schema.json` | Control 관리자 | Audit Pack 검토자 | Guide 승인과 별개인 PC-01~18 원문 인용 승인 계약 |
| `guide_ingest_manifest.schema.json` | Guide 적재 승인 도구 | PostgreSQL+pgvector 적재기 | 악성코드·추출 품질·이용 조건 Gate와 적재 대상 |
| `guide_search_result.schema.json` | Guide 검색 서비스 | RAG·인용 평가기 | 조직·가이드·버전·범위가 고정된 검색 결과와 점수 |
| `guide_question_evaluation.schema.json` | Guide 품질 검토자 | 실제 DB 검색 검증기 | 대표 질문의 정답 Control·페이지·문단 근거와 근거 없음 완료 기준 |
| `model_runtime_capability.schema.json` | 모델 연결 관리자 | API·사용자 상태 화면 | OpenRouter·로컬 vLLM 연결 형태, 모델·license·빠른/정밀 profile과 공식 판정 write 금지 |
| `chat_thread.schema.json` | 대화 API | 대화 기록·UI | 조직·소유자·가이드 범위·실행 profile·보존 검토 상태를 가진 대화방 |
| `chat_message.schema.json` | 대화 API·AI Worker | 대화 기록·UI | 덮어쓰지 않는 사용자·AI 메시지, 부모·분기·편집·재시도 버전 |
| `chat_citation.schema.json` | 근거 결합기 | 대화 메시지·출처 화면 | 답변 위치와 exact 가이드·쪽·절·문단·chunk의 변경 불가능한 연결 |

## 2. 데이터 흐름

```text
collector_manifest
  → Collector 실행
  → audit_package + payload.zip
  → archive·file hash와 인증 검증
  → normalized_evidence
  → approved audit_pack 규칙 평가
  → finding
  ├→ ai_explanation(선택, 판정 변경 불가)
  └→ remediation_plan(1차 MVP는 PLAN_ONLY)
```

`audit_package` JSON은 `payload.zip` 밖에 있는 detached descriptor다. `archive_sha256`은 exact ZIP bytes의 hash이며, `file_inventory`는 압축 해제한 허용 file 각각의 hash다. ZIP 내부 layout은 다음으로 제한한다.

```text
collector_manifest.json
evidence/<UUID>.json
errors/<UUID>.json
```

경로는 `/` separator만 사용한다. 절대 경로, `..`, backslash, symlink, hardlink, reparse point, 암호화 ZIP과 중첩 archive는 금지한다. Schema 검증만으로 ZIP bomb를 막을 수 없으므로 API는 압축 전·후 byte, file count, compression ratio, path canonicalization과 nesting을 streaming 추출 전에 별도 검사한다.

## 3. 공통 규칙

- 주요 document는 `schema_version`, `id`, `created_at`, `source`, `producer_name`, `producer_version`, `correlation_id`를 가진다.
- `id`, `job_id`, `asset_id` 등 opaque ID는 UUID를 사용한다.
- JSON object의 중복 key를 parser 단계에서 거부한다.
- 알 수 없는 property는 기본적으로 거부한다.
- secret, password, token, cookie, private key와 전체 command output은 어떤 document에도 넣지 않는다.
- 사용자 이름보다 SID를 사용하고, PC-12의 `DefaultPassword`는 값이 아니라 존재 여부만 기록한다.
- hash와 signature는 다르다. SHA-256 일치만으로 생산자 신원을 주장하지 않는다.
- `$ref`는 이 directory에 등록된 `$id`만 offline으로 해석한다. Runtime에서 network `$ref`를 가져오지 않는다.
- `format`은 annotation으로 끝내지 않고 validator의 `FormatChecker`를 활성화한다.
- Schema 통과는 신뢰 결정을 의미하지 않는다. 인증, nonce replay, manifest 만료, scope, hash, 서명, Audit Pack 승인과 RBAC를 별도 검증한다.

## 4. Hash와 서명 대상

JSON content hash와 signature input은 RFC 8785 JCS canonical bytes를 사용한다. 서명 field가 document 안에 있는 경우 자기 참조를 피하기 위해 해당 Schema가 지정한 `signature` 또는 `authorization` property 전체를 제거한 document를 JCS로 canonicalize한 후 SHA-256을 계산한다.

- Manifest: 자기 hash field인 `manifest_content_sha256`과 `authorization`을 제외한 JCS bytes
- Audit Pack: 자기 hash field인 `content_sha256`과 `approval`을 제외한 JCS bytes
- 기타 signed envelope: `signature` property를 제외한 JCS bytes
- Archive: canonicalization하지 않고 exact archive bytes
- Evidence set: evidence ID와 검증된 evidence hash를 ID 순으로 정렬한 JCS array

`IMP-016`에서 Finding hash profile을 다음과 같이 고정했다.

- `rule_result.input_sha256`: schema ID·version, organization/job/asset/Control/subject,
  exact Pack ID·version·content hash·approval, applicability/evaluation rule, engine
  version·artifact hash, 전체 normalized evidence, ID 정렬 evidence refs·set hash,
  policy/reference refs와 `evaluation_as_of`를 JCS로 canonicalize한 SHA-256
- `rule_result.output_sha256`: Finding에서 실행 envelope인 `id`, `created_at`,
  `correlation_id`, `evaluated_at`과 자기 참조 field인 `rule_result.output_sha256`만
  제거한 decision payload의 JCS SHA-256
- evidence 입력 순서와 JSON property 순서는 hash에 영향을 주지 않는다.
- `evaluated_at` 변경은 판정 output hash에 영향을 주지 않지만 감사용 Finding에는 보존한다.
- DRAFT Pack은 builder의 명시적 개발 opt-in에서만 Schema-valid 개발 결과를 만들 수 있고,
  승인·서명·활성화 및 append-only 저장 전에는 공식 Finding으로 취급하지 않는다.

`IMP-017`에서 `rule_result.input_sha256`를 Finding의 논리 멱등 key로 고정했다.
동일 key와 동일 Finding ID·output hash는 새 row를 만들지 않고 기존 Finding을 반환한다.
동일 key의 output 또는 ID가 다르면 결정론 위반이므로 overwrite하지 않고 충돌로 거부한다.
`IMP-018`에서 이 pure 계약을 `finding_versions.input_sha256` named unique constraint와
`INSERT ... ON CONFLICT DO NOTHING` repository로 연결했다. 동일 fingerprint는 기존 row를
반환하고 충돌 replay는 거부한다. 정본 version의 UPDATE·DELETE·TRUNCATE는 PostgreSQL
trigger가 차단하며 현재 상태는 별도 `finding_current` projection으로 관리한다.

`IMP-019` application E2E에서 수집 실패 Evidence도 Control subject를 잃지 않아야 함을 추가로 확인했다. `collection_status != COLLECTED`인 PC-07 volume record는 원시 오류를 판정값으로 바꾸지 않되, allowlisted `normalized_candidate.volume_id`로 `subject.subject_key`를 보존한다. 따라서 Probe ERROR는 `FAIL`로 오분류되지 않으면서 동일 subject의 결정론적 `ERROR` Finding을 만들 수 있다.

`IMP-009`에서 archive hash 계약을 다음과 같이 고정했다.

- `archive_sha256`: detached `payload.zip` 전체 exact byte의 SHA-256
- `compressed_bytes`: ZIP header와 central directory를 포함한 `payload.zip` 전체 byte 길이
- `uncompressed_bytes`: 허용된 모든 member를 제한 내에서 읽어 측정한 실제 byte 합계
- `file_count`: directory entry 없이 허용된 JSON member 수
- `content_set_sha256`: `collector_manifest.json`을 제외하고, evidence·error member의 파일명 UUID를 `evidence_id`, 검증된 member hash를 `evidence_sha256`으로 만든 뒤 evidence ID 순으로 정렬한 RFC 8785 JCS array의 SHA-256

서버 절대 상한은 archive 100 MiB, 전체 해제 500 MiB, 1,024 files, member당 1 MiB, path 240자, member·전체 압축률 100:1이다. 서명된 Manifest나 endpoint 정책은 이 값을 줄일 수 있지만 늘릴 수 없다. ZIP member를 filesystem에 추출하지 않고 streaming read로 실제 크기·CRC·hash·strict JSON을 확인한다.

정확한 허용 signature algorithm, certificate trust, key rotation과 폐기는 인증 ADR에서 확정한다. Schema의 algorithm enum은 wire format 상한이며 실제 허용 목록은 더 좁아야 한다.

## 5. 상태 경계

- Collector와 정규화기는 공식 Finding 상태를 만들지 않는다.
- 공식 `PASS`, `FAIL`, `REVIEW`, `ERROR`, `N/A`는 승인된 Audit Pack 규칙 엔진만 `finding`으로 생성한다.
- 권한 부족, timeout, parse 실패와 hash 불일치는 `FAIL`이 아니다.
- AI 설명은 `official_finding_status`를 복사해 표시할 수만 있고 `official_status_unchanged=true`를 만족해야 한다.
- Remediation은 `execution_mode=PLAN_ONLY`, `mvp_execution_allowed=false`, `official_status_change_allowed=false`로 고정한다.

## 6. Version과 호환성

- Schema `$id`는 배포 후 수정하지 않는다. 변경 시 새 `$id`와 새 file version을 발행한다.
- Major: 필수 field 삭제·이름 변경, 의미·type·enum 축소 같은 비호환 변경.
- Minor: 소비자가 무시해도 안전한 선택 field 추가. 이 계약은 unknown property를 거부하므로 새 minor Schema를 명시적으로 배포·협상해야 한다.
- Patch: 설명·example·검증 script 수정처럼 instance 유효성 집합을 바꾸지 않는 변경.
- 생산자는 자신이 발행한 정확한 `schema_version`을 기록한다.
- 소비자는 지원하지 않는 version을 추측 변환하지 않고 `SCHEMA_VERSION_UNSUPPORTED`로 거부한다.
- 운영 저장소는 수신 당시 exact JSON bytes, schema `$id`, schema version과 검증 결과를 연결해 보존한다.

## 7. Audit Pack 추가 Gate

JSON Schema는 array item의 특정 property가 유일한지 완전히 보장하지 못한다. `KISA-2026-PC-MVP` Audit Pack을 `APPROVED`로 배포할 때 다음 semantic Gate를 추가 적용한다.

- `PC-01`~`PC-18`이 정확히 한 번씩 존재한다.
- `control_id`, `rule_id`, `evidence requirement id`가 중복되지 않는다.
- 모든 rule·Probe·policy reference가 version 고정되고 allowlist에 존재한다.
- 모든 Control에 원문 page, 중요도, 적용성, PASS/FAIL/ERROR fixture가 있다.
- `AUTO-CONDITIONAL`에는 REVIEW fixture, 적용성 Control에는 N/A fixture가 있다.
- approval signature와 content hash가 일치하고 승인·폐기 상태가 유효하다.

## 8. 검증

Locked `jsonschema==4.26.0` 환경에서 실행한다.

```powershell
python database\schemas\validate_examples.py
```

검증기는 모든 Schema 자체 검사, valid example의 통과, invalid example의 거부와 일부 cross-field semantic rule을 확인한다. 실제 archive, 서명, nonce 저장소와 object hash 검증은 integration test에서 추가한다.

## 9. 승인 조건

- [x] 14개 Schema와 26개 valid·invalid example이 Draft 2020-12 검사를 통과한다.
- [ ] 주요 Schema 각각에 valid·invalid example이 있다.
- [ ] Collector와 API가 동일 Schema와 FormatChecker를 사용한다.
- [ ] 중복 JSON key와 remote `$ref`가 거부된다.
- [ ] archive path·size·file count 제한 integration test가 있다.
- [ ] hash canonicalization test vector가 Collector·서버에서 일치한다.
- [ ] 승인 Audit Pack의 PC-01~PC-18 semantic Gate가 통과한다.
- [ ] 인증 ADR에서 signature·certificate profile을 확정한다.

## 10. 공식 근거

- [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12)
- [JSON Schema 2020-12 release notes](https://json-schema.org/draft/2020-12/release-notes)
- [RFC 8785 JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html)
- [RFC 3339 date and time](https://www.rfc-editor.org/rfc/rfc3339.html)

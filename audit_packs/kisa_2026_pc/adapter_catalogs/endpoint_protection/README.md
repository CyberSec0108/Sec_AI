# IMP-024 Endpoint Protection Adapter Catalog

이 디렉터리는 PC-13~15가 해석할 수 있는 제품 Adapter의 정확한 ID, 버전, 입력 필드와 출처 계약을 고정한다.

- `secai.microsoft-defender-antivirus@0.1.0`: `Get-MpComputerStatus` 기반 DRAFT 매핑
- `secai.windows-firewall@0.1.0`: `Get-NetFirewallProfile -PolicyStore ActiveStore` 기반 DRAFT 매핑
- `secai.synthetic-third-party-firewall@0.1.0`: 대체 방화벽 분기 시험 전용이며 실제 제품 지원을 뜻하지 않음

목록에 없는 백신·방화벽은 이름이나 `productState` 숫자만으로 상태를 추측하지 않고 `REVIEW`로 처리한다. 실제 타사 제품 Adapter는 IMP-031 Collector 확대 단계에서 제품별 API·권한·상태 매핑과 서명을 검증한 뒤 별도 버전으로 추가한다.

현재 카탈로그는 서명 없는 `DRAFT`, `SYNTHETIC_TEST_ONLY`다. 운영 공식 판정에 사용할 수 없다.

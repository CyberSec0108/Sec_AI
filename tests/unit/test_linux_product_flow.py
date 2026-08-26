from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy.exc import IntegrityError
from starlette.requests import Request

from security_audit.application.device_ai_token_stream import (
    DeviceAIContractError,
    DeviceAITokenStreamService,
    enrich_linux_audit_history_result,
    public_linux_control,
    validate_stored_device_result,
)
from security_audit.application.device_report import build_linux_report_document
from security_audit.llm import (
    ChatCompletionInput,
    ChatCompletionStreamChunk,
    InternalModelGatewayClient,
)
from security_audit.platforms import AssetContext, DeviceAuditResult
from security_audit.platforms.linux_adapters import LinuxDistribution
from security_audit.platforms.linux_kisa import (
    control_ids_for_probe,
    evaluate_kisa_unix,
    probe_ids_for_control,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 2, 15, 0, tzinfo=UTC)


def _stored_result() -> dict[str, object]:
    fixture = json.loads(
        (PROJECT_ROOT / "tests/fixtures/platforms/linux/rocky_9_kisa_sample.json").read_text(
            encoding="utf-8"
        )
    )
    controls = evaluate_kisa_unix(
        {key: value.encode() for key, value in fixture["outputs"].items()},
        captured_at=NOW,
        distribution=LinuxDistribution.ROCKY_9,
    )
    result = enrich_linux_audit_history_result(DeviceAuditResult(
        schema_version="1.0.0",
        run_id=uuid4(),
        asset=AssetContext(
            asset_id=uuid4(),
            asset_type="LINUX_SERVER",
            platform="LINUX",
            platform_version="Rocky Linux 9",
            vendor="Rocky Enterprise Software Foundation",
            product_family="Rocky Linux",
        ),
        benchmark_id="KISA_2026_UNIX_U01_U67",
        benchmark_version="2026",
        criteria_profile_id=None,
        criteria_sha256="a" * 64,
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=10),
        controls=controls,
    ).to_json())
    return result


class _StreamingModel:
    def __init__(self) -> None:
        self.requests: list[ChatCompletionInput] = []

    def stream(self, request: ChatCompletionInput) -> Iterator[ChatCompletionStreamChunk]:
        self.requests.append(request)
        yield ChatCompletionStreamChunk(model_id="test", content_delta="## 왜 중요한가요?\n\n")
        yield ChatCompletionStreamChunk(model_id="test", content_delta="실시간 설명 [1][3]")
        yield ChatCompletionStreamChunk(model_id="test", content_delta="", finish_reason="stop")


def test_linux_result_hash_and_67_control_contract_are_verified() -> None:
    result = _stored_result()
    digest = str(result["result_sha256"])

    validate_stored_device_result(result, digest)
    official = result["official_explanations"]
    ai_inputs = result["ai_explanation_inputs"]
    assert isinstance(official, list)
    assert isinstance(ai_inputs, list)
    assert len(official) == 67
    assert len(ai_inputs) == 67
    tampered = dict(result)
    tampered["criteria_sha256"] = "b" * 64

    with pytest.raises(DeviceAIContractError, match="DEVICE_RESULT_HASH_MISMATCH"):
        validate_stored_device_result(tampered, digest)


def test_linux_ai_stream_emits_provider_deltas_with_separated_sources() -> None:
    result = _stored_result()
    controls = result["controls"]
    assert isinstance(controls, list)
    model = _StreamingModel()

    deltas = list(DeviceAITokenStreamService(model).stream_control(controls[0]))

    assert deltas == ["## 왜 중요한가요?\n\n", "실시간 설명 [1][3]"]
    user_prompt = model.requests[0].messages[-1].content
    system_prompt = model.requests[0].messages[0].content
    assert '"1": "이 서버의 실제 확인값"' in user_prompt
    assert '"2": "KISA UNIX 서버 점검 근거"' in user_prompt
    assert '"3": "AI 일반 보안지식(설명 보조)"' in user_prompt
    assert "규칙 판정" not in user_prompt
    assert "## 1. 왜 중요한가요?" in system_prompt
    assert "## 2. 이 서버 결과의 의미" in system_prompt
    assert "문장부호 뒤에 공백 없이" in system_prompt
    assert "출처 번호로 시작하지" in system_prompt


def test_linux_public_ai_context_and_report_do_not_expose_raw_output() -> None:
    result = _stored_result()
    controls = result["controls"]
    assert isinstance(controls, list)
    public = public_linux_control(controls[0])
    user_report = build_linux_report_document(result, technical=False)
    technical_report = build_linux_report_document(result, technical=True)

    assert "raw_output_sha256" not in json.dumps(public, ensure_ascii=False)
    assert "내부 판정 코드:" not in "\n".join(user_report.lines)
    assert "수집 시점 지문(원문, 재검증 불가):" not in "\n".join(user_report.lines)
    assert user_report.report_kind.value == "USER"
    assert "내부 판정 코드:" in "\n".join(technical_report.lines)
    assert "수집 시점 지문(원문, 재검증 불가):" in "\n".join(technical_report.lines)
    assert technical_report.report_kind.value == "TECHNICAL"
    assert "해당 없음" in "\n".join(user_report.lines)


def test_linux_web_contract_supports_live_progress_stream_cancel_and_follow_up() -> None:
    scan = (PROJECT_ROOT / "apps/web/static/app/linux-scan.js").read_text(encoding="utf-8")
    ai = (PROJECT_ROOT / "apps/web/static/app/linux-ai.js").read_text(encoding="utf-8")
    ai_page = (PROJECT_ROOT / "apps/web/templates/pages/linux_ai.html").read_text(encoding="utf-8")
    linux_api = (PROJECT_ROOT / "apps/api/linux_audit.py").read_text(encoding="utf-8")
    results = (PROJECT_ROOT / "apps/web/static/app/linux-results.js").read_text(encoding="utf-8")
    results_page = (
        PROJECT_ROOT / "apps/web/templates/pages/linux_results.html"
    ).read_text(encoding="utf-8")

    assert "new EventSource" in scan
    assert '"PROBE_PROGRESS"' in scan
    assert '"PREFLIGHT_RETRY"' in scan
    assert '"CONTROL_COMPLETED"' in scan
    assert "restoreStartControls" in scan
    assert "resetProgress" in scan
    assert "response.body.getReader()" in ai
    assert "new AbortController()" in ai
    assert "/ai/cancel" in ai
    assert "/follow-up/stream" in ai
    assert "SecAIRestrictedMarkdown" in ai
    assert "normalizeIncompleteParagraphs" in ai
    assert "allowedCitationIds" in ai
    assert "onCitationActivate" in ai
    assert "createStreamingRenderer" in ai
    assert "throttleMs: 60" in ai
    assert 'classList.remove("ai-stream-caret")' in ai
    assert 'id="linux-ai-stop"' in ai_page
    assert "AI 점검 결과 설명" in ai_page
    assert "전체 상태와 우선 조치를 먼저 종합" in ai_page
    assert ai_page.index('id="linux-ai-summary"') < ai_page.index(
        'id="linux-ai-controls"'
    )
    assert linux_api.index('"SUMMARY_STARTED"') < linux_api.index(
        '"CONTROL_STARTED"'
    )
    assert '_AI_OUTPUT_VERSION = "V4"' in linux_api
    assert '"SUMMARY_FAILED"' in linux_api
    assert '"CONTROL_FAILED"' in linux_api
    assert "integrated-result-section" in results
    assert 'addFact(facts, "판정 이유"' in results
    assert 'addFact(facts, "다음 행동"' not in results
    assert "확인 방법과 기술 정보" not in results
    assert "명령과 검증값 보기" not in results
    assert 'class="panel technical-integrity linux-result-integrity"' in results_page
    assert 'id="linux-integrated-results"' in results_page


def test_linux_ui_uses_windows_progress_integrated_result_and_default_criteria_contract() -> None:
    scan_page = (
        PROJECT_ROOT / "apps/web/templates/pages/linux_scan.html"
    ).read_text(encoding="utf-8")
    scan_script = (
        PROJECT_ROOT / "apps/web/static/app/linux-scan.js"
    ).read_text(encoding="utf-8")
    result_page = (
        PROJECT_ROOT / "apps/web/templates/pages/linux_results.html"
    ).read_text(encoding="utf-8")
    result_script = (
        PROJECT_ROOT / "apps/web/static/app/linux-results.js"
    ).read_text(encoding="utf-8")

    assert 'class="scan-control-progress"' in scan_page
    assert 'id="linux-control-progress-list"' in scan_page
    assert "KISA·SecAI Linux 안전 기본 기준" in scan_page
    assert 'id="linux-criteria-reset"' in scan_page
    assert "criteria:" in scan_script
    assert "secai_linux_criteria_v1" in scan_script
    assert "scan-control-progress-item" in scan_script

    assert '/static/app/restricted-markdown.js' in result_page
    assert 'id="linux-integrated-results"' in result_page
    assert 'id="linux-ai-summary"' in result_page
    assert "AI에게 추가 질문" in result_page
    assert 'data-result-view-button="combined"' in result_page
    assert 'id="linux-result-observed-at"' in result_page
    assert 'id="linux-result-report-panel"' in result_page
    assert 'id="linux-recheck-panel"' in result_page
    assert 'class="integrated-results-heading"' in result_page
    assert "button.dataset.linuxResultStatus = entry[3]" in result_script
    assert '["ALL", "PASS", "FAIL", "ERROR", "N/A"]' in result_script
    assert "applyStatusFilter" in result_script
    assert 'querySelectorAll("button[data-linux-result-status]")' in result_script
    assert "knowledge_sources" in result_script
    assert 'sentence.trimEnd() + citations' in result_script
    assert "CONTROL_DELTA" in result_script
    assert "ANALYSIS_COMPLETED" in result_script
    assert 'type === "SUMMARY_FAILED"' in result_script
    assert 'type === "CONTROL_FAILED"' in result_script
    assert 'classList.remove("ai-stream-caret")' in result_script
    assert "설명 생성 완료" not in result_script
    assert "기준 확인 필요" not in result_page
    assert "기준 확인 필요" not in result_script
    assert result_script.count("addFact(facts,") == 4
    assert result_script.index('addFact(facts, "무엇을 확인했나요"') < result_script.index(
        'addFact(facts, "내 서버에서 확인한 값"'
    )
    assert result_script.index('addFact(facts, "내 서버에서 확인한 값"') < result_script.index(
        'addFact(facts, "KISA 권고 기준"'
    )
    assert result_script.index('addFact(facts, "KISA 권고 기준"') < result_script.index(
        'addFact(facts, "판정 이유"'
    )
    assert 'resultSection.setAttribute("aria-label"' in result_script
    assert 'aiSection.setAttribute("aria-label"' in result_script


def test_linux_ai_summary_keeps_all_67_controls_without_priority_item_limit() -> None:
    result = _stored_result()
    controls = result["controls"]
    assert isinstance(controls, list)
    model = _StreamingModel()

    list(DeviceAITokenStreamService(model).stream_summary(controls, profile="FAST"))

    request = model.requests[0]
    user_prompt = request.messages[-1].content
    payload = json.loads(
        user_prompt.removeprefix("<untrusted_results>").removesuffix(
            "</untrusted_results>"
        )
    )
    assert len(payload) == 67
    assert [item["control_id"] for item in payload] == [
        f"U-{number:02d}" for number in range(1, 68)
    ]
    assert request.max_tokens == 4_000


def test_linux_ai_moves_to_all_controls_when_completed_summary_hits_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from apps.api import linux_audit as linux_api

    result = _stored_result()
    principal = SimpleNamespace(organization_id=uuid4(), user_id=uuid4())
    record = SimpleNamespace(result_json=result)

    class _FakeSession:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def __enter__(self) -> _FakeSession:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def begin(self) -> _FakeSession:
            return self

    class _LengthEndingService:
        def __init__(self, _model: object) -> None:
            pass

        def stream_summary(
            self, _controls: object, *, profile: str
        ) -> Iterator[str]:
            yield "정상적으로 표시할 전체 요약"
            raise DeviceAIContractError("OUTPUT_TOKEN_LIMIT_REACHED")

        def stream_control(
            self, control: dict[str, object], *, profile: str
        ) -> Iterator[str]:
            yield f"{control['control_id']} 항목 설명"

    monkeypatch.setattr(linux_api, "_load_result", lambda *_args: (principal, record))
    monkeypatch.setattr(linux_api, "verify_browser_csrf", lambda *_args: None)
    monkeypatch.setattr(linux_api, "Session", _FakeSession)
    monkeypatch.setattr(linux_api, "_engine", lambda: object())
    monkeypatch.setattr(linux_api, "get_ai_output", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(linux_api, "append_ai_output", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(linux_api, "DeviceAITokenStreamService", _LengthEndingService)
    monkeypatch.setattr(
        InternalModelGatewayClient,
        "from_environment",
        lambda: object(),
    )
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/linux/audits/test/ai/stream",
            "headers": [],
        }
    )
    response = linux_api.linux_ai_stream(
        request,
        uuid4(),
        linux_api.LinuxAIStreamBody(profile="FAST"),
        csrf_token=None,
    )

    async def collect() -> str:
        chunks: list[str] = []
        async for chunk in response.body_iterator:
            chunks.append(chunk if isinstance(chunk, str) else bytes(chunk).decode())
        return "".join(chunks)

    stream = asyncio.run(collect())

    assert "정상적으로 표시할 전체 요약" in stream
    assert "event: SUMMARY_FAILED" in stream
    assert stream.count("event: CONTROL_STARTED") == 67
    assert stream.count("event: CONTROL_COMPLETED") == 67
    assert "event: ANALYSIS_COMPLETED" in stream


def test_linux_ai_cache_write_failure_does_not_stop_summary_or_control_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from apps.api import linux_audit as linux_api

    result = _stored_result()
    principal = SimpleNamespace(organization_id=uuid4(), user_id=uuid4())
    record = SimpleNamespace(result_json=result)

    class _FakeSession:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def __enter__(self) -> _FakeSession:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def begin(self) -> _FakeSession:
            return self

    class _CompleteService:
        def __init__(self, _model: object) -> None:
            pass

        def stream_summary(self, _controls: object, *, profile: str) -> Iterator[str]:
            yield "정상 종합 설명"

        def stream_control(
            self, control: dict[str, object], *, profile: str
        ) -> Iterator[str]:
            yield f"{control['control_id']} 항목 설명"

    def reject_cache_write(*_args: object, **_kwargs: object) -> None:
        raise IntegrityError("INSERT linux_audit_ai_outputs", {}, RuntimeError("constraint"))

    monkeypatch.setattr(linux_api, "_load_result", lambda *_args: (principal, record))
    monkeypatch.setattr(linux_api, "verify_browser_csrf", lambda *_args: None)
    monkeypatch.setattr(linux_api, "Session", _FakeSession)
    monkeypatch.setattr(linux_api, "_engine", lambda: object())
    monkeypatch.setattr(linux_api, "get_ai_output", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(linux_api, "append_ai_output", reject_cache_write)
    monkeypatch.setattr(linux_api, "DeviceAITokenStreamService", _CompleteService)
    monkeypatch.setattr(
        InternalModelGatewayClient,
        "from_environment",
        lambda: object(),
    )
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/linux/audits/test/ai/stream",
            "headers": [],
        }
    )
    response = linux_api.linux_ai_stream(
        request,
        uuid4(),
        linux_api.LinuxAIStreamBody(profile="FAST"),
        csrf_token=None,
    )

    async def collect() -> str:
        chunks: list[str] = []
        async for chunk in response.body_iterator:
            chunks.append(chunk if isinstance(chunk, str) else bytes(chunk).decode())
        return "".join(chunks)

    stream = asyncio.run(collect())

    assert "event: SUMMARY_COMPLETED" in stream
    assert stream.count("event: CONTROL_STARTED") == 67
    assert stream.count("event: CONTROL_COMPLETED") == 67
    assert "event: ANALYSIS_COMPLETED" in stream
    assert "event: FAILED" not in stream


def test_linux_ai_output_key_migration_accepts_versioned_cache_keys() -> None:
    migration = (
        PROJECT_ROOT
        / "database/alembic/versions/0021_linux_ai_output_v4_keys.py"
    ).read_text(encoding="utf-8")

    assert 'revision: str = "0021_linux_ai_v4_keys"' in migration
    assert 'down_revision: str | None = "0020_guide_id_length"' in migration
    assert "linux_audit_ai_outputs_output_key_check" in migration
    assert "op.f(_CONSTRAINT)" in migration
    assert "V4:" in migration
    assert "U-(0[1-9]|[1-5][0-9]|6[0-7])" in migration


def test_linux_completed_ai_snapshot_requires_summary_and_all_67_controls() -> None:
    from apps.api import linux_audit as linux_api

    result = _stored_result()
    controls = result["controls"]
    assert isinstance(controls, list)
    outputs = {"V4:SUMMARY": "저장된 Linux 종합 설명"}
    outputs.update(
        {f"V4:U-{number:02d}": f"U-{number:02d} 저장 설명" for number in range(1, 68)}
    )

    snapshot = linux_api._completed_linux_ai_snapshot(controls, outputs)

    assert snapshot["available"] is True
    assert snapshot["total_controls"] == 67
    restored = snapshot["controls"]
    assert isinstance(restored, list)
    assert restored[0]["content"] == "U-01 저장 설명"
    del outputs["V4:U-67"]
    assert linux_api._completed_linux_ai_snapshot(controls, outputs) == {
        "available": False,
        "version": "V4",
    }


def test_linux_runtime_mount_and_nullable_failure_update_are_unambiguous() -> None:
    compose = (PROJECT_ROOT / "deploy/compose/compose.yml").read_text(encoding="utf-8")
    repository = (
        PROJECT_ROOT
        / "src/security_audit/persistence/database/linux_audit_repository.py"
    ).read_text(encoding="utf-8")

    assert "source: .runtime/vmware" in compose
    assert "COALESCE(CAST(:result_json AS jsonb), result_json)" in repository


def test_linux_preflight_accepts_current_patch_versions_and_separates_missing_output() -> None:
    from security_audit.application.linux_audit_service import (
        _validate_target_distribution,
    )

    assert (
        _validate_target_distribution(
            b'ID=ubuntu\nVERSION_ID="24.04"\n',
            LinuxDistribution.UBUNTU_24_04,
        )
        is LinuxDistribution.UBUNTU_24_04
    )
    assert (
        _validate_target_distribution(
            b'ID=rocky\nVERSION_ID="9.8"\n',
            LinuxDistribution.ROCKY_9,
        )
        is LinuxDistribution.ROCKY_9
    )
    with pytest.raises(RuntimeError, match="LINUX_PREFLIGHT_COLLECTION_FAILED"):
        _validate_target_distribution(None, LinuxDistribution.UBUNTU_24_04)


def test_linux_preflight_retries_transient_collection_failure() -> None:
    service = (
        PROJECT_ROOT / "src/security_audit/application/linux_audit_service.py"
    ).read_text(encoding="utf-8")
    scan = (PROJECT_ROOT / "apps/web/static/app/linux-scan.js").read_text(
        encoding="utf-8"
    )

    assert "_PREFLIGHT_ATTEMPTS = 2" in service
    assert '"PREFLIGHT_RETRY"' in service
    assert '"PREFLIGHT_RETRY"' in scan


def test_linux_central_preflight_auto_selects_adapter_without_distribution_input() -> None:
    service = (
        PROJECT_ROOT / "src/security_audit/application/linux_audit_service.py"
    ).read_text(encoding="utf-8")
    page = (PROJECT_ROOT / "apps/web/templates/pages/linux_scan.html").read_text(
        encoding="utf-8"
    )

    assert '"linux.architecture"' in service
    assert "discover_linux_platform" in service
    assert "current_platform_support_catalog" in service
    assert '"PLATFORM_IDENTIFIED"' in service
    assert "linux_adapter_for(detected)" in service
    assert "서버 종류와 버전은 시스템이 자동으로 확인합니다" in page


def test_linux_central_ui_selects_server_alias_without_distribution_choice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from security_audit.application.linux_audit_service import linux_lab_targets

    monkeypatch.delenv("SECAI_LINUX_UBUNTU_LABEL", raising=False)
    monkeypatch.delenv("SECAI_LINUX_ROCKY_LABEL", raising=False)
    targets = linux_lab_targets()
    page = (PROJECT_ROOT / "apps/web/templates/pages/linux_scan.html").read_text(
        encoding="utf-8"
    )
    scan = (PROJECT_ROOT / "apps/web/static/app/linux-scan.js").read_text(
        encoding="utf-8"
    )

    assert [target.label for target in targets.values()] == [
        "Linux 시험 서버 A",
        "Linux 시험 서버 B",
    ]
    assert all("distribution" not in target.public_view() for target in targets.values())
    assert "{{ asset.distribution }}" not in page
    assert "{{ asset.platform_hint }}" in page
    assert all(
        target.public_view()["platform_hint"] == "운영체제는 연결 후 자동 확인"
        for target in targets.values()
    )
    assert "Linux 서버 자동 확인 및 점검 시작" in page
    assert 'id="linux-detected-platform"' in page
    assert '"PLATFORM_IDENTIFIED"' in scan
    assert "확인된 서버에 맞는 읽기 전용 명령" in scan


def test_linux_probe_progress_identifies_affected_and_ready_controls() -> None:
    service = (
        PROJECT_ROOT / "src/security_audit/application/linux_audit_service.py"
    ).read_text(encoding="utf-8")
    scan = (PROJECT_ROOT / "apps/web/static/app/linux-scan.js").read_text(
        encoding="utf-8"
    )

    assert probe_ids_for_control("U-28") == (
        "linux.firewall-state",
        "linux.firewall-rules",
        "linux.listening-sockets",
    )
    assert "U-28" in control_ids_for_probe("linux.firewall-rules")
    assert "affected_control_ids" in service
    assert "ready_control_ids" in service
    assert "affected_control_ids" in scan
    assert "ready_control_ids" in scan
    assert "자료 수집 중" in scan
    assert "판정 대기" in scan

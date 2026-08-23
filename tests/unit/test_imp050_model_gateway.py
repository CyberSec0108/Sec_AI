from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from apps.api import model_runtime as model_runtime_api
from apps.api.main import app as audit_api_app
from apps.model_gateway.main import app as model_gateway_app
from fastapi.testclient import TestClient

from security_audit.llm import (
    ChatCompletionInput,
    ChatMessage,
    ModelGatewaySettings,
    OpenAICompatibleProvider,
    ProviderConfigurationError,
    ProviderRequestError,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _secret(path: Path, value: str) -> str:
    path.write_text(value, encoding="utf-8")
    return str(path)


def _settings(
    tmp_path: Path,
    *,
    base_url: str = "https://openrouter.ai/api/v1",
) -> ModelGatewaySettings:
    return ModelGatewaySettings(
        api_base=base_url,
        model_id="openai/gpt-oss-120b",
        api_key_file=_secret(tmp_path / "api-key", "test-upstream-key"),
        gateway_token_file=_secret(tmp_path / "gateway-token", "test-gateway-token"),
        request_timeout_seconds=240.0,
        reasoning_effort="low",
    )


def test_openai_compatible_settings_support_remote_now_and_local_vllm_later(
    tmp_path: Path,
) -> None:
    remote = _settings(tmp_path)
    local = _settings(
        tmp_path,
        base_url="http://vllm:8000/v1",
    ).with_model("secai-local-gpt-oss")

    assert remote.provider_kind == "OPENROUTER"
    assert remote.deployment_mode == "REMOTE_API"
    assert remote.chat_completions_url == (
        "https://openrouter.ai/api/v1/chat/completions"
    )
    assert remote.model_license == "Apache-2.0"
    assert remote.external_data_transfer is True

    assert local.provider_kind == "VLLM"
    assert local.deployment_mode == "LOCAL_VLLM"
    assert local.chat_completions_url == "http://vllm:8000/v1/chat/completions"
    assert local.model_id == "secai-local-gpt-oss"
    assert local.external_data_transfer is False


def test_model_gateway_allows_large_bounded_result_explanation_outputs(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    capability = settings.public_capability()
    profiles = capability["profiles"]

    assert isinstance(profiles, dict)
    assert profiles["FAST"]["max_output_tokens"] == 8_000
    assert profiles["PRECISE"]["max_output_tokens"] == 16_000
    assert settings.request_timeout_seconds == 240.0
    ChatCompletionInput(
        messages=(ChatMessage(role="user", content="빠른 설명"),),
        profile="FAST",
        max_tokens=8_000,
    )
    ChatCompletionInput(
        messages=(ChatMessage(role="user", content="정밀 설명"),),
        profile="PRECISE",
        max_tokens=16_000,
    )
    with pytest.raises(ValueError, match="CHAT_MAX_TOKENS_INVALID"):
        ChatCompletionInput(
            messages=(ChatMessage(role="user", content="과도한 설명"),),
            profile="PRECISE",
            max_tokens=32_001,
        )


@pytest.mark.parametrize(
    "base_url",
    (
        "http://openrouter.ai/api/v1",
        "https://user:password@openrouter.ai/api/v1",
        "https://openrouter.ai/api/v1?debug=true",
        "file:///tmp/model",
        "http://8.8.8.8/v1",
    ),
)
def test_provider_url_validation_rejects_unsafe_remote_targets(
    tmp_path: Path,
    base_url: str,
) -> None:
    with pytest.raises(ProviderConfigurationError):
        _settings(tmp_path, base_url=base_url)


def test_provider_overrides_model_bounds_input_and_never_returns_reasoning(
    tmp_path: Path,
) -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["authorization"] = request.headers.get("authorization")
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "id": "generation-1",
                "model": "provider/internal-name",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "연결 확인",
                            "reasoning": "공개하면 안 되는 내부 추론",
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 4,
                    "completion_tokens": 2,
                    "total_tokens": 6,
                },
            },
        )

    settings = _settings(tmp_path)
    provider = OpenAICompatibleProvider(
        settings,
        transport=httpx.MockTransport(handler),
    )
    result = provider.complete(
        ChatCompletionInput(
            messages=(ChatMessage(role="user", content="연결 시험"),),
            profile="FAST",
            max_tokens=32,
        )
    )

    body = captured["body"]
    assert isinstance(body, dict)
    assert captured["authorization"] == "Bearer test-upstream-key"
    assert body["model"] == "openai/gpt-oss-120b"
    assert body["reasoning_effort"] == "low"
    assert result.content == "연결 확인"
    assert result.model_id == "openai/gpt-oss-120b"
    assert "reasoning" not in result.public_view()
    assert "test-upstream-key" not in json.dumps(result.public_view())


@pytest.mark.parametrize(
    ("status_code", "category", "retryable"),
    (
        (401, "AUTHENTICATION_FAILED", False),
        (402, "USAGE_LIMIT_REACHED", False),
        (429, "RATE_LIMITED", True),
        (503, "MODEL_UNAVAILABLE", True),
    ),
)
def test_provider_maps_errors_without_exposing_upstream_body(
    tmp_path: Path,
    status_code: int,
    category: str,
    retryable: bool,
) -> None:
    provider = OpenAICompatibleProvider(
        _settings(tmp_path),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                status_code,
                json={"error": {"message": "secret provider diagnostic"}},
            )
        ),
    )

    with pytest.raises(ProviderRequestError) as captured:
        provider.complete(
            ChatCompletionInput(
                messages=(ChatMessage(role="user", content="연결 시험"),),
                max_tokens=16,
            )
        )

    assert captured.value.category == category
    assert captured.value.retryable is retryable
    assert "secret provider diagnostic" not in str(captured.value)


def test_gateway_requires_internal_token_and_exposes_no_upstream_secret(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)

    class StubProvider:
        def probe(self) -> dict[str, object]:
            return {
                "connection_status": "AVAILABLE",
                "configured_model_found": True,
                "resolved_model_id": settings.model_id,
            }

    monkeypatch.setattr("apps.model_gateway.main.gateway_settings", lambda: settings)
    monkeypatch.setattr("apps.model_gateway.main.gateway_provider", lambda: StubProvider())

    with TestClient(model_gateway_app) as client:
        denied = client.get("/internal/v1/capabilities")
        allowed = client.get(
            "/internal/v1/capabilities",
            headers={"X-SecAI-Gateway-Token": "test-gateway-token"},
        )

    assert denied.status_code == 401
    assert allowed.status_code == 200
    body = allowed.json()
    assert body["provider_kind"] == "OPENROUTER"
    assert body["deployment_mode"] == "REMOTE_API"
    assert body["model_id"] == "openai/gpt-oss-120b"
    assert body["connection_status"] == "AVAILABLE"
    assert body["automatic_model_fallback_allowed"] is False
    assert body["failure_behavior"] == "AI_UNAVAILABLE_CORE_CONTINUES"
    serialized = json.dumps(body)
    assert "test-upstream-key" not in serialized
    assert "test-gateway-token" not in serialized
    assert "api_key" not in serialized


def test_authenticated_product_ui_shows_safe_model_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    monkeypatch.setattr(
        model_runtime_api,
        "_load_runtime_status",
        lambda: {
            "schema_version": "1.0.0",
            "runtime_id": "secai-model-gateway",
            "protocol": "OPENAI_CHAT_COMPLETIONS",
            "provider_kind": "OPENROUTER",
            "deployment_mode": "REMOTE_API",
            "model_id": "openai/gpt-oss-120b",
            "model_license": "Apache-2.0",
            "provider_terms_review": "OPENROUTER_TERMS_APPLY",
            "external_data_transfer": True,
            "local_model_loaded": False,
            "supports_streaming": False,
            "profiles": {},
            "official_finding_write_allowed": False,
            "audit_pack_write_allowed": False,
            "automatic_model_fallback_allowed": False,
            "failure_behavior": "AI_UNAVAILABLE_CORE_CONTINUES",
            "connection_status": "AVAILABLE",
            "configured_model_found": True,
            "resolved_model_id": "openai/gpt-oss-120b",
            "retryable": False,
        },
    )

    with TestClient(audit_api_app) as client:
        page = client.get("/ui/model-runtime")
        api = client.get("/api/v1/model-runtime")

    assert page.status_code == 200
    for phrase in (
        "AI 연결 상태",
        "OpenRouter 원격 API",
        "openai/gpt-oss-120b",
        "현재 로컬 모델 엔진은 실행하지 않습니다",
        "주소와 모델 이름만 변경",
        "공식 점검 결과나 점검 기준을 만들거나 변경할 권한",
        "기술 정보 보기",
    ):
        assert phrase in page.text
    assert api.status_code == 200
    serialized = json.dumps(api.json())
    assert "api_key" not in serialized
    assert "gateway_token" not in serialized
    assert "chat/completions" not in serialized


def test_model_gateway_container_is_internal_secret_file_only_and_vllm_ready() -> None:
    compose = (PROJECT_ROOT / "deploy" / "compose" / "compose.yml").read_text(
        encoding="utf-8"
    )
    dockerfile = (
        PROJECT_ROOT / "deploy" / "docker" / "model-gateway.Dockerfile"
    ).read_text(encoding="utf-8")
    env_example = (PROJECT_ROOT / ".env.example").read_text(encoding="utf-8")

    section = compose.split("\n  model-gateway:\n", maxsplit=1)[1].split(
        "\n  postgres:\n", maxsplit=1
    )[0]
    assert "sec-ai-mvp/model-gateway:0.1.0" in section
    assert "SECAI_LLM_API_KEY_FILE: /run/secrets/llm_api_key" in section
    assert "SECAI_LLM_GATEWAY_TOKEN_FILE: /run/secrets/model_gateway_token" in section
    assert "ports:" not in section
    assert "frontend_net" in section
    assert "app_net" in section
    assert "read_only: true" in compose
    assert "no-new-privileges:true" in compose
    assert "USER 10001:10001" in dockerfile
    assert "api.lock" in dockerfile
    assert "python:3.14.6-alpine3.23@sha256:" in section
    assert "python:3.14.6-slim-bookworm" not in section
    assert "07efb08123ba9367a7107325adb9d5626dca1ca9" in dockerfile
    assert "5c5ed245889135564e75dfed9a47aeb6b4d3e5a2e9614d918a986767e3747539" in (
        dockerfile
    )
    assert "from vllm/" not in dockerfile.casefold()
    assert "pip install vllm" not in dockerfile.casefold()
    assert "SECAI_LLM_API_BASE=https://openrouter.ai/api/v1" in env_example
    assert "SECAI_LLM_MODEL=openai/gpt-oss-120b" in env_example
    assert "DEEPSEEK_API_KEY" not in compose
    assert "sk-or-" not in compose


def test_model_runtime_schema_and_examples_are_registered() -> None:
    catalog = json.loads(
        (PROJECT_ROOT / "database" / "schemas" / "schema-catalog.json").read_text(
            encoding="utf-8"
        )
    )
    examples = json.loads(
        (PROJECT_ROOT / "database" / "schemas" / "examples" / "index.json").read_text(
            encoding="utf-8"
        )
    )
    schema_id = "https://schemas.sec-ai.local/v1/model_runtime_capability.schema.json"

    assert any(entry["id"] == schema_id for entry in catalog["schemas"])
    assert any(
        entry["schema"] == "model_runtime_capability.schema.json"
        for entry in examples["examples"]
    )

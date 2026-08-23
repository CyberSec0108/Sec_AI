from __future__ import annotations

from pathlib import Path

import pytest

from security_audit.llm.local_vllm_preparation import LocalVLLMPreparation

PROJECT_ROOT = Path(__file__).resolve().parents[2]
VLLM_BASE_DIGEST = (
    "sha256:3a1e7f5904e1a1192a02aa0086ceaffc33985d7044c7bb25b3a43d61bdbe3ac0"
)
VLLM_IMAGE_DIGEST = (
    "sha256:48f9f370497eee3748a693c01030c82dbcee87a0db52f5e7901c9744787f4a00"
)


def _read(relative_path: str) -> str:
    return (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")


def test_current_runtime_remains_openrouter_and_local_vllm_is_opt_in() -> None:
    compose = _read("deploy/compose/compose.yml")
    env_example = _read(".env.example")

    model_gateway = compose.split("\n  model-gateway:\n", 1)[1].split(
        "\n  postgres:\n", 1
    )[0]
    vllm = compose.split("\n  vllm:\n", 1)[1].split("\n  postgres:\n", 1)[0]

    assert "https://openrouter.ai/api/v1" in model_gateway
    assert "openai/gpt-oss-120b" in model_gateway
    assert 'profiles: ["local-vllm"]' in vllm
    assert "sec-ai-mvp/vllm-openai-gpu:0.23.0" in vllm
    assert "gpus: all" in vllm
    assert "ports:" not in vllm
    assert "restart: \"no\"" in vllm
    assert "model_net" in vllm
    assert "/models/NOT_CONFIGURED" in vllm
    assert "http://vllm:8000/v1" in env_example
    assert "SECAI_VLLM_SERVED_MODEL=NOT_CONFIGURED" in env_example


def test_vllm_wrapper_is_pinned_and_contains_no_model_weight() -> None:
    dockerfile = _read("deploy/docker/vllm.Dockerfile")

    assert "vllm/vllm-openai:v0.23.0@" in dockerfile
    assert VLLM_BASE_DIGEST in dockerfile
    assert "COPY" not in dockerfile
    assert "ADD" not in dockerfile
    assert "sec-ai-mvp.component=vllm" in dockerfile


def test_local_vllm_preparation_is_safe_public_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SECAI_LOCAL_VLLM_STATUS", "PREPARED_NOT_ACTIVE")
    monkeypatch.setenv(
        "SECAI_LOCAL_VLLM_IMAGE",
        "sec-ai-mvp/vllm-openai-gpu:0.23.0",
    )
    monkeypatch.setenv(
        "SECAI_LOCAL_VLLM_BASE_DIGEST",
        VLLM_BASE_DIGEST,
    )
    monkeypatch.setenv("SECAI_LOCAL_VLLM_IMAGE_DIGEST", VLLM_IMAGE_DIGEST)

    public = LocalVLLMPreparation.from_environment().to_public()

    assert public["status"] == "PREPARED_NOT_ACTIVE"
    assert public["runtime_active"] is False
    assert public["model_weights_loaded"] is False
    assert public["profile"] == "local-vllm"
    assert public["accelerator"] == "NVIDIA_GPU"
    assert public["image_digest"] == VLLM_IMAGE_DIGEST
    assert public["runtime_gate"] == "BLOCKED_VULNERABILITIES_GPU_MODEL"
    assert "api" not in " ".join(public).casefold()


def test_theme_and_chat_panels_use_accessible_icons_not_action_text() -> None:
    header = _read("apps/web/templates/components/audit_ui.html")
    chat = _read("apps/web/templates/pages/guide_chat.html")
    theme_script = _read("apps/web/static/app/theme.js")
    chat_script = _read("apps/web/static/app/guide-chat.js")

    assert 'class="theme-icon theme-icon-moon"' in header
    assert 'class="theme-icon theme-icon-sun"' in header
    assert 'id="theme-toggle-label" class="sr-only"' in header
    assert "button.textContent" not in theme_script
    assert 'button.setAttribute("aria-label"' in theme_script
    for panel in ("history", "source"):
        assert f'class="panel-toggle-icon panel-toggle-icon-{panel}"' in chat
    assert 'class="panel-toggle-label sr-only"' in chat
    assert 'toggle.setAttribute("aria-label"' in chat_script


def test_final_user_contract_keeps_sse_pdf_and_runtime_boundaries_visible() -> None:
    chat_script = _read("apps/web/static/app/guide-chat.js")
    results_script = _read("apps/web/static/app/product-results.js")
    results_page = _read("apps/web/templates/pages/product_results.html")
    runtime_page = _read("apps/web/templates/pages/model_runtime.html")

    assert "EventSource" in chat_script
    assert 'state.status === "COMPLETED"' in chat_script
    assert "getReader()" in results_script
    assert "사용자용 PDF" in results_page
    assert "기술 검증용 PDF" in results_page
    assert "runtime.local_vllm_preparation.status" in runtime_page
    assert "OpenRouter" in runtime_page
    assert "실행하지 않습니다" in runtime_page

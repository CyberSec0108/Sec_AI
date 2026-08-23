"""Safe model-runtime inventory without exposing provider credentials."""

from __future__ import annotations

import os
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from apps.api.auth_support import require_administrator
from security_audit.common.secret_files import SecretFileError, read_required_secret
from security_audit.llm.local_vllm_preparation import LocalVLLMPreparation

router = APIRouter()
templates = Jinja2Templates(directory="apps/web/templates")


def _require_product_demo() -> None:
    if os.getenv("SECAI_DEV_DEMO_ENABLED", "false").casefold() != "true":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found.")


def _unavailable_status(category: str = "UNAVAILABLE") -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "runtime_id": "secai-model-gateway",
        "protocol": "OPENAI_CHAT_COMPLETIONS",
        "provider_kind": "UNKNOWN",
        "deployment_mode": "REMOTE_API",
        "model_id": "설정 확인 필요",
        "model_license": "REVIEW_REQUIRED",
        "provider_terms_review": "REVIEW_REQUIRED",
        "external_data_transfer": True,
        "local_model_loaded": False,
        "supports_streaming": False,
        "profiles": {},
        "official_finding_write_allowed": False,
        "audit_pack_write_allowed": False,
        "automatic_model_fallback_allowed": False,
        "failure_behavior": "AI_UNAVAILABLE_CORE_CONTINUES",
        "connection_status": category,
        "configured_model_found": False,
        "resolved_model_id": None,
        "retryable": True,
    }


def _load_runtime_status() -> dict[str, object]:
    base_url = os.getenv(
        "SECAI_MODEL_GATEWAY_URL", "http://model-gateway:8010"
    ).rstrip("/")
    token_file = os.getenv(
        "SECAI_MODEL_GATEWAY_TOKEN_FILE",
        "/run/secrets/model_gateway_token",
    )
    try:
        token = read_required_secret(token_file)
        with httpx.Client(timeout=httpx.Timeout(5.0), follow_redirects=False) as client:
            response = client.get(
                f"{base_url}/internal/v1/capabilities",
                headers={"X-SecAI-Gateway-Token": token},
            )
        if response.status_code != 200:
            return _unavailable_status("MODEL_GATEWAY_UNAVAILABLE")
        payload: Any = response.json()
        if not isinstance(payload, dict):
            return _unavailable_status("INVALID_GATEWAY_RESPONSE")
        return payload
    except (OSError, ValueError, SecretFileError, httpx.HTTPError):
        return _unavailable_status()


def _public_status(status_value: dict[str, object]) -> dict[str, object]:
    allowed = {
        "schema_version",
        "runtime_id",
        "protocol",
        "provider_kind",
        "deployment_mode",
        "model_id",
        "model_license",
        "provider_terms_review",
        "external_data_transfer",
        "local_model_loaded",
        "supports_streaming",
        "profiles",
        "official_finding_write_allowed",
        "audit_pack_write_allowed",
        "automatic_model_fallback_allowed",
        "failure_behavior",
        "connection_status",
        "configured_model_found",
        "resolved_model_id",
        "retryable",
    }
    public = {key: status_value.get(key) for key in allowed}
    public["local_vllm_preparation"] = (
        LocalVLLMPreparation.from_environment().to_public()
    )
    return public


@router.get("/api/v1/model-runtime")
def model_runtime_api(request: Request) -> dict[str, object]:
    _require_product_demo()
    require_administrator(request)
    return _public_status(_load_runtime_status())


@router.get("/ui/model-runtime", response_class=HTMLResponse)
def model_runtime_page(request: Request) -> HTMLResponse:
    _require_product_demo()
    require_administrator(request)
    return templates.TemplateResponse(
        request=request,
        name="pages/model_runtime.html",
        context={"runtime": _public_status(_load_runtime_status())},
    )

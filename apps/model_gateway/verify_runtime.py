from __future__ import annotations

import json

import httpx

from security_audit.llm import ModelGatewaySettings


def main() -> int:
    settings = ModelGatewaySettings.from_environment()
    token = settings.gateway_token()
    headers = {"X-SecAI-Gateway-Token": token}
    with httpx.Client(
        base_url="http://127.0.0.1:8010",
        timeout=httpx.Timeout(settings.request_timeout_seconds),
        follow_redirects=False,
    ) as client:
        capability_response = client.get(
            "/internal/v1/capabilities",
            headers=headers,
        )
        capability_response.raise_for_status()
        capability = capability_response.json()
        completion_response = client.post(
            "/internal/v1/chat/completions",
            headers=headers,
            json={
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "This is a non-sensitive connectivity test. "
                            "Reply briefly that the model connection works."
                        ),
                    },
                    {
                        "role": "user",
                        "content": "Sec_AI model gateway connectivity test.",
                    },
                ],
                "profile": "FAST",
                "max_tokens": 64,
                "temperature": 0.0,
            },
        )
        completion = completion_response.json()

    content = completion.get("content")
    error_detail = completion.get("detail", {})
    error_category = (
        error_detail.get("category")
        if isinstance(error_detail, dict)
        else "UNKNOWN_ERROR"
    )
    accepted = (
        completion_response.status_code == 200
        and capability.get("connection_status") == "AVAILABLE"
        and capability.get("configured_model_found") is True
        and capability.get("official_finding_write_allowed") is False
        and capability.get("audit_pack_write_allowed") is False
        and capability.get("automatic_model_fallback_allowed") is False
        and capability.get("failure_behavior")
        == "AI_UNAVAILABLE_CORE_CONTINUES"
        and isinstance(content, str)
        and bool(content.strip())
    )
    summary = {
        "imp": "IMP-050",
        "accepted": accepted,
        "protocol": capability.get("protocol"),
        "provider_kind": capability.get("provider_kind"),
        "deployment_mode": capability.get("deployment_mode"),
        "configured_model": capability.get("model_id"),
        "resolved_model": capability.get("resolved_model_id"),
        "model_license": capability.get("model_license"),
        "external_data_transfer": capability.get("external_data_transfer"),
        "local_model_loaded": capability.get("local_model_loaded"),
        "connection_status": capability.get("connection_status"),
        "response_received": isinstance(content, str) and bool(content.strip()),
        "completion_http_status": completion_response.status_code,
        "error_category": error_category,
        "finish_reason": completion.get("finish_reason"),
        "usage": completion.get("usage"),
        "test_payload_classification": "NON_SENSITIVE_CONNECTIVITY_TEST",
        "secret_values_printed": False,
        "official_finding_write_allowed": False,
        "audit_pack_write_allowed": False,
        "automatic_model_fallback_allowed": capability.get(
            "automatic_model_fallback_allowed"
        ),
        "failure_behavior": capability.get("failure_behavior"),
    }
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())

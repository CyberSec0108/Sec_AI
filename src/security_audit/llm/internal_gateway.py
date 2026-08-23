"""Core API에서 내부 model-gateway만 호출하는 제한 클라이언트."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import httpx

from security_audit.common.secret_files import read_required_secret
from security_audit.llm.contracts import (
    ChatCompletionInput,
    ChatCompletionResult,
    ChatCompletionStreamChunk,
    ProviderRequestError,
)


@dataclass(frozen=True, slots=True)
class InternalModelGatewaySettings:
    base_url: str
    token_file: str
    timeout_seconds: float = 130.0

    def __post_init__(self) -> None:
        base = self.base_url.strip().rstrip("/")
        if not base.startswith(
            ("http://model-gateway:", "http://localhost:", "http://127.0.0.1:")
        ):
            raise ValueError("INTERNAL_MODEL_GATEWAY_URL_INVALID")
        if not 1.0 <= self.timeout_seconds <= 300.0:
            raise ValueError("INTERNAL_MODEL_GATEWAY_TIMEOUT_INVALID")
        object.__setattr__(self, "base_url", base)

    @classmethod
    def from_environment(cls) -> InternalModelGatewaySettings:
        return cls(
            base_url=os.getenv(
                "SECAI_MODEL_GATEWAY_URL",
                "http://model-gateway:8010",
            ),
            token_file=os.getenv(
                "SECAI_MODEL_GATEWAY_TOKEN_FILE",
                "/run/secrets/model_gateway_token",
            ),
            timeout_seconds=float(
                os.getenv("SECAI_RESULT_AI_TIMEOUT_SECONDS", "260")
            ),
        )

    def token(self) -> str:
        return read_required_secret(self.token_file)


class InternalModelGatewayClient:
    def __init__(
        self,
        settings: InternalModelGatewaySettings,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._settings = settings
        self._transport = transport

    @classmethod
    def from_environment(cls) -> InternalModelGatewayClient:
        return cls(InternalModelGatewaySettings.from_environment())

    def _headers(self) -> dict[str, str]:
        return {
            "X-SecAI-Gateway-Token": self._settings.token(),
            "Content-Type": "application/json",
        }

    def _client(self) -> httpx.Client:
        return httpx.Client(
            timeout=httpx.Timeout(self._settings.timeout_seconds),
            follow_redirects=False,
            transport=self._transport,
        )

    def capabilities(self) -> dict[str, object]:
        try:
            with self._client() as client:
                response = client.get(
                    f"{self._settings.base_url}/internal/v1/capabilities",
                    headers=self._headers(),
                )
        except (OSError, httpx.HTTPError) as exc:
            raise ProviderRequestError(
                "MODEL_GATEWAY_UNAVAILABLE",
                retryable=True,
            ) from exc
        if response.status_code != 200:
            raise ProviderRequestError(
                "MODEL_GATEWAY_UNAVAILABLE",
                retryable=True,
            )
        try:
            payload: Any = response.json()
        except ValueError as exc:
            raise ProviderRequestError(
                "INVALID_GATEWAY_RESPONSE",
                retryable=False,
            ) from exc
        if not isinstance(payload, dict):
            raise ProviderRequestError(
                "INVALID_GATEWAY_RESPONSE",
                retryable=False,
            )
        return dict(payload)

    def complete(self, request: ChatCompletionInput) -> ChatCompletionResult:
        body = {
            "messages": [
                {"role": message.role, "content": message.content}
                for message in request.messages
            ],
            "profile": request.profile,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
        }
        try:
            with self._client() as client:
                response = client.post(
                    f"{self._settings.base_url}/internal/v1/chat/completions",
                    headers=self._headers(),
                    json=body,
                )
        except (OSError, httpx.HTTPError) as exc:
            raise ProviderRequestError(
                "MODEL_GATEWAY_UNAVAILABLE",
                retryable=True,
            ) from exc
        if response.status_code != 200:
            category = "MODEL_GATEWAY_REQUEST_FAILED"
            retryable = response.status_code >= 500
            try:
                detail = response.json().get("detail", {})
                if isinstance(detail, dict):
                    supplied_category = detail.get("category")
                    supplied_retryable = detail.get("retryable")
                    if isinstance(supplied_category, str):
                        category = supplied_category
                    if isinstance(supplied_retryable, bool):
                        retryable = supplied_retryable
            except (AttributeError, ValueError):
                pass
            raise ProviderRequestError(category, retryable=retryable)
        try:
            payload: Any = response.json()
            usage = payload.get("usage") or {}
            model_id = payload["model_id"]
            content = payload["content"]
            finish_reason = payload["finish_reason"]
        except (KeyError, TypeError, ValueError) as exc:
            raise ProviderRequestError(
                "INVALID_GATEWAY_RESPONSE",
                retryable=False,
            ) from exc
        if (
            not isinstance(model_id, str)
            or not model_id.strip()
            or not isinstance(content, str)
            or not content.strip()
            or not isinstance(finish_reason, str)
            or not isinstance(usage, dict)
        ):
            raise ProviderRequestError(
                "INVALID_GATEWAY_RESPONSE",
                retryable=False,
            )
        return ChatCompletionResult(
            model_id=model_id.strip(),
            content=content.strip(),
            finish_reason=finish_reason,
            prompt_tokens=_optional_int(usage.get("prompt_tokens")),
            completion_tokens=_optional_int(usage.get("completion_tokens")),
            total_tokens=_optional_int(usage.get("total_tokens")),
        )

    def stream(
        self,
        request: ChatCompletionInput,
    ) -> Iterator[ChatCompletionStreamChunk]:
        body = {
            "messages": [
                {"role": message.role, "content": message.content}
                for message in request.messages
            ],
            "profile": request.profile,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
        }
        emitted = False
        try:
            with self._client() as client:
                with client.stream(
                    "POST",
                    f"{self._settings.base_url}/internal/v1/chat/completions/stream",
                    headers=self._headers(),
                    json=body,
                ) as response:
                    if response.status_code != 200:
                        raise ProviderRequestError(
                            "MODEL_GATEWAY_REQUEST_FAILED",
                            retryable=response.status_code >= 500,
                        )
                    for line in response.iter_lines():
                        if not line.startswith("data:"):
                            continue
                        raw = line[5:].strip()
                        if not raw or raw == "[DONE]":
                            continue
                        try:
                            payload: Any = json.loads(raw)
                            model_id = payload["model_id"]
                            content = payload.get("content_delta") or ""
                            finish_reason = payload.get("finish_reason")
                        except (KeyError, TypeError, ValueError) as exc:
                            raise ProviderRequestError(
                                "INVALID_GATEWAY_RESPONSE",
                                retryable=False,
                            ) from exc
                        if not isinstance(model_id, str) or not isinstance(content, str):
                            raise ProviderRequestError(
                                "INVALID_GATEWAY_RESPONSE",
                                retryable=False,
                            )
                        if content or finish_reason is not None:
                            emitted = emitted or bool(content)
                            yield ChatCompletionStreamChunk(
                                model_id=model_id,
                                content_delta=content,
                                finish_reason=(
                                    str(finish_reason)
                                    if finish_reason is not None
                                    else None
                                ),
                            )
        except ProviderRequestError:
            raise
        except (OSError, httpx.HTTPError) as exc:
            raise ProviderRequestError(
                "MODEL_GATEWAY_UNAVAILABLE",
                retryable=True,
            ) from exc
        if not emitted:
            raise ProviderRequestError("EMPTY_GATEWAY_RESPONSE", retryable=False)


def _optional_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value

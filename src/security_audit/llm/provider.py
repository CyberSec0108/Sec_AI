from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from typing import Any

import httpx

from security_audit.llm.contracts import (
    ChatCompletionInput,
    ChatCompletionResult,
    ChatCompletionStreamChunk,
    ModelGatewaySettings,
    ProviderRequestError,
)


def _safe_error_category(status_code: int) -> tuple[str, bool]:
    if status_code in {401, 403}:
        return ("AUTHENTICATION_FAILED", False)
    if status_code == 402:
        return ("USAGE_LIMIT_REACHED", False)
    if status_code == 408:
        return ("UPSTREAM_TIMEOUT", True)
    if status_code == 429:
        return ("RATE_LIMITED", True)
    if status_code in {502, 503, 504}:
        return ("MODEL_UNAVAILABLE", True)
    if 400 <= status_code < 500:
        return ("REQUEST_REJECTED", False)
    return ("UPSTREAM_ERROR", True)


class OpenAICompatibleProvider:
    def __init__(
        self,
        settings: ModelGatewaySettings,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._settings = settings
        self._transport = transport

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._settings.api_key()}",
            "Content-Type": "application/json",
            "User-Agent": "Sec_AI-Model-Gateway/0.1.0",
        }

    def _client(self) -> httpx.Client:
        return httpx.Client(
            timeout=httpx.Timeout(self._settings.request_timeout_seconds),
            follow_redirects=False,
            transport=self._transport,
        )

    def probe(self) -> dict[str, object]:
        try:
            with self._client() as client:
                response = client.get(
                    self._settings.models_url,
                    headers=self._headers(),
                )
            if response.status_code != 200:
                category, retryable = _safe_error_category(response.status_code)
                return {
                    "connection_status": category,
                    "configured_model_found": False,
                    "resolved_model_id": None,
                    "retryable": retryable,
                }
            payload = response.json()
            data = payload.get("data", []) if isinstance(payload, Mapping) else []
            model_ids = {
                item.get("id")
                for item in data
                if isinstance(item, Mapping) and isinstance(item.get("id"), str)
            }
            found = self._settings.model_id in model_ids
            return {
                "connection_status": "AVAILABLE" if found else "MODEL_NOT_FOUND",
                "configured_model_found": found,
                "resolved_model_id": self._settings.model_id if found else None,
                "retryable": not found,
            }
        except (OSError, ValueError, httpx.HTTPError):
            return {
                "connection_status": "UNAVAILABLE",
                "configured_model_found": False,
                "resolved_model_id": None,
                "retryable": True,
            }

    def complete(self, request: ChatCompletionInput) -> ChatCompletionResult:
        reasoning_effort = (
            self._settings.reasoning_effort
            if request.profile == "FAST"
            else "high"
        )
        body = {
            "model": self._settings.model_id,
            "messages": [
                {"role": message.role, "content": message.content}
                for message in request.messages
            ],
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "reasoning_effort": reasoning_effort,
            "stream": False,
        }
        try:
            with self._client() as client:
                response = client.post(
                    self._settings.chat_completions_url,
                    headers=self._headers(),
                    json=body,
                )
        except (OSError, httpx.HTTPError) as exc:
            raise ProviderRequestError("UPSTREAM_UNAVAILABLE", retryable=True) from exc
        if response.status_code != 200:
            category, retryable = _safe_error_category(response.status_code)
            raise ProviderRequestError(category, retryable=retryable)
        try:
            payload: Any = response.json()
            choice = payload["choices"][0]
            content = choice["message"]["content"]
            finish_reason = choice.get("finish_reason") or "unknown"
            usage = payload.get("usage") or {}
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise ProviderRequestError(
                "INVALID_UPSTREAM_RESPONSE", retryable=False
            ) from exc
        if not isinstance(content, str) or not content.strip():
            raise ProviderRequestError("EMPTY_UPSTREAM_RESPONSE", retryable=False)
        return ChatCompletionResult(
            model_id=self._settings.model_id,
            content=content.strip(),
            finish_reason=str(finish_reason),
            prompt_tokens=_optional_non_negative_int(usage.get("prompt_tokens")),
            completion_tokens=_optional_non_negative_int(
                usage.get("completion_tokens")
            ),
            total_tokens=_optional_non_negative_int(usage.get("total_tokens")),
        )

    def stream(
        self,
        request: ChatCompletionInput,
    ) -> Iterator[ChatCompletionStreamChunk]:
        """OpenRouter와 vLLM이 공통 지원하는 OpenAI SSE를 증분 전달한다."""

        reasoning_effort = (
            self._settings.reasoning_effort
            if request.profile == "FAST"
            else "high"
        )
        body = {
            "model": self._settings.model_id,
            "messages": [
                {"role": message.role, "content": message.content}
                for message in request.messages
            ],
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "reasoning_effort": reasoning_effort,
            "stream": True,
        }
        emitted = False
        try:
            with self._client() as client:
                with client.stream(
                    "POST",
                    self._settings.chat_completions_url,
                    headers=self._headers(),
                    json=body,
                ) as response:
                    if response.status_code != 200:
                        category, retryable = _safe_error_category(
                            response.status_code
                        )
                        raise ProviderRequestError(category, retryable=retryable)
                    for line in response.iter_lines():
                        if not line.startswith("data:"):
                            continue
                        raw = line[5:].strip()
                        if not raw or raw == "[DONE]":
                            continue
                        try:
                            payload: Any = json.loads(raw)
                            choice = payload["choices"][0]
                            delta = choice.get("delta") or {}
                            content = delta.get("content") or ""
                            finish_reason = choice.get("finish_reason")
                            model_id = payload.get("model") or self._settings.model_id
                        except (KeyError, IndexError, TypeError, ValueError) as exc:
                            raise ProviderRequestError(
                                "INVALID_UPSTREAM_RESPONSE",
                                retryable=False,
                            ) from exc
                        if not isinstance(content, str) or not isinstance(
                            model_id, str
                        ):
                            raise ProviderRequestError(
                                "INVALID_UPSTREAM_RESPONSE",
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
                "UPSTREAM_UNAVAILABLE",
                retryable=True,
            ) from exc
        if not emitted:
            raise ProviderRequestError("EMPTY_UPSTREAM_RESPONSE", retryable=False)


def _optional_non_negative_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from security_audit.common.secret_files import read_required_secret

_MODEL_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
_ALLOWED_ROLES = frozenset({"system", "user", "assistant"})
_ALLOWED_REASONING = frozenset({"low", "medium", "high"})
_MAX_MESSAGES = 24
_MAX_MESSAGE_CHARS = 24_000
_MAX_TOTAL_CHARS = 64_000
MAX_CHAT_OUTPUT_TOKENS = 32_000
FAST_MAX_OUTPUT_TOKENS = 8_000
PRECISE_MAX_OUTPUT_TOKENS = 16_000


class ProviderConfigurationError(ValueError):
    """Raised when a model endpoint cannot be used safely."""


class ProviderRequestError(RuntimeError):
    """Safe upstream failure without provider response content."""

    def __init__(self, category: str, *, retryable: bool) -> None:
        super().__init__(category)
        self.category = category
        self.retryable = retryable


def _is_local_host(hostname: str) -> bool:
    host = hostname.casefold()
    if host in {"localhost", "host.docker.internal"} or "." not in host:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host.endswith((".local", ".internal"))
    return address.is_private or address.is_loopback or address.is_link_local


@dataclass(frozen=True, slots=True)
class ModelGatewaySettings:
    api_base: str
    model_id: str
    api_key_file: str
    gateway_token_file: str
    request_timeout_seconds: float = 240.0
    reasoning_effort: str = "low"
    fast_max_output_tokens: int = FAST_MAX_OUTPUT_TOKENS
    precise_max_output_tokens: int = PRECISE_MAX_OUTPUT_TOKENS

    def __post_init__(self) -> None:
        base = self.api_base.strip().rstrip("/")
        parsed = urlsplit(base)
        hostname = (parsed.hostname or "").casefold()
        if parsed.scheme not in {"http", "https"} or not hostname:
            raise ProviderConfigurationError("LLM_API_BASE_INVALID")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ProviderConfigurationError("LLM_API_BASE_UNSAFE")
        if not parsed.path.endswith("/v1"):
            raise ProviderConfigurationError("LLM_API_BASE_MUST_END_WITH_V1")
        if parsed.scheme == "http" and not _is_local_host(hostname):
            raise ProviderConfigurationError("REMOTE_LLM_REQUIRES_HTTPS")
        if not _MODEL_ID_PATTERN.fullmatch(self.model_id.strip()):
            raise ProviderConfigurationError("LLM_MODEL_ID_INVALID")
        if not 1.0 <= float(self.request_timeout_seconds) <= 300.0:
            raise ProviderConfigurationError("LLM_TIMEOUT_OUT_OF_RANGE")
        if self.reasoning_effort not in _ALLOWED_REASONING:
            raise ProviderConfigurationError("LLM_REASONING_EFFORT_INVALID")
        if not 1 <= self.fast_max_output_tokens <= MAX_CHAT_OUTPUT_TOKENS:
            raise ProviderConfigurationError("LLM_FAST_TOKEN_LIMIT_INVALID")
        if not 1 <= self.precise_max_output_tokens <= MAX_CHAT_OUTPUT_TOKENS:
            raise ProviderConfigurationError("LLM_PRECISE_TOKEN_LIMIT_INVALID")
        if self.fast_max_output_tokens > self.precise_max_output_tokens:
            raise ProviderConfigurationError("LLM_TOKEN_PROFILE_ORDER_INVALID")
        object.__setattr__(self, "api_base", base)
        object.__setattr__(self, "model_id", self.model_id.strip())

    @classmethod
    def from_environment(cls) -> ModelGatewaySettings:
        return cls(
            api_base=os.getenv(
                "SECAI_LLM_API_BASE", "https://openrouter.ai/api/v1"
            ),
            model_id=os.getenv("SECAI_LLM_MODEL", "openai/gpt-oss-120b"),
            api_key_file=os.getenv(
                "SECAI_LLM_API_KEY_FILE", "/run/secrets/llm_api_key"
            ),
            gateway_token_file=os.getenv(
                "SECAI_LLM_GATEWAY_TOKEN_FILE",
                "/run/secrets/model_gateway_token",
            ),
            request_timeout_seconds=float(
                os.getenv("SECAI_LLM_REQUEST_TIMEOUT_SECONDS", "240")
            ),
            reasoning_effort=os.getenv(
                "SECAI_LLM_REASONING_EFFORT", "low"
            ).casefold(),
            fast_max_output_tokens=int(
                os.getenv(
                    "SECAI_LLM_FAST_MAX_OUTPUT_TOKENS",
                    str(FAST_MAX_OUTPUT_TOKENS),
                )
            ),
            precise_max_output_tokens=int(
                os.getenv(
                    "SECAI_LLM_PRECISE_MAX_OUTPUT_TOKENS",
                    str(PRECISE_MAX_OUTPUT_TOKENS),
                )
            ),
        )

    @property
    def hostname(self) -> str:
        return (urlsplit(self.api_base).hostname or "").casefold()

    @property
    def provider_kind(self) -> str:
        if self.hostname == "openrouter.ai":
            return "OPENROUTER"
        return "VLLM" if _is_local_host(self.hostname) else "OPENAI_COMPATIBLE"

    @property
    def deployment_mode(self) -> str:
        return "LOCAL_VLLM" if _is_local_host(self.hostname) else "REMOTE_API"

    @property
    def external_data_transfer(self) -> bool:
        return self.deployment_mode == "REMOTE_API"

    @property
    def model_license(self) -> str:
        if self.model_id.startswith("openai/gpt-oss-"):
            return "Apache-2.0"
        return "REVIEW_REQUIRED"

    @property
    def chat_completions_url(self) -> str:
        return f"{self.api_base}/chat/completions"

    @property
    def models_url(self) -> str:
        return f"{self.api_base}/models"

    def api_key(self) -> str:
        return read_required_secret(self.api_key_file)

    def gateway_token(self) -> str:
        return read_required_secret(self.gateway_token_file)

    def with_model(self, model_id: str) -> ModelGatewaySettings:
        return replace(self, model_id=model_id)

    def public_capability(self) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "runtime_id": "secai-model-gateway",
            "protocol": "OPENAI_CHAT_COMPLETIONS",
            "provider_kind": self.provider_kind,
            "deployment_mode": self.deployment_mode,
            "model_id": self.model_id,
            "model_license": self.model_license,
            "provider_terms_review": (
                "OPENROUTER_TERMS_APPLY"
                if self.provider_kind == "OPENROUTER"
                else "LOCAL_OPERATION"
            ),
            "external_data_transfer": self.external_data_transfer,
            "local_model_loaded": self.deployment_mode == "LOCAL_VLLM",
            "supports_streaming": True,
            "profiles": {
                "FAST": {
                    "reasoning_effort": self.reasoning_effort,
                    "max_output_tokens": self.fast_max_output_tokens,
                },
                "PRECISE": {
                    "reasoning_effort": "high",
                    "max_output_tokens": self.precise_max_output_tokens,
                },
            },
            "official_finding_write_allowed": False,
            "audit_pack_write_allowed": False,
            "automatic_model_fallback_allowed": False,
            "failure_behavior": "AI_UNAVAILABLE_CORE_CONTINUES",
        }


@dataclass(frozen=True, slots=True)
class ChatMessage:
    role: Literal["system", "user", "assistant"]
    content: str

    def __post_init__(self) -> None:
        if self.role not in _ALLOWED_ROLES:
            raise ValueError("CHAT_ROLE_NOT_ALLOWED")
        content = self.content.strip()
        if not content or len(content) > _MAX_MESSAGE_CHARS:
            raise ValueError("CHAT_MESSAGE_LENGTH_INVALID")
        object.__setattr__(self, "content", content)


@dataclass(frozen=True, slots=True)
class ChatCompletionInput:
    messages: tuple[ChatMessage, ...]
    profile: Literal["FAST", "PRECISE"] = "FAST"
    max_tokens: int = 1200
    temperature: float = 0.1

    def __post_init__(self) -> None:
        if not 1 <= len(self.messages) <= _MAX_MESSAGES:
            raise ValueError("CHAT_MESSAGE_COUNT_INVALID")
        if sum(len(message.content) for message in self.messages) > _MAX_TOTAL_CHARS:
            raise ValueError("CHAT_INPUT_TOO_LARGE")
        if self.profile not in {"FAST", "PRECISE"}:
            raise ValueError("CHAT_PROFILE_INVALID")
        if not 1 <= self.max_tokens <= MAX_CHAT_OUTPUT_TOKENS:
            raise ValueError("CHAT_MAX_TOKENS_INVALID")
        if not 0.0 <= self.temperature <= 1.0:
            raise ValueError("CHAT_TEMPERATURE_INVALID")


@dataclass(frozen=True, slots=True)
class ChatCompletionResult:
    model_id: str
    content: str
    finish_reason: str
    prompt_tokens: int | None
    completion_tokens: int | None
    total_tokens: int | None

    def public_view(self) -> dict[str, object]:
        return {
            "model_id": self.model_id,
            "content": self.content,
            "finish_reason": self.finish_reason,
            "usage": {
                "prompt_tokens": self.prompt_tokens,
                "completion_tokens": self.completion_tokens,
                "total_tokens": self.total_tokens,
            },
        }


@dataclass(frozen=True, slots=True)
class ChatCompletionStreamChunk:
    """OpenAI 호환 SSE에서 검증해 추출한 텍스트 증분."""

    model_id: str
    content_delta: str
    finish_reason: str | None = None

    def __post_init__(self) -> None:
        if not self.model_id.strip():
            raise ValueError("CHAT_STREAM_MODEL_INVALID")
        if not self.content_delta and self.finish_reason is None:
            raise ValueError("CHAT_STREAM_CHUNK_EMPTY")

    def public_view(self) -> dict[str, object]:
        return {
            "model_id": self.model_id,
            "content_delta": self.content_delta,
            "finish_reason": self.finish_reason,
        }


def ensure_secret_file_is_not_source(path_value: str, project_root: Path) -> None:
    """Protect container/API keys from being placed in source directories."""

    path = Path(path_value).resolve()
    runtime_root = (project_root / "runtime").resolve()
    if runtime_root not in path.parents:
        raise ProviderConfigurationError("LLM_SECRET_MUST_BE_RUNTIME_ONLY")

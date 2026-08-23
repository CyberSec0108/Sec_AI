"""OpenAI-compatible model runtime contracts for remote APIs and local vLLM."""

from security_audit.llm.contracts import (
    FAST_MAX_OUTPUT_TOKENS,
    MAX_CHAT_OUTPUT_TOKENS,
    PRECISE_MAX_OUTPUT_TOKENS,
    ChatCompletionInput,
    ChatCompletionResult,
    ChatCompletionStreamChunk,
    ChatMessage,
    ModelGatewaySettings,
    ProviderConfigurationError,
    ProviderRequestError,
)
from security_audit.llm.internal_gateway import (
    InternalModelGatewayClient,
    InternalModelGatewaySettings,
)
from security_audit.llm.provider import OpenAICompatibleProvider

__all__ = [
    "ChatCompletionInput",
    "ChatCompletionResult",
    "ChatCompletionStreamChunk",
    "ChatMessage",
    "FAST_MAX_OUTPUT_TOKENS",
    "InternalModelGatewayClient",
    "InternalModelGatewaySettings",
    "ModelGatewaySettings",
    "MAX_CHAT_OUTPUT_TOKENS",
    "OpenAICompatibleProvider",
    "ProviderConfigurationError",
    "ProviderRequestError",
    "PRECISE_MAX_OUTPUT_TOKENS",
]

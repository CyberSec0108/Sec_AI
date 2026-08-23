from __future__ import annotations

import hmac
import json
from collections.abc import Iterator
from functools import lru_cache
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from security_audit.llm import (
    MAX_CHAT_OUTPUT_TOKENS,
    ChatCompletionInput,
    ChatMessage,
    ModelGatewaySettings,
    OpenAICompatibleProvider,
    ProviderRequestError,
)

app = FastAPI(
    title="Sec_AI Model Gateway",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


class MessageBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["system", "user", "assistant"]
    content: str = Field(min_length=1, max_length=24_000)


class CompletionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    messages: list[MessageBody] = Field(min_length=1, max_length=24)
    profile: Literal["FAST", "PRECISE"] = "FAST"
    max_tokens: int = Field(default=1200, ge=1, le=MAX_CHAT_OUTPUT_TOKENS)
    temperature: float = Field(default=0.1, ge=0.0, le=1.0)


@lru_cache(maxsize=1)
def gateway_settings() -> ModelGatewaySettings:
    return ModelGatewaySettings.from_environment()


@lru_cache(maxsize=1)
def gateway_provider() -> OpenAICompatibleProvider:
    return OpenAICompatibleProvider(gateway_settings())


def require_gateway_token(
    token: Annotated[str | None, Header(alias="X-SecAI-Gateway-Token")] = None,
) -> None:
    expected = gateway_settings().gateway_token()
    if token is None or not hmac.compare_digest(token, expected):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Internal model gateway authentication required.",
        )


@app.get("/health/live")
def health_live() -> dict[str, str]:
    return {"status": "ok", "service": "model-gateway", "version": "0.1.0"}


@app.get("/health/ready")
def health_ready() -> dict[str, object]:
    probe = gateway_provider().probe()
    available = probe["connection_status"] == "AVAILABLE"
    if not available:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "status": "not_ready",
                "service": "model-gateway",
                "connection_status": probe["connection_status"],
            },
        )
    return {
        "status": "ready",
        "service": "model-gateway",
        "connection_status": "AVAILABLE",
    }


@app.get(
    "/internal/v1/capabilities",
    dependencies=[Depends(require_gateway_token)],
)
def capabilities() -> dict[str, object]:
    result = gateway_settings().public_capability()
    result.update(gateway_provider().probe())
    return result


@app.post(
    "/internal/v1/chat/completions",
    dependencies=[Depends(require_gateway_token)],
)
def chat_completions(body: CompletionBody) -> dict[str, object]:
    try:
        settings = gateway_settings()
        profile_limit = (
            settings.fast_max_output_tokens
            if body.profile == "FAST"
            else settings.precise_max_output_tokens
        )
        if body.max_tokens > profile_limit:
            raise ValueError("CHAT_MAX_TOKENS_INVALID")
        request = ChatCompletionInput(
            messages=tuple(
                ChatMessage(role=message.role, content=message.content)
                for message in body.messages
            ),
            profile=body.profile,
            max_tokens=body.max_tokens,
            temperature=body.temperature,
        )
        return gateway_provider().complete(request).public_view()
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Model request contract rejected.",
        ) from exc
    except ProviderRequestError as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE
            if exc.retryable
            else status.HTTP_502_BAD_GATEWAY,
            detail={
                "category": exc.category,
                "retryable": exc.retryable,
            },
        ) from exc


@app.post(
    "/internal/v1/chat/completions/stream",
    dependencies=[Depends(require_gateway_token)],
)
def stream_chat_completions(body: CompletionBody) -> StreamingResponse:
    try:
        settings = gateway_settings()
        profile_limit = (
            settings.fast_max_output_tokens
            if body.profile == "FAST"
            else settings.precise_max_output_tokens
        )
        if body.max_tokens > profile_limit:
            raise ValueError("CHAT_MAX_TOKENS_INVALID")
        request = ChatCompletionInput(
            messages=tuple(
                ChatMessage(role=message.role, content=message.content)
                for message in body.messages
            ),
            profile=body.profile,
            max_tokens=body.max_tokens,
            temperature=body.temperature,
        )
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Model request contract rejected.",
        ) from exc

    def event_stream() -> Iterator[str]:
        try:
            for chunk in gateway_provider().stream(request):
                yield "data: " + json.dumps(chunk.public_view()) + "\n\n"
            yield "data: [DONE]\n\n"
        except ProviderRequestError as exc:
            payload = {
                "error": {
                    "category": exc.category,
                    "retryable": exc.retryable,
                }
            }
            yield "event: error\ndata: " + json.dumps(payload) + "\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )

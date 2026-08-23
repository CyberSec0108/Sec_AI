"""로컬 vLLM 준비 상태를 자격 증명 없이 공개하는 안전한 메타데이터."""

from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass

_ALLOWED_STATUSES = {"NOT_PREPARED", "PREPARED_NOT_ACTIVE", "ACTIVE_VALIDATED"}
_ALLOWED_RUNTIME_GATES = {
    "BLOCKED_VULNERABILITIES_GPU_MODEL",
    "PENDING_GPU_MODEL_VALIDATION",
    "PASS",
}
_SAFE_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9._-]+$")
_SAFE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class LocalVLLMPreparation:
    """모델 가중치나 접속 비밀을 포함하지 않는 로컬 실행 준비 정보."""

    status: str
    image: str | None
    image_digest: str | None
    base_image_digest: str | None
    profile: str = "local-vllm"
    accelerator: str = "NVIDIA_GPU"
    runtime_gate: str = "BLOCKED_VULNERABILITIES_GPU_MODEL"
    runtime_active: bool = False
    model_weights_loaded: bool = False

    @classmethod
    def from_environment(cls) -> LocalVLLMPreparation:
        status = os.getenv(
            "SECAI_LOCAL_VLLM_STATUS", "PREPARED_NOT_ACTIVE"
        ).strip()
        if status not in _ALLOWED_STATUSES:
            status = "NOT_PREPARED"

        image_value = os.getenv(
            "SECAI_LOCAL_VLLM_IMAGE",
            "sec-ai-mvp/vllm-openai-gpu:0.23.0",
        ).strip()
        image = image_value if _SAFE_IMAGE.fullmatch(image_value) else None

        image_digest_value = os.getenv(
            "SECAI_LOCAL_VLLM_IMAGE_DIGEST",
            (
                "sha256:"
                "48f9f370497eee3748a693c01030c82dbcee87a0db52f5e7901c9744787f4a00"
            ),
        ).strip()
        image_digest = (
            image_digest_value
            if _SAFE_DIGEST.fullmatch(image_digest_value)
            else None
        )

        digest_value = os.getenv(
            "SECAI_LOCAL_VLLM_BASE_DIGEST",
            (
                "sha256:"
                "3a1e7f5904e1a1192a02aa0086ceaffc33985d7044c7bb25b3a43d61bdbe3ac0"
            ),
        ).strip()
        digest = (
            digest_value if _SAFE_DIGEST.fullmatch(digest_value) else None
        )

        runtime_gate = os.getenv(
            "SECAI_LOCAL_VLLM_RUNTIME_GATE",
            "BLOCKED_VULNERABILITIES_GPU_MODEL",
        ).strip()
        if runtime_gate not in _ALLOWED_RUNTIME_GATES:
            runtime_gate = "BLOCKED_VULNERABILITIES_GPU_MODEL"

        return cls(
            status=status,
            image=image,
            image_digest=image_digest,
            base_image_digest=digest,
            runtime_active=status == "ACTIVE_VALIDATED",
            model_weights_loaded=status == "ACTIVE_VALIDATED",
            runtime_gate=runtime_gate,
        )

    def to_public(self) -> dict[str, str | bool | None]:
        return asdict(self)

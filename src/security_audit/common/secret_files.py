from __future__ import annotations

from pathlib import Path


class SecretFileError(RuntimeError):
    """Raised when a required runtime secret cannot be read safely."""


def read_required_secret(path_value: str) -> str:
    path = Path(path_value)
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SecretFileError(f"required secret file is unavailable: {path}") from exc
    if not value:
        raise SecretFileError(f"required secret file is empty: {path}")
    if "\n" in value or "\r" in value:
        raise SecretFileError(f"required secret file contains multiple lines: {path}")
    return value

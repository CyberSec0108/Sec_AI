"""Strict UTF-8 JSON loading for untrusted collector package members."""

from __future__ import annotations

import json
import math
from collections.abc import Iterable
from typing import cast

from security_audit.common.canonical_json import JsonValue

from .contracts import PackageValidationCode, PackageValidationError

_MAX_SAFE_INTEGER = (2**53) - 1
_UTF8_BOM = b"\xef\xbb\xbf"


def _object_without_duplicates(pairs: Iterable[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PackageValidationError(
                PackageValidationCode.DUPLICATE_JSON_KEY,
                "JSON object contains a duplicate property.",
            )
        result[key] = value
    return result


def _safe_integer(token: str) -> int:
    value = int(token)
    if not -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER:
        raise PackageValidationError(
            PackageValidationCode.JSON_NUMBER_INVALID,
            "JSON integer is outside the RFC 8785 safe range.",
        )
    return value


def _finite_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise PackageValidationError(
            PackageValidationCode.JSON_NUMBER_INVALID,
            "JSON number is not finite.",
        )
    return value


def _reject_constant(_token: str) -> float:
    raise PackageValidationError(
        PackageValidationCode.JSON_NUMBER_INVALID,
        "Non-standard JSON numeric constants are forbidden.",
    )


def load_strict_json(data: bytes, *, require_object: bool = True) -> JsonValue:
    """Decode one UTF-8 JSON document without lossy or ambiguous extensions."""

    if data.startswith(_UTF8_BOM):
        raise PackageValidationError(
            PackageValidationCode.JSON_BOM_NOT_ALLOWED,
            "UTF-8 BOM is forbidden in package JSON.",
        )
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise PackageValidationError(
            PackageValidationCode.JSON_ENCODING_INVALID,
            "Package JSON must be strict UTF-8.",
        ) from exc

    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_int=_safe_integer,
            parse_float=_finite_float,
            parse_constant=_reject_constant,
        )
    except PackageValidationError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise PackageValidationError(
            PackageValidationCode.INVALID_JSON,
            "Package member is not one complete JSON document.",
        ) from exc

    if require_object and not isinstance(value, dict):
        raise PackageValidationError(
            PackageValidationCode.JSON_TOP_LEVEL_INVALID,
            "Package JSON must contain an object at the top level.",
        )
    return cast(JsonValue, value)


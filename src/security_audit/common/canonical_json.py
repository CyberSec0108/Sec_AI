"""RFC 8785 JSON canonicalization and SHA-256 helpers.

The canonical byte representation is the only JSON representation used as an
input to Sec_AI content hashes and signatures.  Presentation JSON must never
be hashed directly.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
from hashlib import sha256

import rfc8785

type JsonScalar = None | bool | int | float | str
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]


class SecAICanonicalizationError(ValueError):
    """Raised when a value cannot be represented by the Sec_AI JCS profile."""


def canonicalize_json(value: JsonValue) -> bytes:
    """Return the RFC 8785 JCS UTF-8 representation of *value*.

    The underlying implementation rejects non-finite numbers, integers outside
    the IEEE-754 safe domain, lone Unicode surrogates, non-string object keys,
    and values that are not JSON data types.
    """

    try:
        return rfc8785.dumps(value)
    except rfc8785.CanonicalizationError as exc:
        raise SecAICanonicalizationError(str(exc)) from exc


def canonical_sha256(value: JsonValue) -> str:
    """Return the lowercase SHA-256 hex digest of RFC 8785 canonical bytes."""

    return sha256(canonicalize_json(value)).hexdigest()


def without_top_level_fields(
    document: Mapping[str, JsonValue], excluded_fields: Collection[str]
) -> dict[str, JsonValue]:
    """Copy a JSON object while excluding named top-level envelope fields.

    This supports the approved hash profiles such as Manifest without
    ``authorization`` and Audit Pack without ``approval``.  The caller's object
    is never mutated.
    """

    excluded = frozenset(excluded_fields)
    return {key: value for key, value in document.items() if key not in excluded}


def canonical_sha256_without_fields(
    document: Mapping[str, JsonValue], excluded_fields: Collection[str]
) -> str:
    """Hash an envelope after removing its explicitly approved top-level fields."""

    return canonical_sha256(without_top_level_fields(document, excluded_fields))

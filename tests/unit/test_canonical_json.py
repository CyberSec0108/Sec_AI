from __future__ import annotations

import math

import pytest

from security_audit.common.canonical_json import (
    JsonValue,
    SecAICanonicalizationError,
    canonical_sha256,
    canonical_sha256_without_fields,
    canonicalize_json,
    without_top_level_fields,
)

RFC_8785_SAMPLE_BYTES = bytes.fromhex(
    "7b226c69746572616c73223a5b6e756c6c2c747275652c66616c73655d2c"
    "226e756d62657273223a5b3333333333333333332e333333333333332c31"
    "652b33302c342e352c302e3030322c31652d32375d2c22737472696e6722"
    "3a22e282ac245c75303030665c6e4127425c225c5c5c5c5c222f227d"
)
RFC_8785_SAMPLE_SHA256 = "2d5e01a318d0f0879ab568c4be289c8b1f64ef8921a53c6277d5e069978baacb"


def test_matches_rfc_8785_section_3_sample_bytes() -> None:
    value: JsonValue = {
        "numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 1e-27],
        "string": "€$\x0f\nA'B\"\\\\\"/",
        "literals": [None, True, False],
    }

    assert canonicalize_json(value) == RFC_8785_SAMPLE_BYTES


def test_rfc_sample_hash_is_a_fixed_cross_runtime_vector() -> None:
    value: JsonValue = {
        "numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 1e-27],
        "string": "€$\x0f\nA'B\"\\\\\"/",
        "literals": [None, True, False],
    }

    assert canonical_sha256(value) == RFC_8785_SAMPLE_SHA256


def test_property_order_does_not_change_canonical_hash() -> None:
    first: JsonValue = {"z": 1, "nested": {"b": True, "a": None}, "a": "value"}
    second: JsonValue = {"a": "value", "nested": {"a": None, "b": True}, "z": 1}

    assert canonical_sha256(first) == canonical_sha256(second)


def test_utf16_property_order_matches_rfc_8785() -> None:
    value: JsonValue = {
        "€": "Euro Sign",
        "\r": "Carriage Return",
        "דּ": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "😀": "Emoji: Grinning Face",
        "\x80": "Control",
        "ö": "Latin Small Letter O With Diaeresis",
    }

    canonical = canonicalize_json(value).decode("utf-8")
    expected_values = [
        "Carriage Return",
        "One",
        "Control",
        "Latin Small Letter O With Diaeresis",
        "Euro Sign",
        "Emoji: Grinning Face",
        "Hebrew Letter Dalet With Dagesh",
    ]
    assert [canonical.index(f'"{value}"') for value in expected_values] == sorted(
        canonical.index(f'"{value}"') for value in expected_values
    )


def test_excluded_envelope_field_is_not_hashed_and_input_is_not_mutated() -> None:
    first: dict[str, JsonValue] = {
        "pack_id": "KISA-PC",
        "version": "1.0.0",
        "approval": {"status": "DRAFT"},
    }
    second: dict[str, JsonValue] = {
        "pack_id": "KISA-PC",
        "version": "1.0.0",
        "approval": {"status": "APPROVED"},
    }

    assert canonical_sha256_without_fields(first, {"approval"}) == (
        canonical_sha256_without_fields(second, {"approval"})
    )
    assert "approval" in first
    assert without_top_level_fields(first, {"approval"}) == {
        "pack_id": "KISA-PC",
        "version": "1.0.0",
    }


@pytest.mark.parametrize("number", [math.nan, math.inf, -math.inf])
def test_non_finite_numbers_are_rejected(number: float) -> None:
    with pytest.raises(SecAICanonicalizationError):
        canonicalize_json({"number": number})


def test_integer_outside_ieee754_safe_domain_is_rejected() -> None:
    with pytest.raises(SecAICanonicalizationError):
        canonicalize_json({"number": 2**53})

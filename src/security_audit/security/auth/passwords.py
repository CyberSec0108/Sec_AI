"""Approved local password policy and Argon2id hashing."""

from __future__ import annotations

import string
import unicodedata
from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

_PUNCTUATION = frozenset(string.punctuation)
_BLOCKED = frozenset(
    {
        "password",
        "password1!",
        "qwerty123!",
        "secai123!",
        "admin123!",
    }
)


@dataclass(frozen=True, slots=True)
class PasswordPolicyResult:
    accepted: bool
    reasons: tuple[str, ...]


def normalize_password(password: str) -> str:
    return unicodedata.normalize("NFC", password)


def validate_password_policy(password: str, username: str) -> PasswordPolicyResult:
    normalized = normalize_password(password)
    reasons: list[str] = []
    if len(normalized) < 9:
        reasons.append("비밀번호는 9자 이상이어야 합니다.")
    if len(normalized) > 128 or len(normalized.encode("utf-8")) > 512:
        reasons.append("비밀번호가 허용 길이를 초과했습니다.")
    if any(unicodedata.category(character).startswith("C") for character in normalized):
        reasons.append("제어 문자는 사용할 수 없습니다.")
    if not any(character.isalpha() for character in normalized):
        reasons.append("문자를 한 개 이상 포함해야 합니다.")
    if not any(character in string.digits for character in normalized):
        reasons.append("숫자를 한 개 이상 포함해야 합니다.")
    if not any(character in _PUNCTUATION for character in normalized):
        reasons.append("특수문자를 한 개 이상 포함해야 합니다.")
    folded = normalized.casefold()
    if folded in _BLOCKED or username.casefold() in folded:
        reasons.append("쉽게 추측할 수 있는 비밀번호는 사용할 수 없습니다.")
    return PasswordPolicyResult(not reasons, tuple(reasons))


class Argon2PasswordService:
    def __init__(self) -> None:
        self._hasher = PasswordHasher(
            time_cost=3,
            memory_cost=65536,
            parallelism=1,
        )
        self._dummy_hash = self._hasher.hash("Dummy-only-9!Never-A-Login")

    def hash(self, password: str) -> str:
        return self._hasher.hash(normalize_password(password))

    def verify(self, encoded_hash: str, password: str) -> bool:
        try:
            return self._hasher.verify(encoded_hash, normalize_password(password))
        except (InvalidHashError, VerificationError):
            return False

    def verify_dummy(self, password: str) -> None:
        self.verify(self._dummy_hash, password)

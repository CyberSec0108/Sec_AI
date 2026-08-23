"""Detached Ed25519/X.509 offline Package signature verification."""

from __future__ import annotations

import base64
import binascii
import hmac
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Never, cast

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtensionOID, NameOID, ObjectIdentifier

from security_audit.analysis.package_validation import (
    PackageSchemaCatalog,
    PackageValidationCode,
    PackageValidationError,
    load_strict_json,
)
from security_audit.common.canonical_json import JsonValue, canonical_sha256, canonicalize_json

OFFLINE_PACKAGE_EKU_OID = "1.3.6.1.4.1.55555.1.1"
MAX_OFFLINE_ENVELOPE_BYTES = 64 * 1024
MAX_REVOCATION_AGE = timedelta(hours=24)


class OfflineSignatureCode(StrEnum):
    ENVELOPE_TOO_LARGE = "OFFLINE_ENVELOPE_TOO_LARGE"
    ENVELOPE_INVALID = "OFFLINE_ENVELOPE_INVALID"
    TIME_INVALID = "OFFLINE_TIME_INVALID"
    CERTIFICATE_INVALID = "OFFLINE_CERTIFICATE_INVALID"
    CERTIFICATE_UNTRUSTED = "OFFLINE_CERTIFICATE_UNTRUSTED"
    CERTIFICATE_WRONG_EKU = "OFFLINE_CERTIFICATE_WRONG_EKU"
    CERTIFICATE_SUBJECT_MISMATCH = "OFFLINE_CERTIFICATE_SUBJECT_MISMATCH"
    CERTIFICATE_REVOKED = "OFFLINE_CERTIFICATE_REVOKED"
    REVOCATION_UNAVAILABLE = "OFFLINE_REVOCATION_UNAVAILABLE"
    SIGNATURE_INVALID = "OFFLINE_SIGNATURE_INVALID"
    PAYLOAD_SCOPE_MISMATCH = "OFFLINE_PAYLOAD_SCOPE_MISMATCH"


class OfflineSignatureError(ValueError):
    def __init__(self, code: OfflineSignatureCode, message: str) -> None:
        super().__init__(message)
        self.code = code


class CertificateRevocationStatus(StrEnum):
    GOOD = "GOOD"
    REVOKED = "REVOKED"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class CertificateRevocationVerification:
    status: CertificateRevocationStatus
    certificate_sha256: str
    checked_at: datetime
    source_version: str

    def __post_init__(self) -> None:
        if self.checked_at.tzinfo is None or self.checked_at.utcoffset() is None:
            raise ValueError("checked_at must be timezone-aware.")
        if not self.source_version:
            raise ValueError("source_version cannot be empty.")


@dataclass(frozen=True, slots=True)
class VerifiedOfflineSigner:
    organization_id: str
    asset_id: str
    certificate_sha256: str
    trust_anchor_sha256: str
    key_id: str
    payload_sha256: str
    assurance_level: str = "MEDIUM"


class OfflineTrustStore:
    """Pinned organization roots only; it never consults the host trust store."""

    def __init__(self, roots: Sequence[x509.Certificate]) -> None:
        self._roots = {
            certificate.fingerprint(hashes.SHA256()).hex(): certificate
            for certificate in roots
        }
        if not self._roots:
            raise ValueError("At least one offline organization root is required.")

    def get(self, fingerprint: str) -> x509.Certificate | None:
        return self._roots.get(fingerprint)


def _reject(code: OfflineSignatureCode, message: str) -> Never:
    raise OfflineSignatureError(code, message)


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _reject(OfflineSignatureCode.ENVELOPE_INVALID, "Offline envelope object is invalid.")
    return cast(Mapping[str, object], value)


def _string(value: Mapping[str, object], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str):
        _reject(OfflineSignatureCode.ENVELOPE_INVALID, "Offline envelope field is invalid.")
    return item


def _timestamp(value: Mapping[str, object], key: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(_string(value, key).removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise OfflineSignatureError(
            OfflineSignatureCode.ENVELOPE_INVALID,
            "Offline envelope timestamp is invalid.",
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _reject(OfflineSignatureCode.ENVELOPE_INVALID, "Timezone is required.")
    return parsed


def _decode_base64url(value: str) -> bytes:
    try:
        return base64.b64decode(
            value + ("=" * (-len(value) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise OfflineSignatureError(
            OfflineSignatureCode.ENVELOPE_INVALID,
            "Offline envelope base64url field is invalid.",
        ) from exc


def _certificate(value: str) -> x509.Certificate:
    try:
        return x509.load_der_x509_certificate(_decode_base64url(value))
    except ValueError as exc:
        raise OfflineSignatureError(
            OfflineSignatureCode.CERTIFICATE_INVALID,
            "Offline certificate cannot be parsed.",
        ) from exc


def _ed25519_key(certificate: x509.Certificate) -> Ed25519PublicKey:
    public_key = certificate.public_key()
    if not isinstance(public_key, Ed25519PublicKey):
        _reject(
            OfflineSignatureCode.CERTIFICATE_INVALID,
            "Offline certificate public key is not Ed25519.",
        )
    return public_key


def _extension(
    certificate: x509.Certificate,
    oid: ObjectIdentifier,
) -> x509.Extension[x509.ExtensionType]:
    try:
        return certificate.extensions.get_extension_for_oid(oid)
    except x509.ExtensionNotFound as exc:
        raise OfflineSignatureError(
            OfflineSignatureCode.CERTIFICATE_INVALID,
            "A required offline certificate extension is missing.",
        ) from exc


class OfflinePackageSignatureVerifier:
    """Verify a detached payload against a pinned one-root organization chain."""

    def __init__(self, schema_root: Path, trust_store: OfflineTrustStore) -> None:
        self._schemas = PackageSchemaCatalog(schema_root)
        self._trust_store = trust_store

    def verify(
        self,
        envelope_bytes: bytes,
        *,
        received_at: datetime,
        revocation: CertificateRevocationVerification,
    ) -> tuple[dict[str, JsonValue], VerifiedOfflineSigner]:
        if received_at.tzinfo is None or received_at.utcoffset() is None:
            raise ValueError("received_at must be timezone-aware.")
        if len(envelope_bytes) > MAX_OFFLINE_ENVELOPE_BYTES:
            _reject(OfflineSignatureCode.ENVELOPE_TOO_LARGE, "Offline envelope is too large.")
        try:
            raw = load_strict_json(envelope_bytes)
            if not isinstance(raw, dict):
                _reject(
                    OfflineSignatureCode.ENVELOPE_INVALID,
                    "Offline envelope must be an object.",
                )
            envelope = raw
            self._schemas.validate(
                envelope,
                "offline_signature_envelope.schema.json",
                PackageValidationCode.DESCRIPTOR_SCHEMA_INVALID,
            )
        except PackageValidationError as exc:
            raise OfflineSignatureError(
                OfflineSignatureCode.ENVELOPE_INVALID,
                "Offline envelope failed strict JSON or Schema validation.",
            ) from exc

        envelope_object = cast(Mapping[str, object], envelope)
        payload = cast(dict[str, JsonValue], envelope["payload"])
        payload_object = cast(Mapping[str, object], payload)
        signer = _mapping(envelope_object.get("signer"))
        signature = _mapping(envelope_object.get("signature"))
        issued_at = _timestamp(payload_object, "issued_at")
        expires_at = _timestamp(payload_object, "expires_at")
        if (
            expires_at <= issued_at
            or received_at < issued_at
            or received_at > expires_at
        ):
            _reject(
                OfflineSignatureCode.TIME_INVALID,
                "Offline signature envelope is not currently valid.",
            )

        leaf = _certificate(_string(signer, "leaf_certificate_der_base64url"))
        chain_values = signer.get("chain_der_base64url")
        if not isinstance(chain_values, list) or len(chain_values) != 1:
            _reject(
                OfflineSignatureCode.CERTIFICATE_INVALID,
                "Offline certificate chain must contain one organization root.",
            )
        root_value = chain_values[0]
        if not isinstance(root_value, str):
            _reject(OfflineSignatureCode.CERTIFICATE_INVALID, "Root certificate is invalid.")
        root = _certificate(root_value)
        leaf_sha256 = leaf.fingerprint(hashes.SHA256()).hex()
        root_sha256 = root.fingerprint(hashes.SHA256()).hex()
        trusted_root = self._trust_store.get(root_sha256)
        if trusted_root is None or trusted_root.public_bytes(
            encoding=Encoding.DER
        ) != root.public_bytes(encoding=Encoding.DER):
            _reject(
                OfflineSignatureCode.CERTIFICATE_UNTRUSTED,
                "Offline certificate root is not pinned.",
            )
        self._verify_chain(leaf, root, received_at)

        certificate_claims = (
            _string(signer, "certificate_sha256"),
            _string(signature, "certificate_sha256"),
        )
        if any(
            not hmac.compare_digest(claim, leaf_sha256)
            for claim in certificate_claims
        ):
            _reject(
                OfflineSignatureCode.CERTIFICATE_INVALID,
                "Offline certificate digest is mismatched.",
            )
        self._verify_revocation(leaf_sha256, received_at, revocation)
        organization_id = _string(payload_object, "organization_id")
        asset_id = _string(payload_object, "asset_id")
        self._verify_subject(leaf, organization_id, asset_id)

        payload_sha256 = canonical_sha256(payload)
        if not hmac.compare_digest(
            _string(signature, "signed_sha256"),
            payload_sha256,
        ):
            _reject(
                OfflineSignatureCode.SIGNATURE_INVALID,
                "Offline signature digest is mismatched.",
            )
        signature_bytes = _decode_base64url(_string(signature, "value"))
        try:
            _ed25519_key(leaf).verify(signature_bytes, canonicalize_json(payload))
        except (InvalidSignature, ValueError) as exc:
            raise OfflineSignatureError(
                OfflineSignatureCode.SIGNATURE_INVALID,
                "Offline package signature verification failed.",
            ) from exc
        return payload, VerifiedOfflineSigner(
            organization_id=organization_id,
            asset_id=asset_id,
            certificate_sha256=leaf_sha256,
            trust_anchor_sha256=root_sha256,
            key_id=_string(signature, "key_id"),
            payload_sha256=payload_sha256,
        )

    def _verify_chain(
        self,
        leaf: x509.Certificate,
        root: x509.Certificate,
        received_at: datetime,
    ) -> None:
        if leaf.issuer != root.subject or root.issuer != root.subject:
            _reject(
                OfflineSignatureCode.CERTIFICATE_INVALID,
                "Offline certificate issuer chain is invalid.",
            )
        try:
            _ed25519_key(root).verify(root.signature, root.tbs_certificate_bytes)
            _ed25519_key(root).verify(leaf.signature, leaf.tbs_certificate_bytes)
        except (InvalidSignature, ValueError) as exc:
            raise OfflineSignatureError(
                OfflineSignatureCode.CERTIFICATE_INVALID,
                "Offline certificate chain signature is invalid.",
            ) from exc
        if not (
            root.not_valid_before_utc <= received_at <= root.not_valid_after_utc
            and leaf.not_valid_before_utc <= received_at <= leaf.not_valid_after_utc
        ):
            _reject(
                OfflineSignatureCode.CERTIFICATE_INVALID,
                "Offline certificate is outside its validity period.",
            )
        root_constraints = cast(
            x509.BasicConstraints,
            _extension(root, ExtensionOID.BASIC_CONSTRAINTS).value,
        )
        leaf_constraints = cast(
            x509.BasicConstraints,
            _extension(leaf, ExtensionOID.BASIC_CONSTRAINTS).value,
        )
        key_usage = cast(
            x509.KeyUsage,
            _extension(leaf, ExtensionOID.KEY_USAGE).value,
        )
        root_key_usage = cast(
            x509.KeyUsage,
            _extension(root, ExtensionOID.KEY_USAGE).value,
        )
        if (
            not root_constraints.ca
            or not root_key_usage.key_cert_sign
            or leaf_constraints.ca
            or not key_usage.digital_signature
        ):
            _reject(
                OfflineSignatureCode.CERTIFICATE_INVALID,
                "Offline certificate constraints are invalid.",
            )
        eku = cast(
            x509.ExtendedKeyUsage,
            _extension(leaf, ExtensionOID.EXTENDED_KEY_USAGE).value,
        )
        if ObjectIdentifier(OFFLINE_PACKAGE_EKU_OID) not in eku:
            _reject(
                OfflineSignatureCode.CERTIFICATE_WRONG_EKU,
                "Offline certificate is not authorized for package signing.",
            )

    def _verify_subject(
        self,
        leaf: x509.Certificate,
        organization_id: str,
        asset_id: str,
    ) -> None:
        organizations = leaf.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        san = cast(
            x509.SubjectAlternativeName,
            _extension(leaf, ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value,
        )
        uris = san.get_values_for_type(x509.UniformResourceIdentifier)
        if (
            len(organizations) != 1
            or organizations[0].value != organization_id
            or uris != [f"urn:secai:asset:{asset_id}"]
        ):
            _reject(
                OfflineSignatureCode.CERTIFICATE_SUBJECT_MISMATCH,
                "Offline certificate is not bound to this organization and Asset.",
            )

    def _verify_revocation(
        self,
        certificate_sha256: str,
        received_at: datetime,
        revocation: CertificateRevocationVerification,
    ) -> None:
        if (
            not hmac.compare_digest(
                revocation.certificate_sha256,
                certificate_sha256,
            )
            or revocation.checked_at > received_at
            or received_at - revocation.checked_at > MAX_REVOCATION_AGE
        ):
            _reject(
                OfflineSignatureCode.REVOCATION_UNAVAILABLE,
                "Offline revocation proof is not bound to this certificate and time.",
            )
        if revocation.status is CertificateRevocationStatus.UNAVAILABLE:
            _reject(
                OfflineSignatureCode.REVOCATION_UNAVAILABLE,
                "Offline revocation status is unavailable.",
            )
        if revocation.status is CertificateRevocationStatus.REVOKED:
            _reject(
                OfflineSignatureCode.CERTIFICATE_REVOKED,
                "Offline certificate was revoked.",
            )

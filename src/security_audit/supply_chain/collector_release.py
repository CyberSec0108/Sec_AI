"""Fail-closed IMP-035 development Authenticode acceptance."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

ARTIFACT_NAME = "SecAI-Collector-Windows-x64.exe"
ACCEPTANCE_NAME = "imp035-acceptance.json"
MANIFEST_NAME = "SecAI-Collector-Windows-x64-0.1.0.dev-release-manifest.json"
SIGNING_CONTEXT_NAME = "imp035-signing-context.json"
CLAMAV_NAME = "SecAI-Collector-Windows-x64-0.1.0.signed.clamav.json"
DEFENDER_NAME = "SecAI-Collector-Windows-x64-0.1.0.signed.defender.json"
CODE_SIGNING_EKU = "1.3.6.1.5.5.7.3.3"
MAX_REVOCATION_AGE = timedelta(hours=24)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object.")
    return cast(dict[str, Any], value)


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _utc(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a UTC timestamp.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be a UTC timestamp.") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone.")
    return parsed.astimezone(UTC)


def validate_revocation_status(
    status: object,
    checked_at: object,
    *,
    now: datetime,
) -> None:
    if status != "GOOD":
        raise ValueError("Signer revocation status must be GOOD.")
    age = now.astimezone(UTC) - _utc(checked_at, "revocation.checked_at")
    if age < timedelta(0) or age > MAX_REVOCATION_AGE:
        raise ValueError("Signer revocation status is stale or from the future.")


def _required_object(parent: dict[str, Any], key: str) -> dict[str, Any]:
    value = parent.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"{key} must be an object.")
    return cast(dict[str, Any], value)


def finalize_imp035_release(
    project_root: Path,
    output_directory: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    project_root = project_root.resolve()
    output_directory = output_directory.resolve()
    expected_runtime = (project_root / "runtime" / "imp035-artifacts").resolve()
    if expected_runtime not in output_directory.parents:
        raise ValueError("IMP-035 output must remain under runtime/imp035-artifacts.")

    paths = {
        "artifact": output_directory / ARTIFACT_NAME,
        "context": output_directory / SIGNING_CONTEXT_NAME,
        "clamav": output_directory / CLAMAV_NAME,
        "defender": output_directory / DEFENDER_NAME,
        "imp034": output_directory / "imp034-acceptance.source.json",
        "sbom": output_directory / "SecAI-Collector-Windows-x64-0.1.0.cdx.json",
        "vulnerability": output_directory
        / "SecAI-Collector-Windows-x64-0.1.0.vulnerability.json",
    }
    for path in paths.values():
        if not path.is_file() or path.stat().st_size <= 0:
            raise ValueError(f"Required IMP-035 output is missing: {path.name}")

    context = _load_object(paths["context"])
    clamav = _load_object(paths["clamav"])
    defender = _load_object(paths["defender"])
    imp034 = _load_object(paths["imp034"])
    vulnerability = _load_object(paths["vulnerability"])
    signature = _required_object(context, "signature")
    certificate = _required_object(context, "certificate")
    chain = _required_object(context, "chain")
    revocation = _required_object(context, "revocation")
    tamper = _required_object(context, "tamper_test")
    execution = _required_object(context, "execution")
    trust_cleanup = _required_object(context, "trust_cleanup")
    current = (now or datetime.now(UTC)).astimezone(UTC)
    validate_revocation_status(
        revocation.get("status"),
        revocation.get("checked_at"),
        now=current,
    )

    artifact_hash = _sha256(paths["artifact"])
    original = _required_object(imp034, "artifact")
    post_sign_hash = context.get("post_sign_sha256")
    pre_sign_hash = context.get("pre_sign_sha256")
    dependencies = vulnerability.get("dependencies")
    vulnerability_count = (
        sum(
            len(item.get("vulns", []))
            for item in dependencies
            if isinstance(item, dict) and isinstance(item.get("vulns"), list)
        )
        if isinstance(dependencies, list)
        else -1
    )
    scan_hashes_match = all(
        report.get("artifact_sha256") == artifact_hash
        for report in (clamav, defender)
    )
    implementation_checks = [
        {
            "id": "IMP035-C01",
            "title": "IMP-034 unsigned PASS input과 pre-sign hash 결합",
            "passed": (
                imp034.get("acceptance_status") == "PASS"
                and original.get("release_channel") == "DEV-UNSIGNED"
                and original.get("sha256") == pre_sign_hash
            ),
        },
        {
            "id": "IMP035-C02",
            "title": "Authenticode SHA-256 signature와 post-sign hash",
            "passed": (
                signature.get("status_at_signing")
                == "CryptographicallyValidUntrustedRoot"
                and signature.get("digest_algorithm") == "SHA256"
                and post_sign_hash == artifact_hash
                and pre_sign_hash != artifact_hash
            ),
        },
        {
            "id": "IMP035-C03",
            "title": "RSA 3072·Code Signing EKU·non-exportable DEV key",
            "passed": (
                certificate.get("key_algorithm") == "RSA"
                and int(certificate.get("key_bits", 0)) >= 3072
                and certificate.get("eku_oid") == CODE_SIGNING_EKU
                and certificate.get("private_key_exportable") is False
            ),
        },
        {
            "id": "IMP035-C04",
            "title": "self-signed DEV trust anchor·signer pin·trust store 미등록",
            "passed": (
                chain.get("valid_at_signing") is True
                and chain.get("elements") == 1
                and chain.get("root_pinned") is True
            ),
        },
        {
            "id": "IMP035-C05",
            "title": "외부 Authenticode timestamp 존재",
            "passed": (
                signature.get("timestamp_present") is True
                and isinstance(signature.get("timestamp_subject"), str)
                and bool(signature.get("timestamp_subject"))
            ),
        },
        {
            "id": "IMP035-C06",
            "title": "DEV CA revocation GOOD·24시간 이내",
            "passed": revocation.get("status") == "GOOD",
        },
        {
            "id": "IMP035-C07",
            "title": "서명 후 byte 변조 Authenticode 거부",
            "passed": (
                tamper.get("rejected") is True
                and tamper.get("signature_status") in {"HashMismatch", "NotSigned"}
            ),
        },
        {
            "id": "IMP035-C08",
            "title": "서명된 EXE frozen self-check",
            "passed": (
                execution.get("self_check") == "PASS"
                and execution.get("frozen_runtime") is True
                and execution.get("actual_collection_started") is False
                and execution.get("settings_modified") is False
            ),
        },
        {
            "id": "IMP035-C09",
            "title": "signed artifact ClamAV·Defender CLEAN",
            "passed": (
                scan_hashes_match
                and clamav.get("status") == "CLEAN"
                and defender.get("status") == "CLEAN"
            ),
        },
        {
            "id": "IMP035-C10",
            "title": "알려진 dependency 취약점 0건 유지",
            "passed": vulnerability_count == 0,
        },
        {
            "id": "IMP035-C11",
            "title": "임시 trust·private key cleanup",
            "passed": (
                trust_cleanup.get("root_store_removed") is True
                and trust_cleanup.get("publisher_store_removed") is True
                and trust_cleanup.get("private_keys_removed") is True
            ),
        },
        {
            "id": "IMP035-C12",
            "title": "운영 배포·다운로드·Finding·이동 묶음 없음",
            "passed": (
                context.get("production_release") is False
                and context.get("download_enabled") is False
                and context.get("official_finding_created") is False
                and context.get("portable_bundle_created") is False
            ),
        },
    ]
    implementation_passed = all(
        bool(check["passed"]) for check in implementation_checks
    )
    external_gates = [
        {
            "id": "IMP035-X01",
            "title": "조직 code-signing 인증서·승인된 Publisher",
            "status": "DEFERRED",
        },
        {
            "id": "IMP035-X02",
            "title": "운영 CRL/OCSP 폐기 확인",
            "status": "DEFERRED",
        },
        {
            "id": "IMP035-X03",
            "title": "clean Windows 11 VM·SmartScreen 인수",
            "status": "DEFERRED",
        },
    ]
    status = (
        "PASS_WITH_DEFERRED_EXTERNAL_GATES" if implementation_passed else "FAIL"
    )
    generated_at = current.isoformat().replace("+00:00", "Z")
    acceptance = {
        "imp": "IMP-035",
        "acceptance_status": status,
        "implementation_complete": implementation_passed,
        "imp_complete": False,
        "production_release_ready": False,
        "profile": "DEV-EPHEMERAL-AUTHENTICODE",
        "artifact": {
            "name": ARTIFACT_NAME,
            "bytes": paths["artifact"].stat().st_size,
            "pre_sign_sha256": pre_sign_hash,
            "post_sign_sha256": artifact_hash,
            "release_channel": "DEV-SIGNED-UNTRUSTED-OUTSIDE-TEST",
        },
        "certificate": {
            "subject": certificate.get("subject"),
            "issuer": certificate.get("issuer"),
            "eku_oid": certificate.get("eku_oid"),
            "private_key_exportable": False,
        },
        "timestamp_present": signature.get("timestamp_present"),
        "revocation": {
            "profile": revocation.get("profile"),
            "status": revocation.get("status"),
            "checked_at": revocation.get("checked_at"),
        },
        "malware_scan": {
            "clamav": clamav.get("status"),
            "microsoft_defender": defender.get("status"),
        },
        "known_vulnerabilities": vulnerability_count,
        "implementation_checks": implementation_checks,
        "external_gates": external_gates,
        "download_enabled": False,
        "portable_bundle_created": False,
        "official_finding_created": False,
        "next_action": "PROVIDE_ORGANIZATION_CERT_AND_CLEAN_WIN11_VM",
    }
    manifest = {
        "schema_version": "1.0.0",
        "imp": "IMP-035",
        "status": status,
        "generated_at": generated_at,
        "profile": acceptance["profile"],
        "artifact": acceptance["artifact"],
        "source_imp034_acceptance_sha256": _sha256(paths["imp034"]),
        "sbom_sha256": _sha256(paths["sbom"]),
        "vulnerability_report_sha256": _sha256(paths["vulnerability"]),
        "clamav_report_sha256": _sha256(paths["clamav"]),
        "defender_report_sha256": _sha256(paths["defender"]),
        "signing_context_sha256": _sha256(paths["context"]),
        "production_release_ready": False,
        "external_gates": external_gates,
    }
    _write_json(output_directory / ACCEPTANCE_NAME, acceptance)
    _write_json(output_directory / MANIFEST_NAME, manifest)
    if not implementation_passed:
        raise ValueError("IMP-035 development acceptance failed.")
    return acceptance

"""Reproducible IMP-028 acceptance report using synthetic data only."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from security_audit.collector import (
    CollectorManifestVerifier,
    ExternalSignatureStatus,
    ManifestSignatureProof,
    ManifestVerificationCode,
    ManifestVerificationContext,
    ManifestVerificationError,
    MockCollectionCode,
    MockCollectionError,
    MockCollector,
    NonceStatus,
    ProbeAllowlist,
)
from security_audit.common.canonical_json import JsonValue, canonical_sha256_without_fields


def _load_manifest(project_root: Path) -> dict[str, JsonValue]:
    path = (
        project_root
        / "collectors"
        / "one_shot"
        / "fixtures"
        / "imp028"
        / "valid_manifest.json"
    )
    return cast(dict[str, JsonValue], json.loads(path.read_text(encoding="utf-8")))


def _signature(
    manifest: dict[str, JsonValue],
    status: ExternalSignatureStatus = ExternalSignatureStatus.VERIFIED,
) -> ManifestSignatureProof:
    authorization = cast(dict[str, Any], manifest["authorization"])
    signature = cast(dict[str, Any], authorization["signature"])
    return ManifestSignatureProof(
        status=status,
        manifest_sha256=cast(str, manifest["manifest_content_sha256"]),
        key_id=cast(str, signature["key_id"]),
    )


def _reseal(manifest: dict[str, JsonValue]) -> ManifestSignatureProof:
    digest = canonical_sha256_without_fields(
        manifest,
        {"manifest_content_sha256", "authorization"},
    )
    manifest["manifest_content_sha256"] = digest
    authorization = cast(dict[str, Any], manifest["authorization"])
    signature = cast(dict[str, Any], authorization["signature"])
    signature["signed_sha256"] = digest
    return _signature(manifest)


def _context(**overrides: Any) -> ManifestVerificationContext:
    values: dict[str, Any] = {
        "expected_job_id": "28000000-0000-4000-8000-000000000003",
        "expected_asset_id": "28000000-0000-4000-8000-000000000004",
        "expected_endpoint_id": "imp028-mock-upload",
        "expected_nonce": "SU1QLTAyOC1ub25jZS0wMDAx",
        "checked_at": datetime(2026, 7, 23, 6, 15, tzinfo=UTC),
        "nonce_status": NonceStatus.FRESH,
    }
    values.update(overrides)
    return ManifestVerificationContext(**values)


def _rejection(
    verifier: CollectorManifestVerifier,
    name: str,
    manifest: dict[str, JsonValue],
    expected: ManifestVerificationCode,
    *,
    context: ManifestVerificationContext | None = None,
    signature: ManifestSignatureProof | None = None,
) -> dict[str, object]:
    try:
        verifier.verify(
            manifest,
            context or _context(),
            signature or _signature(manifest),
        )
    except ManifestVerificationError as exc:
        return {
            "name": name,
            "expected_code": expected.value,
            "actual_code": exc.code.value,
            "passed": exc.code is expected,
        }
    return {
        "name": name,
        "expected_code": expected.value,
        "actual_code": "ACCEPTED",
        "passed": False,
    }


def run_mock_collector_acceptance(project_root: Path) -> dict[str, Any]:
    """Run protocol gates without reading Registry, CIM, PowerShell, or host files."""

    allowlist = ProbeAllowlist.from_file(
        project_root
        / "collectors"
        / "one_shot"
        / "contracts"
        / "imp028_probe_allowlist.json"
    )
    verifier = CollectorManifestVerifier(project_root / "database" / "schemas", allowlist)
    manifest = _load_manifest(project_root)
    plan = verifier.verify(manifest, _context(), _signature(manifest))
    collector = MockCollector()
    run = collector.execute(plan)

    tampered = copy.deepcopy(manifest)
    tampered["expires_at"] = "2026-07-23T06:31:00Z"

    unknown = copy.deepcopy(manifest)
    unknown_probes = cast(list[dict[str, Any]], unknown["probes"])
    unknown_probes[0]["probe_id"] = "win.untrusted.command"
    unknown_signature = _reseal(unknown)

    over_limit = copy.deepcopy(manifest)
    over_limit_probes = cast(list[dict[str, Any]], over_limit["probes"])
    over_limit_probes[0]["timeout_seconds"] = 31
    over_limit_signature = _reseal(over_limit)

    rejections = [
        _rejection(
            verifier,
            "내용 변조",
            tampered,
            ManifestVerificationCode.HASH_MISMATCH,
        ),
        _rejection(
            verifier,
            "만료",
            manifest,
            ManifestVerificationCode.MANIFEST_EXPIRED,
            context=_context(checked_at=datetime(2026, 7, 23, 6, 31, tzinfo=UTC)),
        ),
        _rejection(
            verifier,
            "다른 자산",
            manifest,
            ManifestVerificationCode.MANIFEST_SCOPE_MISMATCH,
            context=_context(expected_asset_id="28000000-0000-4000-8000-000000000099"),
        ),
        _rejection(
            verifier,
            "nonce 재사용",
            manifest,
            ManifestVerificationCode.NONCE_REPLAYED,
            context=_context(nonce_status=NonceStatus.REPLAYED),
        ),
        _rejection(
            verifier,
            "미허용 Probe",
            unknown,
            ManifestVerificationCode.PROBE_NOT_ALLOWED,
            signature=unknown_signature,
        ),
        _rejection(
            verifier,
            "Probe 제한 확대",
            over_limit,
            ManifestVerificationCode.PROBE_CONTRACT_MISMATCH,
            signature=over_limit_signature,
        ),
    ]
    replay_code = "ACCEPTED"
    try:
        collector.execute(plan)
    except MockCollectionError as exc:
        replay_code = exc.code.value

    checks = [
        {
            "id": "IMP028-C01",
            "title": "정상 Manifest 검증",
            "passed": len(plan.probes) == 3,
        },
        {
            "id": "IMP028-C02",
            "title": "내장 allowlist Probe만 선택",
            "passed": tuple(probe.probe_id for probe in plan.probes) == allowlist.probe_ids,
        },
        {
            "id": "IMP028-C03",
            "title": "Mock 결과만 생성",
            "passed": (
                run.execution_mode == "MOCK_ONLY"
                and run.real_os_access is False
                and all(result.synthetic for result in run.results)
            ),
        },
        {
            "id": "IMP028-C04",
            "title": "공식 Finding 미생성",
            "passed": not hasattr(run, "finding") and not hasattr(run, "status"),
        },
        {
            "id": "IMP028-C05",
            "title": "변조·만료·다른 자산·nonce 차단",
            "passed": all(item["passed"] for item in rejections[:4]),
        },
        {
            "id": "IMP028-C06",
            "title": "미허용 Probe와 제한 확대 차단",
            "passed": all(item["passed"] for item in rejections[4:]),
        },
        {
            "id": "IMP028-C07",
            "title": "같은 프로세스 재실행 차단",
            "passed": replay_code == MockCollectionCode.REPLAY_DETECTED.value,
        },
        {
            "id": "IMP028-C08",
            "title": "실제 Windows 접근 없음",
            "passed": run.real_os_access is False,
        },
    ]
    return {
        "imp": "IMP-028",
        "acceptance_status": "PASS" if all(item["passed"] for item in checks) else "FAIL",
        "scope": "Mock Collector and Manifest verifier",
        "collector": {
            "name": allowlist.collector_name,
            "version": allowlist.collector_version,
            "release_channel": allowlist.release_channel,
            "execution_mode": run.execution_mode,
            "real_os_access": run.real_os_access,
        },
        "manifest_sha256": plan.manifest_sha256,
        "allowlisted_probes": list(allowlist.probe_ids),
        "mock_results": [
            {
                "probe_id": result.probe_id,
                "probe_version": result.probe_version,
                "collection_status": result.collection_status.value,
                "synthetic": result.synthetic,
                "payload": result.payload,
            }
            for result in run.results
        ],
        "rejection_cases": rejections,
        "checks": checks,
        "official_finding_created": False,
        "next_imp": "IMP-029",
    }

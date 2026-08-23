"""IMP-028 protocol test double that never touches the host OS."""

from __future__ import annotations

from collections.abc import Callable
from types import MappingProxyType

from security_audit.common.canonical_json import JsonValue

from .contracts import (
    MockCollectionCode,
    MockCollectionError,
    MockCollectionRun,
    MockProbeResult,
    VerifiedExecutionPlan,
    VerifiedProbeRequest,
)

MockHandler = Callable[[VerifiedProbeRequest], JsonValue]


def _mock_disks(_request: VerifiedProbeRequest) -> JsonValue:
    return {"device_count": 1, "devices": [{"device_id": 0, "bus_type": "NVMe"}]}


def _mock_partitions(_request: VerifiedProbeRequest) -> JsonValue:
    return {
        "partition_count": 1,
        "partitions": [{"disk_id": 0, "partition_id": 3, "kind": "BASIC_DATA"}],
    }


def _mock_volumes(_request: VerifiedProbeRequest) -> JsonValue:
    return {
        "volume_count": 1,
        "volumes": [
            {
                "volume_id": "mock-volume-001",
                "filesystem": "NTFS",
                "drive_type": "FIXED",
                "bitlocker_state": "UNLOCKED",
            }
        ],
    }


_MOCK_HANDLERS: MappingProxyType[str, MockHandler] = MappingProxyType(
    {
        "win.storage.disks": _mock_disks,
        "win.storage.partitions": _mock_partitions,
        "win.storage.volumes": _mock_volumes,
    }
)


class MockCollector:
    """Execute only verified plans against fixed synthetic handlers."""

    def __init__(self) -> None:
        self._used_nonces: set[str] = set()

    def execute(self, plan: VerifiedExecutionPlan) -> MockCollectionRun:
        if plan.nonce in self._used_nonces:
            raise MockCollectionError(
                MockCollectionCode.REPLAY_DETECTED,
                "This Manifest nonce has already been executed by this Collector process.",
            )
        for request in plan.probes:
            if request.probe_id not in _MOCK_HANDLERS:
                raise MockCollectionError(
                    MockCollectionCode.PLAN_INVALID,
                    "Verified plan does not map to a built-in mock handler.",
                )
        self._used_nonces.add(plan.nonce)
        results = tuple(
            MockProbeResult(
                probe_id=request.probe_id,
                probe_version=request.probe_version,
                control_ids=request.control_ids,
                collection_status=MockCollectionCode.COLLECTED,
                synthetic=True,
                payload=_MOCK_HANDLERS[request.probe_id](request),
            )
            for request in plan.probes
        )
        return MockCollectionRun(
            manifest_id=plan.manifest_id,
            manifest_sha256=plan.manifest_sha256,
            job_id=plan.job_id,
            asset_id=plan.asset_id,
            execution_mode="MOCK_ONLY",
            real_os_access=False,
            results=results,
        )

"""Closed Probe catalog loader for the signed Collector release."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from types import MappingProxyType
from typing import Never, cast

from security_audit.analysis.package_validation import PackageValidationError, load_strict_json
from security_audit.common.canonical_json import JsonScalar

from .contracts import ManifestVerificationCode, ManifestVerificationError, ProbeContract

_EXPECTED_TOP_LEVEL = {
    "contract_version",
    "collector_name",
    "collector_version",
    "release_channel",
    "execution_mode",
    "real_os_access",
    "probes",
}
_EXPECTED_PROBE_FIELDS = {
    "probe_id",
    "probe_version",
    "control_ids",
    "required_privilege",
    "max_timeout_seconds",
    "max_output_bytes",
    "parameters",
}


def _reject(message: str) -> Never:
    raise ManifestVerificationError(ManifestVerificationCode.PROBE_CONTRACT_MISMATCH, message)


def _string(value: object) -> str:
    if not isinstance(value, str) or not value:
        _reject("The embedded Probe catalog contains an invalid string.")
    return value


def _positive_integer(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        _reject("The embedded Probe catalog contains an invalid limit.")
    return value


def _scalar_mapping(value: object) -> MappingProxyType[str, JsonScalar]:
    if not isinstance(value, Mapping):
        _reject("The embedded Probe parameters are invalid.")
    source = cast(Mapping[object, object], value)
    result: dict[str, JsonScalar] = {}
    for raw_key, raw_value in source.items():
        if not isinstance(raw_key, str) or not isinstance(
            raw_value, (str, int, float, bool, type(None))
        ):
            _reject("The embedded Probe parameters are invalid.")
        result[raw_key] = raw_value
    return MappingProxyType(result)


class ProbeAllowlist:
    """The exact protocol surface compiled into one Collector release."""

    def __init__(
        self,
        *,
        collector_name: str,
        collector_version: str,
        release_channel: str,
        execution_mode: str,
        real_os_access: bool,
        probes: Mapping[str, ProbeContract],
    ) -> None:
        self.collector_name = collector_name
        self.collector_version = collector_version
        self.release_channel = release_channel
        self.execution_mode = execution_mode
        self.real_os_access = real_os_access
        self._probes = MappingProxyType(dict(probes))

    @classmethod
    def from_file(cls, path: Path) -> ProbeAllowlist:
        try:
            raw = load_strict_json(path.read_bytes())
        except (OSError, PackageValidationError) as exc:
            raise ManifestVerificationError(
                ManifestVerificationCode.PROBE_CONTRACT_MISMATCH,
                "The embedded Probe catalog is unavailable or invalid.",
            ) from exc
        if not isinstance(raw, dict) or set(raw) != _EXPECTED_TOP_LEVEL:
            _reject("The embedded Probe catalog envelope is invalid.")
        root = cast(Mapping[str, object], raw)
        execution_mode = root.get("execution_mode")
        real_os_access = root.get("real_os_access")
        if root.get("contract_version") != "1.0.0" or (
            (execution_mode, real_os_access)
            not in {
                ("MOCK_ONLY", False),
                ("WINDOWS_READ_ONLY", True),
            }
        ):
            _reject("The embedded Collector execution boundary is invalid.")
        raw_probes = root.get("probes")
        if not isinstance(raw_probes, Sequence) or isinstance(raw_probes, (str, bytes)):
            _reject("The embedded Probe list is invalid.")
        probe_items = cast(Sequence[object], raw_probes)
        probes: dict[str, ProbeContract] = {}
        for raw_probe in probe_items:
            if not isinstance(raw_probe, Mapping) or set(raw_probe) != _EXPECTED_PROBE_FIELDS:
                _reject("An embedded Probe contract is invalid.")
            probe = cast(Mapping[str, object], raw_probe)
            probe_id = _string(probe.get("probe_id"))
            if probe_id in probes:
                _reject("The embedded Probe catalog contains a duplicate ID.")
            controls = probe.get("control_ids")
            if not isinstance(controls, Sequence) or isinstance(controls, (str, bytes)):
                _reject("An embedded Probe Control scope is invalid.")
            control_items = cast(Sequence[object], controls)
            control_ids = frozenset(_string(item) for item in control_items)
            if not control_ids or len(control_ids) != len(control_items):
                _reject("An embedded Probe Control scope is empty or duplicated.")
            probes[probe_id] = ProbeContract(
                probe_id=probe_id,
                probe_version=_string(probe.get("probe_version")),
                control_ids=control_ids,
                required_privilege=_string(probe.get("required_privilege")),
                max_timeout_seconds=_positive_integer(probe.get("max_timeout_seconds")),
                max_output_bytes=_positive_integer(probe.get("max_output_bytes")),
                parameters=_scalar_mapping(probe.get("parameters")),
            )
        if not probes:
            _reject("The embedded Probe catalog is empty.")
        return cls(
            collector_name=_string(root.get("collector_name")),
            collector_version=_string(root.get("collector_version")),
            release_channel=_string(root.get("release_channel")),
            execution_mode=cast(str, execution_mode),
            real_os_access=cast(bool, real_os_access),
            probes=probes,
        )

    def get(self, probe_id: str) -> ProbeContract | None:
        return self._probes.get(probe_id)

    @property
    def probe_ids(self) -> tuple[str, ...]:
        return tuple(self._probes)

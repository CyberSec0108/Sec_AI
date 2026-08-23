from __future__ import annotations

from pathlib import Path

from security_audit.analysis.package_validation import PackageValidationCode
from security_audit.application.demo_evaluation import SyntheticPc07Pipeline

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_demo_hash_tampering_is_rejected_before_finding_creation() -> None:
    result = SyntheticPc07Pipeline(PROJECT_ROOT).verify_archive_tamper_rejected(
        "pc07-pass"
    )

    assert result is PackageValidationCode.ARCHIVE_HASH_MISMATCH


def test_gateway_uses_runtime_dns_resolution_for_api_recreation() -> None:
    config = (PROJECT_ROOT / "deploy" / "gateway" / "nginx.conf").read_text("utf-8")

    assert "resolver 127.0.0.11" in config
    assert "set $api_upstream api:8000;" in config
    assert "proxy_pass http://$api_upstream;" in config
    assert "proxy_pass http://api:8000;" not in config

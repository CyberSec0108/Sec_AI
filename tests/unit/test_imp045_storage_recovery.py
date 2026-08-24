from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from apps.api.main import app
from fastapi.testclient import TestClient

from security_audit.application.product_features import (
    FeatureState,
    public_feature_registry,
)
from security_audit.persistence.database.models import StorageRecoveryRunRecord
from security_audit.persistence.database.storage_recovery_repository import (
    public_run_values,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = PROJECT_ROOT / "database" / "schemas"


def test_imp045_policy_preserves_truth_and_primary_volumes() -> None:
    policy = json.loads(
        (SCHEMA_ROOT / "imp045_storage_recovery_policy.json").read_text(
            encoding="utf-8"
        )
    )

    assert policy["truth"]["business_state"] == "PostgreSQL"
    assert policy["truth"]["original_bytes"] == "AIStor exact object version"
    assert policy["truth"]["redis"] == "REBUILDABLE_TRANSPORT"
    assert policy["recovery"]["primary_volume_overwrite_allowed"] is False
    assert policy["recovery"]["isolated_restore_required"] is True
    assert policy["development_limitations"]["real_evidence_allowed"] is False
    assert (
        policy["development_limitations"]["production_recovery_approved"] is False
    )
    assert policy["safety"]["official_finding_created"] is False


def test_recovery_manifest_is_synthetic_hash_only_and_version_aware() -> None:
    schema = json.loads(
        (SCHEMA_ROOT / "storage_recovery_manifest.schema.json").read_text(
            encoding="utf-8"
        )
    )
    serialized = json.dumps(schema).casefold()

    assert "synthetic_dev_only" in serialized
    assert "source_version_id" in serialized
    assert "finding_lineage_sha256" in serialized
    assert "independent_failure_domain_required" in serialized
    for prohibited in ("password", "cookie", "private_key", "raw_evidence"):
        assert prohibited not in serialized


def test_imp045_migration_has_recovery_inventory_and_runtime_grants() -> None:
    source = (
        PROJECT_ROOT
        / "database"
        / "alembic"
        / "versions"
        / "0004_imp045_storage_recovery.py"
    ).read_text(encoding="utf-8")

    assert "storage_recovery_runs" in source
    assert "evidence_artifacts" in source
    assert "uq_evidence_artifacts_object_version" in source
    assert "ck_storage_recovery_runs_development_gate_only" in source
    assert "GRANT SELECT, INSERT, UPDATE" in source
    assert "GRANT SELECT ON alembic_version TO secai_runtime" in source


def test_recovery_compose_uses_only_isolated_named_restore_volumes() -> None:
    source = (
        PROJECT_ROOT / "deploy" / "compose" / "compose.imp045-recovery.yml"
    ).read_text(encoding="utf-8")

    for name in (
        "sec-ai-mvp-imp045-postgres-restore",
        "sec-ai-mvp-imp045-redis-restore",
        "sec-ai-mvp-imp045-aistor-restore",
    ):
        assert name in source
    assert "sec-ai-mvp-postgres-data" not in source
    assert "sec-ai-mvp-redis-data" not in source
    assert "sec-ai-mvp-aistor-data" not in source
    assert "ports:" not in source
    assert "external: true" in source


def test_storage_recovery_cli_verifies_exact_versions_hashes_and_lineage() -> None:
    source = (
        PROJECT_ROOT / "apps" / "worker" / "storage_recovery_cli.py"
    ).read_text(encoding="utf-8")

    for phrase in (
        "source_version_id",
        "version_id=version_id",
        "finding_lineage_matches",
        "artifact_inventory_matches",
        "canonicalize_json(manifest)",
        "SYNTHETIC_DEV_ONLY",
    ):
        assert phrase in source
    assert '"password"' not in source
    assert "print(type(exc).__name__" in source


def test_public_storage_status_never_contains_ids_paths_or_raw_data() -> None:
    record = StorageRecoveryRunRecord(
        status="SUCCEEDED",
        postgres_status="RESTORED",
        redis_status="REBUILT",
        aistor_status="RESTORED",
        finding_lineage_reproduced=True,
        object_hash_reproduced=True,
        pending_outbox_reconciled=True,
        independent_failure_domain=False,
        production_gate_complete=False,
    )

    values = public_run_values(record)
    serialized = json.dumps(values).casefold()

    assert values["production_gate_complete"] is False
    for prohibited in (
        "run_id",
        "artifact_id",
        "object_key",
        "version_id",
        "worker_pid",
        "password",
        "file_path",
    ):
        assert prohibited not in serialized


def test_storage_recovery_page_is_live_and_explains_dev_limitations(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    monkeypatch.setattr(
        "apps.api.storage_recovery.latest_storage_recovery_summary",
        lambda: {
            "status": "SUCCEEDED",
            "status_label": "개발 복구훈련 완료",
            "dependency_available": True,
            "postgres_status": "RESTORED",
            "redis_status": "REBUILT",
            "aistor_status": "RESTORED",
            "postgres_rpo_seconds": 2,
            "postgres_rto_seconds": 8,
            "evidence_rpo_seconds": 1,
            "evidence_rto_seconds": 6,
            "finding_lineage_reproduced": True,
            "object_hash_reproduced": True,
            "pending_outbox_reconciled": True,
            "independent_failure_domain": False,
            "production_gate_complete": False,
            "raw_data_exposed": False,
            "secret_exposed": False,
        },
    )
    with TestClient(app) as client:
        page = client.get("/ui/storage-recovery")
        response = client.get("/api/v1/storage-recovery/status")

    assert page.status_code == 200
    for phrase in (
        "저장소가 멈춰도 원본과 결과 관계를 다시 확인합니다",
        "운영 재해복구 승인을 뜻하지 않습니다",
        "hash 일치",
        "관계 일치",
        "다시 전달됨",
    ):
        assert phrase in page.text
    assert 'data-ui-standard="storage-recovery-v1"' in page.text
    assert response.status_code == 200
    assert response.json()["production_gate_complete"] is False
    registry = public_feature_registry()
    assert registry["storage_recovery"].state is FeatureState.LIVE
    assert registry["storage_recovery"].href == "/ui/storage-recovery"


def test_storage_recovery_page_returns_safe_guidance_during_postgres_outage(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    monkeypatch.setattr(
        "apps.api.storage_recovery.latest_storage_recovery_summary",
        lambda: {
            "status": "DEPENDENCY_UNAVAILABLE",
            "status_label": "저장소 연결 확인 필요",
            "dependency_available": False,
            "postgres_status": "연결 확인 필요",
            "redis_status": "상태 확인 대기",
            "aistor_status": "상태 확인 대기",
            "finding_lineage_reproduced": False,
            "object_hash_reproduced": False,
            "pending_outbox_reconciled": False,
            "independent_failure_domain": False,
            "production_gate_complete": False,
            "raw_data_exposed": False,
            "secret_exposed": False,
        },
    )
    with TestClient(app) as client:
        response = client.get("/api/v1/storage-recovery/status")
        page = client.get("/ui/storage-recovery")

    assert response.status_code == 200
    assert response.json()["status"] == "DEPENDENCY_UNAVAILABLE"
    assert "잠시 뒤 다시 확인하세요" in page.text
    for prohibited in ("traceback", "postgresql+", "password=", "/run/secrets"):
        assert prohibited not in page.text.casefold()


def test_storage_recovery_surface_is_hidden_outside_development(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "false")
    with TestClient(app) as client:
        assert client.get("/ui/storage-recovery").status_code == 404
        assert client.get("/api/v1/storage-recovery/status").status_code == 404

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from apps.api import dev_signed_downloads as download_api
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from security_audit.security.auth import AuthenticatedPrincipal, HumanRole
from security_audit.supply_chain.dev_signed_download import (
    DevArtifactPlatform,
    build_dev_signed_catalog,
    verify_dev_signed_catalog,
)


def _principal(now: datetime) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        user_id=uuid4(),
        username="download-user",
        display_name="다운로드 사용자",
        organization_id=uuid4(),
        roles=frozenset({HumanRole.USER}),
        asset_ids=frozenset(),
        auth_methods=frozenset({"PASSWORD", "DEV_CODE"}),
        session_created_at=now,
        reauthenticated_at=now,
    )


def _release(root: Path, now: datetime) -> Any:
    values = {
        DevArtifactPlatform.WINDOWS_X64: (
            "SecAI-Collector-Windows-x64.exe",
            b"windows-download",
        ),
        DevArtifactPlatform.LINUX_AUTO_X64: (
            "secai-linux-check-x86_64",
            b"automatic-linux-download",
        ),
        DevArtifactPlatform.UBUNTU_24_04_X64: (
            "secai-linux-check-ubuntu24-x86_64",
            b"ubuntu-download",
        ),
        DevArtifactPlatform.ROCKY_9_X64: (
            "secai-linux-check-rocky9-x86_64",
            b"rocky-download",
        ),
    }
    artifacts = {}
    for platform, (filename, content) in values.items():
        path = root / filename
        path.write_bytes(content)
        artifacts[platform] = path
    key = Ed25519PrivateKey.generate()
    catalog = build_dev_signed_catalog(
        artifacts=artifacts,
        created_at=now,
        expires_at=now + timedelta(days=1),
        sign=lambda payload: ("api-test-key", key.sign(payload)),
        provenance={
            platform: {"source_profile": "TEST", "security_gates": "PASS"}
            for platform in DevArtifactPlatform
        },
    )
    return verify_dev_signed_catalog(
        catalog,
        artifact_root=root,
        public_keys={"api-test-key": key.public_key()},
        now=now,
        fail_closed=True,
    )


def test_authenticated_issue_and_public_one_time_fetch(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    now = datetime.now(UTC)
    release = _release(tmp_path, now)
    principal = _principal(now)
    monkeypatch.setenv("SECAI_DEV_SIGNED_DOWNLOAD_ENABLED", "true")
    monkeypatch.setenv("SECAI_AUTH_PROFILE", "DEV-LOCAL")
    monkeypatch.setattr(download_api, "_require_user", lambda _request: principal)
    monkeypatch.setattr(
        download_api,
        "_load_release",
        lambda **_named: release,
    )

    def verify_csrf(_request: object, value: str | None) -> None:
        if value != "csrf-test":
            raise HTTPException(403, "CSRF rejected")

    monkeypatch.setattr(download_api, "verify_browser_csrf", verify_csrf)
    download_api._runtime.cache_clear()
    app = FastAPI()
    app.include_router(download_api.router)

    with TestClient(app) as client:
        missing_csrf = client.post(
            "/api/v1/dev-downloads/codes",
            json={"platform": "WINDOWS_X64"},
        )
        assert missing_csrf.status_code == 403

        issued = client.post(
            "/api/v1/dev-downloads/codes",
            json={"platform": "WINDOWS_X64"},
            headers={"X-CSRF-Token": "csrf-test"},
        )
        assert issued.status_code == 201
        value = issued.json()
        assert value["release_channel"] == "DEV-SIGNED-TEST"
        assert value["production_release"] is False
        assert "code=" not in value["fetch_url"]

        downloaded = client.post(
            value["fetch_url"],
            content=value["code"],
            headers={"Content-Type": "text/plain"},
        )
        assert downloaded.status_code == 200
        assert downloaded.content == b"windows-download"
        assert downloaded.headers["x-secai-sha256"] == value["sha256"]
        assert downloaded.headers["cache-control"] == "no-store"
        assert "attachment" in downloaded.headers["content-disposition"]

        replay = client.post(
            value["fetch_url"],
            content=value["code"],
            headers={"Content-Type": "text/plain"},
        )
        assert replay.status_code == 401

    download_api._runtime.cache_clear()

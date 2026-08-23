from __future__ import annotations

from collections.abc import Iterator

import pytest
from apps.api.main import app
from fastapi.testclient import TestClient


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


def test_live_endpoint_identifies_service(client: TestClient) -> None:
    response = client.get("/health/live")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "audit-api",
        "version": "0.1.0",
    }


def test_ready_endpoint_is_fail_closed(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def unavailable_dependencies() -> dict[str, bool]:
        return {
            "postgres": True,
            "redis": True,
            "aistor": False,
            "clamav": True,
        }

    monkeypatch.setattr("apps.api.main.check_dependencies", unavailable_dependencies)
    response = client.get("/health/ready")

    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"
    assert response.json()["dependencies"]["aistor"] is False


def test_ready_endpoint_requires_every_dependency(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def available_dependencies() -> dict[str, bool]:
        return {
            "postgres": True,
            "redis": True,
            "aistor": True,
            "clamav": True,
        }

    monkeypatch.setattr("apps.api.main.check_dependencies", available_dependencies)
    response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json()["status"] == "ready"

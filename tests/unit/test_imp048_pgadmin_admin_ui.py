from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_pgadmin_is_digest_locked_loopback_only_and_opt_in() -> None:
    compose = (PROJECT_ROOT / "deploy" / "compose" / "compose.dev.yml").read_text(
        encoding="utf-8"
    )
    dockerfile = (PROJECT_ROOT / "deploy" / "docker" / "pgadmin.Dockerfile").read_text(
        encoding="utf-8"
    )
    cpython_patch = (
        PROJECT_ROOT
        / "deploy"
        / "patches"
        / "cpython-3.14-CVE-2026-15308.patch"
    ).read_text(encoding="utf-8")
    security_lock = (
        PROJECT_ROOT / "requirements" / "lock" / "pgadmin-security.lock"
    ).read_text(encoding="utf-8")
    lock = (
        PROJECT_ROOT / "deploy" / "locks" / "container-images.lock.yml"
    ).read_text(encoding="utf-8")

    assert 'profiles: ["admin-tools"]' in compose
    assert "${SECAI_PGADMIN_BIND:-127.0.0.1}" in compose
    assert "${SECAI_PGADMIN_PORT:-18490}:5050" in compose
    assert "PGADMIN_DEFAULT_PASSWORD_FILE: /run/secrets/pgadmin_default_password" in compose
    assert "no-new-privileges:true" in compose
    assert "cap_drop:" in compose
    assert "dpage/pgadmin4:9.16@sha256:66a300a7" in dockerfile
    assert "cpython-3.14-CVE-2026-15308.patch" in dockerfile
    assert "python/cpython@07efb08123ba9367a7107325adb9d5626dca1ca9" in dockerfile
    assert "self._parse_threshold = len(self.rawdata)" in cpython_patch
    assert "pillow==12.3.0" in security_lock
    assert "--hash=sha256:" in security_lock
    assert "index_digest: sha256:40fa840c" in lock
    assert "no-postgres-host-port" in lock


def test_pgadmin_uses_a_non_superuser_database_management_role() -> None:
    migrate = (PROJECT_ROOT / "database" / "migrate.py").read_text(encoding="utf-8")
    migration = (
        PROJECT_ROOT
        / "database"
        / "alembic"
        / "versions"
        / "0007_imp048_real_guide_and_inventory.py"
    ).read_text(encoding="utf-8")
    scope_migration = (
        PROJECT_ROOT
        / "database"
        / "alembic"
        / "versions"
        / "0008_imp048_pgadmin_scope.py"
    ).read_text(encoding="utf-8")
    server_definition = (
        PROJECT_ROOT / "deploy" / "pgadmin" / "servers.json"
    ).read_text(encoding="utf-8")

    assert '_DB_ADMIN_ROLE = "secai_db_admin"' in migrate
    assert "NOSUPERUSER NOCREATEDB NOCREATEROLE" in migrate
    assert "NOINHERIT NOREPLICATION" in migrate
    assert "GRANT pg_monitor TO secai_db_admin" in migration
    assert "GRANT SELECT, INSERT, UPDATE, DELETE" in migration
    assert "SET secai.organization_id" in scope_migration
    assert "46000000-0000-4000-8000-000000000001" in scope_migration
    assert '"Username": "secai_db_admin"' in server_definition
    assert '"SavePassword": false' in server_definition


def test_postgresql_remains_internal_without_a_host_port() -> None:
    compose = (PROJECT_ROOT / "deploy" / "compose" / "compose.yml").read_text(
        encoding="utf-8"
    )
    postgres_section = compose.split("\n  postgres:\n", maxsplit=1)[1].split(
        "\n  redis:\n", maxsplit=1
    )[0]

    assert "ports:" not in postgres_section
    assert "app_net" in postgres_section

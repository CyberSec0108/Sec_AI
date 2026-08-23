"""Bootstrap the fixed runtime role, then run Alembic as the migration owner."""

from __future__ import annotations

import os

import psycopg
from alembic import command
from alembic.config import Config
from psycopg import sql

from security_audit.common.secret_files import read_required_secret

_RUNTIME_ROLE = "secai_runtime"
_DB_ADMIN_ROLE = "secai_db_admin"


def _required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Required migration setting is missing: {name}.")
    return value


def _upsert_login_role(
    cursor: psycopg.Cursor[tuple[object, ...]],
    *,
    role_name: str,
    password: str,
) -> None:
    cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role_name,))
    if cursor.fetchone() is None:
        cursor.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                "NOINHERIT NOREPLICATION PASSWORD {}"
            ).format(sql.Identifier(role_name), sql.Literal(password))
        )
    else:
        cursor.execute(
            sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                sql.Identifier(role_name),
                sql.Literal(password),
            )
        )


def _bootstrap_database_roles() -> None:
    runtime_user = os.getenv("SECAI_POSTGRES_RUNTIME_USER", _RUNTIME_ROLE)
    admin_user = os.getenv("SECAI_POSTGRES_DB_ADMIN_USER", _DB_ADMIN_ROLE)
    if runtime_user != _RUNTIME_ROLE or admin_user != _DB_ADMIN_ROLE:
        raise RuntimeError("Database role names are fixed by the migration contract.")
    runtime_password = read_required_secret(_required("SECAI_POSTGRES_RUNTIME_PASSWORD_FILE"))
    admin_password = read_required_secret(_required("SECAI_POSTGRES_DB_ADMIN_PASSWORD_FILE"))
    migrator_password = read_required_secret(_required("SECAI_POSTGRES_PASSWORD_FILE"))
    with psycopg.connect(
        host=_required("SECAI_POSTGRES_HOST"),
        port=int(_required("SECAI_POSTGRES_PORT")),
        dbname=_required("SECAI_POSTGRES_DB"),
        user=_required("SECAI_POSTGRES_USER"),
        password=migrator_password,
        autocommit=True,
    ) as connection:
        with connection.cursor() as cursor:
            _upsert_login_role(
                cursor,
                role_name=runtime_user,
                password=runtime_password,
            )
            _upsert_login_role(
                cursor,
                role_name=admin_user,
                password=admin_password,
            )


def main() -> None:
    _bootstrap_database_roles()
    command.upgrade(Config("alembic.ini"), "head")


if __name__ == "__main__":
    main()

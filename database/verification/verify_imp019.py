"""Verify the IMP-019 least-privilege runtime database contract."""

from __future__ import annotations

import json

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import DBAPIError

from security_audit.common.service_settings import ServiceSettings


def _must_be_rejected(engine: Engine, statement: str) -> str:
    try:
        with engine.begin() as connection:
            connection.execute(text(statement))
    except DBAPIError as exc:
        return type(exc.orig).__name__
    raise AssertionError("A forbidden runtime database operation was allowed.")


def main() -> None:
    settings = ServiceSettings.from_environment()
    if settings.postgres_user != "secai_runtime":
        raise AssertionError("Application is not using the fixed runtime database role.")
    engine = create_engine(settings.postgres_url())
    with engine.connect() as connection:
        current_user = connection.scalar(text("SELECT current_user"))
        finding_count = connection.scalar(text("SELECT count(*) FROM finding_versions"))
    result = {
        "current_user": current_user,
        "finding_count": finding_count,
        "ddl": _must_be_rejected(
            engine,
            "CREATE TABLE imp019_forbidden(id integer)",
        ),
        "finding_delete": _must_be_rejected(engine, "DELETE FROM finding_versions"),
        "finding_update": _must_be_rejected(
            engine,
            "UPDATE finding_versions SET status = status",
        ),
    }
    engine.dispose()
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()

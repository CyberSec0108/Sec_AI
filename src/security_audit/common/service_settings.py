from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import quote

from security_audit.common.secret_files import read_required_secret


@dataclass(frozen=True, slots=True)
class ServiceSettings:
    postgres_host: str
    postgres_port: int
    postgres_database: str
    postgres_user: str
    postgres_password_file: str
    redis_host: str
    redis_port: int
    redis_user: str
    redis_password_file: str
    aistor_endpoint: str
    clamav_host: str
    clamav_port: int
    dependency_timeout_seconds: float

    @classmethod
    def from_environment(cls) -> ServiceSettings:
        return cls(
            postgres_host=os.getenv("SECAI_POSTGRES_HOST", "postgres"),
            postgres_port=int(os.getenv("SECAI_POSTGRES_PORT", "5432")),
            postgres_database=os.getenv("SECAI_POSTGRES_DB", "secai"),
            postgres_user=os.getenv("SECAI_POSTGRES_USER", "secai_app"),
            postgres_password_file=os.getenv(
                "SECAI_POSTGRES_PASSWORD_FILE", "/run/secrets/postgres_password"
            ),
            redis_host=os.getenv("SECAI_REDIS_HOST", "redis"),
            redis_port=int(os.getenv("SECAI_REDIS_PORT", "6379")),
            redis_user=os.getenv("SECAI_REDIS_USER", "secai_celery"),
            redis_password_file=os.getenv(
                "SECAI_REDIS_PASSWORD_FILE", "/run/secrets/redis_password"
            ),
            aistor_endpoint=os.getenv("SECAI_AISTOR_ENDPOINT", "http://aistor:9000"),
            clamav_host=os.getenv("SECAI_CLAMAV_HOST", "clamav"),
            clamav_port=int(os.getenv("SECAI_CLAMAV_PORT", "3310")),
            dependency_timeout_seconds=float(
                os.getenv("SECAI_DEPENDENCY_TIMEOUT_SECONDS", "2.0")
            ),
        )

    def redis_url(self, database: int = 0) -> str:
        password = read_required_secret(self.redis_password_file)
        username = quote(self.redis_user, safe="")
        encoded_password = quote(password, safe="")
        return (
            f"redis://{username}:{encoded_password}@{self.redis_host}:"
            f"{self.redis_port}/{database}"
        )

    def postgres_url(self) -> str:
        """Build a psycopg SQLAlchemy URL without exposing the secret in configuration."""

        password = read_required_secret(self.postgres_password_file)
        username = quote(self.postgres_user, safe="")
        encoded_password = quote(password, safe="")
        database = quote(self.postgres_database, safe="")
        return (
            f"postgresql+psycopg://{username}:{encoded_password}@{self.postgres_host}:"
            f"{self.postgres_port}/{database}"
        )

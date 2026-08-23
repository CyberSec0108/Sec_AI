from __future__ import annotations

from redis import Redis
from redis.exceptions import RedisError

from security_audit.common.secret_files import SecretFileError
from security_audit.common.service_settings import ServiceSettings


def main() -> int:
    try:
        settings = ServiceSettings.from_environment()
        client: Redis = Redis.from_url(
            settings.redis_url(),
            socket_connect_timeout=settings.dependency_timeout_seconds,
            socket_timeout=settings.dependency_timeout_seconds,
        )
        try:
            return 0 if client.ping() else 1
        finally:
            client.close()
    except (OSError, SecretFileError, RedisError):
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

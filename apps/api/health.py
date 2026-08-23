from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

import httpx
import psycopg
from redis import Redis
from redis.exceptions import RedisError

from security_audit.common.secret_files import SecretFileError, read_required_secret
from security_audit.common.service_settings import ServiceSettings


def _postgres_ping(settings: ServiceSettings) -> bool:
    password = read_required_secret(settings.postgres_password_file)
    with psycopg.connect(
        host=settings.postgres_host,
        port=settings.postgres_port,
        dbname=settings.postgres_database,
        user=settings.postgres_user,
        password=password,
        connect_timeout=max(1, int(settings.dependency_timeout_seconds)),
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            return cursor.fetchone() == (1,)


def _redis_ping(settings: ServiceSettings) -> bool:
    client: Redis = Redis.from_url(
        settings.redis_url(),
        socket_connect_timeout=settings.dependency_timeout_seconds,
        socket_timeout=settings.dependency_timeout_seconds,
    )
    try:
        return bool(client.ping())
    finally:
        client.close()


async def _aistor_ping(settings: ServiceSettings) -> bool:
    timeout = httpx.Timeout(settings.dependency_timeout_seconds)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        response = await client.get(f"{settings.aistor_endpoint}/minio/health/ready")
    return response.status_code == 200


async def _clamav_ping(settings: ServiceSettings) -> bool:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(settings.clamav_host, settings.clamav_port),
        timeout=settings.dependency_timeout_seconds,
    )
    try:
        writer.write(b"zPING\x00")
        await writer.drain()
        response = await asyncio.wait_for(
            reader.read(16), timeout=settings.dependency_timeout_seconds
        )
        return response.rstrip(b"\x00\n") == b"PONG"
    finally:
        writer.close()
        await writer.wait_closed()


async def check_dependencies(
    settings: ServiceSettings | None = None,
) -> dict[str, bool]:
    current = settings or ServiceSettings.from_environment()

    async def safe_thread_check(check: Callable[[], bool]) -> bool:
        try:
            return bool(
                await asyncio.wait_for(
                    asyncio.to_thread(check),
                    timeout=current.dependency_timeout_seconds + 0.5,
                )
            )
        except (OSError, TimeoutError, SecretFileError, psycopg.Error, RedisError):
            return False

    async def safe_async_check(check: Awaitable[bool]) -> bool:
        try:
            return bool(await check)
        except (OSError, TimeoutError, httpx.HTTPError):
            return False

    postgres, redis, aistor, clamav = await asyncio.gather(
        safe_thread_check(lambda: _postgres_ping(current)),
        safe_thread_check(lambda: _redis_ping(current)),
        safe_async_check(_aistor_ping(current)),
        safe_async_check(_clamav_ping(current)),
    )
    return {
        "postgres": postgres,
        "redis": redis,
        "aistor": aistor,
        "clamav": clamav,
    }

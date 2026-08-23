from __future__ import annotations

import argparse
import hashlib
import json
import socket
import struct
from pathlib import Path

MAX_SCAN_BYTES = 100 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_response(connection: socket.socket) -> str:
    chunks: list[bytes] = []
    while True:
        chunk = connection.recv(4096)
        if not chunk:
            break
        chunks.append(chunk)
        if b"\0" in chunk:
            break
    return b"".join(chunks).rstrip(b"\0\n").decode("utf-8", errors="replace")


def _version(host: str, port: int) -> str:
    with socket.create_connection((host, port), timeout=10) as connection:
        connection.sendall(b"zVERSION\0")
        return _read_response(connection)


def _scan(path: Path, host: str, port: int) -> str:
    with socket.create_connection((host, port), timeout=10) as connection:
        connection.settimeout(120)
        connection.sendall(b"zINSTREAM\0")
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(CHUNK_BYTES), b""):
                connection.sendall(struct.pack("!I", len(chunk)))
                connection.sendall(chunk)
        connection.sendall(struct.pack("!I", 0))
        return _read_response(connection)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--host", default="clamav")
    parser.add_argument("--port", default=3310, type=int)
    arguments = parser.parse_args()
    artifact = arguments.artifact.resolve()
    if (
        not artifact.is_file()
        or artifact.stat().st_size <= 0
        or artifact.stat().st_size > MAX_SCAN_BYTES
    ):
        raise RuntimeError("Artifact is missing or outside the ClamAV scan limit.")
    response = _scan(artifact, arguments.host, arguments.port)
    clean = response.endswith(": OK")
    report = {
        "scanner": "ClamAV",
        "engine": _version(arguments.host, arguments.port),
        "artifact_name": artifact.name,
        "artifact_sha256": _sha256(artifact),
        "artifact_bytes": artifact.stat().st_size,
        "status": "CLEAN" if clean else "DETECTED_OR_ERROR",
        "response": response.replace(str(artifact), artifact.name),
    }
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0 if clean else 1


if __name__ == "__main__":
    raise SystemExit(main())

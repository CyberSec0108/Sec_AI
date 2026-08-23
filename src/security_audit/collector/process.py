"""Bounded child-process execution for fixed Collector Probe commands."""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO


class BoundedExecutionCode(StrEnum):
    START_FAILED = "START_FAILED"
    STDIN_FAILED = "STDIN_FAILED"
    TIMEOUT = "TIMEOUT"
    OUTPUT_TOO_LARGE = "OUTPUT_TOO_LARGE"


class BoundedExecutionError(RuntimeError):
    def __init__(self, code: BoundedExecutionCode, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class BoundedCommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def _read_stream(
    stream: BinaryIO,
    sink: bytearray,
    max_output_bytes: int,
    exceeded: threading.Event,
) -> None:
    try:
        while True:
            chunk = stream.read(4096)
            if not chunk:
                return
            remaining = max_output_bytes - len(sink)
            if remaining > 0:
                sink.extend(chunk[:remaining])
            if len(chunk) > remaining:
                exceeded.set()
                return
    finally:
        stream.close()


class BoundedProcessExecutor:
    """Run one fixed command with live byte caps and process-tree termination."""

    def __init__(self, *, platform_name: str | None = None) -> None:
        self._platform_name = platform_name or os.name

    def __call__(
        self,
        command: tuple[str, ...],
        timeout_seconds: int,
        stdin_bytes: bytes,
        max_output_bytes: int,
    ) -> BoundedCommandResult:
        if timeout_seconds <= 0 or max_output_bytes <= 0:
            raise ValueError("Process bounds must be positive.")
        creationflags = 0
        start_new_session = False
        if self._platform_name == "nt":
            creationflags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0)) | int(
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            )
        else:
            start_new_session = True
        try:
            process = subprocess.Popen(  # noqa: S603 - caller supplies a fixed trusted command
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                bufsize=0,
                creationflags=creationflags,
                start_new_session=start_new_session,
            )
        except OSError as exc:
            raise BoundedExecutionError(
                BoundedExecutionCode.START_FAILED,
                "The fixed Probe process could not start.",
            ) from exc

        if process.stdin is None or process.stdout is None or process.stderr is None:
            self._terminate_tree(process)
            raise BoundedExecutionError(
                BoundedExecutionCode.START_FAILED,
                "The fixed Probe process streams are unavailable.",
            )
        try:
            if stdin_bytes:
                process.stdin.write(stdin_bytes)
                process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            self._terminate_tree(process)
            raise BoundedExecutionError(
                BoundedExecutionCode.STDIN_FAILED,
                "The fixed Probe process rejected its input.",
            ) from exc
        finally:
            process.stdin.close()

        stdout = bytearray()
        stderr = bytearray()
        exceeded = threading.Event()
        readers = (
            threading.Thread(
                target=_read_stream,
                args=(process.stdout, stdout, max_output_bytes, exceeded),
                daemon=True,
            ),
            threading.Thread(
                target=_read_stream,
                args=(process.stderr, stderr, max_output_bytes, exceeded),
                daemon=True,
            ),
        )
        for reader in readers:
            reader.start()

        deadline = time.monotonic() + timeout_seconds
        while process.poll() is None:
            if exceeded.wait(timeout=0.01):
                self._terminate_tree(process)
                self._join_readers(readers)
                raise BoundedExecutionError(
                    BoundedExecutionCode.OUTPUT_TOO_LARGE,
                    "The fixed Probe process exceeded its byte limit.",
                )
            if time.monotonic() >= deadline:
                self._terminate_tree(process)
                self._join_readers(readers)
                raise BoundedExecutionError(
                    BoundedExecutionCode.TIMEOUT,
                    "The fixed Probe process exceeded its runtime limit.",
                )

        self._join_readers(readers)
        if exceeded.is_set():
            self._terminate_tree(process)
            raise BoundedExecutionError(
                BoundedExecutionCode.OUTPUT_TOO_LARGE,
                "The fixed Probe process exceeded its byte limit.",
            )
        return BoundedCommandResult(
            returncode=process.returncode,
            stdout=bytes(stdout),
            stderr=bytes(stderr),
        )

    @staticmethod
    def _join_readers(readers: tuple[threading.Thread, threading.Thread]) -> None:
        for reader in readers:
            reader.join(timeout=1)

    def _terminate_tree(self, process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        if self._platform_name == "nt":
            system_root = os.environ.get("SystemRoot")
            if system_root:
                taskkill = Path(system_root) / "System32" / "taskkill.exe"
                if taskkill.is_file():
                    subprocess.run(  # noqa: S603 - PID is the exact child just created
                        (
                            str(taskkill),
                            "/PID",
                            str(process.pid),
                            "/T",
                            "/F",
                        ),
                        check=False,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        shell=False,
                        creationflags=int(getattr(subprocess, "CREATE_NO_WINDOW", 0)),
                    )
        else:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except OSError:
                pass
        if process.poll() is None:
            process.kill()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass

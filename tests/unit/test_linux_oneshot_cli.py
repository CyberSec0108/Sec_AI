from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from security_audit.collector import linux_cli
from security_audit.platforms import LinuxDistribution


@contextmanager
def _unlocked() -> Iterator[None]:
    yield


def test_distribution_specific_artifact_cannot_be_switched_by_argument(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(linux_cli, "_single_instance_lock", _unlocked)
    observed: list[LinuxDistribution] = []

    def run_stub(
        *,
        server_url: str,
        distribution: LinuxDistribution,
        output_directory: Path,
    ) -> int:
        observed.append(distribution)
        return 0

    monkeypatch.setattr(linux_cli, "run", run_stub)

    assert (
        linux_cli.main(
            ["--server-url", "https://secai.example", "--output-directory", "."],
            forced_distribution=LinuxDistribution.ROCKY_9,
        )
        == 0
    )
    assert observed == [LinuxDistribution.ROCKY_9]


def test_distribution_specific_artifact_rejects_distribution_override() -> None:
    with pytest.raises(SystemExit) as raised:
        linux_cli.main(
            ["--distribution", "ROCKY_9"],
            forced_distribution=LinuxDistribution.UBUNTU_24_04,
        )

    assert raised.value.code == 2


def test_generic_artifact_does_not_accept_or_require_distribution_argument(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(linux_cli, "_single_instance_lock", _unlocked)
    observed: list[LinuxDistribution | None] = []

    def run_stub(
        *,
        server_url: str,
        distribution: LinuxDistribution | None,
        output_directory: Path,
    ) -> int:
        del server_url, output_directory
        observed.append(distribution)
        return 0

    monkeypatch.setattr(linux_cli, "run", run_stub)

    assert linux_cli.main(["--server-url", "https://secai.example"]) == 0
    assert observed == [None]
    with pytest.raises(SystemExit) as rejected:
        linux_cli.main(["--distribution", "UBUNTU_24_04"])
    assert rejected.value.code == 2

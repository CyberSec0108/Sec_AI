from security_audit import __version__


def test_package_version_is_stage_one_baseline() -> None:
    assert __version__ == "0.1.0"


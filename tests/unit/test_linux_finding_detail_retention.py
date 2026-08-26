from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

from security_audit.platforms import LinuxDistribution, evaluate_kisa_unix
from security_audit.platforms.linux_kisa import LIST_EVIDENCE_PROBES

NOW = datetime(2026, 8, 23, 6, 0, tzinfo=UTC)


def _outputs(**overrides: str) -> dict[str, bytes]:
    from security_audit.platforms import linux_adapter_for

    plan = linux_adapter_for(LinuxDistribution.UBUNTU_24_04).plan
    values = {command.command_id: b"" for command in plan.commands}
    values["linux.os-release"] = b'ID=ubuntu\nVERSION_ID="24.04"\n'
    for key, text in overrides.items():
        values[key.replace("_", ".", 1).replace("_", "-")] = text.encode("utf-8")
    return values


def _control(results: tuple[object, ...], control_id: str) -> dict[str, Any]:
    for item in results:
        payload = cast(dict[str, Any], item.to_json())  # type: ignore[attr-defined]
        if payload["control_id"] == control_id:
            return payload
    raise AssertionError(f"{control_id} 결과가 없습니다.")


def test_review_control_keeps_the_list_so_the_auditor_can_act() -> None:
    outputs = _outputs()
    outputs["linux.home-hidden"] = b"/root/.bashrc\n/home/app/.ssh\n"

    results = evaluate_kisa_unix(
        outputs,
        captured_at=NOW,
        distribution=LinuxDistribution.UBUNTU_24_04,
    )
    control = _control(results, "U-33")
    evidence = control["evidence"][0]

    assert control["status"] == "REVIEW"
    assert evidence["normalized_value"] == "/root/.bashrc\n/home/app/.ssh"
    assert evidence["normalized_value_included"] is True


def test_passing_control_keeps_only_the_summary() -> None:
    outputs = _outputs()
    outputs["linux.time-sync"] = b"yes\n"

    results = evaluate_kisa_unix(
        outputs,
        captured_at=NOW,
        distribution=LinuxDistribution.UBUNTU_24_04,
    )
    control = _control(results, "U-65")
    evidence = control["evidence"][0]

    assert control["status"] == "PASS"
    assert evidence["normalized_value_included"] is False
    assert "normalized_value" not in evidence


def test_only_list_shaped_probes_are_retained() -> None:
    assert "linux.suid-sgid" in LIST_EVIDENCE_PROBES
    assert "linux.world-writable" in LIST_EVIDENCE_PROBES
    assert "linux.home-hidden" in LIST_EVIDENCE_PROBES
    assert "linux.ownerless" in LIST_EVIDENCE_PROBES
    # 단일 값 판정은 요약이 곧 원본이라 보존 대상이 아닙니다.
    assert "linux.time-sync" not in LIST_EVIDENCE_PROBES
    assert "linux.sshd-effective" not in LIST_EVIDENCE_PROBES


def _result_with_list_evidence(status: str) -> dict[str, object]:
    from security_audit.platforms.linux_kisa import KISA_2026_UNIX_CONTROLS

    controls = []
    for definition in KISA_2026_UNIX_CONTROLS:
        entry: dict[str, object] = {
            "control_id": definition.control_id,
            "title": definition.title,
            "status": "PASS",
            "result_code": f"{definition.control_id.replace('-', '_')}_COMPLIANT",
            "observed_summary": "확인했습니다.",
            "expected_summary": "기준 충족",
            "action_guidance": "유지하세요.",
            "evidence": [],
        }
        if definition.control_id == "U-33":
            entry["status"] = status
            entry["evidence"] = [
                {
                    "method_summary": "고정 읽기 명령",
                    "technical_locator": "/usr/bin/find /root /home -name .*",
                    "collection_status": "COLLECTED",
                    "raw_output_sha256": "a" * 64,
                    "normalized_sha256": "b" * 64,
                    "normalized_value_included": True,
                    "normalized_value": "/root/.bashrc\n/home/app/.ssh",
                }
            ]
        controls.append(entry)
    return {"controls": controls, "asset": {}, "result_sha256": "c" * 64}


def test_technical_report_prints_the_retained_list_for_action() -> None:
    from security_audit.application.device_report import build_linux_report_document

    document = build_linux_report_document(
        _result_with_list_evidence("REVIEW"),
        technical=True,
    )
    body = "\n".join(document.lines)

    assert "확인 대상 목록" in body
    assert "/root/.bashrc" in body
    assert "/home/app/.ssh" in body


def test_user_report_keeps_the_list_out() -> None:
    from security_audit.application.device_report import build_linux_report_document

    document = build_linux_report_document(
        _result_with_list_evidence("REVIEW"),
        technical=False,
    )
    body = "\n".join(document.lines)

    assert "/root/.bashrc" not in body


def test_result_screen_lists_the_targets_for_review_and_fail() -> None:
    from pathlib import Path

    script = (
        Path(__file__).resolve().parents[2]
        / "apps/web/static/app/linux-results.js"
    ).read_text(encoding="utf-8")

    assert "normalized_value" in script
    assert "확인 대상 목록" in script


def test_technical_report_labels_the_two_hashes_by_what_they_prove() -> None:
    """원문 해시는 대조할 원본이 없으므로 무결성 증명으로 적지 않습니다."""

    from security_audit.application.device_report import build_linux_report_document

    document = build_linux_report_document(
        _result_with_list_evidence("REVIEW"),
        technical=True,
    )
    body = "\n".join(document.lines)

    assert "수집 시점 지문(원문, 재검증 불가)" in body
    assert "정규화 해시(재검증 가능)" in body
    assert "원문 해시:" not in body

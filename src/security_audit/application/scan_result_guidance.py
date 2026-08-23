"""IMP-042 user-facing, non-official scan result guidance.

This module intentionally translates collection metadata only.  It never receives
or stores raw Windows values and it does not create an official Finding.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True, slots=True)
class ControlGuidance:
    control_id: str
    title: str
    importance: str
    pages: str
    probe_ids: tuple[str, ...]
    administrator_required: bool
    checked_summary: str
    evidence_summary: str
    action_guidance: str


_CONTROLS: Final[tuple[ControlGuidance, ...]] = (
    ControlGuidance(
        "PC-01",
        "비밀번호의 주기적 변경",
        "상",
        "555~556",
        ("win.security.password-age",),
        False,
        "현재 적용되는 비밀번호 최대 사용 기간을 읽었습니다.",
        "유효 비밀번호 정책의 최대 사용 기간과 정책 출처",
        "조직 기준과 다르면 Windows 계정 정책 담당자에게 변경을 요청하세요.",
    ),
    ControlGuidance(
        "PC-02",
        "비밀번호 관리정책 설정",
        "상",
        "557~558",
        ("win.security.password-policy",),
        True,
        "비밀번호 길이·복잡성·재사용 정책은 관리자 추가 점검에서 확인합니다.",
        "유효 비밀번호 정책과 승인된 조직 암호 기준",
        "관리자 추가 점검 후 조직의 승인된 암호 기준과 비교하세요.",
    ),
    ControlGuidance(
        "PC-03",
        "복구 콘솔 자동 로그온 금지",
        "중",
        "559~560",
        ("win.security.recovery-console",),
        False,
        "복구 콘솔의 자동 관리자 로그온 정책을 읽었습니다.",
        "복구 콘솔 정책의 설정 여부와 정책 출처",
        "허용 상태라면 담당자 승인 후 복구 콘솔 자동 로그온을 사용하지 않도록 설정하세요.",
    ),
    ControlGuidance(
        "PC-04",
        "불필요한 공유 폴더 제거",
        "상",
        "561~565",
        ("win.network.smb-shares",),
        True,
        "공유 폴더와 접근 권한은 관리자 추가 점검에서 확인합니다.",
        "SMB 공유 목록, 공유 권한과 파일시스템 접근 권한",
        "업무에 필요하지 않은 공유만 담당자 확인 후 제거하고 "
        "필요한 공유는 최소 권한으로 제한하세요.",
    ),
    ControlGuidance(
        "PC-05",
        "불필요한 서비스 제거",
        "상",
        "566~569",
        ("win.services.inventory",),
        False,
        "Windows 서비스의 존재와 실행 상태를 읽었습니다.",
        "서비스 이름·시작 유형·실행 상태와 승인 목록 비교용 정보",
        "용도를 모르는 서비스는 즉시 중지하지 말고 시스템 담당자에게 필요 여부를 확인하세요.",
    ),
    ControlGuidance(
        "PC-06",
        "비인가 메신저 사용 금지",
        "상",
        "570",
        ("win.software.messengers",),
        True,
        "설치·실행 중인 메신저 확인은 관리자 추가 점검에서 수행합니다.",
        "설치·실행 제품 식별 정보와 조직의 허용·금지 목록",
        "조직이 허용하지 않은 제품으로 확인되면 업무 자료를 전송하지 말고 "
        "담당자 안내에 따라 제거하세요.",
    ),
    ControlGuidance(
        "PC-07",
        "파일시스템을 NTFS 형식으로 설정",
        "중",
        "571~572",
        (
            "win.storage.disks",
            "win.storage.partitions",
            "win.storage.volumes",
        ),
        False,
        "연결된 디스크·파티션·고정 볼륨의 구조 정보를 읽었습니다.",
        "평가 대상 볼륨 식별과 파일시스템 형식 확인용 수집 상태",
        "비 NTFS 볼륨이 의심되면 먼저 백업하고 저장장치 담당자와 변환·재구성 방법을 검토하세요.",
    ),
    ControlGuidance(
        "PC-08",
        "Windows 외 다른 OS 부팅 제한",
        "중",
        "573~574",
        ("win.boot.entries",),
        True,
        "부팅 항목 확인은 관리자 추가 점검에서 수행합니다.",
        "Windows 부팅 구성 항목과 복구·진단 항목 구분 정보",
        "모르는 부팅 항목을 직접 삭제하지 말고 시스템 담당자에게 업무상 필요 여부를 확인하세요.",
    ),
    ControlGuidance(
        "PC-09",
        "브라우저 종료 시 임시 파일 삭제",
        "상",
        "575~576",
        ("win.browser.wininet-cache-policy",),
        False,
        "WinINet·IE 모드의 종료 시 캐시 삭제 정책을 읽었습니다.",
        "기능 적용 여부, 대상 사용자와 유효 정책 출처",
        "해당 기능을 사용하는데 삭제 정책이 없으면 "
        "조직 브라우저 정책 담당자에게 적용을 요청하세요.",
    ),
    ControlGuidance(
        "PC-10",
        "보안 패치와 벤더 권고사항 적용",
        "상",
        "577~578",
        ("win.update.compliance",),
        True,
        "업데이트 적합성 확인은 관리자 추가 점검에서 수행합니다.",
        "OS 빌드·업데이트 정책·설치 이력과 승인된 패치 기준",
        "Windows Update 또는 조직 패치 도구에서 보류 사유를 확인한 뒤 승인된 패치를 적용하세요.",
    ),
    ControlGuidance(
        "PC-11",
        "지원이 종료되지 않은 Windows 사용",
        "상",
        "579",
        ("win.os.lifecycle",),
        False,
        "Windows 제품·버전·빌드 식별 정보를 읽었습니다.",
        "OS 수명주기 대조에 필요한 제품·버전·빌드 수집 상태",
        "지원 종료 버전이 의심되면 업무 프로그램 호환성을 확인하고 지원 버전 전환 일정을 세우세요.",
    ),
    ControlGuidance(
        "PC-12",
        "Windows 자동 로그온 제거",
        "중",
        "580~581",
        ("win.autologon.config",),
        False,
        "자동 관리자 로그온 구성의 존재와 활성 상태를 확인했습니다.",
        "AutoAdminLogon 상태와 관련 구성 존재 여부(비밀번호 값 제외)",
        "자동 로그온이 사용 중이면 담당자 승인 후 해제하고 저장된 자격증명도 안전하게 정리하세요.",
    ),
    ControlGuidance(
        "PC-13",
        "백신 설치와 주기적 업데이트",
        "상",
        "582~583",
        ("win.antivirus.update-status",),
        False,
        "Microsoft Defender의 설치·업데이트 상태를 읽었습니다.",
        "백신 활성 상태와 엔진·정의 업데이트 상태 수집 여부",
        "업데이트가 오래되었거나 백신이 없다고 의심되면 "
        "네트워크 연결과 조직 보안 정책을 확인하세요.",
    ),
    ControlGuidance(
        "PC-14",
        "백신 실시간 감시 활성화",
        "상",
        "584",
        ("win.antivirus.realtime-status",),
        False,
        "Microsoft Defender의 실시간 보호 상태를 읽었습니다.",
        "실시간 보호·서비스 상태와 동작 모드 수집 여부",
        "실시간 보호가 꺼진 것으로 의심되면 임의 예외를 만들지 말고 보안 담당자에게 확인하세요.",
    ),
    ControlGuidance(
        "PC-15",
        "침입차단 기능 활성화",
        "상",
        "585~586",
        ("win.firewall.effective-profiles",),
        False,
        "현재 적용되는 Windows 방화벽 프로필 상태를 읽었습니다.",
        "Domain·Private·Public 유효 프로필의 활성 상태 수집 여부",
        "사용 중인 프로필의 방화벽이 꺼진 것으로 의심되면 "
        "조직 정책을 확인한 뒤 활성화를 요청하세요.",
    ),
    ControlGuidance(
        "PC-16",
        "화면보호기 대기 시간과 암호 보호",
        "상",
        "587~588",
        ("win.user.screensaver-policy",),
        False,
        "현재 사용자의 화면보호기 활성·대기 시간·암호 보호 정책을 읽었습니다.",
        "현재 사용자 SID 범위의 유효 화면보호기 정책 수집 여부",
        "10분 이내 대기와 다시 시작할 때 암호 보호가 적용되도록 "
        "사용자 또는 조직 정책을 확인하세요.",
    ),
    ControlGuidance(
        "PC-17",
        "이동식 미디어 자동실행 방지",
        "상",
        "589~590",
        ("win.media.autoplay-policy",),
        False,
        "AutoRun·AutoPlay의 유효 정책을 읽었습니다.",
        "사용자·컴퓨터 정책의 자동실행 차단 범위 수집 여부",
        "자동실행이 허용된 것으로 의심되면 이동식 미디어를 열기 전에 검사하고 "
        "정책 적용을 요청하세요.",
    ),
    ControlGuidance(
        "PC-18",
        "원격지원 금지 정책 설정",
        "중",
        "591~592",
        ("win.remote-assistance.policy",),
        False,
        "요청·제안형 원격지원의 유효 정책을 읽었습니다.",
        "Remote Assistance 정책의 활성 상태와 정책 출처",
        "원격지원이 허용된 것으로 의심되면 사용 목적을 확인하고 "
        "불필요한 허용 정책을 해제 요청하세요.",
    ),
)

_IMPORTANCE_ORDER: Final[dict[str, int]] = {"상": 0, "중": 1, "하": 2}
_ALLOWED_COLLECTION_STATUSES: Final[frozenset[str]] = frozenset(
    {"COLLECTED", "ERROR", "UNSUPPORTED"}
)


def build_control_results(
    receipt: Mapping[str, object],
    *,
    assessments: Mapping[str, Mapping[str, object]] | None = None,
) -> list[dict[str, object]]:
    """Translate a fixed receipt into safe display rows sorted by importance."""

    values = receipt.get("results")
    if not isinstance(values, Sequence) or isinstance(
        values, (str, bytes, bytearray)
    ):
        raise RuntimeError("Standard scan receipt is invalid.")

    probe_statuses: dict[str, str] = {}
    for value in values:
        if not isinstance(value, Mapping):
            raise RuntimeError("Standard scan result is invalid.")
        probe_id = value.get("probe_id")
        status = value.get("collection_status")
        if not isinstance(probe_id, str) or status not in _ALLOWED_COLLECTION_STATUSES:
            raise RuntimeError("Standard scan result metadata is invalid.")
        if probe_id in probe_statuses:
            raise RuntimeError("Standard scan contains a duplicate Probe result.")
        probe_statuses[probe_id] = str(status)

    rows: list[dict[str, object]] = []
    for control in _CONTROLS:
        statuses = [probe_statuses.get(probe_id) for probe_id in control.probe_ids]
        if control.administrator_required:
            display_status = "ADMIN_REQUIRED"
            status_label = "관리자 추가 확인 필요"
        elif statuses and all(status == "COLLECTED" for status in statuses):
            display_status = "EVIDENCE_COLLECTED"
            status_label = "자료 확인 완료"
        else:
            display_status = "REVIEW_REQUIRED"
            status_label = "추가 확인 필요"
        row: dict[str, object] = {
            "control_id": control.control_id,
            "title": control.title,
            "importance": control.importance,
            "source": f"2026 KISA 07. PC, {control.pages}쪽",
            "display_status": display_status,
            "status_label": status_label,
            "checked_summary": control.checked_summary,
            "evidence_summary": control.evidence_summary,
            "action_guidance": control.action_guidance,
            "probe_count": len(control.probe_ids),
            "administrator_required": control.administrator_required,
        }
        assessment = (
            assessments.get(control.control_id) if assessments is not None else None
        )
        if assessment is not None:
            assessment_status = assessment.get("status")
            if assessment_status not in {"PASS", "FAIL", "ERROR", "REVIEW", "N/A"}:
                raise RuntimeError("Live DRAFT assessment status is invalid.")
            row.update(
                {
                    "assessment_status": assessment_status,
                    "assessment_label": assessment.get("status_label"),
                    "actual": assessment.get("actual"),
                    "expected": assessment.get("expected"),
                    "result_code": assessment.get("result_code"),
                    "assessment_kind": assessment.get("assessment_kind"),
                }
            )
            additional_criteria = assessment.get("additional_criteria")
            if isinstance(additional_criteria, Mapping):
                row["additional_criteria"] = dict(additional_criteria)
        rows.append(row)
    return sorted(
        rows,
        key=lambda row: (
            _IMPORTANCE_ORDER[str(row["importance"])],
            str(row["control_id"]),
        ),
    )


def summarize_control_results(
    controls: Sequence[Mapping[str, object]],
) -> dict[str, int]:
    counts = {
        "evidence_collected": 0,
        "review_required": 0,
        "administrator_required": 0,
    }
    for control in controls:
        status = control.get("display_status")
        if status == "EVIDENCE_COLLECTED":
            counts["evidence_collected"] += 1
        elif status == "REVIEW_REQUIRED":
            counts["review_required"] += 1
        elif status == "ADMIN_REQUIRED":
            counts["administrator_required"] += 1
        else:
            raise RuntimeError("Unknown display status.")
    return counts


def summarize_draft_assessments(
    controls: Sequence[Mapping[str, object]],
) -> dict[str, int]:
    """Count safe live DRAFT decisions separately from collection states."""

    counts = {
        "pass": 0,
        "fail": 0,
        "error": 0,
        "review": 0,
        "not_applicable": 0,
        "not_evaluated": 0,
    }
    keys = {
        "PASS": "pass",
        "FAIL": "fail",
        "ERROR": "error",
        "REVIEW": "review",
        "N/A": "not_applicable",
    }
    for control in controls:
        status = control.get("assessment_status")
        if status is None:
            counts["not_evaluated"] += 1
            continue
        key = keys.get(str(status))
        if key is None:
            raise RuntimeError("Unknown live DRAFT assessment status.")
        counts[key] += 1
    return counts

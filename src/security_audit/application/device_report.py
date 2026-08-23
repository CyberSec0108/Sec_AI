"""다중 장비 점검 결과의 사용자용·기술 검증용 PDF 문서를 만듭니다."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, cast

from security_audit.application.result_report import ReportDocument, ReportKind
from security_audit.application.switch_audit_service import present_switch_controls
from security_audit.common.canonical_json import JsonValue, canonical_sha256
from security_audit.platforms.linux_kisa import KISA_2026_UNIX_CONTROLS


def build_linux_report_document(
    result: Mapping[str, Any],
    *,
    technical: bool,
) -> ReportDocument:
    controls = result.get("controls")
    if not isinstance(controls, list) or len(controls) != 67:
        raise ValueError("LINUX_CONTROL_COVERAGE_INVALID")
    raw_asset = result.get("asset")
    asset: Mapping[str, Any] = raw_asset if isinstance(raw_asset, dict) else {}
    counts = Counter(str(item.get("status")) for item in controls if isinstance(item, dict))
    title = "Linux 서버 기술 검증 보고서" if technical else "Linux 서버 보안 점검 보고서"
    lines = [
        title,
        f"생성 시각: {datetime.now(UTC).isoformat()}",
        f"대상 장비: {asset.get('product_family', 'Linux 서버')}",
        "점검 기준: KISA 주요정보통신기반시설 UNIX U-01~U-67",
        f"결과 확인값(SHA-256): {result.get('result_sha256', '')}",
        (
            "요약: 전체 67개 / "
            f"양호 {counts['PASS']} / 취약 {counts['FAIL']} / "
            f"확인 필요 {counts['ERROR'] + counts['REVIEW']} / "
            f"해당 없음 {counts['N/A']}"
        ),
        "",
    ]
    definition_by_id = {item.control_id: item for item in KISA_2026_UNIX_CONTROLS}
    for control in controls:
        if not isinstance(control, dict):
            continue
        control_id = str(control.get("control_id"))
        definition = definition_by_id[control_id]
        status_label = {
            "PASS": "양호",
            "FAIL": "취약",
            "ERROR": "확인 필요",
            "REVIEW": "확인 필요",
            "N/A": "해당 없음",
        }.get(str(control.get("status")), "확인 필요")
        lines.extend(
            [
                f"{control_id} {control.get('title', '')} [{status_label}]",
                f"확인한 내용: {control.get('observed_summary', '')}",
                f"안전 기준: {control.get('expected_summary', '')}",
                f"다음 행동: {control.get('action_guidance', '')}",
                (
                    "KISA 근거: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 "
                    f"상세가이드 {definition.page_start}~{definition.page_end}쪽"
                ),
            ]
        )
        if technical:
            lines.append(f"내부 판정 코드: {control.get('result_code', '')}")
            evidence = control.get("evidence")
            if isinstance(evidence, list):
                for item in evidence:
                    if not isinstance(item, dict):
                        continue
                    lines.extend(
                        [
                            f"  확인 방법: {item.get('method_summary', '')}",
                            f"  확인 위치: {item.get('technical_locator', '')}",
                            f"  수집 상태: {item.get('collection_status', '')}",
                            f"  원문 해시: {item.get('raw_output_sha256', '')}",
                            f"  정규화 해시: {item.get('normalized_sha256', '')}",
                        ]
                    )
        lines.append("")
    content_sha256 = canonical_sha256({"title": title, "lines": cast(list[JsonValue], lines)})
    return ReportDocument(
        title=title,
        lines=tuple(lines),
        content_sha256=content_sha256,
        report_kind=ReportKind.TECHNICAL if technical else ReportKind.USER,
    )


def build_switch_report_document(
    result: Mapping[str, Any],
    *,
    technical: bool,
) -> ReportDocument:
    """무결성이 확인된 Switch 결과를 사용자용·기술 검증용 문서로 변환합니다."""

    controls = result.get("controls")
    if not isinstance(controls, list) or len(controls) not in {6, 38}:
        raise ValueError("SWITCH_CONTROL_COVERAGE_INVALID")
    typed_controls = [item for item in controls if isinstance(item, dict)]
    if len(typed_controls) != len(controls):
        raise ValueError("SWITCH_CONTROL_COVERAGE_INVALID")
    presented_controls = present_switch_controls(typed_controls)
    raw_asset = result.get("asset")
    asset: Mapping[str, Any] = raw_asset if isinstance(raw_asset, dict) else {}
    raw_benchmark = result.get("benchmark")
    benchmark: Mapping[str, Any] = (
        raw_benchmark if isinstance(raw_benchmark, dict) else {}
    )
    raw_criteria = result.get("criteria_summary")
    criteria: Mapping[str, Any] = raw_criteria if isinstance(raw_criteria, dict) else {}
    counts = Counter(str(item.get("status")) for item in typed_controls)
    title = (
        "네트워크 스위치 기술 검증 보고서"
        if technical
        else "네트워크 스위치 보안 점검 보고서"
    )
    control_range = "N-01~N-38" if len(controls) == 38 else "SW-01~SW-06"
    organization_count = criteria.get(
        "organization_supplemental_assessment_count",
        0,
    )
    organization_applied = criteria.get(
        "organization_supplemental_assessment_applied_count",
        0,
    )
    lines = [
        title,
        f"생성 시각: {datetime.now(UTC).isoformat()}",
        (
            "대상 장비: "
            f"{asset.get('vendor', '네트워크 장비')} "
            f"{asset.get('product_family', '스위치')} · "
            f"{asset.get('platform_version', '')}"
        ),
        (
            "점검 기준: "
            f"{benchmark.get('id', 'KISA 네트워크 장비 기준')} · "
            f"{benchmark.get('version', '')}"
        ),
        "판정 상태: 개발용 DRAFT 판정 · 공식 Finding을 생성하지 않음",
        f"점검 범위: {control_range}",
        f"결과 확인값(SHA-256): {result.get('result_sha256', '')}",
        f"기준 확인값(SHA-256): {result.get('criteria_sha256', '')}",
        (
            f"조직 보완 판정: 입력 {organization_count}개 · "
            f"적용 {organization_applied}개 · 장비 REST 수집값과 분리"
        ),
        (
            f"요약: 전체 {len(controls)}개 / "
            f"양호 {counts['PASS']} / 취약 {counts['FAIL']} / "
            f"확인 필요 {counts['ERROR'] + counts['REVIEW']} / "
            f"해당 없음 {counts['N/A']}"
        ),
        "",
    ]
    raw_by_id = {str(item.get("control_id")): item for item in typed_controls}
    for control in presented_controls:
        control_id = str(control.get("control_id", ""))
        status_label = {
            "PASS": "양호",
            "FAIL": "취약",
            "ERROR": "확인 필요",
            "REVIEW": "확인 필요",
            "N/A": "해당 없음",
        }.get(str(control.get("status")), "확인 필요")
        lines.extend(
            [
                f"{control_id} {control.get('title', '')} [{status_label}]",
                f"무엇을 확인했나요: {control.get('what_was_checked', '')}",
                f"내 스위치에서 확인한 값: {control.get('observed_summary', '')}",
                f"적용된 안전 기준: {control.get('expected_summary', '')}",
                f"판정 이유: {control.get('judgement_explanation', '')}",
                f"다음 행동: {control.get('action_guidance', '')}",
            ]
        )
        source_pages = control.get("source_pages")
        if isinstance(source_pages, str) and source_pages:
            lines.append(
                "KISA 근거: 주요정보통신기반시설 기술적 취약점 분석·평가 방법 "
                f"상세가이드 {source_pages}쪽"
            )
        judgement_source = control.get("judgement_source_label")
        if isinstance(judgement_source, str) and judgement_source:
            lines.append(f"판정 입력 구분: {judgement_source}")
        if technical:
            raw_control = raw_by_id[control_id]
            lines.append(f"내부 판정 코드: {raw_control.get('result_code', '')}")
            evidence = raw_control.get("evidence")
            if isinstance(evidence, list):
                for item in evidence:
                    if not isinstance(item, dict):
                        continue
                    lines.extend(
                        [
                            f"  확인 방법: {item.get('method_summary', '')}",
                            f"  확인 출처: {item.get('source_label', '')}",
                            f"  기술 확인 위치: {item.get('technical_locator', '')}",
                            f"  수집 상태: {item.get('collection_status', '')}",
                            f"  원문 해시: {item.get('raw_output_sha256', '')}",
                            f"  정규화 해시: {item.get('normalized_sha256', '')}",
                            f"  비식별 처리: {item.get('redaction_applied', False)}",
                        ]
                    )
        lines.append("")
    content_sha256 = canonical_sha256(
        {"title": title, "lines": cast(list[JsonValue], lines)}
    )
    return ReportDocument(
        title=title,
        lines=tuple(lines),
        content_sha256=content_sha256,
        report_kind=ReportKind.TECHNICAL if technical else ReportKind.USER,
    )

"""실제 로그인 API에서 PRODUCT-AI-08 사용자 보고서와 권한 경계를 검증한다."""

from __future__ import annotations

import json
import re
from http.cookiejar import CookieJar
from typing import cast
from urllib.error import HTTPError
from urllib.parse import urlencode, urlparse
from urllib.request import (
    HTTPCookieProcessor,
    Request,
    build_opener,
)
from uuid import uuid4

from security_audit.common.canonical_json import (
    JsonValue,
    canonical_sha256_without_fields,
)

BASE_URL = "http://127.0.0.1:8000"
CANONICAL_ORIGIN = "http://localhost:18480"
CANONICAL_HOST = urlparse(CANONICAL_ORIGIN).netloc


def _csrf(html: str, *, meta: bool = False) -> str:
    pattern = (
        r'name="csrf-token" content="([^"]+)"'
        if meta
        else r'name="csrf_token" value="([^"]+)"'
    )
    match = re.search(pattern, html)
    if match is None:
        raise RuntimeError("PRODUCT-AI-08 CSRF token not found.")
    return match.group(1)


def _explanation(index: int) -> dict[str, JsonValue]:
    control_id = f"PC-{index:02d}"
    value: dict[str, JsonValue] = {
        "schema_version": "1.0.0",
        "control_id": control_id,
        "title": f"{control_id} PRODUCT-AI-08 검증",
        "importance": "HIGH",
        "what_was_checked": "Windows에 실제 적용된 보안 설정을 확인했습니다.",
        "observed_summary": "검증용 비식별 실제값입니다.",
        "normalized_facts": {"actual_summary": "검증용 비식별 실제값"},
        "collection_methods": [
            {
                "probe_id": f"win.verify.{index}",
                "method_code": "WINDOWS_API",
                "method_summary": "Windows API로 읽기 전용 확인",
                "collection_status": "COLLECTED",
            }
        ],
        "execution_tools": [
            {
                "probe_id": f"win.verify.{index}",
                "probe_version": "0.1.0",
                "tool_name": "SecAI Windows 읽기 전용 점검 도구",
                "collector_name": "sec-ai-one-shot-collector",
                "collector_version": "0.1.0",
                "adapter_id": "secai.windows-native",
                "adapter_version": "0.1.0",
            }
        ],
        "source_locations": [
            {
                "probe_id": f"win.verify.{index}",
                "user_label": "Windows 보안 설정",
                "technical_locator": "Windows API verification locator",
            }
        ],
        "rule_status": "FAIL" if index == 1 else "PASS",
        "status_authority": "RULE_ENGINE",
        "result_code": f"PRODUCT_AI_08_VERIFY_{index:02d}",
        "result_code_visibility": "TECHNICAL_ONLY",
        "expected_summary": "KISA 권고 기준을 충족",
        "judgement_explanation": "실제값을 규칙 기준과 비교한 결과입니다.",
        "collection_limitations": [],
        "importance_source": "상",
        "kisa_citations": [
            {
                "guide_id": "kisa-major-infrastructure-detailed-guide",
                "guide_version": "2026",
                "source_sha256": "a" * 64,
                "document_code": "KISA-2026-07-PC",
                "page_start": 554 + index,
                "page_end": 554 + index,
                "section_label": f"{control_id} 점검 항목",
                "mapping_status": "DRAFT",
            }
        ],
        "allowed_actions": ["조직의 보안 담당자와 설정을 확인하세요."],
        "assessment_kind": "DEVELOPMENT_DRAFT",
        "source_rule_result_sha256": f"{index:064x}",
        "official_finding_write_allowed": False,
        "safety": {
            "raw_evidence_included": False,
            "sensitive_identifiers_included": False,
            "rule_status_unchanged": True,
            "internal_reason_code_user_visible": False,
        },
    }
    value["explanation_input_sha256"] = canonical_sha256_without_fields(
        value,
        {"explanation_input_sha256"},
    )
    return value


def _request_json(
    opener: object,
    path: str,
    *,
    method: str = "GET",
    body: dict[str, object] | None = None,
    csrf_token: str | None = None,
) -> tuple[int, dict[str, object], object]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Accept": "application/json", "Host": CANONICAL_HOST}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if csrf_token is not None:
        headers["X-CSRF-Token"] = csrf_token
        headers["Origin"] = CANONICAL_ORIGIN
        headers["Sec-Fetch-Site"] = "same-origin"
    request = Request(  # noqa: S310 - 고정된 loopback HTTP 검증 주소만 사용
        BASE_URL + path,
        data=data,
        headers=headers,
        method=method,
    )
    try:
        response = opener.open(request, timeout=15)  # type: ignore[attr-defined]
        payload = json.loads(response.read())
        return response.status, payload, response
    except HTTPError as exc:
        payload = json.loads(exc.read())
        return exc.code, payload, exc


def main() -> None:
    opener = build_opener(HTTPCookieProcessor(CookieJar()))
    login = opener.open(
        Request(  # noqa: S310 - 고정된 loopback HTTP 검증 주소만 사용
            BASE_URL + "/auth/login",
            headers={"Host": CANONICAL_HOST},
        ),
        timeout=10,
    )
    login_csrf = _csrf(login.read().decode("utf-8"))
    password = open(
        "/run/secrets/auth_dev_password", encoding="utf-8"
    ).read().strip()
    login_form = urlencode(
        {
            "username": "local-owner",
            "password": password,
            "csrf_token": login_csrf,
            "next": "/ui/results",
        }
    ).encode()
    login_result = opener.open(
        Request(  # noqa: S310 - 고정된 loopback HTTP 검증 주소만 사용
            BASE_URL + "/auth/login",
            data=login_form,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Host": CANONICAL_HOST,
                "Origin": CANONICAL_ORIGIN,
                "Sec-Fetch-Site": "same-origin",
            },
        ),
        timeout=10,
    )
    mfa_html = login_result.read().decode("utf-8")
    mfa_csrf = _csrf(mfa_html)
    mfa_code = open(
        "/run/secrets/auth_dev_mfa_code", encoding="utf-8"
    ).read().strip()
    mfa_form = urlencode(
        {"code": mfa_code, "csrf_token": mfa_csrf, "next": "/ui/results"}
    ).encode()
    result_page = opener.open(
        Request(  # noqa: S310 - 고정된 loopback HTTP 검증 주소만 사용
            BASE_URL + "/auth/mfa",
            data=mfa_form,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Host": CANONICAL_HOST,
                "Origin": CANONICAL_ORIGIN,
                "Sec-Fetch-Site": "same-origin",
            },
        ),
        timeout=10,
    )
    authenticated_csrf = _csrf(
        result_page.read().decode("utf-8"),
        meta=True,
    )

    capability_status, capability, _ = _request_json(
        opener, "/api/v1/result-reports/capabilities"
    )
    if (
        capability_status != 200
        or capability.get("user_report_allowed") is not True
        or capability.get("technical_report_allowed") is not True
    ):
        raise RuntimeError("PRODUCT-AI-08 capability gate failed.")

    csrf_status, _, _ = _request_json(
        opener,
        "/api/v1/result-reports",
        method="POST",
        body={
            "result_id": "0808080808080808",
            "result_version": 1,
            "observed_at_utc": "2026-07-26T08:00:00Z",
            "explanation_inputs": [_explanation(index) for index in range(1, 19)],
            "ai_explanation": None,
            "report_kind": "USER",
            "test_environment_result": True,
        },
        csrf_token=authenticated_csrf + "-invalid",
    )
    if csrf_status != 403:
        raise RuntimeError("PRODUCT-AI-08 CSRF gate failed.")

    report_body = {
        "result_id": "0808080808080808",
        "result_version": 1,
        "observed_at_utc": "2026-07-26T08:00:00Z",
        "explanation_inputs": [_explanation(index) for index in range(1, 19)],
        "ai_explanation": None,
        "report_kind": "USER",
        "test_environment_result": True,
    }
    first_status, first, _ = _request_json(
        opener,
        "/api/v1/result-reports",
        method="POST",
        body=report_body,
        csrf_token=authenticated_csrf,
    )
    second_status, second, _ = _request_json(
        opener,
        "/api/v1/result-reports",
        method="POST",
        body=report_body,
        csrf_token=authenticated_csrf,
    )
    if first_status != 201 or second_status != 201:
        raise RuntimeError(f"PRODUCT-AI-08 report generation failed: {first} {second}")
    first_version = cast(int, first["report_version"])
    second_version = cast(int, second["report_version"])
    if second_version != first_version + 1:
        raise RuntimeError("PRODUCT-AI-08 append-only version gate failed.")
    if first["pdf_sha256"] != second["pdf_sha256"]:
        # 보고서 버전·생성 시각이 문서에 포함되므로 재생성 PDF hash는 달라야 한다.
        pass
    elif first["report_version"] != second["report_version"]:
        raise RuntimeError("PRODUCT-AI-08 regenerated PDF hash must change.")

    download = opener.open(
        Request(  # noqa: S310 - 고정된 loopback HTTP 검증 주소만 사용
            BASE_URL + str(first["download_url"]),
            headers={"Host": CANONICAL_HOST},
        ),
        timeout=10,
    )
    pdf = download.read()
    if (
        download.status != 200
        or not pdf.startswith(b"%PDF-1.4")
        or "attachment" not in download.headers.get("Content-Disposition", "")
    ):
        raise RuntimeError("PRODUCT-AI-08 PDF download gate failed.")

    technical_body = dict(report_body)
    technical_body["report_kind"] = "TECHNICAL"
    technical_status, technical, _ = _request_json(
        opener,
        "/api/v1/result-reports",
        method="POST",
        body=technical_body,
        csrf_token=authenticated_csrf,
    )
    if technical_status != 201:
        raise RuntimeError(
            f"PRODUCT-AI-08 technical report generation failed: {technical}"
        )
    technical_download = opener.open(
        Request(  # noqa: S310 - 고정된 loopback HTTP 검증 주소만 사용
            BASE_URL + str(technical["download_url"]),
            headers={"Host": CANONICAL_HOST},
        ),
        timeout=10,
    )
    technical_pdf = technical_download.read()
    if (
        technical_download.status != 200
        or not technical_pdf.startswith(b"%PDF-1.4")
        or "secai-result-technical.pdf"
        not in technical_download.headers.get("Content-Disposition", "")
    ):
        raise RuntimeError("PRODUCT-AI-08 technical PDF download gate failed.")

    list_status, report_list, _ = _request_json(
        opener,
        "/api/v1/result-reports?result_id=0808080808080808&result_version=1",
    )
    reports = report_list.get("reports")
    if list_status != 200 or not isinstance(reports, list) or len(reports) < 2:
        raise RuntimeError("PRODUCT-AI-08 report history gate failed.")

    idor_status, _, _ = _request_json(
        opener,
        f"/api/v1/result-reports/{uuid4()}/download",
    )
    if idor_status != 404:
        raise RuntimeError("PRODUCT-AI-08 IDOR gate failed.")

    print(
        json.dumps(
            {
                "stage": "PRODUCT-AI-08",
                "authenticated_user_pdf": True,
                "append_only_versions": [
                    first["report_version"],
                    second["report_version"],
                ],
                "pdf_download": True,
                "technical_report_download": True,
                "csrf_rejected": True,
                "idor_hidden": True,
                "history_count": len(reports),
                "pdf_sha256": first["pdf_sha256"],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

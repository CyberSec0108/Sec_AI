from __future__ import annotations

from pathlib import Path
from typing import Any

from apps.api import product as product_api
from apps.api.main import app
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_beginner_pages_share_navigation_theme_and_skip_contract(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    monkeypatch.setenv("SECAI_CHAT_LIVE_ENABLED", "true")
    monkeypatch.setattr(
        product_api,
        "browser_csrf_token",
        lambda _request: "csrf-test-token",
    )

    with TestClient(app) as client:
        pages = {
            path: client.get(path)
            for path in ("/", "/ui/results", "/ui/guide-chat", "/ui/help")
        }

    for path, response in pages.items():
        assert response.status_code == 200, path
        assert 'class="skip-link" href="#main-content"' in response.text
        assert 'id="main-content"' in response.text
        assert 'id="theme-toggle"' in response.text
        assert 'src="/static/app/theme.js"' in response.text
    assert "명령어" in pages["/ui/help"].text


def test_beginner_flow_distinguishes_official_result_from_guide_explanation(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    monkeypatch.setenv("SECAI_CHAT_LIVE_ENABLED", "true")
    monkeypatch.setattr(
        product_api,
        "browser_csrf_token",
        lambda _request: "csrf-test-token",
    )

    with TestClient(app) as client:
        home = client.get("/").text
        help_page = client.get("/ui/help").text

    for step in (
        "1. 점검 장비 선택",
        "2. 결과 확인",
    ):
        assert step in home
    for tab_name in (
        "Windows PC",
        "알려진 취약점",
        "Linux 서버",
        "네트워크 점검",
        "가이드 질의",
        "계정 관리",
    ):
        assert tab_name in help_page


def test_help_topics_open_the_requested_feature_tab(monkeypatch: Any) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")

    expected = {
        "windows": "내 PC를 원클릭으로 점검하는 방법",
        "vulnerability": "Windows와 설치 구성요소의 알려진 문제를 확인하는 방법",
        "linux": "지원 Linux 서버를 점검하는 방법",
        "network": "스위치 설정을 확인하는 방법",
        "guide": "보안 가이드에 질문하는 방법",
        "account": "내 계정과 점검 기준을 관리하는 방법",
    }

    with TestClient(app) as client:
        for topic, heading in expected.items():
            response = client.get(f"/ui/help?topic={topic}")
            assert response.status_code == 200
            assert heading in response.text
            assert f'href="/ui/help?topic={topic}" aria-current="page"' in response.text

        invalid = client.get("/ui/help?topic=unknown")

    assert invalid.status_code == 200
    assert expected["windows"] in invalid.text


def test_help_lists_current_supported_platform_versions_and_boundaries(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")

    with TestClient(app) as client:
        windows = client.get("/ui/help?topic=windows")
        linux = client.get("/ui/help?topic=linux")
        network = client.get("/ui/help?topic=network")

    assert windows.status_code == 200
    assert 'data-ui-standard="product-help-v5"' in windows.text
    for text in (
        "Windows 11 x64",
        "Windows 10 x64",
        "Windows 11 전용 기준은 확인 필요",
        "지원됨",
        "Windows Server·Domain Controller",
        "지원 안 함",
    ):
        assert text in windows.text

    assert linux.status_code == 200
    for text in (
        "Ubuntu Server 24.04 LTS x64",
        "Rocky Linux 9.x x64",
        "Ubuntu Server 22.04 LTS x64",
        "Debian 12.x x64",
        "Red Hat Enterprise Linux 9.x x64",
        "AlmaLinux 9.x x64",
        "실제 VM 반복 인수 완료",
        "공식 구독 이미지 인수 전",
        "시험 지원",
        "/ui/linux-self-scan",
    ):
        assert text in linux.text

    assert network.status_code == 200
    for text in (
        "HPE Aruba Networking AOS-CX 10.13",
        "N-01~N-38",
        "개발용 DRAFT",
        'href="/ui/switch-scan"',
    ):
        assert text in network.text


def test_vulnerability_help_explains_supported_inputs_and_candidate_boundary(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")

    with TestClient(app) as client:
        response = client.get("/ui/help?topic=vulnerability")

    assert response.status_code == 200
    assert 'href="/ui/help?topic=vulnerability" aria-current="page"' in response.text
    assert 'href="/ui/vulnerability-check"' in response.text
    for text in (
        "Windows 10·11 x64",
        "설치 프로그램",
        "Python",
        "Node.js",
        "Java",
        "영향 가능성 후보",
        "후보가 없어도 안전하다고 확정하지 않습니다",
        "공식 취약 판정이 아닙니다",
        "Windows PC 점검을 먼저 완료합니다",
    ):
        assert text in response.text


def test_guide_chat_supports_keyboard_source_focus_copy_and_long_answers() -> None:
    template = (
        PROJECT_ROOT / "apps/web/templates/pages/guide_chat.html"
    ).read_text(encoding="utf-8")
    script = (
        PROJECT_ROOT / "apps/web/static/app/guide-chat.js"
    ).read_text(encoding="utf-8")
    stylesheet = (
        PROJECT_ROOT / "apps/web/static/app/app.css"
    ).read_text(encoding="utf-8")

    assert 'aria-describedby="question-count"' in template
    assert "Shift+Enter로 줄바꿈" in template
    assert 'id="question-count"' in template
    assert 'id="source-title" tabindex="-1"' in template
    assert 'aria-busy="false"' in template
    for panel_id in ("history-panel-toggle", "source-panel-toggle"):
        assert f'id="{panel_id}"' in template
    for label in ("질문 확인", "통합 가이드 검색", "답변과 출처 정리"):
        assert label in script
    assert 'event.key === "Escape"' in script
    assert 'messageList.setAttribute("aria-busy"' in script
    assert '"답변 복사"' in script
    assert "navigator.clipboard.writeText" in script
    assert "sourceTitle.focus()" in script
    assert 'matchMedia("(max-width: 640px)")' in script
    assert 'state.status === "COMPLETED"' in script
    assert "await refreshConversation()" in script
    assert "renderAnswerContent" in script
    assert "encodeURIComponent" in (
        PROJECT_ROOT / "apps/web/static/app/product-results.js"
    ).read_text(encoding="utf-8")
    assert "position: sticky" in stylesheet
    assert "overflow-wrap: anywhere" in stylesheet


def test_theme_and_responsive_accessibility_contract_is_local_only() -> None:
    script = (
        PROJECT_ROOT / "apps/web/static/app/theme.js"
    ).read_text(encoding="utf-8")
    stylesheet = (
        PROJECT_ROOT / "apps/web/static/app/app.css"
    ).read_text(encoding="utf-8")

    assert "localStorage" in script
    assert "prefers-color-scheme: dark" in script
    assert "fetch(" not in script
    assert '[data-theme="dark"]' in stylesheet
    assert "@media (prefers-color-scheme: dark)" in stylesheet
    assert "@media (prefers-reduced-motion: reduce)" in stylesheet
    assert ".skip-link" in stylesheet
    assert "min-height: 44px" in stylesheet


def test_dark_theme_emphasis_and_action_colors_keep_readable_contrast() -> None:
    stylesheet = (
        PROJECT_ROOT / "apps/web/static/app/app.css"
    ).read_text(encoding="utf-8")

    def relative_luminance(hex_color: str) -> float:
        channels = [
            int(hex_color[index : index + 2], 16) / 255
            for index in (1, 3, 5)
        ]
        linear = [
            value / 12.92
            if value <= 0.04045
            else ((value + 0.055) / 1.055) ** 2.4
            for value in channels
        ]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    def contrast_ratio(first: str, second: str) -> float:
        first_luminance = relative_luminance(first)
        second_luminance = relative_luminance(second)
        lighter = max(first_luminance, second_luminance)
        darker = min(first_luminance, second_luminance)
        return (lighter + 0.05) / (darker + 0.05)

    for foreground, background in (
        ("#f4f8fb", "#173750"),
        ("#ffffff", "#0c5aa6"),
        ("#ffffff", "#084b8c"),
        ("#66d1ad", "#153d34"),
        ("#ff8c96", "#4b2429"),
        ("#f1bd62", "#493819"),
        ("#69b7f2", "#14344c"),
    ):
        assert contrast_ratio(foreground, background) >= 4.5

    for contract in (
        "--emphasis-surface: #173750;",
        "--emphasis-text: #f4f8fb;",
        "--action-bg: #0c5aa6;",
        "--action-hover: #084b8c;",
        "background: var(--emphasis-surface);",
        "color: var(--emphasis-text);",
        "background: var(--action-bg);",
        "color: var(--action-text);",
    ):
        assert contract in stylesheet


def test_local_answer_contract_has_readable_sections() -> None:
    model = (
        PROJECT_ROOT
        / "src"
        / "security_audit"
        / "application"
        / "local_grounded_summary.py"
    ).read_text(encoding="utf-8")

    for heading in ("핵심 답변", "확인 기준", "출처", "알아두세요"):
        assert heading in model
    assert (
        PROJECT_ROOT / "tools" / "verify-imp054-beginner-usability.ps1"
    ).is_file()

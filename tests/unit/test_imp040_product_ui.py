from __future__ import annotations

from pathlib import Path
from typing import Any

from apps.api.main import app
from fastapi.testclient import TestClient

from security_audit.security.auth import (
    AuthenticationCode,
    AuthenticationError,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class _RejectingAuthenticationService:
    def authenticate(self, *_values: object, **_named: object) -> None:
        raise AuthenticationError(
            AuthenticationCode.SESSION_EXPIRED,
            "Authentication required.",
        )


def test_product_home_leads_with_one_click_scan_and_clear_feature_states(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == 200
    for navigation_label in (
        "원클릭 점검",
        "점검 결과",
        "가이드 질의",
        "계정정보",
    ):
        assert f">{navigation_label}</a>" in response.text
    assert 'href="/ui/help?topic=windows"' in response.text
    for phrase in (
        "내 장비의 보안 상태를 간편하게 점검 하세요",
        "1. 점검 장비 선택",
        "PC 점검",
        "리눅스 서버 점검",
        "네트워크 스위치 점검",
        "가이드 질의",
        "알려진 취약점 점검",
        "도움말",
        "관리자 권한이 필요한 확인 항목",
    ):
        assert phrase in response.text
    for removed_phrase in (
        "처음 사용하는 방법",
        "내 계정의 로그인 상태와 보안 설정을 확인합니다.",
        "Windows 실행 파일에서 한 번만 누르면",
        "점검 결과와 KISA 가이드 답변은 역할이 다릅니다",
        "작업 복구 상태",
        "저장소 복구 상태",
        "AI 연결 상태",
        "에이전트 활용",
        "기술 정보 보기",
        "테스트 화면",
    ):
        assert removed_phrase not in response.text
    assert 'data-ui-standard="product-home-v1"' in response.text
    assert '<button type="button" id="start-standard-scan"' in response.text
    assert 'id="scan-consent-dialog"' in response.text
    assert 'id="administrator-scan-disclosure"' in response.text
    assert 'id="confirm-standard-scan"' in response.text
    assert 'data-consent-version="imp043-v1"' in response.text
    assert response.text.count('data-administrator-probe-id="') == 5
    assert "권한 확인창에서 반드시" in response.text
    assert "‘예’" in response.text
    assert "동의하고 전체 점검 시작" in response.text
    assert 'id="scan-progress"' not in response.text
    assert 'id="cancel-standard-scan"' not in response.text
    assert 'id="retry-standard-scan"' not in response.text
    assert "feature-state-live" not in response.text
    assert "feature-state-preview" not in response.text
    assert 'src="/static/app/product.js"' in response.text
    assert "audit_pack_draft_assist" not in response.text

    header = (
        PROJECT_ROOT / "apps/web/templates/components/audit_ui.html"
    ).read_text(encoding="utf-8")
    styles = (
        PROJECT_ROOT / "apps/web/static/app/app.css"
    ).read_text(encoding="utf-8")
    admin = (
        PROJECT_ROOT / "apps/web/templates/pages/admin_accounts.html"
    ).read_text(encoding="utf-8")
    feature_registry = (
        PROJECT_ROOT / "src/security_audit/application/product_features.py"
    ).read_text(encoding="utf-8")
    assert '<div class="environment">' not in header
    assert "border-radius: 50%" in styles
    assert "1740px" in styles
    assert "@media (min-width: 1200px)" in styles
    assert "width: 70%" in styles
    assert ".feature-card > .feature-action" in styles
    assert "align-self: center" in styles
    for admin_feature in (
        "점검 결과",
        "관리자 추가 점검",
        "작업 복구 상태",
        "저장소 복구 상태",
        "AI 연결 상태",
    ):
        assert admin_feature in admin + feature_registry
    assert "administrator_features" not in admin
    assert "운영 및 점검 관리" not in admin

    product_script = (
        PROJECT_ROOT / "apps/web/static/app/product.js"
    ).read_text(encoding="utf-8")
    assert "secai_pending_administrator_scan_consent" in product_script
    assert "[data-administrator-probe-id]" in product_script
    assert "consent_version: consentVersion" in product_script
    assert "probe_ids: probeIds" in product_script
    assert 'href="/?new_scan=1"' in header
    assert 'get(\n    "new_scan"\n  ) === "1"' in product_script
    assert (
        "!explicitNewScan && launcherTokenIsAvailable && pendingConsentIsValid()"
        in product_script
    )

    results = (
        PROJECT_ROOT / "apps/web/templates/pages/product_results.html"
    ).read_text(encoding="utf-8")
    assert 'class="back-link" href="/?new_scan=1"' in results


def test_product_home_maintenance_markers_and_dev_web_mount() -> None:
    home = (
        PROJECT_ROOT / "apps/web/templates/pages/product_home.html"
    ).read_text(encoding="utf-8")
    styles = (
        PROJECT_ROOT / "apps/web/static/app/app.css"
    ).read_text(encoding="utf-8")
    product_script = (
        PROJECT_ROOT / "apps/web/static/app/product.js"
    ).read_text(encoding="utf-8")
    feature_registry = (
        PROJECT_ROOT / "src/security_audit/application/product_features.py"
    ).read_text(encoding="utf-8")
    compose_dev = (
        PROJECT_ROOT / "deploy/compose/compose.dev.yml"
    ).read_text(encoding="utf-8")

    assert "처음 사용하는 방법" not in home
    assert "개인 기준 사용 안 함" not in home
    assert "KISA 가이드 기준 (기본)" in home
    assert "점검 기준 선택" in home
    assert "KISA·제품 기본 기준을 자동 적용합니다." in product_script
    assert 'selection_kind=KISA_DEFAULT' not in product_script
    assert 'void loadCriteriaOptions("", true);' in product_script
    assert "personalCriteria.dataset.defaultKind = resolvedDefaultKind" in product_script
    assert 'new Option("조직 기본 기준 (현재 적용)", "")' in product_script
    assert 'personalCriteria.dataset.selectedKind === "PERSONAL"' in product_script
    assert "readSelectedCriteriaId" not in product_script
    assert "[카드수정]" in home
    assert "[카드수정]" in styles
    assert "[카드수정]" in product_script
    assert "[카드수정]" in feature_registry
    assert "source: apps/web" in compose_dev
    assert "target: /app/apps/web" in compose_dev
    assert "source: src" in compose_dev
    assert "target: /app/src" in compose_dev
    assert "source: apps/api" in compose_dev
    assert "target: /app/apps/api" in compose_dev
    assert 'WATCHFILES_FORCE_POLLING: "true"' in compose_dev
    assert "- --reload" in compose_dev
    assert "- /app/src" in compose_dev
    assert "- /app/apps/api" in compose_dev
    assert "read_only: true" in compose_dev


def test_product_download_cta_is_above_larger_feature_cards() -> None:
    home = (
        PROJECT_ROOT / "apps/web/templates/pages/product_home.html"
    ).read_text(encoding="utf-8")
    header = (
        PROJECT_ROOT / "apps/web/templates/components/audit_ui.html"
    ).read_text(encoding="utf-8")
    styles = (
        PROJECT_ROOT / "apps/web/static/app/app.css"
    ).read_text(encoding="utf-8")

    hero = home.split('<header class="product-hero">', 1)[1].split("</header>", 1)[0]
    feature_heading = home.split('<div class="product-section-heading">', 1)[1].split(
        '<div class="feature-grid">', 1
    )[0]
    top_navigation = header.split('<nav class="top-nav"', 1)[1].split("</nav>", 1)[0]

    assert "/ui/dev-downloads" not in hero
    assert "/ui/dev-downloads" not in top_navigation
    assert "프로그램 다운로드" not in top_navigation
    assert 'class="button-link button-link-primary product-download-link"' in feature_heading
    assert 'href="/ui/dev-downloads"' in feature_heading
    assert '[data-ui-standard="product-home-v1"] .feature-card' in styles
    assert "min-height: 230px" in styles
    assert "width: fit-content" in styles
    assert ".product-download-link" in styles


def test_result_navigation_separates_windows_linux_and_switch_pages(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    with TestClient(app) as client:
        center = client.get("/ui/result-center")
        switch = client.get("/ui/switch-scan")

    assert center.status_code == 200
    assert "장비별 점검 결과" in center.text
    assert 'href="/ui/results"' in center.text
    assert 'href="/ui/linux-results/latest"' in center.text
    assert 'href="/ui/switch-results"' in center.text
    assert "Windows PC 점검 결과" in center.text
    assert "Linux 서버 점검 결과" in center.text
    assert "네트워크 스위치 점검 결과" in center.text
    assert switch.status_code == 200
    assert "네트워크 스위치 점검" in switch.text
    assert 'id="switch-password"' in switch.text

    windows_page = (
        PROJECT_ROOT / "apps/web/templates/pages/product_results.html"
    ).read_text(encoding="utf-8")
    assert "Windows PC 보안설정 점검 결과" in windows_page

    header = (
        PROJECT_ROOT / "apps/web/templates/components/audit_ui.html"
    ).read_text(encoding="utf-8")
    assert '<a href="/ui/result-center"' in header


def test_product_home_allows_only_the_exact_loopback_launcher_bridge(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    with TestClient(app) as client:
        response = client.get("/")

    csp = response.headers["Content-Security-Policy"]
    assert (
        "connect-src 'self' http://127.0.0.1:18481 "
        "http://127.0.0.1:18482"
    ) in csp
    assert "http://127.0.0.1:*" not in csp
    assert "http://localhost:*" not in csp

    gateway = (PROJECT_ROOT / "deploy" / "gateway" / "nginx.conf").read_text(
        encoding="utf-8"
    )
    assert (
        "connect-src 'self' http://127.0.0.1:18481 "
        "http://127.0.0.1:18482"
    ) in gateway


def test_launcher_connection_handoff_survives_login_and_retries_transient_failure(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    monkeypatch.setenv("SECAI_AUTH_ENABLED", "true")
    monkeypatch.setenv("SECAI_AUTH_PROFILE", "DEV-LOCAL")
    monkeypatch.setenv(
        "SECAI_AUTH_CANONICAL_ORIGIN",
        "http://localhost:18480",
    )

    from apps.api import auth_support

    auth_support.auth_settings.cache_clear()
    monkeypatch.setattr(
        auth_support,
        "get_auth_service",
        _RejectingAuthenticationService,
    )
    try:
        with TestClient(app) as client:
            response = client.get("/ui/launcher-connect", follow_redirects=False)
    finally:
        auth_support.auth_settings.cache_clear()

    assert response.status_code == 200
    assert 'src="/static/app/launcher-connect.js"' in response.text

    handoff_script = (
        PROJECT_ROOT / "apps" / "web" / "static" / "app" / "launcher-connect.js"
    ).read_text(encoding="utf-8")
    assert 'sessionStorage.setItem("secai_launcher_token"' in handoff_script
    assert 'location.replace("/")' in handoff_script

    product_script = (
        PROJECT_ROOT / "apps" / "web" / "static" / "app" / "product.js"
    ).read_text(encoding="utf-8")
    assert "secai_pending_standard_scan_consent" in product_script
    assert 'sessionStorage.getItem(\n    "secai_launcher_token"' in product_script
    assert 'location.assign("/ui/results?start_scan=1")' in product_script
    assert 'sessionStorage.removeItem("secai_launcher_token")' not in product_script
    results_script = (
        PROJECT_ROOT / "apps" / "web" / "static" / "app" / "product-results.js"
    ).read_text(encoding="utf-8")
    assert "startRequestedStandardScan" in results_script
    assert 'request("/v1/scan", "POST")' in results_script


def test_windows_result_disconnected_state_offers_launcher_recovery_actions() -> None:
    template = (
        PROJECT_ROOT / "apps/web/templates/pages/product_results.html"
    ).read_text(encoding="utf-8")
    results_script = (
        PROJECT_ROOT / "apps/web/static/app/product-results.js"
    ).read_text(encoding="utf-8")
    handoff_script = (
        PROJECT_ROOT / "apps/web/static/app/launcher-connect.js"
    ).read_text(encoding="utf-8")
    styles = (
        PROJECT_ROOT / "apps/web/static/app/app.css"
    ).read_text(encoding="utf-8")

    assert 'id="launcher-recovery"' in template
    assert 'href="/ui/dev-downloads"' in template
    assert "점검 프로그램 다운로드" in template
    assert 'id="launcher-open-help"' in template
    assert "다운로드한 파일 여는 방법" in template
    assert 'id="launcher-retry-connection"' in template
    assert "연결 다시 확인" in template
    assert 'href="/?new_scan=1"' in template
    assert "원클릭 점검으로 돌아가기" in template
    assert "경고를 임의로 우회하지 마세요" in template

    assert "showLauncherRecovery" in results_script
    assert "takeLauncherContinuation" in results_script
    assert "retryLauncherConnection" in results_script
    assert 'request("/v1/status", "GET")' in results_script
    assert 'localStorage.setItem("secai_launcher_continuation"' in handoff_script
    assert 'localStorage.removeItem("secai_launcher_continuation")' in results_script
    assert 'localStorage.removeItem("secai_launcher_continuation")' in (
        PROJECT_ROOT / "apps/web/static/app/product.js"
    ).read_text(encoding="utf-8")
    assert ".launcher-recovery-actions" in styles


def test_browser_loopback_alias_redirects_to_login_canonical_origin(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    monkeypatch.setenv("SECAI_AUTH_ENABLED", "true")
    monkeypatch.setenv("SECAI_AUTH_PROFILE", "DEV-LOCAL")
    monkeypatch.setenv(
        "SECAI_AUTH_CANONICAL_ORIGIN",
        "http://localhost:18480",
    )

    from apps.api import auth_support

    auth_support.auth_settings.cache_clear()
    monkeypatch.setattr(
        auth_support,
        "get_auth_service",
        _RejectingAuthenticationService,
    )
    try:
        with TestClient(
            app,
            base_url="http://127.0.0.1:18480",
        ) as client:
            response = client.get(
                "/ui/results?start_scan=1",
                follow_redirects=False,
            )
    finally:
        auth_support.auth_settings.cache_clear()

    assert response.status_code == 307
    assert response.headers["location"] == (
        "http://localhost:18480/ui/results?start_scan=1"
    )


def test_login_redirect_preserves_pending_scan_query(monkeypatch: Any) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    monkeypatch.setenv("SECAI_AUTH_ENABLED", "true")
    monkeypatch.setenv("SECAI_AUTH_PROFILE", "DEV-LOCAL")
    monkeypatch.setenv(
        "SECAI_AUTH_CANONICAL_ORIGIN",
        "http://localhost:18480",
    )

    from apps.api import auth_support

    auth_support.auth_settings.cache_clear()
    monkeypatch.setattr(
        auth_support,
        "get_auth_service",
        _RejectingAuthenticationService,
    )
    try:
        with TestClient(
            app,
            base_url="http://localhost:18480",
        ) as client:
            response = client.get(
                "/ui/results?start_scan=1",
                follow_redirects=False,
            )
    finally:
        auth_support.auth_settings.cache_clear()

    assert response.status_code == 303
    assert response.headers["location"] == (
        "/auth/login?next=/ui/results%3Fstart_scan%3D1"
    )


def test_demonstration_surfaces_are_closed_and_administrator_redirects_to_results(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    with TestClient(app) as client:
        retired_paths = (
            "/ui/preview/network_switch_scan",
            "/ui/storage",
            "/ui/account-policy",
            "/ui/service-management",
            "/ui/patch-lifecycle",
            "/ui/endpoint-protection",
            "/ui/user-media-remote",
            "/ui/full-audit",
            "/ui/collector-job",
            "/ui/collector-coverage",
            "/ui/collector-build",
            "/ui/collector-release",
            "/ui/windows-context",
            "/ui/windows-baseline",
            "/ui/windows-collection",
            "/ui/windows-evaluation",
            "/ui/online-submission",
            "/ui/offline-submission",
            "/ui/submission-attack",
        )
        retired = {path: client.get(path).status_code for path in retired_paths}
        administrator = client.get(
            "/ui/administrator-scan",
            follow_redirects=False,
        )

    assert retired == {path: 404 for path in retired_paths}
    assert administrator.status_code == 307
    assert administrator.headers["location"] == "/ui/results#administrator-scan"


def test_feature_api_excludes_hidden_features_and_has_no_action_endpoint(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    with TestClient(app) as client:
        response = client.get("/api/v1/product/features")
        forbidden_action = client.post("/api/v1/product/preview/guide_chat/run")

    assert response.status_code == 200
    body = response.json()
    assert body["features"]["pc_scan"]["state"] == "LIVE"
    assert body["features"]["guide_chat"]["state"] == "LIVE"
    assert "history" not in body["features"]
    assert "audit_pack_draft_assist" not in body["features"]
    assert forbidden_action.status_code == 404


def test_launcher_return_is_summary_only_and_not_an_official_result(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "true")
    with TestClient(app) as client:
        response = client.get(
            "/ui/launcher-return"
            "?status=COMPLETED&total=15&collected=14&errors=1"
        )

    assert response.status_code == 200
    for phrase in (
        "일반 권한 점검을 마쳤습니다",
        "수집 완료 14개",
        "확인 필요 1개",
        "공식 점검 결과가 아닙니다",
        "원본 설정값을 저장하지 않았습니다",
    ):
        assert phrase in response.text


def test_product_surface_is_hidden_outside_development(monkeypatch: Any) -> None:
    monkeypatch.setenv("SECAI_DEV_DEMO_ENABLED", "false")
    with TestClient(app) as client:
        assert client.get("/").status_code == 404
        assert client.get("/api/v1/product/features").status_code == 404

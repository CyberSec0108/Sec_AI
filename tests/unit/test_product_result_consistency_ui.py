from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _read(relative: str) -> str:
    return (PROJECT_ROOT / relative).read_text(encoding="utf-8")


def test_result_cards_are_sorted_and_completion_labels_are_not_rendered() -> None:
    integrated = _read("apps/web/static/app/product-results-integrated.js")
    analysis = _read("apps/web/static/app/result-ai-analysis.js")
    results = _read("apps/web/static/app/product-results.js")

    assert "sortControlsById" in integrated
    assert "mergeAdministratorResults" in results
    assert "canonicalAdministratorResults" in results
    assert "설명 생성 완료" not in integrated
    assert "설명 생성 완료" not in analysis


def test_all_windows_controls_are_available_in_a_default_closed_recheck_panel() -> None:
    template = _read("apps/web/templates/pages/product_results.html")
    product_api = _read("apps/api/product.py")

    assert '<details id="recheck-controls-panel"' in template
    assert '<details id="recheck-controls-panel" open' not in template
    assert "recheck_controls" in template
    for number in range(1, 19):
        assert f'"PC-{number:02d}"' in product_api


def test_result_status_borders_and_narrow_buttons_have_distinct_safe_layout() -> None:
    stylesheet = _read("apps/web/static/app/app.css")

    assert (
        ".integrated-control-card.integrated-status-pass { border-left-color: var(--pass); }"
        in stylesheet
    )
    assert (
        ".integrated-control-card.integrated-status-fail { border-left-color: var(--fail); }"
        in stylesheet
    )
    assert (
        ".integrated-control-card.integrated-status-review { border-left-color: var(--blue); }"
        in stylesheet
    )
    assert ".control-result-review { border-left-color: var(--blue); }" in stylesheet
    assert ".result-view-switch {" in stylesheet
    assert "grid-template-columns: repeat(3, minmax(0, 1fr));" in stylesheet
    assert "width: min(100%, 24rem);" in stylesheet
    assert ".result-view-switch button {" in stylesheet
    assert "font-size: clamp(.72rem, 1.4vw, .88rem);" in stylesheet
    assert ".result-view-switch { display: grid; grid-template-columns: 1fr; }" not in stylesheet
    assert ".result-toolbar-actions button" in stylesheet
    assert "flex: 1 1" in stylesheet
    assert ".summary-list-four .summary-pass button strong { color: var(--pass); }" in stylesheet
    assert ".summary-list-four .summary-fail button strong { color: var(--fail); }" in stylesheet
    assert ".summary-list-four .summary-error button strong { color: var(--error); }" in stylesheet


def test_clicks_inside_ai_results_do_not_trigger_status_filter_scroll() -> None:
    integrated = _read("apps/web/static/app/product-results-integrated.js")

    assert 'document.querySelectorAll("button[data-result-status]")' in integrated
    assert 'document.querySelectorAll("[data-result-status]")' not in integrated
    assert "panel.scrollIntoView" not in integrated


def test_windows_result_cards_do_not_render_technical_evidence_details() -> None:
    integrated = _read("apps/web/static/app/product-results-integrated.js")

    assert "확인 방법과 기술 증적" not in integrated
    assert "createTechnicalDetails" not in integrated


def test_completed_windows_ai_screen_is_durable_until_explicit_regeneration() -> None:
    integrated = _read("apps/web/static/app/product-results-integrated.js")
    results = _read("apps/web/static/app/product-results.js")

    assert 'const completedSnapshotPrefix = "secai_result_ai_screen_v1:"' in integrated
    assert "window.localStorage.setItem(" in integrated
    assert "window.localStorage.getItem(" in integrated
    assert "window.sessionStorage.setItem(" not in integrated
    assert "window.sessionStorage.getItem(" not in integrated
    assert "function saveCompletedSnapshot" in integrated
    assert "function restoreCompletedSnapshot" in integrated
    assert "if (restoreCompletedSnapshot(detail))" in integrated
    assert 'stopButton.textContent = "AI 설명 재생성"' in integrated
    assert 'runState === "completed" && latest' in integrated
    assert "loadServerCompletedSnapshot" in integrated
    assert "secai:windows-ai-snapshot-completed" in integrated
    assert "/api/v1/audit-history/windows/presentation" in results


def test_linux_and_switch_restore_server_ai_snapshot_before_starting_stream() -> None:
    linux_api = _read("apps/api/linux_audit.py")
    linux_results = _read("apps/web/static/app/linux-results.js")
    switch_api = _read("apps/api/switch_audit.py")
    switch_results = _read("apps/web/static/app/switch-results.js")

    assert '@router.get("/api/v1/linux/audits/{run_id}/ai/snapshot")' in linux_api
    assert "function restoreAISnapshot" in linux_results
    assert "await restoreAISnapshot()" in linux_results
    assert "if (!restored)" in linux_results
    assert "const restored = await restoreAISnapshot();" in linux_results

    assert '@router.get("/api/v1/switch/audits/{run_id}/ai/snapshot")' in switch_api
    assert "function restoreAISnapshot" in switch_results
    assert "void restoreAISnapshot();" in switch_results
    assert 'startButton.textContent = "AI 설명 재생성"' in switch_results


def test_linux_and_switch_snapshot_reads_are_owner_scoped_and_bulk_loaded() -> None:
    linux_repository = _read(
        "src/security_audit/persistence/database/linux_audit_repository.py"
    )
    switch_repository = _read(
        "src/security_audit/persistence/database/switch_audit_repository.py"
    )

    assert "def get_ai_outputs(" in linux_repository
    assert "set_linux_audit_scope(session, organization_id, owner_user_id)" in linux_repository
    assert "output_key LIKE :prefix" in linux_repository
    assert "def get_switch_ai_outputs(" in switch_repository
    assert "set_switch_audit_scope(session, organization_id, owner_user_id)" in switch_repository
    assert "output_key LIKE :output_prefix" in switch_repository

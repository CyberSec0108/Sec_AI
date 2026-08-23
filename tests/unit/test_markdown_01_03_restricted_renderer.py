from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_ai_analysis_loads_restricted_markdown_before_stream_controller() -> None:
    template = (
        PROJECT_ROOT / "apps/web/templates/pages/result_ai_analysis.html"
    ).read_text(encoding="utf-8")

    renderer = '<script src="/static/app/restricted-markdown.js" defer></script>'
    controller = '<script src="/static/app/result-ai-analysis.js" defer></script>'
    assert renderer in template
    assert template.index(renderer) < template.index(controller)
    assert 'role="document"' in template
    assert 'aria-label="AI 종합 설명 내용"' in template


def test_token_stream_uses_ast_renderer_and_plain_text_fail_safe() -> None:
    script = (
        PROJECT_ROOT / "apps/web/static/app/result-ai-analysis.js"
    ).read_text(encoding="utf-8")
    renderer = (
        PROJECT_ROOT / "apps/web/static/app/restricted-markdown.js"
    ).read_text(encoding="utf-8")

    assert "SecAIRestrictedMarkdown" in script
    assert "createStreamingRenderer" in script
    assert "card.renderer.append(event.delta)" in script
    assert "card.renderer.complete()" in script
    assert "summaryRenderer.append(event.delta)" in script
    assert "summaryRenderer.complete()" in script
    assert "textContent += event.delta" not in script
    assert "innerHTML" not in script
    assert "innerHTML" not in renderer
    assert "replaceChildren" in renderer
    assert "fallbackToPlainText" in renderer


def test_restricted_markdown_contract_and_security_allowlist_are_explicit() -> None:
    renderer = (
        PROJECT_ROOT / "apps/web/static/app/restricted-markdown.js"
    ).read_text(encoding="utf-8")

    for token in (
        "secai.restricted-markdown.v3",
        "heading",
        "paragraph",
        "unordered_list",
        "ordered_list",
        "table",
        "strong",
        "emphasis",
        "inline_code",
        "link",
        "citation_ref",
        "https:",
        "same_origin",
    ):
        assert token in renderer
    for blocked in (
        "javascript:",
        "data:",
        "vbscript:",
        "protocol_relative",
        "raw_html",
        "image",
        "fenced_code",
    ):
        assert blocked in renderer


def test_markdown_styles_cover_mobile_accessibility_and_long_untrusted_text() -> None:
    stylesheet = (
        PROJECT_ROOT / "apps/web/static/app/app.css"
    ).read_text(encoding="utf-8")

    assert ".ai-markdown" in stylesheet
    assert "overflow-wrap: anywhere" in stylesheet
    assert ".ai-markdown-fallback" in stylesheet
    assert "@media (max-width: 760px)" in stylesheet
    assert "@media (prefers-reduced-motion: reduce)" in stylesheet
    assert ".ai-markdown a:focus-visible" in stylesheet
    assert ".ai-citation-ref:focus-visible" in stylesheet
    assert ".ai-source-list" in stylesheet
    assert ".ai-markdown-table-wrap" in stylesheet
    assert "overflow-x: auto" in stylesheet
    assert ".ai-control-stream-heading .status" in stylesheet
    assert ".ai-stream-progress-actions" in stylesheet
    assert "min-width: 0" in stylesheet


def test_stream_renderer_uses_throttle_instead_of_debounce() -> None:
    renderer = (
        PROJECT_ROOT / "apps/web/static/app/restricted-markdown.js"
    ).read_text(encoding="utf-8")
    schedule = renderer.split("function schedule()", 1)[1].split(
        "function append(delta)", 1
    )[0]

    assert "if (timer !== null)" in schedule
    assert "clearTimer();" not in schedule


def test_csp_requires_trusted_types_without_relaxing_existing_policy() -> None:
    main = (PROJECT_ROOT / "apps/api/main.py").read_text(encoding="utf-8")
    gateway = (
        PROJECT_ROOT / "deploy/gateway/nginx.conf"
    ).read_text(encoding="utf-8")

    for source in (main, gateway):
        assert "require-trusted-types-for 'script'" in source
        assert "trusted-types 'none'" in source
        assert "script-src 'self'" in source
        assert "object-src 'none'" in source
        assert "unsafe-inline" not in source
        assert "unsafe-eval" not in source

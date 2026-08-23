from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_download_page_has_windows_and_auto_linux_without_secret_in_url() -> None:
    template = (
        PROJECT_ROOT / "apps/web/templates/pages/dev_signed_downloads.html"
    ).read_text(encoding="utf-8")
    script = (
        PROJECT_ROOT / "apps/web/static/app/dev-signed-downloads.js"
    ).read_text(encoding="utf-8")

    for platform in ("WINDOWS_X64", "LINUX_AUTO_X64"):
        assert f'data-platform="{platform}"' in template
    assert 'data-platform="UBUNTU_24_04_X64"' not in template
    assert 'data-platform="ROCKY_9_X64"' not in template
    assert "개발시험 전용" in template
    assert "운영 서명이 아닙니다" in template
    assert "ssh -N -R 18480:127.0.0.1:18480" in template
    assert "VM에는 웹브라우저가 필요하지 않습니다" in template
    assert 'method: "POST"' in script
    assert 'headers: {"Content-Type": "text/plain"}' in script
    assert "?code=" not in script
    assert "crypto.subtle.digest" in script


def test_download_api_is_fail_closed_and_public_fetch_is_exactly_exempted() -> None:
    api = (PROJECT_ROOT / "apps/api/dev_signed_downloads.py").read_text(
        encoding="utf-8"
    )
    main = (PROJECT_ROOT / "apps/api/main.py").read_text(encoding="utf-8")
    compose = (PROJECT_ROOT / "deploy/compose/compose.dev.yml").read_text(
        encoding="utf-8"
    )

    assert "load_verified_dev_release" in api
    assert "verify_browser_csrf" in api
    assert "hashlib.sha256(payload).hexdigest()" in api
    assert "Response" in api
    assert "Cache-Control\": \"no-store" in api
    assert '"/api/v1/dev-downloads/fetch/"' in main
    assert "SECAI_DEV_SIGNED_DOWNLOAD_ENABLED" in compose
    assert "read_only: true" in compose


def test_gateway_streams_large_download_without_small_tmpfs_buffer() -> None:
    nginx = (PROJECT_ROOT / "deploy/gateway/nginx.conf").read_text(
        encoding="utf-8"
    )

    location = "location ^~ /api/v1/dev-downloads/fetch/"
    assert location in nginx
    block = nginx.split(location, maxsplit=1)[1].split("}", maxsplit=1)[0]
    assert "proxy_buffering off;" in block
    assert "proxy_cache off;" in block

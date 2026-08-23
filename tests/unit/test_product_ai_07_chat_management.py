from __future__ import annotations

from pathlib import Path

import pytest

from security_audit.chat import ChatContractError
from security_audit.persistence.database.chat_repository import (
    normalize_chat_folder,
    normalize_chat_search,
    normalize_chat_title,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_management_values_are_normalized_and_fail_closed() -> None:
    assert normalize_chat_title("  비밀번호 기준  ") == "비밀번호 기준"
    assert normalize_chat_folder("  재점검 결과  ") == "재점검 결과"
    assert normalize_chat_folder(None) is None
    assert normalize_chat_search("  PC-07  ") == "PC-07"

    with pytest.raises(ChatContractError, match="CHAT_TITLE_LENGTH_INVALID"):
        normalize_chat_title(" ")
    with pytest.raises(ChatContractError, match="CHAT_FOLDER_LENGTH_INVALID"):
        normalize_chat_folder("x" * 81)
    with pytest.raises(ChatContractError, match="CHAT_SEARCH_LENGTH_INVALID"):
        normalize_chat_search("x" * 101)
    with pytest.raises(ChatContractError, match="CHAT_MANAGEMENT_TEXT_INVALID"):
        normalize_chat_title("이름\n변조")


def test_new_migration_preserves_tombstones_rls_and_management_audit() -> None:
    migration = (
        PROJECT_ROOT
        / "database"
        / "alembic"
        / "versions"
        / "0011_product_ai_07_chat_management.py"
    ).read_text(encoding="utf-8")

    for field in ("is_pinned", "folder_name", "status_before_tombstone"):
        assert field in migration
    assert "chat_thread_management_events" in migration
    assert "ENABLE ROW LEVEL SECURITY" in migration
    assert "FORCE ROW LEVEL SECURITY" in migration
    assert "secai_runtime" in migration
    assert "DELETE ON chat_threads" not in migration
    assert "ON DELETE RESTRICT" in migration


def test_chat_management_api_is_owner_scoped_and_has_no_physical_delete() -> None:
    api = (
        PROJECT_ROOT / "apps" / "api" / "chat_conversation.py"
    ).read_text(encoding="utf-8")
    repository = (
        PROJECT_ROOT
        / "src"
        / "security_audit"
        / "persistence"
        / "database"
        / "chat_repository.py"
    ).read_text(encoding="utf-8")

    for path in (
        "/title",
        "/pin",
        "/folder",
        "/archive",
        "/tombstone",
        "/undo-delete",
    ):
        assert path in api
    assert "organization_id, owner_user_id = _scope(request)" in api
    assert "delete(" not in repository
    assert "ThreadStatus.TOMBSTONED" in repository
    assert "CHAT_DELETE_UNDO_EXPIRED" in repository
    assert "ChatThreadManagementEventRecord" in repository


def test_guide_chat_integrates_search_management_and_delete_undo() -> None:
    header = (
        PROJECT_ROOT
        / "apps"
        / "web"
        / "templates"
        / "components"
        / "audit_ui.html"
    ).read_text(encoding="utf-8")
    template = (
        PROJECT_ROOT
        / "apps"
        / "web"
        / "templates"
        / "pages"
        / "guide_chat.html"
    ).read_text(encoding="utf-8")
    script = (
        PROJECT_ROOT / "apps" / "web" / "static" / "app" / "guide-chat.js"
    ).read_text(encoding="utf-8")
    styles = (
        PROJECT_ROOT / "apps" / "web" / "static" / "app" / "app.css"
    ).read_text(encoding="utf-8")

    assert 'href="/ui/guide-chat#history"' not in header
    for element_id in (
        "thread-search",
        "thread-view",
        "thread-delete-undo",
        "history-panel-resizer",
    ):
        assert f'id="{element_id}"' in template
        assert f'getElementById("{element_id}")' in script
    for removed_element_id in (
        "thread-management-panel",
        "thread-title-input",
        "thread-folder-input",
    ):
        assert f'id="{removed_element_id}"' not in template
    for function_name in (
        "startInlineThreadRename",
        "initializeHistoryPanelResizer",
    ):
        assert function_name in script
    for icon_name in ('"pin"', '"edit"', '"archive"', '"trash"'):
        assert icon_name in script
    assert "openInlineFolderEditor" not in script
    assert '"folder"' not in script
    assert "thread.folder_name" not in script
    assert "폴더로 이동" not in script
    assert "대화 이름 수정" in script
    assert "삭제 취소" in template
    assert "innerHTML" not in script
    assert 'savedValue !== null && savedValue.trim() !== ""' in script
    assert "white-space: nowrap" in styles
    assert "text-overflow: ellipsis" in styles
    assert "pointer-events: none" in styles

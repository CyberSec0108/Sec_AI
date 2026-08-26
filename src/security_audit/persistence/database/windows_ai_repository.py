"""완성된 Windows AI 설명을 소유자 범위로 보관합니다.

Linux·Switch와 같은 방식으로, 같은 결과를 다시 열 때 모델을 재호출하지 않고
저장된 설명을 그대로 복원하기 위한 캐시입니다.
"""

from __future__ import annotations

import re
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session

from .audit_history_repository import set_audit_history_scope

OUTPUT_KEY_PATTERN = re.compile(r"^(PC-(0[1-9]|1[0-8])|SUMMARY)$")


class WindowsAIOutputError(ValueError):
    """저장하려는 AI 출력 키나 범위가 계약과 다를 때 발생합니다."""


def append_windows_ai_output(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    snapshot_id: UUID,
    output_key: str,
    content: str,
    content_sha256: str,
) -> None:
    if OUTPUT_KEY_PATTERN.fullmatch(output_key) is None:
        raise WindowsAIOutputError("WINDOWS_AI_OUTPUT_KEY_INVALID")
    set_audit_history_scope(session, organization_id, owner_user_id)
    session.execute(
        text(
            """
            INSERT INTO windows_audit_ai_outputs (
                snapshot_id, organization_id, owner_user_id,
                output_key, content, content_sha256
            ) VALUES (
                :snapshot_id, :organization_id, :owner_user_id,
                :output_key, :content, :content_sha256
            )
            ON CONFLICT (snapshot_id, output_key) DO NOTHING
            """
        ),
        {
            "snapshot_id": snapshot_id,
            "organization_id": organization_id,
            "owner_user_id": owner_user_id,
            "output_key": output_key,
            "content": content,
            "content_sha256": content_sha256,
        },
    )


def get_windows_ai_outputs(
    session: Session,
    *,
    organization_id: UUID,
    owner_user_id: UUID,
    snapshot_id: UUID,
) -> dict[str, str]:
    """한 결과의 저장된 AI 설명 세대를 한 번에 돌려줍니다."""

    set_audit_history_scope(session, organization_id, owner_user_id)
    rows = session.execute(
        text(
            "SELECT output_key, content FROM windows_audit_ai_outputs "
            "WHERE snapshot_id = :snapshot_id ORDER BY output_key"
        ),
        {"snapshot_id": snapshot_id},
    ).all()
    return {str(row[0]): str(row[1]) for row in rows}

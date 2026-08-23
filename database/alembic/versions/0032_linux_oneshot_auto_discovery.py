"""Allow a one-shot run to stay unbound until read-only platform discovery."""

from collections.abc import Sequence

from alembic import op

revision: str = "0032_linux_auto_discovery"
down_revision: str | None = "0031_unified_audit_history"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TABLE linux_audit_runs DROP CONSTRAINT ck_linux_audit_asset")
    op.execute("ALTER TABLE linux_audit_runs DROP CONSTRAINT ck_linux_audit_distribution")
    op.execute(
        """
        ALTER TABLE linux_audit_runs ADD CONSTRAINT ck_linux_audit_asset
        CHECK (asset_key IN (
            'ubuntu24', 'rocky9', 'self-ubuntu24', 'self-rocky9', 'self-auto'
        ))
        """
    )
    op.execute(
        """
        ALTER TABLE linux_audit_runs ADD CONSTRAINT ck_linux_audit_distribution
        CHECK (distribution IN ('UBUNTU_24_04', 'ROCKY_9', 'AUTO'))
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM linux_audit_runs
                WHERE distribution = 'AUTO' OR asset_key = 'self-auto'
            ) THEN
                RAISE EXCEPTION 'Bind or remove AUTO one-shot runs before downgrade';
            END IF;
        END
        $$
        """
    )
    op.execute("ALTER TABLE linux_audit_runs DROP CONSTRAINT ck_linux_audit_asset")
    op.execute("ALTER TABLE linux_audit_runs DROP CONSTRAINT ck_linux_audit_distribution")
    op.execute(
        """
        ALTER TABLE linux_audit_runs ADD CONSTRAINT ck_linux_audit_asset
        CHECK (asset_key IN ('ubuntu24', 'rocky9', 'self-ubuntu24', 'self-rocky9'))
        """
    )
    op.execute(
        """
        ALTER TABLE linux_audit_runs ADD CONSTRAINT ck_linux_audit_distribution
        CHECK (distribution IN ('UBUNTU_24_04', 'ROCKY_9'))
        """
    )

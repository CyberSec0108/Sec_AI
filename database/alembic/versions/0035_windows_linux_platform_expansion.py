"""Expand Windows client and Linux distribution support contracts."""

from collections.abc import Sequence

from alembic import op

revision: str = "0035_platform_expansion"
down_revision: str | None = "0034_linux_managed_assets"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_DISTRIBUTIONS = (
    "'UBUNTU_22_04', 'UBUNTU_24_04', 'DEBIAN_12', "
    "'ROCKY_9', 'RHEL_9', 'ALMALINUX_9'"
)
_UUID_V4_PATTERN = (
    r"^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-"
    r"[89ab][a-f0-9]{3}-[a-f0-9]{12}$"
)


def upgrade() -> None:
    op.execute("ALTER TABLE linux_audit_runs DROP CONSTRAINT ck_linux_audit_asset")
    op.execute(
        "ALTER TABLE linux_audit_runs DROP CONSTRAINT ck_linux_audit_distribution"
    )
    op.execute("ALTER TABLE linux_audit_runs ALTER COLUMN asset_key TYPE varchar(64)")
    op.execute(
        f"""
        ALTER TABLE linux_audit_runs ADD CONSTRAINT ck_linux_audit_asset
        CHECK (
            asset_key IN (
                'ubuntu24', 'rocky9', 'self-auto',
                'self-ubuntu22', 'self-ubuntu24', 'self-debian12',
                'self-rocky9', 'self-rhel9', 'self-alma9'
            )
            OR asset_key ~ '{_UUID_V4_PATTERN}'
        )
        """
    )
    op.execute(
        f"""
        ALTER TABLE linux_audit_runs ADD CONSTRAINT ck_linux_audit_distribution
        CHECK (distribution IN ({_DISTRIBUTIONS}, 'AUTO'))
        """
    )
    op.execute(
        "ALTER TABLE linux_managed_assets "
        "DROP CONSTRAINT ck_linux_managed_asset_distribution"
    )
    op.execute(
        f"""
        ALTER TABLE linux_managed_assets
        ADD CONSTRAINT ck_linux_managed_asset_distribution
        CHECK (distribution IS NULL OR distribution IN ({_DISTRIBUTIONS}))
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM linux_audit_runs
                WHERE distribution NOT IN ('UBUNTU_24_04', 'ROCKY_9', 'AUTO')
                   OR asset_key NOT IN (
                        'ubuntu24', 'rocky9', 'self-ubuntu24',
                        'self-rocky9', 'self-auto'
                   )
            ) OR EXISTS (
                SELECT 1 FROM linux_managed_assets
                WHERE distribution IS NOT NULL
                  AND distribution NOT IN ('UBUNTU_24_04', 'ROCKY_9')
            ) THEN
                RAISE EXCEPTION 'Expanded Linux platform records block downgrade';
            END IF;
        END
        $$
        """
    )
    op.execute(
        "ALTER TABLE linux_managed_assets "
        "DROP CONSTRAINT ck_linux_managed_asset_distribution"
    )
    op.execute(
        """
        ALTER TABLE linux_managed_assets
        ADD CONSTRAINT ck_linux_managed_asset_distribution
        CHECK (distribution IS NULL OR distribution IN ('UBUNTU_24_04', 'ROCKY_9'))
        """
    )
    op.execute("ALTER TABLE linux_audit_runs DROP CONSTRAINT ck_linux_audit_asset")
    op.execute(
        "ALTER TABLE linux_audit_runs DROP CONSTRAINT ck_linux_audit_distribution"
    )
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
    op.execute("ALTER TABLE linux_audit_runs ALTER COLUMN asset_key TYPE varchar(32)")

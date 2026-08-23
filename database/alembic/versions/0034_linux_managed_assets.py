"""Add administrator-managed Linux SSH assets and append-only events."""

from collections.abc import Sequence

from alembic import op

revision: str = "0034_linux_managed_assets"
down_revision: str | None = "0033_windows_presentations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE linux_managed_assets (
            asset_id uuid PRIMARY KEY,
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
            alias varchar(80) NOT NULL,
            host inet NOT NULL,
            port integer NOT NULL,
            ssh_username varchar(32) NOT NULL,
            credential_ref uuid NOT NULL UNIQUE,
            public_key text NOT NULL,
            host_key text,
            host_key_fingerprint varchar(64),
            distribution varchar(32),
            platform_version varchar(64),
            architecture varchar(32),
            state varchar(32) NOT NULL,
            created_by uuid NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT fk_linux_managed_asset_scope
                FOREIGN KEY (asset_id, organization_id)
                REFERENCES assets(id, organization_id) ON DELETE RESTRICT,
            CONSTRAINT uq_linux_managed_asset_scope UNIQUE (asset_id, organization_id),
            CONSTRAINT fk_linux_managed_asset_creator_scope
                FOREIGN KEY (created_by, organization_id)
                REFERENCES user_accounts(id, organization_id) ON DELETE RESTRICT,
            CONSTRAINT uq_linux_managed_asset_alias UNIQUE (organization_id, alias),
            CONSTRAINT uq_linux_managed_asset_endpoint UNIQUE (organization_id, host, port),
            CONSTRAINT ck_linux_managed_asset_port CHECK (port BETWEEN 1 AND 65535),
            CONSTRAINT ck_linux_managed_asset_public_key CHECK (
                public_key LIKE 'ssh-ed25519 %'
            ),
            CONSTRAINT ck_linux_managed_asset_host_key CHECK (
                host_key IS NULL OR host_key LIKE 'ssh-ed25519 %'
            ),
            CONSTRAINT ck_linux_managed_asset_distribution CHECK (
                distribution IS NULL OR distribution IN ('UBUNTU_24_04', 'ROCKY_9')
            ),
            CONSTRAINT ck_linux_managed_asset_state CHECK (
                state IN ('KEY_INSTALL_PENDING', 'ACTIVE', 'SUSPENDED')
            ),
            CONSTRAINT ck_linux_managed_asset_active_material CHECK (
                state <> 'ACTIVE' OR (
                    host_key IS NOT NULL
                    AND host_key_fingerprint IS NOT NULL
                    AND distribution IS NOT NULL
                    AND platform_version IS NOT NULL
                    AND architecture IS NOT NULL
                )
            )
        )
        """
    )
    op.execute(
        """
        CREATE INDEX ix_linux_managed_asset_org_state
        ON linux_managed_assets (organization_id, state, alias)
        """
    )
    op.execute(
        """
        CREATE TABLE linux_managed_asset_events (
            id uuid PRIMARY KEY,
            organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
            asset_id uuid NOT NULL,
            actor_user_id uuid NOT NULL,
            event_type varchar(40) NOT NULL,
            detail jsonb NOT NULL,
            created_at timestamptz NOT NULL DEFAULT now(),
            CONSTRAINT fk_linux_managed_asset_event_scope
                FOREIGN KEY (asset_id, organization_id)
                REFERENCES linux_managed_assets(asset_id, organization_id)
                ON DELETE RESTRICT,
            CONSTRAINT fk_linux_managed_asset_event_actor_scope
                FOREIGN KEY (actor_user_id, organization_id)
                REFERENCES user_accounts(id, organization_id) ON DELETE RESTRICT,
            CONSTRAINT ck_linux_managed_asset_event_type CHECK (
                event_type IN ('REGISTERED', 'CONNECTION_VERIFIED', 'SUSPENDED')
            ),
            CONSTRAINT ck_linux_managed_asset_event_detail CHECK (
                jsonb_typeof(detail) = 'object'
            )
        )
        """
    )
    op.execute(
        """
        CREATE INDEX ix_linux_managed_asset_event_org_time
        ON linux_managed_asset_events (organization_id, created_at DESC)
        """
    )
    for table in ("linux_managed_assets", "linux_managed_asset_events"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY linux_managed_assets_org_select
        ON linux_managed_assets FOR SELECT
        USING (
            organization_id = NULLIF(current_setting('secai.organization_id', true), '')::uuid
        )
        """
    )
    op.execute(
        """
        CREATE POLICY linux_managed_assets_admin_insert
        ON linux_managed_assets FOR INSERT
        WITH CHECK (
            organization_id = NULLIF(current_setting('secai.organization_id', true), '')::uuid
            AND NULLIF(current_setting('secai.is_administrator', true), '')::boolean
        )
        """
    )
    op.execute(
        """
        CREATE POLICY linux_managed_assets_admin_update
        ON linux_managed_assets FOR UPDATE
        USING (
            organization_id = NULLIF(current_setting('secai.organization_id', true), '')::uuid
            AND NULLIF(current_setting('secai.is_administrator', true), '')::boolean
        )
        WITH CHECK (
            organization_id = NULLIF(current_setting('secai.organization_id', true), '')::uuid
            AND NULLIF(current_setting('secai.is_administrator', true), '')::boolean
        )
        """
    )
    op.execute(
        """
        CREATE POLICY linux_managed_asset_events_org_select
        ON linux_managed_asset_events FOR SELECT
        USING (
            organization_id = NULLIF(current_setting('secai.organization_id', true), '')::uuid
        )
        """
    )
    op.execute(
        """
        CREATE POLICY linux_managed_asset_events_admin_insert
        ON linux_managed_asset_events FOR INSERT
        WITH CHECK (
            organization_id = NULLIF(current_setting('secai.organization_id', true), '')::uuid
            AND NULLIF(current_setting('secai.is_administrator', true), '')::boolean
        )
        """
    )
    op.execute(
        """
        CREATE FUNCTION secai_reject_linux_managed_asset_event_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'linux_managed_asset_events is append-only; % is forbidden', TG_OP;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_linux_managed_asset_event_reject_row_mutation
        BEFORE UPDATE OR DELETE ON linux_managed_asset_events
        FOR EACH ROW EXECUTE FUNCTION secai_reject_linux_managed_asset_event_mutation()
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_linux_managed_asset_event_reject_truncate
        BEFORE TRUNCATE ON linux_managed_asset_events
        FOR EACH STATEMENT EXECUTE FUNCTION secai_reject_linux_managed_asset_event_mutation()
        """
    )
    op.execute(
        "GRANT SELECT, INSERT, UPDATE ON linux_managed_assets TO secai_runtime"
    )
    op.execute(
        "GRANT SELECT, INSERT ON linux_managed_asset_events TO secai_runtime"
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER trg_linux_managed_asset_event_reject_truncate "
        "ON linux_managed_asset_events"
    )
    op.execute(
        "DROP TRIGGER trg_linux_managed_asset_event_reject_row_mutation "
        "ON linux_managed_asset_events"
    )
    op.execute("DROP FUNCTION secai_reject_linux_managed_asset_event_mutation()")
    op.execute("DROP TABLE linux_managed_asset_events")
    op.execute(
        "CREATE TEMP TABLE secai_removed_linux_assets "
        "AS SELECT asset_id FROM linux_managed_assets"
    )
    op.execute("DROP TABLE linux_managed_assets")
    op.execute("DELETE FROM assets WHERE id IN (SELECT asset_id FROM secai_removed_linux_assets)")

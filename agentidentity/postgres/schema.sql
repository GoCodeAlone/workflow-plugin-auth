-- Explicit, unapplied host prerequisite. Run in one caller-owned transaction
-- with a reviewed schema search_path. Constructors never execute this file.
-- These rows contain service grants/public keys, not human credentials.
CREATE TABLE agent_grants (
    id TEXT PRIMARY KEY CHECK (id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    subject TEXT NOT NULL CHECK (subject ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    assertion_issuer TEXT NOT NULL CHECK (length(assertion_issuer) BETWEEN 1 AND 2048),
    key_id TEXT NOT NULL CHECK (key_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    public_key_der BYTEA NOT NULL CHECK (octet_length(public_key_der) BETWEEN 1 AND 512),
    version BIGINT NOT NULL CHECK (version > 0),
    tenant_id BIGINT NOT NULL CHECK (tenant_id > 0),
    approved_by TEXT NOT NULL CHECK (approved_by ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    created_at TIMESTAMPTZ NOT NULL CHECK (isfinite(created_at)),
    expires_at TIMESTAMPTZ NOT NULL CHECK (isfinite(expires_at)),
    revoked BOOLEAN NOT NULL DEFAULT false,
    api_audience TEXT NOT NULL CHECK (length(api_audience) BETWEEN 1 AND 2048),
    scopes JSONB NOT NULL CHECK (jsonb_typeof(scopes) = 'array' AND jsonb_array_length(scopes) BETWEEN 1 AND 4),
    update_page_ids JSONB NOT NULL CHECK (jsonb_typeof(update_page_ids) = 'array' AND jsonb_array_length(update_page_ids) <= 128),
    preview JSONB CHECK (preview IS NULL OR jsonb_typeof(preview) = 'object'),
    revoked_by TEXT CHECK (revoked_by ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    revoked_at TIMESTAMPTZ CHECK (isfinite(revoked_at)),
    CHECK (expires_at > created_at AND expires_at - created_at <= interval '720 hours'),
    CHECK ((NOT revoked AND revoked_by IS NULL AND revoked_at IS NULL) OR
           (revoked AND version > 1 AND revoked_by IS NOT NULL AND revoked_at IS NOT NULL AND revoked_at >= created_at))
);
CREATE INDEX agent_grants_tenant_id ON agent_grants (tenant_id, id);
CREATE TABLE agent_assertion_uses (
    jti_hash TEXT PRIMARY KEY CHECK (jti_hash ~ '^[0-9a-f]{64}$'),
    grant_id TEXT NOT NULL REFERENCES agent_grants(id),
    grant_version BIGINT NOT NULL CHECK (grant_version > 0),
    consumed_at TIMESTAMPTZ NOT NULL CHECK (isfinite(consumed_at)),
    expires_at TIMESTAMPTZ NOT NULL CHECK (isfinite(expires_at)),
    CHECK (expires_at > consumed_at AND expires_at - consumed_at <= interval '1 minute')
);
-- The primary key is GLOBAL in this adapter's shared schema. Grant/version are
-- metadata only; partitioning uniqueness by either would allow replay.
CREATE TABLE agent_token_revocations (
    jti_hash TEXT PRIMARY KEY CHECK (jti_hash ~ '^[0-9a-f]{64}$'),
    revoked_by TEXT NOT NULL CHECK (revoked_by ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    revoked_at TIMESTAMPTZ NOT NULL CHECK (isfinite(revoked_at)),
    expires_at TIMESTAMPTZ NOT NULL CHECK (isfinite(expires_at)),
    CHECK (expires_at > revoked_at AND expires_at - revoked_at <= interval '15 minutes')
);
-- Immutable audit rows form an outbox. Delivery cursors belong to the host;
-- successful delivery never deletes or edits these retained records.
CREATE TABLE agent_management_audit (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event JSONB NOT NULL CHECK (jsonb_typeof(event) = 'object'),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION agent_refuse_retained_rewrite() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'retained service identity record is append-only';
END;
$$;
CREATE TRIGGER agent_audit_append_only BEFORE UPDATE OR DELETE ON agent_management_audit
    FOR EACH ROW EXECUTE FUNCTION agent_refuse_retained_rewrite();
CREATE TRIGGER agent_audit_no_truncate BEFORE TRUNCATE ON agent_management_audit
    FOR EACH STATEMENT EXECUTE FUNCTION agent_refuse_retained_rewrite();
CREATE TRIGGER agent_assertion_append_only BEFORE UPDATE OR DELETE ON agent_assertion_uses
    FOR EACH ROW EXECUTE FUNCTION agent_refuse_retained_rewrite();
CREATE TRIGGER agent_assertion_no_truncate BEFORE TRUNCATE ON agent_assertion_uses
    FOR EACH STATEMENT EXECUTE FUNCTION agent_refuse_retained_rewrite();
CREATE TRIGGER agent_revocation_append_only BEFORE UPDATE OR DELETE ON agent_token_revocations
    FOR EACH ROW EXECUTE FUNCTION agent_refuse_retained_rewrite();
CREATE TRIGGER agent_revocation_no_truncate BEFORE TRUNCATE ON agent_token_revocations
    FOR EACH STATEMENT EXECUTE FUNCTION agent_refuse_retained_rewrite();

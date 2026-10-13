CREATE TABLE IF NOT EXISTS audit_events (
    sequence BIGINT PRIMARY KEY,
    previous TEXT NOT NULL,
    hash TEXT NOT NULL UNIQUE,
    event TEXT NOT NULL
);

-- Prevent accidental UPDATE/DELETE even for this development table owner.
-- A database administrator can still disable triggers; anchor hashes externally.
CREATE FUNCTION prevent_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'audit events are append-only'; END;
$$;
CREATE TRIGGER audit_immutable BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION prevent_audit_mutation();

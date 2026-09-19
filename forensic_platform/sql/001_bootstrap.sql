-- Forensic platform bootstrap: schema, least-privilege role, evidence/audit tables.
-- Idempotent: safe to re-run.

CREATE SCHEMA IF NOT EXISTS _forensic;

-- The forensic_app role itself is created separately by scripts/bootstrap.py
-- (via a parameterized psycopg2 statement) so its password never has to be
-- templated into this file. This script assumes the role already exists.

CREATE TABLE IF NOT EXISTS _forensic.datasets (
    dataset_id      BIGSERIAL PRIMARY KEY,
    source_schema   TEXT NOT NULL,
    source_table    TEXT NOT NULL,
    row_count       BIGINT NOT NULL,
    column_hash     TEXT NOT NULL,
    table_hash      TEXT,
    imported_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    imported_by     TEXT NOT NULL,
    notes           TEXT
);

CREATE TABLE IF NOT EXISTS _forensic.audit_log (
    id              BIGSERIAL PRIMARY KEY,
    ts              TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor           TEXT NOT NULL,
    operation       TEXT NOT NULL,
    dataset_id      BIGINT REFERENCES _forensic.datasets(dataset_id),
    script_ref      TEXT,
    params_json     JSONB,
    row_counts      JSONB,
    status          TEXT NOT NULL,
    error_text      TEXT
);

CREATE TABLE IF NOT EXISTS _forensic.test_runs (
    run_id              BIGSERIAL PRIMARY KEY,
    test_name           TEXT NOT NULL,
    test_version        TEXT NOT NULL,
    dataset_id          BIGINT NOT NULL REFERENCES _forensic.datasets(dataset_id),
    fields_used         TEXT[] NOT NULL,
    params_json         JSONB NOT NULL,
    executed_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    records_examined    BIGINT NOT NULL,
    result_count        BIGINT NOT NULL,
    query_text          TEXT NOT NULL,
    limitations         TEXT,
    validation_status   TEXT NOT NULL DEFAULT 'unvalidated',
    status              TEXT NOT NULL,
    error_text          TEXT
);

CREATE TABLE IF NOT EXISTS _forensic.findings (
    finding_id      BIGSERIAL PRIMARY KEY,
    run_id          BIGINT NOT NULL REFERENCES _forensic.test_runs(run_id),
    classification  TEXT NOT NULL CHECK (classification IN
                        ('FACT','OBSERVATION','ANOMALY','RISK INDICATOR','INVESTIGATION LEAD','CONCLUSION')),
    description     TEXT NOT NULL,
    reviewer_status TEXT NOT NULL DEFAULT 'pending',
    reviewer_notes  TEXT,
    reviewed_by     TEXT,
    reviewed_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS _forensic.evidence_links (
    id                  BIGSERIAL PRIMARY KEY,
    finding_id          BIGINT NOT NULL REFERENCES _forensic.findings(finding_id),
    source_schema       TEXT NOT NULL,
    source_table        TEXT NOT NULL,
    source_pk_column    TEXT NOT NULL,
    source_pk_value     TEXT NOT NULL
);

-- Append-only enforcement: no one, including the table owner, may UPDATE/DELETE audit_log,
-- test_runs, datasets, or evidence_links. findings.reviewer_* fields are the one legitimate
-- mutation path (human review workflow, Phase 5) and are left updatable.
CREATE OR REPLACE FUNCTION _forensic.reject_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION '% is append-only: % is not permitted', TG_TABLE_NAME, TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_log_immutable ON _forensic.audit_log;
CREATE TRIGGER audit_log_immutable
    BEFORE UPDATE OR DELETE ON _forensic.audit_log
    FOR EACH ROW EXECUTE FUNCTION _forensic.reject_mutation();

DROP TRIGGER IF EXISTS test_runs_immutable ON _forensic.test_runs;
CREATE TRIGGER test_runs_immutable
    BEFORE UPDATE OR DELETE ON _forensic.test_runs
    FOR EACH ROW EXECUTE FUNCTION _forensic.reject_mutation();

DROP TRIGGER IF EXISTS datasets_immutable ON _forensic.datasets;
CREATE TRIGGER datasets_immutable
    BEFORE UPDATE OR DELETE ON _forensic.datasets
    FOR EACH ROW EXECUTE FUNCTION _forensic.reject_mutation();

DROP TRIGGER IF EXISTS evidence_links_immutable ON _forensic.evidence_links;
CREATE TRIGGER evidence_links_immutable
    BEFORE UPDATE OR DELETE ON _forensic.evidence_links
    FOR EACH ROW EXECUTE FUNCTION _forensic.reject_mutation();

-- Least-privilege grants: forensic_app reads any source schema, but can only
-- append to the forensic evidence tables (plus update findings.reviewer_* later).
GRANT USAGE ON SCHEMA _forensic TO forensic_app;
GRANT SELECT, INSERT ON _forensic.datasets, _forensic.audit_log, _forensic.test_runs, _forensic.evidence_links TO forensic_app;
GRANT SELECT, INSERT, UPDATE ON _forensic.findings TO forensic_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA _forensic TO forensic_app;

GRANT USAGE ON SCHEMA public TO forensic_app;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO forensic_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO forensic_app;

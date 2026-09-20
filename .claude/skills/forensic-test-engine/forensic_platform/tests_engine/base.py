"""
Shared plumbing for every forensic subtest: registry lookup, field validation,
dataset registration, audit logging, and writing test_runs/findings rows.
Individual test modules (e.g. benford.py) contain only the deterministic
calculation itself — they never touch _forensic tables directly.
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml

REGISTRY_PATH = Path(__file__).resolve().parents[1] / "registry" / "test_registry.yaml"


def load_registry() -> dict:
    return yaml.safe_load(REGISTRY_PATH.read_text(encoding="utf-8"))


def get_test_entry(test_name: str) -> dict:
    registry = load_registry()
    if test_name not in registry["tests"]:
        raise ValueError(f"Unknown subtest '{test_name}'. Known subtests: {sorted(registry['tests'])}")
    return registry["tests"][test_name]


def column_info(cur, schema: str, table: str, column: str):
    cur.execute(
        "SELECT data_type FROM information_schema.columns "
        "WHERE table_schema=%s AND table_name=%s AND column_name=%s",
        (schema, table, column),
    )
    row = cur.fetchone()
    return row[0] if row else None


def get_or_register_dataset(cur, schema: str, table: str, actor: str) -> int:
    """Resolve the dataset version a run should cite.

    Reuses the registered version only if the table still has the row count that
    was recorded at acquisition. If it does not, the snapshot has changed since
    it was fingerprinted, so a NEW version is registered rather than silently
    attributing new results to the old one.
    """
    cur.execute(
        "SELECT dataset_id, row_count FROM _forensic.datasets "
        "WHERE source_schema=%s AND source_table=%s ORDER BY imported_at DESC LIMIT 1",
        (schema, table),
    )
    row = cur.fetchone()
    if row:
        dataset_id, recorded_rows = row
        cur.execute(f'SELECT count(*) FROM "{schema}"."{table}"')
        if cur.fetchone()[0] == recorded_rows:
            return dataset_id
        # fall through: source no longer matches its registered version

    from ..core.hashing import column_signature

    cur.execute(f"SELECT count(*) FROM {schema}.{table}")
    row_count = cur.fetchone()[0]
    cur.execute(
        "SELECT column_name, data_type FROM information_schema.columns WHERE table_schema=%s AND table_name=%s",
        (schema, table),
    )
    col_hash = column_signature(cur.fetchall())
    cur.execute(
        "INSERT INTO _forensic.datasets (source_schema, source_table, row_count, column_hash, imported_by) "
        "VALUES (%s,%s,%s,%s,%s) RETURNING dataset_id",
        (schema, table, row_count, col_hash, actor),
    )
    return cur.fetchone()[0]


def log_audit(cur, actor, operation, dataset_id, script_ref, params, status, error_text=None):
    cur.execute(
        "INSERT INTO _forensic.audit_log (actor, operation, dataset_id, script_ref, params_json, status, error_text) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s)",
        (actor, operation, dataset_id, script_ref, json.dumps(params), status, error_text),
    )


def record_test_run(
    cur,
    test_name: str,
    test_version: str,
    dataset_id: int,
    fields_used: list[str],
    params: dict,
    records_examined: int,
    result_count: int,
    query_text: str,
    limitations: str,
    status: str,
    error_text: str | None = None,
) -> int:
    cur.execute(
        "INSERT INTO _forensic.test_runs "
        "(test_name, test_version, dataset_id, fields_used, params_json, records_examined, "
        " result_count, query_text, limitations, validation_status, status, error_text) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING run_id",
        (
            test_name, test_version, dataset_id, fields_used, json.dumps(params),
            records_examined, result_count, query_text, limitations, "unvalidated",
            status, error_text,
        ),
    )
    return cur.fetchone()[0]


def record_finding(cur, run_id: int, classification: str, description: str) -> int:
    cur.execute(
        "INSERT INTO _forensic.findings (run_id, classification, description) "
        "VALUES (%s,%s,%s) RETURNING finding_id",
        (run_id, classification, description),
    )
    return cur.fetchone()[0]


def record_evidence_links(
    cur,
    finding_id: int,
    source_schema: str,
    source_table: str,
    identity,
    rows: list,
) -> int:
    """Link a finding to the specific source records that produced it.

    Without this a finding is an unsupported assertion: nobody can get from the
    conclusion back to the rows. `identity` is a core.identity.RowIdentity and each
    entry of `rows` is a tuple of that identity's column values (one value for a
    single-column key). Uses execute_values so large evidence sets are written in one
    round trip rather than row by row.
    """
    if not rows:
        return 0
    from psycopg2.extras import execute_values

    execute_values(
        cur,
        "INSERT INTO _forensic.evidence_links "
        "(finding_id, source_schema, source_table, source_pk_column, source_pk_value) VALUES %s",
        [(finding_id, source_schema, source_table, *identity.encode(row)) for row in rows],
        page_size=5000,
    )
    return len(rows)

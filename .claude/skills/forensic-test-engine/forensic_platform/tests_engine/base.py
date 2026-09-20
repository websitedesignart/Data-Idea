"""
Shared plumbing for every forensic subtest: registry lookup, field validation,
dataset registration, audit logging, and writing test_runs/findings rows.
Individual test modules (e.g. benford.py) contain only the deterministic
calculation itself — they never touch _forensic tables directly.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import psycopg2
import psycopg2.errors
import yaml
from psycopg2 import sql

from ..core.sqlsafe import ident

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


FINGERPRINT_TAG = "s56"


@dataclass(frozen=True)
class DatasetRef:
    """Which version of a dataset a run cites, and how strongly that version is established."""
    dataset_id: int
    basis: str                 # "content": fingerprinted | "row_count": fingerprint unavailable
    fingerprint: str | None
    row_count: int
    registered_now: bool


def content_fingerprint(cur, schema: str, table: str) -> str:
    """Order-independent fingerprint of a table's CONTENT: 's56:<rows>:<sum of row hashes>'.

    Each row's text form is hashed with SHA-256, its first 56 bits are kept, and the hashes are
    summed, so the result does not depend on row order or physical layout. It is a change
    detector (any edit, insert or delete alters it), not tamper-proofing: an adversary with
    write access could craft a collision, and detecting that is the audit log's job. Text
    rendering is pinned by the session settings in core.db, so the same data gives the same value.
    """
    cur.execute(sql.SQL(
        "SELECT count(*), coalesce(sum((('x' || encode(substring(sha256(convert_to(t::text, 'UTF8')) "
        "from 1 for 7), 'hex'))::bit(56)::bigint)::numeric), 0) FROM {} AS t"
    ).format(ident(schema, table)))
    n, total = cur.fetchone()
    return f"{FINGERPRINT_TAG}:{n}:{total}"


def resolve_dataset_version(cur, schema: str, table: str, actor: str) -> DatasetRef:
    """Resolve (or register) the dataset version a run should cite.

    A version is the table's CONTENT plus its column layout. Unchanged content reuses the
    registered version; any change registers a new one, so a finding can never be attributed
    to data it was not computed on. Returning to earlier content maps back to that earlier
    version. Hashes recorded by other algorithms (e.g. Excel ingestion's) are never trusted for
    reuse, since they cannot be compared.

    If the fingerprint cannot be computed within the statement timeout, this falls back to the
    weaker row-count basis, and records that it did (table_hash NULL, a note). It never claims
    a content-verified version it did not verify.
    """
    from ..core.hashing import column_signature

    cur.execute("SAVEPOINT dataset_fp")
    try:
        fingerprint = content_fingerprint(cur, schema, table)
        cur.execute("RELEASE SAVEPOINT dataset_fp")
    except psycopg2.errors.QueryCanceled:
        cur.execute("ROLLBACK TO SAVEPOINT dataset_fp")
        cur.execute("RELEASE SAVEPOINT dataset_fp")
        fingerprint = None

    if fingerprint is not None:
        row_count = int(fingerprint.split(":")[1])
    else:
        cur.execute(sql.SQL("SELECT count(*) FROM {}").format(ident(schema, table)))
        row_count = cur.fetchone()[0]

    cur.execute(
        "SELECT column_name, data_type FROM information_schema.columns WHERE table_schema=%s AND table_name=%s",
        (schema, table),
    )
    col_hash = column_signature(cur.fetchall())

    if fingerprint is not None:
        cur.execute(
            "SELECT dataset_id FROM _forensic.datasets WHERE source_schema=%s AND source_table=%s "
            "AND table_hash=%s AND column_hash=%s ORDER BY imported_at DESC LIMIT 1",
            (schema, table, fingerprint, col_hash),
        )
        note = "basis=content"
    else:
        # Only reuse an earlier row-count-basis version; never let a weaker check claim a
        # content-verified one.
        cur.execute(
            "SELECT dataset_id FROM _forensic.datasets WHERE source_schema=%s AND source_table=%s "
            "AND table_hash IS NULL AND row_count=%s AND column_hash=%s ORDER BY imported_at DESC LIMIT 1",
            (schema, table, row_count, col_hash),
        )
        note = "basis=row_count: content fingerprint exceeded the statement timeout"
    found = cur.fetchone()
    if found:
        return DatasetRef(found[0], "content" if fingerprint else "row_count", fingerprint, row_count, False)

    cur.execute(
        "INSERT INTO _forensic.datasets (source_schema, source_table, row_count, column_hash, table_hash, imported_by, notes) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING dataset_id",
        (schema, table, row_count, col_hash, fingerprint, actor, note),
    )
    return DatasetRef(cur.fetchone()[0], "content" if fingerprint else "row_count", fingerprint, row_count, True)


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

"""
Verifies the Phase 1 bootstrap actually behaves as designed, connecting as
forensic_app (not the superuser) to prove the least-privilege grants and the
append-only trigger work from that role's own perspective.
"""
import json
from pathlib import Path

import psycopg2

PROJECT_ROOT = Path(__file__).resolve().parents[2]
mcp_config = json.loads((PROJECT_ROOT / ".mcp.json").read_text(encoding="utf-8"))
dsn = mcp_config["mcpServers"]["local-postgres-cluster-demo-forensic"]["args"][-1]

conn = psycopg2.connect(dsn)
conn.autocommit = True
cur = conn.cursor()

cur.execute(
    "INSERT INTO _forensic.datasets (source_schema, source_table, row_count, column_hash, imported_by) "
    "VALUES (%s, %s, %s, %s, %s) RETURNING dataset_id",
    ("public", "verify_test", 0, "deadbeef", "verify_bootstrap.py"),
)
dataset_id = cur.fetchone()[0]
print(f"INSERT into datasets OK, dataset_id={dataset_id}")

cur.execute(
    "INSERT INTO _forensic.audit_log (actor, operation, dataset_id, status) VALUES (%s, %s, %s, %s) RETURNING id",
    ("verify_bootstrap.py", "test_insert", dataset_id, "success"),
)
audit_id = cur.fetchone()[0]
print(f"INSERT into audit_log OK, id={audit_id}")

try:
    cur.execute("UPDATE _forensic.audit_log SET status = 'tampered' WHERE id = %s", (audit_id,))
    print("FAIL: UPDATE on audit_log was allowed (should have been rejected)")
except psycopg2.Error as e:
    print(f"OK: UPDATE on audit_log correctly rejected -> {e.pgerror.strip()}")
    conn.rollback()

try:
    cur.execute("DELETE FROM _forensic.audit_log WHERE id = %s", (audit_id,))
    print("FAIL: DELETE on audit_log was allowed (should have been rejected)")
except psycopg2.Error as e:
    print(f"OK: DELETE on audit_log correctly rejected -> {e.pgerror.strip()}")
    conn.rollback()

try:
    cur.execute("CREATE TABLE public.forensic_app_should_not_create (x int)")
    print("FAIL: forensic_app was able to CREATE TABLE in public (should have been rejected)")
except psycopg2.Error as e:
    print(f"OK: CREATE TABLE in public correctly rejected -> {e.pgerror.strip()}")
    conn.rollback()

cur.close()
conn.close()
print("verification complete")

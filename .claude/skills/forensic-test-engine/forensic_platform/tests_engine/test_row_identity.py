"""
Tests for row identity (how evidence points at exact source rows).

    python forensic_platform/tests_engine/test_row_identity.py                  # unit tests only
    python forensic_platform/tests_engine/test_row_identity.py --integration    # + database tests

--integration creates its own uniquely named scratch database (forensic_test_<hex>),
runs the real run_test.py entry point against it, and always drops it afterwards. It
connects only to the maintenance database (to create/drop that scratch database) and to
the scratch database itself, never to any other database. It needs the project's
.mcp.json (found by walking up from the working directory, or $FORENSIC_MCP_CONFIG) with
the admin `local-postgres-cluster` entry and a `*-forensic` entry.
"""
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE.parent))

from forensic_platform.core.identity import RowIdentity, decode  # noqa: E402

failures = 0


def check(label, ok, detail=""):
    global failures
    if not ok:
        failures += 1
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}{(' - ' + str(detail)) if detail else ''}")


# --------------------------------------------------------------------------- unit
def unit_tests():
    print("=== unit: encoding ===")
    single = RowIdentity(("_row_no",), "engine_row_no")
    check("single key keeps the pre-existing stored format", single.encode((9836,)) == ("_row_no", "9836"))
    check("single key round-trips", decode(*single.encode((9836,))) == {"_row_no": "9836"})

    comp = RowIdentity(("a", "b"), "primary_key")
    col, val = comp.encode((7, "x"))
    check("composite key stored as JSON arrays of strings", (col, val) == ('["a", "b"]', '["7", "x"]'), (col, val))
    check("composite key round-trips", decode(col, val) == {"a": "7", "b": "x"})

    odd = ("we\"ird, col", "ünï")
    oddid = RowIdentity(odd, "primary_key")
    check("quotes, commas and unicode survive a round trip",
          decode(*oddid.encode(('va"l,ue', "日本"))) == {odd[0]: 'va"l,ue', odd[1]: "日本"})

    check("plain column name that is not JSON decodes as a single column",
          decode("row_id", "5") == {"row_id": "5"})
    check("malformed composite falls back instead of raising", decode("[oops", "1") == {"[oops": "1"})
    try:
        comp.encode((1,))
        check("arity mismatch is rejected", False)
    except ValueError:
        check("arity mismatch is rejected", True)


# -------------------------------------------------------------------- integration
def integration_tests():
    import psycopg2
    from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
    from forensic_platform.core.config import find_mcp_config, load_mcp_config, superuser_dsn

    try:
        cfg_path = find_mcp_config()
        servers = load_mcp_config()["mcpServers"]
        assert "local-postgres-cluster" in servers
        assert any(n.endswith("-forensic") for n in servers)
    except Exception as exc:
        print(f"  [SKIP] integration tests need .mcp.json with admin and *-forensic entries: {exc}")
        return

    scratch = f"forensic_test_{uuid.uuid4().hex[:8]}"
    assert scratch.startswith("forensic_test_")
    print(f"\n=== integration: scratch database {scratch} ===")

    admin = psycopg2.connect(superuser_dsn("postgres"))
    admin.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    conn = None
    try:
        with admin.cursor() as c:
            c.execute(f'CREATE DATABASE "{scratch}"')
        conn = psycopg2.connect(superuser_dsn(scratch))
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute((ENGINE / "sql" / "001_bootstrap.sql").read_text(encoding="utf-8"))
        cur.execute("""
            CREATE TABLE t_pk (id serial PRIMARY KEY, ref text, name text);
            INSERT INTO t_pk (ref, name) VALUES
              ('A1','ANUPAM KUMAR BHARGAVA'),('A1','DR ANUPAM KUMAR BHARGAVA'),
              ('B2','RAJESH KUMAR SINGH'),('B2','SUNITA DEVI'),
              ('C3','ONLY ONE'),('D4','X'),('D4','X');
            CREATE TABLE t_composite (a int, b text, ref text, PRIMARY KEY (a, b));
            INSERT INTO t_composite VALUES (1,'x','R1'),(1,'y','R1'),(2,'x','R2'),(3,'z','R3'),(3,'w','R3');
            CREATE TABLE t_rowno (ref text, _row_no bigint);
            INSERT INTO t_rowno VALUES ('A',1),('A',2),('B',3);
            CREATE TABLE t_none (ref text);
            INSERT INTO t_none VALUES ('A'),('A'),('B');
            CREATE TABLE t_rowno_dup (ref text, _row_no bigint);
            INSERT INTO t_rowno_dup VALUES ('A',1),('A',1),('B',2);
            CREATE TABLE t_weird ("we""ird id" int PRIMARY KEY, ref text);
            INSERT INTO t_weird VALUES (1,'Q'),(2,'Q'),(3,'R');
            CREATE TABLE t_num (id serial PRIMARY KEY, amount numeric);
            INSERT INTO t_num (amount) SELECT round((10 ^ (((i * 7) % 400) / 100.0))::numeric, 2) FROM generate_series(1, 400) i;
            GRANT SELECT ON ALL TABLES IN SCHEMA public TO forensic_app;
        """)

        env = {**os.environ, "FORENSIC_MCP_CONFIG": str(cfg_path), "FORENSIC_MASK_SALT": "t" * 40}

        def run(*args):
            p = subprocess.run([sys.executable, str(ENGINE / "scripts" / "run_test.py"), "--database", scratch,
                                "--schema", "public", *args], capture_output=True, text=True, env=env)
            try:
                return json.loads(p.stdout)
            except ValueError:
                return {"status": "NOT-JSON", "stdout": p.stdout[-200:], "stderr": p.stderr[-300:]}

        def links(finding_id):
            cur.execute("SELECT source_table, source_pk_column, source_pk_value FROM _forensic.evidence_links "
                        "WHERE finding_id = %s ORDER BY id", (finding_id,))
            return cur.fetchall()

        print("=== declared primary key ===")
        r = run("--subtest", "duplicate-analysis", "--table", "t_pk", "--column", "ref")
        check("duplicate-analysis succeeds on a native-PK table", r.get("status") == "success", r.get("reason") or r.get("stderr"))
        check("3 keys / 6 rows flagged", (r.get("flagged_keys"), r.get("flagged_rows")) == (3, 6), (r.get("flagged_keys"), r.get("flagged_rows")))
        check("6 evidence links, identity is the declared PK",
              r.get("evidence_links_written") == 6 and r.get("evidence_identity") == {"columns": ["id"], "kind": "primary_key"},
              r.get("evidence_identity"))
        rows = links(r["finding_ids"][0]) if r.get("finding_ids") else []
        ids = [int(v) for _, col, v in rows if col == "id"]
        cur.execute("SELECT ref FROM t_pk WHERE id = ANY(%s)", (ids,))
        check("every link resolves to a row of a flagged key", len(ids) == 6 and {x[0] for x in cur.fetchall()} == {"A1", "B2", "D4"})

        r = run("--subtest", "fuzzy-entity-match", "--table", "t_pk", "--column", "ref", "--distinct-of", "name")
        check("fuzzy: A1 collapses (one person), B2 stays flagged", (r.get("status"), r.get("flagged_keys")) == ("success", 1),
              (r.get("status"), r.get("flagged_keys"), r.get("reason")))
        check("fuzzy evidence keyed by PK", r.get("evidence_identity") == {"columns": ["id"], "kind": "primary_key"} and r.get("evidence_links_written") == 2)

        r = run("--subtest", "cross-dataset-match", "--table", "t_pk", "--column", "ref",
                "--right-table", "t_composite", "--right-column", "ref")
        check("cross-dataset-match succeeds on native tables (previously failed unconditionally)",
              r.get("status") == "success" and (r.get("only_left"), r.get("only_right")) == (4, 3), (r.get("status"), r.get("reason")))
        check("cross evidence: all 7 left rows linked by PK", r.get("evidence_links_written") == 7)

        print("\n=== composite primary key ===")
        r = run("--subtest", "duplicate-analysis", "--table", "t_composite", "--column", "ref")
        check("succeeds on a composite-PK table", r.get("status") == "success", r.get("reason") or r.get("stderr"))
        check("identity reports both columns", r.get("evidence_identity") == {"columns": ["a", "b"], "kind": "primary_key"}, r.get("evidence_identity"))
        rows = links(r["finding_ids"][0]) if r.get("finding_ids") else []
        resolved = []
        for _, col, val in rows:
            d = decode(col, val)
            cur.execute("SELECT ref FROM t_composite WHERE a::text = %s AND b::text = %s", (d["a"], d["b"]))
            resolved.append(cur.fetchone()[0])
        check("4 composite links, each resolves to exactly the rows of the flagged keys",
              len(rows) == 4 and sorted(resolved) == ["R1", "R1", "R3", "R3"], sorted(resolved))

        print("\n=== identifier with a quote and space in it ===")
        r = run("--subtest", "duplicate-analysis", "--table", "t_weird", "--column", "ref")
        check("PK column named  we\"ird id  is quoted correctly", r.get("status") == "success"
              and r.get("evidence_identity", {}).get("columns") == ['we"ird id'], r.get("reason") or r.get("stderr"))

        print("\n=== engine ingestion convention (_row_no), backward compatible ===")
        r = run("--subtest", "duplicate-analysis", "--table", "t_rowno", "--column", "ref")
        check("_row_no table still works", r.get("status") == "success" and r.get("evidence_identity") == {"columns": ["_row_no"], "kind": "engine_row_no"},
              r.get("reason") or r.get("evidence_identity"))
        rows = links(r["finding_ids"][0]) if r.get("finding_ids") else []
        check("stored exactly as before: ('_row_no', '1')", [(c, v) for _, c, v in rows] == [("_row_no", "1"), ("_row_no", "2")], rows)

        print("\n=== refusals (nothing may be guessed, nothing may be written) ===")
        cur.execute("SELECT count(*) FROM _forensic.datasets")
        datasets_before = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM _forensic.test_runs")
        runs_before = cur.fetchone()[0]
        r1 = run("--subtest", "duplicate-analysis", "--table", "t_none", "--column", "ref")
        check("no PK and no _row_no -> refused", r1.get("status") == "refused" and "no primary key" in r1.get("reason", ""), r1.get("reason"))
        r2 = run("--subtest", "duplicate-analysis", "--table", "t_rowno_dup", "--column", "ref")
        check("non-unique _row_no -> refused", r2.get("status") == "refused" and "not a unique identity" in r2.get("reason", ""), r2.get("reason"))
        r3 = run("--subtest", "cross-dataset-match", "--table", "t_none", "--column", "ref",
                 "--right-table", "t_pk", "--right-column", "ref")
        check("cross-dataset-match refuses on a left table with no identity", r3.get("status") == "refused")
        r4 = run("--subtest", "fuzzy-entity-match", "--table", "does_not_exist", "--column", "ref", "--distinct-of", "name")
        check("missing table -> refused with a clear reason", r4.get("status") == "refused" and "does not exist" in r4.get("reason", ""), r4.get("reason"))
        cur.execute("SELECT count(*) FROM _forensic.datasets")
        d_after = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM _forensic.test_runs")
        r_after = cur.fetchone()[0]
        check("refusals wrote no dataset row and no test run", (d_after, r_after) == (datasets_before, runs_before), ((datasets_before, d_after), (runs_before, r_after)))
        cur.execute("SELECT count(*) FROM _forensic.audit_log WHERE status = 'refused' AND dataset_id IS NULL")
        check("each refusal is still audit-logged", cur.fetchone()[0] == 4)

        print("\n=== regression: tests without evidence are unaffected ===")
        r = run("--subtest", "benford", "--table", "t_num", "--column", "amount")
        check("benford still runs", r.get("status") == "success" and r.get("records_examined") == 400, r.get("reason") or r.get("records_examined"))
    finally:
        if conn is not None:
            conn.close()
        with admin.cursor() as c:
            c.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = %s", (scratch,))
            c.execute(f'DROP DATABASE IF EXISTS "{scratch}"')
        admin.close()
        print(f"  scratch database {scratch} dropped")


if __name__ == "__main__":
    unit_tests()
    if "--integration" in sys.argv:
        integration_tests()
    print("\n" + ("ALL TESTS PASS" if failures == 0 else f"{failures} TEST(S) FAILED"))
    sys.exit(1 if failures else 0)

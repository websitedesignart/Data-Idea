"""
Tests for dataset version identity: findings must cite the version of the data they were
computed on, and a version must change when the data does.

    python forensic_platform/tests_engine/test_dataset_version.py                  # unit tests only
    python forensic_platform/tests_engine/test_dataset_version.py --integration    # + database tests

--integration creates its own uniquely named scratch database (forensic_test_<hex>), runs the
real run_test.py entry point against it, and always drops it afterwards. It connects only to
the maintenance database (to create/drop that scratch database) and to the scratch database.
It needs the project's .mcp.json (found by walking up from the working directory, or
$FORENSIC_MCP_CONFIG) with the admin `local-postgres-cluster` entry and a `*-forensic` entry.

Before this, a version was decided by row count alone: a table whose VALUES changed but whose
row count did not was silently treated as the same dataset.
"""
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE.parent))

failures = 0


def check(label, ok, detail=""):
    global failures
    if not ok:
        failures += 1
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}{(' - ' + str(detail)) if detail else ''}")


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
    print(f"=== integration: scratch database {scratch} ===")

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
        cur.execute('''
            CREATE TABLE t_ver (id serial PRIMARY KEY, ref text, amount numeric, seen timestamptz);
            INSERT INTO t_ver (ref, amount, seen) VALUES
              ('a', 10, '2024-03-01 10:00:00+00'), ('b', 20, '2024-03-02 11:30:00+00'),
              ('c', 30, '2024-03-03 09:15:00+00'), ('d', 40, '2024-03-04 23:59:59+00'),
              ('e', 50, '2024-03-05 00:00:01+00');
            CREATE TABLE t_legacy (id serial PRIMARY KEY, amount numeric);
            INSERT INTO t_legacy (amount) VALUES (1), (2), (3);
            CREATE FUNCTION slow_amt(i int) RETURNS numeric LANGUAGE plpgsql IMMUTABLE AS $$ BEGIN PERFORM pg_sleep(0.05); RETURN i; END $$;
            -- count(*) never touches the IMMUTABLE plpgsql column, but hashing the whole row does.
            CREATE VIEW v_slow_row AS SELECT i AS id, slow_amt(i) AS amount FROM generate_series(1, 200) i;
            GRANT SELECT ON ALL TABLES IN SCHEMA public TO forensic_app;
        ''')
        env = {**os.environ, "FORENSIC_MCP_CONFIG": str(cfg_path), "FORENSIC_MASK_SALT": "t" * 40}

        def run(table, column="amount"):
            p = subprocess.run([sys.executable, str(ENGINE / "scripts" / "run_test.py"), "--database", scratch,
                                "--schema", "public", "--subtest", "benford", "--confirmed-by", "tester", "--allow-unsuitable", "--table", table, "--column", column],
                               capture_output=True, text=True, env=env)
            try:
                return json.loads(p.stdout)
            except ValueError:
                return {"status": "NOT-JSON", "stderr": p.stderr[-300:]}

        def versions(table):
            cur.execute("SELECT dataset_id, table_hash, notes FROM _forensic.datasets WHERE source_table = %s ORDER BY dataset_id", (table,))
            return cur.fetchall()

        print("\n=== a version is the CONTENT, not the row count ===")
        r1 = run("t_ver")
        v = versions("t_ver")
        check("first run registers one version with a content fingerprint",
              r1.get("status") == "success" and len(v) == 1 and str(v[0][1]).startswith("s56:5:") and "basis=content" in (v[0][2] or ""),
              (r1.get("status"), v))
        id1 = r1.get("dataset_id")
        r2 = run("t_ver")
        check("unchanged data reuses the same version", r2.get("dataset_id") == id1 and len(versions("t_ver")) == 1, (r2.get("dataset_id"), id1))

        cur.execute("UPDATE t_ver SET amount = amount")  # rewrites every tuple, identical content
        r3 = run("t_ver")
        check("rewriting rows with identical content is NOT a new version (order-independent)",
              r3.get("dataset_id") == id1 and len(versions("t_ver")) == 1, (r3.get("dataset_id"), len(versions("t_ver"))))

        cur.execute("UPDATE t_ver SET amount = amount + 1 WHERE id = 1")  # same row count, different value
        r4 = run("t_ver")
        id2 = r4.get("dataset_id")
        check("a changed value with the SAME row count is a new version", id2 != id1 and len(versions("t_ver")) == 2, (id1, id2))

        cur.execute("INSERT INTO t_ver (ref, amount, seen) VALUES ('f', 60, '2024-03-06 00:00:00+00')")
        r5 = run("t_ver")
        id3 = r5.get("dataset_id")
        check("an added row is a new version", id3 not in (id1, id2) and len(versions("t_ver")) == 3, id3)

        cur.execute("DELETE FROM t_ver WHERE ref = 'f'")
        r6 = run("t_ver")
        check("returning to earlier content maps back to that earlier version (content-addressed)",
              r6.get("dataset_id") == id2 and len(versions("t_ver")) == 3, (r6.get("dataset_id"), id2))

        print("\n=== the same data fingerprints the same regardless of session settings ===")
        cur.execute(f"ALTER ROLE forensic_app IN DATABASE \"{scratch}\" SET DateStyle = 'German, DMY'")
        cur.execute(f"ALTER ROLE forensic_app IN DATABASE \"{scratch}\" SET TimeZone = 'Asia/Kolkata'")
        r7 = run("t_ver")
        cur.execute(f"ALTER ROLE forensic_app IN DATABASE \"{scratch}\" RESET DateStyle")
        cur.execute(f"ALTER ROLE forensic_app IN DATABASE \"{scratch}\" RESET TimeZone")
        check("role-level DateStyle/TimeZone defaults do not change the version",
              r7.get("dataset_id") == id2 and len(versions("t_ver")) == 3, (r7.get("dataset_id"), id2))

        print("\n=== an older fingerprint of a different algorithm is never trusted ===")
        cur.execute("INSERT INTO _forensic.datasets (source_schema, source_table, row_count, column_hash, table_hash, imported_by) "
                    "VALUES ('public', 't_legacy', 3, 'x', %s, 'legacy_ingest')", ("f" * 64,))
        ra = run("t_legacy")
        check("a legacy row (untagged hash) is not reused; a content-verified version is registered",
              ra.get("status") == "success" and len(versions("t_legacy")) == 2 and str(versions("t_legacy")[1][1]).startswith("s56:3:"), versions("t_legacy"))
        rb = run("t_legacy")
        check("...and that new version is then reused", rb.get("dataset_id") == ra.get("dataset_id") and len(versions("t_legacy")) == 2)

        print("\n=== if the content fingerprint cannot be computed in time, say so ===")
        os.environ["FORENSIC_MCP_CONFIG"] = str(cfg_path)
        os.environ["FORENSIC_STATEMENT_TIMEOUT_MS"] = "700"
        try:
            from forensic_platform.core import db as enginedb
            from forensic_platform.tests_engine import base
            with enginedb.connect(scratch) as ec:
                ecur = ec.cursor()
                ref1 = base.resolve_dataset_version(ecur, "public", "v_slow_row", "test")
            with enginedb.connect(scratch) as ec:
                ecur = ec.cursor()
                ref2 = base.resolve_dataset_version(ecur, "public", "v_slow_row", "test")
            check("timeout -> falls back to row-count basis and reports it", ref1.basis == "row_count" and ref1.fingerprint is None and ref1.registered_now, ref1)
            v = versions("v_slow_row")
            check("recorded as such: no hash, and the note says why", len(v) == 1 and v[0][1] is None and "basis=row_count" in (v[0][2] or ""), v)
            check("the fallback version is reused while the row count is unchanged", ref2.dataset_id == ref1.dataset_id and not ref2.registered_now and len(versions("v_slow_row")) == 1)
            os.environ.pop("FORENSIC_STATEMENT_TIMEOUT_MS")
            with enginedb.connect(scratch) as ec:
                ecur = ec.cursor()
                fp = base.content_fingerprint(ecur, "public", "t_ver")
            check("content_fingerprint has the documented self-describing form", fp.startswith("s56:5:") and fp.split(":")[2].isdigit(), fp)
            with enginedb.connect(scratch) as ec:
                ecur = ec.cursor()
                check("a fingerprint is repeatable", base.content_fingerprint(ecur, "public", "t_ver") == fp)
        except (ImportError, AttributeError) as exc:
            check("base.resolve_dataset_version / content_fingerprint exist", False, exc)
        finally:
            os.environ.pop("FORENSIC_STATEMENT_TIMEOUT_MS", None)
    finally:
        if conn is not None:
            conn.close()
        with admin.cursor() as c:
            c.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = %s", (scratch,))
            c.execute(f'DROP DATABASE IF EXISTS "{scratch}"')
        admin.close()
        print(f"  scratch database {scratch} dropped")


if __name__ == "__main__":
    if "--integration" in sys.argv:
        integration_tests()
    else:
        print("(no unit tests: dataset versions are only meaningful against a database; run with --integration)")
    print("\n" + ("ALL TESTS PASS" if failures == 0 else f"{failures} TEST(S) FAILED"))
    sys.exit(1 if failures else 0)

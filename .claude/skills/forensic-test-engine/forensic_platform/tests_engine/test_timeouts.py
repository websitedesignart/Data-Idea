"""
Tests for statement/lock timeouts and for compact, audit-logged failure reporting.

    python forensic_platform/tests_engine/test_timeouts.py                  # unit tests only
    python forensic_platform/tests_engine/test_timeouts.py --integration    # + database tests

--integration creates its own uniquely named scratch database (forensic_test_<hex>), runs the
real run_test.py entry point against it, and always drops it afterwards. It connects only to
the maintenance database (to create/drop that scratch database) and to the scratch database.
It needs the project's .mcp.json (found by walking up from the working directory, or
$FORENSIC_MCP_CONFIG) with the admin `local-postgres-cluster` entry and a `*-forensic` entry.
"""
import json
import os
import subprocess
import sys
import time
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


class FakeDbError(Exception):
    def __init__(self, msg, pgcode):
        super().__init__(msg)
        self.pgcode = pgcode


def unit_tests():
    print("=== unit: timeout settings ===")
    try:
        from forensic_platform.core.db import (
            ENV_LOCK_TIMEOUT, ENV_STATEMENT_TIMEOUT, InvalidTimeout, describe_db_error, timeouts)
    except ImportError as exc:
        check("core.db exposes timeouts()", False, exc)
        return

    saved = {k: os.environ.pop(k, None) for k in (ENV_STATEMENT_TIMEOUT, ENV_LOCK_TIMEOUT)}
    try:
        check("defaults: 60 s statement, 5 s lock", timeouts() == {"statement_timeout_ms": 60000, "lock_timeout_ms": 5000}, timeouts())
        os.environ[ENV_STATEMENT_TIMEOUT] = "2500"
        os.environ[ENV_LOCK_TIMEOUT] = "  300 "
        check("environment overrides both (whitespace tolerated)", timeouts() == {"statement_timeout_ms": 2500, "lock_timeout_ms": 300}, timeouts())
        os.environ[ENV_STATEMENT_TIMEOUT] = ""
        check("empty value falls back to the default", timeouts()["statement_timeout_ms"] == 60000)
        os.environ[ENV_STATEMENT_TIMEOUT] = "0"
        check("0 is accepted (PostgreSQL's 'no limit')", timeouts()["statement_timeout_ms"] == 0)
        for bad in ["abc", "-1", "1.5", "1e3", "2147483648", "10 s"]:
            os.environ[ENV_STATEMENT_TIMEOUT] = bad
            try:
                timeouts()
                check(f"refused: {bad!r}", False, "was accepted")
            except InvalidTimeout as exc:
                check(f"refused: {bad!r}", ENV_STATEMENT_TIMEOUT in str(exc))
    finally:
        for k, v in saved.items():
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v

    print("\n=== unit: database errors become a short code ===")
    code, reason = describe_db_error(FakeDbError("canceling statement due to statement timeout", "57014"))
    check("57014 -> STATEMENT_TIMEOUT, actionable", code == "STATEMENT_TIMEOUT" and "FORENSIC_STATEMENT_TIMEOUT_MS" in reason, code)
    code, reason = describe_db_error(FakeDbError("canceling statement due to lock timeout", "55P03"))
    check("55P03 -> LOCK_TIMEOUT, actionable", code == "LOCK_TIMEOUT" and "FORENSIC_LOCK_TIMEOUT_MS" in reason, code)
    long_msg = "boom " * 200 + "\nLINE 1: SELECT secret FROM somewhere\n^"
    code, reason = describe_db_error(FakeDbError(long_msg, "22003"))
    check("anything else -> DATABASE_ERROR, first line only, capped", code == "DATABASE_ERROR" and len(reason) <= 200 and "LINE 1" not in reason, len(reason))


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
    conn = holder = None
    try:
        with admin.cursor() as c:
            c.execute(f'CREATE DATABASE "{scratch}"')
        conn = psycopg2.connect(superuser_dsn(scratch))
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute((ENGINE / "sql" / "001_bootstrap.sql").read_text(encoding="utf-8"))
        cur.execute('''
            CREATE TABLE t_pk (id serial PRIMARY KEY, amount numeric);
            INSERT INTO t_pk (amount) SELECT i FROM generate_series(1, 400) i;
            -- count(*) evaluates the volatile pg_sleep for every row, so even registering the
            -- dataset is slow: exercises a timeout OUTSIDE the test call.
            CREATE VIEW v_slow_count AS SELECT i AS amount, pg_sleep(0.05)::text AS s FROM generate_series(1, 200) i;
            -- count(*) never touches the IMMUTABLE plpgsql column, so registration is fast and only
            -- the analysis query is slow: exercises a timeout INSIDE the test call.
            CREATE FUNCTION slow_amt(i int) RETURNS numeric LANGUAGE plpgsql IMMUTABLE AS $$ BEGIN PERFORM pg_sleep(0.05); RETURN i; END $$;
            CREATE VIEW v_slow_test AS SELECT i AS id, slow_amt(i) AS amount FROM generate_series(1, 200) i;
            GRANT SELECT ON ALL TABLES IN SCHEMA public TO forensic_app;
        ''')

        base_env = {k: v for k, v in os.environ.items() if not k.startswith("FORENSIC_") or k == "FORENSIC_MCP_CONFIG"}
        base_env["FORENSIC_MCP_CONFIG"] = str(cfg_path)
        base_env["FORENSIC_MASK_SALT"] = "t" * 40

        def run(env_extra, *args, timeout=60):
            t0 = time.time()
            p = subprocess.run([sys.executable, str(ENGINE / "scripts" / "run_test.py"), "--database", scratch,
                                "--schema", "public", *args], capture_output=True, text=True,
                               env={**base_env, **env_extra}, timeout=timeout)
            try:
                out = json.loads(p.stdout)
            except ValueError:
                out = {"status": "NOT-JSON", "stderr_chars": len(p.stderr), "stdout": p.stdout[-200:]}
            return out, time.time() - t0, len(p.stdout), len(p.stderr)

        def scalar(sql, params=None):
            cur.execute(sql, params)
            return cur.fetchone()[0]

        print("=== the limits are applied to the session ===")
        os.environ["FORENSIC_MCP_CONFIG"] = str(cfg_path)
        from forensic_platform.core import db as enginedb
        for k in ("FORENSIC_STATEMENT_TIMEOUT_MS", "FORENSIC_LOCK_TIMEOUT_MS"):
            os.environ.pop(k, None)
        with enginedb.connect(scratch) as ec:
            ecur = ec.cursor()
            ecur.execute("SELECT name, setting FROM pg_settings WHERE name IN ('statement_timeout','lock_timeout') ORDER BY name")
            got = dict(ecur.fetchall())
        check("defaults reach PostgreSQL: statement 60000 ms, lock 5000 ms", got == {"lock_timeout": "5000", "statement_timeout": "60000"}, got)
        os.environ["FORENSIC_STATEMENT_TIMEOUT_MS"] = "2500"
        with enginedb.connect(scratch) as ec:
            ecur = ec.cursor()
            ecur.execute("SELECT setting FROM pg_settings WHERE name = 'statement_timeout'")
            check("an override reaches PostgreSQL", ecur.fetchone()[0] == "2500")
        os.environ.pop("FORENSIC_STATEMENT_TIMEOUT_MS")

        print("\n=== a bad setting is refused up front ===")
        for bad in ("abc", "-5", "1.5"):
            out, _, _, _ = run({"FORENSIC_STATEMENT_TIMEOUT_MS": bad}, "--subtest", "benford", "--confirmed-by", "tester", "--allow-unsuitable", "--table", "t_pk", "--column", "amount")
            check(f"FORENSIC_STATEMENT_TIMEOUT_MS={bad!r} -> refused, names the setting",
                  out.get("status") == "refused" and "FORENSIC_STATEMENT_TIMEOUT_MS" in out.get("reason", ""), out.get("reason"))

        print("\n=== normal runs are unaffected ===")
        out, _, _, _ = run({}, "--subtest", "benford", "--confirmed-by", "tester", "--allow-unsuitable", "--table", "t_pk", "--column", "amount")
        check("benford runs under the default limits", (out.get("status"), out.get("records_examined")) == ("success", 400), out.get("reason") or out.get("stderr_chars"))

        print("\n=== a runaway query is cancelled, reported compactly, and logged ===")
        runs_before = scalar("SELECT count(*) FROM _forensic.test_runs")
        findings_before = scalar("SELECT count(*) FROM _forensic.findings")
        out, secs, olen, elen = run({"FORENSIC_STATEMENT_TIMEOUT_MS": "1000"}, "--subtest", "benford", "--confirmed-by", "tester", "--allow-unsuitable", "--table", "v_slow_count", "--column", "amount")
        check("timeout while registering the dataset -> compact error, no traceback",
              out.get("status") == "error" and out.get("code") == "STATEMENT_TIMEOUT" and elen == 0, (out.get("status"), out.get("code"), f"stderr={elen}"))
        check("cancelled after ~1 s, not after the ~10 s the query wanted", secs < 7, f"{secs:.1f}s")
        check("error output is short (<800 chars) and contains no SQL", olen < 800 and "SELECT" not in json.dumps(out), olen)
        check("the failure is in the audit log", scalar("SELECT count(*) FROM _forensic.audit_log WHERE status='error' AND error_text LIKE 'STATEMENT_TIMEOUT:%'") == 1)

        out, secs, olen, elen = run({"FORENSIC_STATEMENT_TIMEOUT_MS": "700"}, "--subtest", "benford", "--confirmed-by", "tester", "--allow-unsuitable", "--table", "v_slow_test", "--column", "amount")
        check("timeout INSIDE the test -> compact error, no traceback",
              out.get("status") == "error" and out.get("code") == "STATEMENT_TIMEOUT" and elen == 0, (out.get("status"), out.get("code"), out.get("reason"), f"stderr={elen}"))
        check("cancelled promptly", secs < 7, f"{secs:.1f}s")
        check("error output is short (<800 chars)", olen < 800, olen)
        check("audit-logged against the dataset that WAS registered (savepoint kept it)",
              scalar("SELECT count(*) FROM _forensic.audit_log a JOIN _forensic.datasets d USING (dataset_id) "
                     "WHERE a.status='error' AND d.source_table='v_slow_test'") == 1)
        check("no test run and no finding was recorded for the cancelled tests",
              (scalar("SELECT count(*) FROM _forensic.test_runs"), scalar("SELECT count(*) FROM _forensic.findings"))
              == (runs_before, findings_before), "counts changed")

        print("\n=== a blocked table does not hang the engine ===")
        holder = psycopg2.connect(superuser_dsn(scratch))
        holder.autocommit = False
        holder.cursor().execute("LOCK TABLE t_pk IN ACCESS EXCLUSIVE MODE")
        out, secs, olen, elen = run({"FORENSIC_LOCK_TIMEOUT_MS": "700"}, "--subtest", "benford", "--confirmed-by", "tester", "--allow-unsuitable", "--table", "t_pk", "--column", "amount", timeout=30)
        check("lock held by another session -> LOCK_TIMEOUT, compact, no traceback",
              out.get("status") == "error" and out.get("code") == "LOCK_TIMEOUT" and elen == 0, (out.get("status"), out.get("code"), f"stderr={elen}"))
        check("gave up after ~0.7 s instead of waiting forever", secs < 10, f"{secs:.1f}s")
        holder.rollback()
        holder.close()
        holder = None
        out, _, _, _ = run({}, "--subtest", "benford", "--confirmed-by", "tester", "--allow-unsuitable", "--table", "t_pk", "--column", "amount")
        check("once the lock is released the same test succeeds", out.get("status") == "success", out.get("reason"))
    finally:
        if holder is not None:
            holder.rollback()
            holder.close()
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

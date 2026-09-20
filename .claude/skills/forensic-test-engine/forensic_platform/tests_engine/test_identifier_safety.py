"""
Tests that caller-supplied schema/table/column names can never run extra SQL.

    python forensic_platform/tests_engine/test_identifier_safety.py                  # unit tests only
    python forensic_platform/tests_engine/test_identifier_safety.py --integration    # + database tests

--integration creates its own uniquely named scratch database (forensic_test_<hex>), runs the
real run_test.py entry point against it, and always drops it afterwards. It connects only to
the maintenance database (to create/drop that scratch database) and to the scratch database.
It needs the project's .mcp.json (found by walking up from the working directory, or
$FORENSIC_MCP_CONFIG) with the admin `local-postgres-cluster` entry and a `*-forensic` entry.

Every attack below tries to forge a row in the append-only audit log by hiding an INSERT in
a name. Before identifiers were quoted properly, `--table` did exactly that.
"""
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE.parent))

from forensic_platform.core.sqlsafe import UnsafeIdentifier, check_identifier  # noqa: E402

failures = 0


def check(label, ok, detail=""):
    global failures
    if not ok:
        failures += 1
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}{(' - ' + str(detail)) if detail else ''}")


FORGE = "INSERT INTO _forensic.audit_log (actor, operation, status) VALUES ('INJECTED','forged','success')"


def unit_tests():
    print("=== unit: which names are accepted, which are refused ===")
    for name in ["a", 'we"ird', "Select", "has space", "semi;colon", "表", "x" * 63, "日" * 21]:
        try:
            check_identifier(name)
            check(f"accepted: {name[:24]!r}", True)
        except UnsafeIdentifier as exc:
            check(f"accepted: {name[:24]!r}", False, exc)
    cases = {"empty": "", "None": None, "NUL": "a\x00b", "percent": "a%b",
             "64 bytes": "x" * 64, "66 bytes (22 x 3-byte)": "日" * 22}
    for label, name in cases.items():
        try:
            check_identifier(name)
            check(f"refused: {label}", False, "was accepted")
        except UnsafeIdentifier:
            check(f"refused: {label}", True)


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
        cur.execute('''
            CREATE TABLE t_num (id serial PRIMARY KEY, amount numeric);
            INSERT INTO t_num (amount) SELECT round((10 ^ (((i * 7) % 400) / 100.0))::numeric, 2) FROM generate_series(1, 400) i;
            CREATE TABLE t_pk (id serial PRIMARY KEY, ref text, name text);
            INSERT INTO t_pk (ref, name) VALUES ('A1','ANUPAM KUMAR BHARGAVA'),('A1','DR ANUPAM KUMAR BHARGAVA'),
              ('B2','RAJESH KUMAR SINGH'),('B2','SUNITA DEVI'),('C3','ONLY ONE'),('D4','X'),('D4','X');
            CREATE TABLE "Odd ""Table" ("Row Id" serial PRIMARY KEY, "Ref Col" text, "Name""Col" text, "Amt ""x""" numeric);
            INSERT INTO "Odd ""Table" ("Ref Col", "Name""Col", "Amt ""x""") VALUES
              ('A1','ANUPAM KUMAR BHARGAVA',1.5),('A1','DR ANUPAM KUMAR BHARGAVA',2),
              ('B2','RAJESH KUMAR SINGH',3),('B2','SUNITA DEVI',4),('C3','ONE',5);
            CREATE TABLE "select" ("from" int PRIMARY KEY, "order" text);
            INSERT INTO "select" VALUES (1,'X'),(2,'X'),(3,'Y');
            CREATE TABLE "表" ("鍵" int PRIMARY KEY, "列" text);
            INSERT INTO "表" VALUES (1,'甲'),(2,'甲'),(3,'乙');
            GRANT SELECT ON ALL TABLES IN SCHEMA public TO forensic_app;
        ''')

        env = {**os.environ, "FORENSIC_MCP_CONFIG": str(cfg_path)}

        def run(*args):
            p = subprocess.run([sys.executable, str(ENGINE / "scripts" / "run_test.py"), "--database", scratch, *args],
                               capture_output=True, text=True, env=env)
            try:
                return json.loads(p.stdout)
            except ValueError:
                return {"status": "NOT-JSON", "stdout": p.stdout[-200:], "stderr": p.stderr[-300:]}

        def forged():
            cur.execute("SELECT count(*) FROM _forensic.audit_log WHERE actor = 'INJECTED'")
            return cur.fetchone()[0]

        print("=== names that are legal but awkward must still work ===")
        r = run("--schema", "public", "--subtest", "duplicate-analysis", "--table", 'Odd "Table', "--column", "Ref Col")
        check("duplicate-analysis: table with a quote and space, column with a space",
              (r.get("status"), r.get("flagged_keys"), r.get("flagged_rows")) == ("success", 2, 4),
              (r.get("status"), r.get("flagged_keys"), r.get("reason") or r.get("stderr")))
        check("evidence keyed by the mixed-case, spaced primary key", r.get("evidence_identity", {}).get("columns") == ["Row Id"], r.get("evidence_identity"))
        r = run("--schema", "public", "--subtest", "fuzzy-entity-match", "--table", 'Odd "Table', "--column", "Ref Col", "--distinct-of", 'Name"Col')
        check("fuzzy-entity-match: quotes in a column name", (r.get("status"), r.get("flagged_keys")) == ("success", 1), (r.get("status"), r.get("reason") or r.get("stderr")))
        r = run("--schema", "public", "--subtest", "benford", "--table", 'Odd "Table', "--column", 'Amt "x"')
        check("benford: mixed-case column (was never quoted before)", (r.get("status"), r.get("records_examined")) == ("success", 5), (r.get("status"), r.get("reason") or r.get("stderr")))
        r = run("--schema", "public", "--subtest", "duplicate-analysis", "--table", "select", "--column", "order")
        check("reserved words as table and column names", (r.get("status"), r.get("flagged_keys")) == ("success", 1), (r.get("status"), r.get("reason") or r.get("stderr")))
        r = run("--schema", "public", "--subtest", "duplicate-analysis", "--table", "表", "--column", "列")
        check("non-ASCII names", (r.get("status"), r.get("flagged_keys")) == ("success", 1), (r.get("status"), r.get("reason") or r.get("stderr")))
        r = run("--schema", "public", "--subtest", "cross-dataset-match", "--table", 'Odd "Table', "--column", "Ref Col",
                "--right-table", "t_pk", "--right-column", "ref")
        check("cross-dataset-match across an awkwardly named table",
              (r.get("status"), r.get("in_both"), r.get("only_left"), r.get("only_right")) == ("success", 3, 0, 1), (r.get("status"), r.get("reason") or r.get("stderr")))

        print("\n=== attacks: a name that hides an INSERT must never execute it ===")
        attacks = [
            ("benford --table (the original exploit)", ["--subtest", "benford", "--table", f"t_num\"; {FORGE}; SELECT 1 --", "--column", "amount"]),
            ("benford --table, unquoted form", ["--subtest", "benford", "--table", f"t_num; {FORGE}; SELECT 1 --", "--column", "amount"]),
            ("duplicate --table", ["--subtest", "duplicate-analysis", "--table", f't_pk"; {FORGE}; SELECT 1 --', "--column", "ref"]),
            ("benford --column", ["--subtest", "benford", "--table", "t_num", "--column", f'amount"; {FORGE}; SELECT 1 --']),
            ("fuzzy --distinct-of", ["--subtest", "fuzzy-entity-match", "--table", "t_pk", "--column", "ref", "--distinct-of", f'name"); {FORGE}; SELECT 1 --']),
            ("cross --right-table", ["--subtest", "cross-dataset-match", "--table", "t_pk", "--column", "ref", "--right-table", f'x" WHERE false; {FORGE}; SELECT 1 --', "--right-column", "ref"]),
            ("cross --right-column", ["--subtest", "cross-dataset-match", "--table", "t_pk", "--column", "ref", "--right-table", "t_pk", "--right-column", f'ref"); {FORGE}; SELECT 1 --']),
            ("cross --right-schema", ["--subtest", "cross-dataset-match", "--table", "t_pk", "--column", "ref", "--right-schema", f'public"; {FORGE}; SELECT 1 --', "--right-table", "t_pk", "--right-column", "ref"]),
        ]
        for label, a in attacks:
            r = run("--schema", "public", *a)
            check(f"{label}: refused as compact JSON, nothing forged",
                  r.get("status") == "refused" and forged() == 0, (r.get("status"), "forged rows:", forged()))
        r = run("--schema", f'public"; {FORGE}; SELECT 1 --', "--subtest", "duplicate-analysis", "--table", "t_pk", "--column", "ref")
        check("--schema: refused, nothing forged", r.get("status") == "refused" and forged() == 0, (r.get("status"), forged()))
        cur.execute("SELECT count(*) FROM t_pk")
        check("the attacked table is intact", cur.fetchone()[0] == 7)

        print("\n=== names that cannot be made safe are refused with a reason ===")
        r = run("--schema", "public", "--subtest", "benford", "--table", "t" * 70, "--column", "amount")
        check("over-long name refused (PostgreSQL would silently truncate it)", r.get("status") == "refused" and "63 bytes" in r.get("reason", ""), r.get("reason"))
        r = run("--schema", "public", "--subtest", "benford", "--table", "t_num", "--column", "amo%unt")
        check("name containing % refused", r.get("status") == "refused" and "'%'" in r.get("reason", ""), r.get("reason"))

        print("\n=== the attempts are themselves recorded ===")
        cur.execute("SELECT count(*) FROM _forensic.audit_log WHERE status = 'refused'")
        n = cur.fetchone()[0]
        check("every refusal above is in the audit log", n >= len(attacks) + 3, n)
        cur.execute("SELECT count(*) FROM _forensic.datasets WHERE source_table LIKE '%INJECTED%' OR source_table LIKE '%INSERT%'")
        check("no dataset was registered under an attack string", cur.fetchone()[0] == 0)
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

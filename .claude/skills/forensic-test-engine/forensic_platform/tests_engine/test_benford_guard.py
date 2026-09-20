"""
Tests for the Benford guard: the test must decline columns it cannot meaningfully test, must not
run on a column nobody confirmed as an amount, and must count values below 1.

    python forensic_platform/tests_engine/test_benford_guard.py                  # unit tests
    python forensic_platform/tests_engine/test_benford_guard.py --integration    # + scratch database

--integration creates its own scratch database (forensic_test_<hex>), runs the real run_test.py
entry point against it, and always drops it.

Every threshold under test is an UNVALIDATED starting default. These tests pin the guard's
behaviour, not the correctness of the numbers: they must not be read as validating them.
"""
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE.parent))

from forensic_platform.core.contract import Verdict as V                       # noqa: E402
from forensic_platform.core.profile import ColumnProfile, TableProfile         # noqa: E402
from forensic_platform.core.roles import Bindings, facts_for                   # noqa: E402
from forensic_platform.core.suitability import assess                          # noqa: E402
from forensic_platform.tests_engine import benford                             # noqa: E402

failures = 0


def check(label, ok, detail=""):
    global failures
    if not ok:
        failures += 1
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}{(' - ' + str(detail)) if detail else ''}")


GOOD = {"role.amount.bound": True, "role.amount.pending": False, "n_eligible": 5000, "n_distinct": 3000,
        "magnitude_span": 4.0, "top10_share": 0.02, "identifier_like": False, "nonpositive_share": 0.0}


def with_facts(**over):
    f = dict(GOOD)
    f.update({k.replace("__", "."): v for k, v in over.items()})
    return f


def unit_tests():
    R = benford.RULESET
    print("=== the Benford rule set ===")
    a = assess(R, GOOD)
    check("a sound, confirmed amount column is SUPPORTED", a.verdict is V.SUPPORTED and not a.reason_codes, a.reason_codes)
    check("the result says its thresholds are unvalidated", a.unvalidated is True and a.summary().get("thresholds") == "unvalidated")
    check("every tunable threshold is marked unvalidated; only structural rules claim otherwise",
          all((not r.threshold.validated) or "structural" in r.threshold.basis for r in R.rules),
          [r.code for r in R.rules if r.threshold.validated and "structural" not in r.threshold.basis])
    a = assess(R, with_facts(role__amount__bound=False, role__amount__pending=True))
    check("proposed but unconfirmed -> REQUIRES_CONFIRMATION", a.verdict is V.REQUIRES_CONFIRMATION and "ROLE_UNCONFIRMED_AMOUNT" in a.reason_codes)
    check("no role at all -> INSUFFICIENT_DATA",
          assess(R, with_facts(role__amount__bound=False, role__amount__pending=False)).verdict is V.INSUFFICIENT_DATA)
    a = assess(R, with_facts(n_eligible=120))
    check("under 300 eligible values -> INSUFFICIENT_DATA and nothing else is reported (they are explained by it)",
          a.verdict is V.INSUFFICIENT_DATA and a.reason_codes == ("FEW_ELIGIBLE_VALUES",), a.reason_codes)
    check("299 declines, 300 does not (boundary)",
          assess(R, with_facts(n_eligible=299)).verdict is V.INSUFFICIENT_DATA and assess(R, with_facts(n_eligible=300)).verdict is V.SUPPORTED)
    check("under 100 distinct values -> NOT_APPLICABLE", assess(R, with_facts(n_distinct=60)).reason_codes == ("FEW_DISTINCT_VALUES",))
    check("span under two orders of magnitude -> NOT_APPLICABLE", assess(R, with_facts(magnitude_span=1.2)).reason_codes == ("NARROW_MAGNITUDE_SPAN",))
    check("ten values holding over 80% -> NOT_APPLICABLE", assess(R, with_facts(top10_share=0.9)).reason_codes == ("FIXED_VALUES_DOMINATE",))
    check("an identifier-like column -> NOT_APPLICABLE", assess(R, with_facts(identifier_like=True)).reason_codes == ("IDENTIFIER_LIKE_COLUMN",))
    a = assess(R, with_facts(nonpositive_share=0.35))
    check("many zero/negative values -> SUPPORTED_WITH_WARNING (still runs)", a.verdict is V.SUPPORTED_WITH_WARNING and a.runnable)
    check("a fact that was not measured is INSUFFICIENT_DATA, never assumed",
          assess(R, {k: v for k, v in GOOD.items() if k != "magnitude_span"}).verdict is V.INSUFFICIENT_DATA)
    check("the profiler is asked for exactly these facts",
          R.facts_required() >= {"n_eligible", "n_distinct", "magnitude_span", "top10_share", "identifier_like", "nonpositive_share"})

    print("\n=== identifier_like fact ===")

    def col(name, *, pk=False, distinct=50, non_null=100, **m):
        c = ColumnProfile(name, "numeric", "numeric", 1, non_null=non_null, distinct=distinct, metrics=m)
        c.is_pk = pk
        return c

    def fact(c):
        t = TableProfile("public", "t", 100, {c.name: c})
        b = Bindings()
        b.confirm("amount", c.name, "A. Reviewer")
        return facts_for(t, b, R, "amount")["identifier_like"]

    check("a primary key is identifier-like", fact(col("id", pk=True, distinct=100)) is True)
    check("a unique whole-number column (serial) is identifier-like", fact(col("sno", distinct=100, integer_share=1.0)) is True)
    check("a unique column WITH decimals is not (distinct amounts are legitimate)", fact(col("net", distinct=100, integer_share=0.4)) is False)
    check("a non-unique whole-number column is not", fact(col("qty", distinct=40, integer_share=1.0)) is False)
    check("a whole-number column with a counter-style name is, even when not unique (a serial that restarts per invoice)",
          all(fact(col(n, distinct=300, non_null=7000, integer_share=1.0)) is True for n in ("sno", "sr_no", "SlNo", "line_seq", "page")))
    check("a counter word does not override an amount word: whole-rupee 'line_amount' / 'row_total' are not counters",
          all(fact(col(n, distinct=300, non_null=7000, integer_share=1.0)) is False for n in ("line_amount", "row_total", "page_fee")))
    check("...but the same name with decimals is not (it is not a counter)", fact(col("sno", distinct=300, non_null=7000, integer_share=0.7)) is False)
    check("a mobile-shaped column is identifier-like", fact(col("contact", distinct=40, mobile_like_share=1.0, aadhaar_like_share=0.0)) is True)
    check("a column named for an account number is identifier-like", fact(col("bank_account_no", distinct=40, integer_share=0.5)) is True)


def integration_tests():
    import psycopg2
    from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
    from forensic_platform.core.config import find_mcp_config, load_mcp_config, superuser_dsn
    from forensic_platform.core.profile import profile_table

    try:
        cfg_path = find_mcp_config()
        servers = load_mcp_config()["mcpServers"]
        assert "local-postgres-cluster" in servers and any(n.endswith("-forensic") for n in servers)
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
            SELECT setseed(0.42);
            CREATE TABLE amt_good AS SELECT g AS id, round(power(10, random()*4)::numeric, 2) AS amount, 'x'::text AS pad FROM generate_series(1, 3000) g;
            ALTER TABLE amt_good ADD PRIMARY KEY (id);
            CREATE TABLE amt_mixed AS SELECT g AS id, round(power(10, random()*4)::numeric, 2) * CASE WHEN random() < 0.3 THEN -1 ELSE 1 END AS amount FROM generate_series(1, 3000) g;
            ALTER TABLE amt_mixed ADD PRIMARY KEY (id);
            CREATE TABLE amt_small AS SELECT g AS id, round(power(10, random()*4)::numeric, 2) AS amount FROM generate_series(1, 50) g;
            ALTER TABLE amt_small ADD PRIMARY KEY (id);
            CREATE TABLE amt_narrow AS SELECT g AS id, (500 + (g % 50))::numeric AS amount FROM generate_series(1, 1000) g;
            ALTER TABLE amt_narrow ADD PRIMARY KEY (id);
            CREATE TABLE amt_fixed AS SELECT g AS id, (ARRAY[10,100,1000,10000,25,250,2500,25000])[1 + g % 8]::numeric AS amount FROM generate_series(1, 1000) g;
            ALTER TABLE amt_fixed ADD PRIMARY KEY (id);
            CREATE TABLE amt_mobile AS SELECT g AS id, (9000000000 + (g % 400))::bigint AS contact FROM generate_series(1, 1000) g;
            ALTER TABLE amt_mobile ADD PRIMARY KEY (id);
            CREATE TABLE small_values (id serial PRIMARY KEY, amount numeric);
            INSERT INTO small_values (amount) VALUES (0.123), (0.0456), (7.5), (0.9), (-0.31), (0), (NULL);
            GRANT SELECT ON ALL TABLES IN SCHEMA public TO forensic_app;
        ''')
        env = {**os.environ, "FORENSIC_MCP_CONFIG": str(cfg_path), "FORENSIC_MASK_SALT": "t" * 40}

        def run(table, column="amount", *extra):
            p = subprocess.run([sys.executable, str(ENGINE / "scripts" / "run_test.py"), "--database", scratch,
                                "--schema", "public", "--subtest", "benford", "--table", table, "--column", column, *extra],
                               capture_output=True, text=True, env=env)
            try:
                return json.loads(p.stdout), p.stdout
            except ValueError:
                return {"status": "NOT-JSON", "stderr": p.stderr[-300:]}, p.stdout

        def count(sql_text):
            cur.execute(sql_text)
            return cur.fetchone()[0]

        print("\n--- values below 1 ---")
        res = benford.run(cur, "public", "small_values", "amount")
        check("first SIGNIFICANT digit is used: 0.123, 0.0456, 7.5, 0.9, -0.31 give digits 1,4,7,9,3 (zero and NULL excluded)",
              res.digit_counts == {1: 1, 3: 1, 4: 1, 7: 1, 9: 1} and res.records_examined == 5, res.digit_counts)

        print("\n--- not confirmed: declined, nothing scanned or recorded ---")
        runs_before = count("SELECT count(*) FROM _forensic.test_runs")
        r, out = run("amt_good")
        check("no --confirmed-by -> declined REQUIRES_CONFIRMATION with the reason code",
              r.get("status") == "declined" and r.get("verdict") == "REQUIRES_CONFIRMATION" and "ROLE_UNCONFIRMED_AMOUNT" in r.get("why", []), r)
        check("the declined output is compact and tells Claude what to do next", len(out) < 500 and "confirm" in r.get("next", ""), len(out))
        check("a declined run records no test run", count("SELECT count(*) FROM _forensic.test_runs") == runs_before)
        check("...but the decline itself is audit-logged",
              count("SELECT count(*) FROM _forensic.audit_log WHERE status='declined' AND error_text LIKE '%ROLE_UNCONFIRMED_AMOUNT%'") == 1)
        r, _ = run("amt_good", "amount", "--confirmed-by", "   ")
        check("a blank name is not a confirmation", r.get("verdict") == "REQUIRES_CONFIRMATION", r.get("verdict"))
        r, _ = run("amt_small", "amount", "--allow-unsuitable")
        check("--allow-unsuitable never overrides a missing confirmation", r.get("status") == "declined" and r.get("verdict") == "REQUIRES_CONFIRMATION", r)

        print("\n--- confirmed and suitable: runs ---")
        r, _ = run("amt_good", "amount", "--confirmed-by", "A. Reviewer")
        s = r.get("suitability", {})
        check("a log-uniform 3,000-row amount column is SUPPORTED and runs",
              r.get("status") == "success" and s.get("verdict") == "SUPPORTED" and s.get("why") == [], (r.get("status"), s))
        check("the run reports unvalidated thresholds, who confirmed it, and the new test version",
              s.get("thresholds") == "unvalidated" and s.get("confirmed_by") == "A. Reviewer" and r.get("test_version") == "1.1.0", (s, r.get("test_version")))
        check("who confirmed it is in the audit log",
              count("SELECT count(*) FROM _forensic.audit_log WHERE status='success' AND params_json->>'confirmed_by' = 'A. Reviewer'") >= 1)
        r, _ = run("amt_mixed", "amount", "--confirmed-by", "A. Reviewer")
        check("30% negatives -> SUPPORTED_WITH_WARNING: still runs, warning travels with it",
              r.get("status") == "success" and r["suitability"]["verdict"] == "SUPPORTED_WITH_WARNING"
              and r["suitability"]["why"] == ["MANY_ZERO_OR_NEGATIVE"], r.get("suitability"))

        print("\n--- confirmed but unsuitable: declined with the reason ---")
        for table, column, verdict, must in (
                ("amt_small", "amount", "INSUFFICIENT_DATA", ["FEW_ELIGIBLE_VALUES"]),
                ("amt_narrow", "amount", "NOT_APPLICABLE", ["FEW_DISTINCT_VALUES", "NARROW_MAGNITUDE_SPAN"]),
                ("amt_fixed", "amount", "NOT_APPLICABLE", ["FIXED_VALUES_DOMINATE"]),
                ("amt_good", "id", "NOT_APPLICABLE", ["IDENTIFIER_LIKE_COLUMN"]),
                ("amt_mobile", "contact", "NOT_APPLICABLE", ["IDENTIFIER_LIKE_COLUMN"])):
            runs_before = count("SELECT count(*) FROM _forensic.test_runs")
            r, _ = run(table, column, "--confirmed-by", "A. Reviewer")
            check(f"{table}.{column}: declined {verdict} with {must}",
                  r.get("status") == "declined" and r.get("verdict") == verdict and all(m in r.get("why", []) for m in must), r)
            check(f"{table}.{column}: nothing recorded as a test run", count("SELECT count(*) FROM _forensic.test_runs") == runs_before)
        r, _ = run("amt_small", "amount", "--confirmed-by", "A. Reviewer")
        check("a small sample reports ONLY the small sample (its other symptoms are explained by it)", r.get("why") == ["FEW_ELIGIBLE_VALUES"], r.get("why"))

        print("\n--- explicit override: allowed, capped, labelled ---")
        r, _ = run("amt_small", "amount", "--confirmed-by", "A. Reviewer", "--allow-unsuitable")
        check("--allow-unsuitable runs an INSUFFICIENT_DATA column and says it was overridden",
              r.get("status") == "success" and r["suitability"].get("overridden") is True
              and r["suitability"]["verdict"] == "INSUFFICIENT_DATA", (r.get("status"), r.get("suitability")))
        cur.execute("SELECT classification, description FROM _forensic.findings WHERE finding_id = %s", (r["finding_ids"][0],))
        cls, desc = cur.fetchone()
        check("the finding is an OBSERVATION and states it must not be read as (non)conformity",
              cls == "OBSERVATION" and "reference only" in desc and "FEW_ELIGIBLE_VALUES" in desc, (cls, desc[:80]))
        r, _ = run("amt_narrow", "amount", "--confirmed-by", "A. Reviewer", "--allow-unsuitable")
        cur.execute("SELECT classification FROM _forensic.findings WHERE finding_id = %s", (r["finding_ids"][0],))
        check("an overridden NOT_APPLICABLE run can never produce an ANOMALY (no nonconformity claim on constrained data)",
              cur.fetchone()[0] == "OBSERVATION")

        print("\n--- the guard profiles only the column it needs ---")
        p = profile_table(cur, "public", "amt_good", columns=["amount"])
        check("restricting to one column profiles that column only", list(p.columns) == ["amount"] and p.row_count == 3000, list(p.columns))
    finally:
        if conn is not None:
            conn.close()
        with admin.cursor() as c:
            c.execute(f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)')
        admin.close()
        print(f"  scratch database {scratch} dropped")


if __name__ == "__main__":
    unit_tests()
    if "--integration" in sys.argv:
        integration_tests()
    print(f"\n{'ALL PASSED' if failures == 0 else str(failures) + ' FAILED'}")
    sys.exit(1 if failures else 0)

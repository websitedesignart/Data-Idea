"""
Tests for run_suite: planning, folding, and the real script against a scratch database.

    python forensic_platform/tests_engine/test_suite.py                  # unit tests (no database)
    python forensic_platform/tests_engine/test_suite.py --integration    # + scratch database

What must hold: nothing runs without a named person's confirmation; a proposal binds nothing; one
method failing never stops the others; every method still leaves its own recorded run; identifiers
never appear; the combined reply stays within its budget without dropping any method.
"""
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE.parent))
sys.path.insert(0, str(ENGINE / "scripts"))

from forensic_platform.core import suite  # noqa: E402
from forensic_platform.core.roles import Suggestion  # noqa: E402

failures = 0


def check(label, ok, detail=""):
    global failures
    if not ok:
        failures += 1
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}{(' - ' + str(detail)) if detail else ''}")


def labels(plan):
    return [s.label for s in plan.steps]


def unit_tests():
    S = suite
    print("=== planning: only confirmed bindings run ===")
    check("no confirmation -> nothing runs, nothing is skipped-with-reason (there is no plan yet)",
          S.plan_steps(amounts=["a"], identifier="i", entity_name="n", confirmed_by=None) == S.Plan((), ()))
    check("a blank name is not a confirmation",
          not S.plan_steps(amounts=["a"], identifier="i", entity_name="n", confirmed_by="   ").steps)
    p = S.plan_steps(amounts=["a"], identifier="i", entity_name="n", confirmed_by="A. Reviewer")
    check("all roles bound: benford, duplicate (shared-identifier) and fuzzy, in a fixed order",
          labels(p) == ["benford:a", "duplicate-analysis:i", "fuzzy-entity-match:i"], labels(p))
    check("benford carries the confirmer's name", p.steps[0].extra == ("--confirmed-by", "A. Reviewer"))
    check("duplicate and fuzzy pair the identifier with the entity name",
          p.steps[1].extra == ("--distinct-of", "n") and p.steps[2].extra == ("--distinct-of", "n"))
    check("cross-dataset-match is always listed as needing a second table",
          {"method": "cross-dataset-match", "why": S.NEEDS_SECOND_TABLE} in p.skipped)
    p = S.plan_steps(amounts=[], identifier="i", entity_name=None, confirmed_by="X")
    check("identifier only: plain duplicate runs; fuzzy is skipped for the missing name role; benford for the missing amount",
          labels(p) == ["duplicate-analysis:i"] and p.steps[0].extra == ()
          and {"method": "fuzzy-entity-match", "why": "NEEDS_ROLE_ENTITY_NAME"} in p.skipped
          and {"method": "benford", "why": "NEEDS_ROLE_AMOUNT"} in p.skipped, (labels(p), p.skipped))
    p = S.plan_steps(amounts=["a"], identifier=None, entity_name="n", confirmed_by="X")
    check("no identifier: duplicate and fuzzy are skipped with the reason, an entity name alone runs nothing",
          labels(p) == ["benford:a"] and {"method": "duplicate-analysis", "why": "NEEDS_ROLE_IDENTIFIER"} in p.skipped)
    p = S.plan_steps(amounts=["a", "b", "a"], identifier=None, entity_name=None, confirmed_by="X")
    check("a repeated amount column runs once", labels(p) == ["benford:a", "benford:b"])
    p = S.plan_steps(amounts=[f"c{i}" for i in range(12)], identifier=None, entity_name=None, confirmed_by="X")
    check("more than 8 amount columns: the first 8 run and the rest are counted as skipped",
          len(p.steps) == 8 and {"method": "benford", "why": "TOO_MANY_AMOUNT_COLUMNS", "n": 4} in p.skipped, p.skipped)

    print("\n=== folding one method's result ===")
    full = {"method": "benford@1.1.0", "status": "completed", "verdict": "SUPPORTED", "dataset": {"id": 3, "basis": "content"},
            "scanned": 900, "findings": 1, "class": "ANOMALY", "summary": {"mad": 0.02},
            "top": [{"kind": "k", "strength": 0.9, "subject": "grp:a"}, {"kind": "k", "strength": 0.5, "subject": "grp:b"},
                    {"kind": "k", "strength": 0.1, "subject": "grp:c"}], "signals": 3,
            "finding_ids": [7], "run": 5, "evidence": {"key": ["id"], "links": 12}, "limits": "benford@1.1.0"}
    e = S.summarise_step(S.Step("benford", "amt"), full)
    check("keeps the method, column, status, class, summary and the pointers",
          e["m"] == "benford" and e["col"] == "amt" and e["status"] == "completed" and e["class"] == "ANOMALY"
          and e["run"] == 5 and e["finding_ids"] == [7] and e["links"] == 12 and e["dataset"] == {"id": 3, "basis": "content"}, e)
    check("only the two strongest signals are kept", len(e["top"]) == 2 and e["signals"] == 3)
    check("nothing else leaks through (no repeated limits pointer)", "limits" not in e and "findings" not in e)
    check("a shared-identifier step records the entity-name column",
          S.summarise_step(S.Step("duplicate-analysis", "i", ("--distinct-of", "n"), "n"), full)["by"] == "n")
    err = S.error_entry(S.Step("benford", "a"), "X_Y", "r" * 500)
    check("an error entry is bounded", err["status"] == "error" and len(err["reason"]) == 200)

    print("\n=== folding the suite ===")
    ok = lambda m, c, cls, ds=(1, "content"), **k: {"m": m, "col": c, "status": "completed", "class": cls,
                                                     "dataset": {"id": ds[0], "basis": ds[1]}, "run": 1, **k}
    entries = [ok("benford", "a", "ANOMALY"), {"m": "benford", "col": "b", "status": "declined", "verdict": "NOT_APPLICABLE", "why": ["X_Y"]},
               {"m": "duplicate-analysis", "col": "i", "status": "refused", "code": "NO_SUCH_COLUMN", "reason": "r"},
               {"m": "fuzzy-entity-match", "col": "i", "status": "error", "code": "STATEMENT_TIMEOUT", "reason": "r"},
               ok("benford", "c", "OBSERVATION"), ok("benford", "d", "ANOMALY")]
    f = S.fold(entries, [{"m": "x"}], table="public.t", confirmed_by="A. Reviewer")
    check("every method lands in exactly one bucket, in plan order",
          [e["col"] for e in f["ran"]] == ["a", "c", "d"] and len(f["declined"]) == 1 and len(f["refused"]) == 1 and len(f["errors"]) == 1)
    check("counts planned and anomalies (declined and refused methods are not anomalies)", f["planned"] == 6 and f["anomalies"] == 2, (f["planned"], f["anomalies"]))
    check("one dataset version is reported once", f["dataset"] == {"id": 1, "basis": "content"} and "warn" not in f)
    f2 = S.fold([ok("benford", "a", "ANOMALY", (1, "content")), ok("benford", "b", "ANOMALY", (2, "content"))], [], table="t", confirmed_by="X")
    check("results on different dataset versions are flagged, not merged",
          "dataset" not in f2 and f2["warn"] == ["DATASET_CHANGED_DURING_SUITE"] and f2["dataset_versions"] == [1, 2], f2)
    check("a suite with nothing run has no dataset and no empty buckets",
          "ran" not in S.fold([], [], table="t", confirmed_by="X"))
    check("an unknown status is treated as an error, never dropped",
          len(S.fold([{"m": "b", "col": "a", "status": "weird"}], [], table="t", confirmed_by="X")["errors"]) == 1)

    print("\n=== fitting the budget ===")
    big = [ok("benford", f"c{i}", "ANOMALY", top=[{"kind": "k", "strength": 0.5, "subject": "grp:x", "metrics": {"m": 1}}] * 2,
              summary={f"k{j}": j for j in range(14)}) for i in range(8)]
    folded = S.fold(big, [], table="t", confirmed_by="X")
    before = S.size(folded)
    fitted = S.fit(folded, max_chars=before - 300)
    check("fit never modifies its input", S.size(folded) == before and "trimmed" not in folded)
    check("trims the extra signals first, and says what it trimmed",
          S.size(fitted) <= before - 300 and fitted["trimmed"][0] == "top", (before, S.size(fitted), fitted.get("trimmed")))
    check("never drops a method or its verdict", len(fitted["ran"]) == 8 and all(e["status"] == "completed" for e in fitted["ran"]))
    import copy
    no_top = S.fold(copy.deepcopy(big), [], table="t", confirmed_by="X")
    for e in no_top["ran"]:
        e.pop("top", None)
    size_no_top = S.size(no_top)
    for e in no_top["ran"]:
        e.pop("summary", None)
    folded = S.fold(copy.deepcopy(big), [], table="t", confirmed_by="X")
    tight = S.fit(folded, max_chars=(size_no_top + S.size(no_top)) // 2)
    check("then trims summaries, last method first, still keeping every method",
          "summary" in tight["trimmed"] and len(tight["ran"]) == 8 and "summary" in tight["ran"][0] and "summary" not in tight["ran"][-1], tight.get("trimmed"))
    try:
        S.fit(S.fold(big, [], table="t", confirmed_by="X"), max_chars=100)
        check("an impossible budget is refused, not silently exceeded", False)
    except ValueError:
        check("an impossible budget is refused, not silently exceeded", True)
    check("the default budget holds for a realistic full suite",
          S.size(S.fit(S.fold(big, [], table="t", confirmed_by="X"))) <= S.MAX_SUITE_CHARS)

    print("\n=== proposals bind nothing ===")
    sug = {"amount": [Suggestion("amount", f"a{i}", "strong", ("name",)) for i in range(6)],
           "identifier": [Suggestion("identifier", "id", "strong", ("primary_key",))], "entity_name": [], "date": [], "sensitive_id": []}
    pr = S.proposals(sug, {"aadhaar_no": "aadhaar", "bank_acct": "account"})
    check("at most 3 proposals per role, with their support label, and empty roles omitted",
          len(pr["amount"]) == 3 and pr["amount"][0] == {"column": "a0", "support": "strong"} and "entity_name" not in pr and "date" not in pr, pr)
    check("sensitive columns are counted and named (names only)", pr["sensitive"] == {"n": 2, "columns": ["aadhaar_no", "bank_acct"]})

    print("\n=== running one step ===")
    import run_suite
    py = sys.executable
    r, code, _ = run_suite.run_step([py, "-c", "import json;print(json.dumps({'status':'completed','x':1}))"], 20)
    check("a usable result is passed through", r == {"status": "completed", "x": 1} and code == "")
    r, code, reason = run_suite.run_step([py, "-c", "import time;time.sleep(30)"], 1)
    check("a method that overruns is stopped and reported, not waited for", r is None and code == "SUITE_METHOD_TIMEOUT", (code, reason))
    r, code, _ = run_suite.run_step([py, "-c", "print('not json')"], 20)
    check("output that is not JSON is reported without echoing it", r is None and code == "SUITE_BAD_OUTPUT")
    r, code, reason = run_suite.run_step([py, "-c", "print('{}')"], 20)
    check("a JSON reply without a status is rejected", r is None and code == "SUITE_BAD_OUTPUT")
    r, code, reason = run_suite.run_step([py, "-c", "import sys;sys.stderr.write('SECRET 123456789012');print('not json')"], 20)
    check("stderr (which can carry data) is never echoed", r is None and "SECRET" not in reason and "123456789012" not in reason, reason)
    r, code, _ = run_suite.run_step([py, "-c", "print('[1,2]')"], 20)
    check("a JSON list is rejected", r is None and code == "SUITE_BAD_OUTPUT")


def integration_tests():
    import psycopg2
    from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
    from forensic_platform.core.config import find_mcp_config, load_mcp_config, superuser_dsn

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
            CREATE TABLE pay AS SELECT i AS id, 'E' || (i % 40) AS emp_code,
                CASE WHEN i % 40 < 8 THEN 'PERSON ' || chr(65 + (i % 7)) || chr(75 + (i % 5)) ELSE 'STAFF ' || i END AS name,
                round(power(10, random()*4)::numeric, 2) AS amount,
                (100 + (i % 5))::numeric AS small_amt,
                (100000000000 + i * 7919)::text AS aadhaar
              FROM generate_series(1, 3000) i;
            ALTER TABLE pay ADD PRIMARY KEY (id);
            CREATE TABLE big_est (a int);
            INSERT INTO big_est SELECT generate_series(1, 20);
            GRANT SELECT ON ALL TABLES IN SCHEMA public TO forensic_app;
        ''')
        cur.execute("UPDATE pg_class SET reltuples = 9000000 WHERE oid = 'big_est'::regclass")
        env = {**os.environ, "FORENSIC_MCP_CONFIG": str(cfg_path), "FORENSIC_MASK_SALT": "t" * 40}
        env.pop("FORENSIC_LEGACY_OUTPUT", None)

        def suite_run(*extra, table="pay", e=None):
            p = subprocess.run([sys.executable, str(ENGINE / "scripts" / "run_suite.py"), "--database", scratch,
                                "--schema", "public", "--table", table, *extra], capture_output=True, text=True, env=e or env)
            try:
                return json.loads(p.stdout), p.stdout
            except ValueError:
                return {"status": "NOT-JSON", "stderr": p.stderr[-300:]}, p.stdout

        def one(q, *params):
            cur.execute(q, params)
            return cur.fetchone()[0]

        raw = ("PERSON A", "STAFF 1", "100000007919", "E7")
        full = ["--amount", "amount", "--amount", "small_amt", "--identifier", "emp_code", "--entity-name", "name",
                "--confirmed-by", "A. Reviewer"]

        print("\n--- without a confirmation: proposals only, nothing runs ---")
        runs0 = one("SELECT count(*) FROM _forensic.test_runs")
        r, out = suite_run()
        check("status needs_confirmation, with a small profile and proposals",
              r.get("status") == "needs_confirmation" and r["profile"]["rows"] == 3000 and "propose" in r, r.get("status"))
        check("amount is proposed (strong) and the Aadhaar-shaped text column is proposed only as sensitive",
              r["propose"]["amount"][0]["column"] in ("amount", "small_amt") and "aadhaar" in r["propose"]["sensitive"]["columns"]
              and "aadhaar" not in [x["column"] for role in ("amount", "identifier", "entity_name") for x in r["propose"].get(role, [])], r.get("propose"))
        check("nothing was run or recorded as a test run", one("SELECT count(*) FROM _forensic.test_runs") == runs0)
        check("the decision is audit-logged", one("SELECT count(*) FROM _forensic.audit_log WHERE operation='suite' AND error_text='NEEDS_CONFIRMATION'") == 1)
        check("no data value appears in the reply", not any(v in out for v in raw) and "\n" not in out.strip() and len(out) < 1500, len(out))
        r, out = suite_run("--amount", "amount", "--identifier", "emp_code")
        check("columns supplied WITHOUT a confirmer are pending, not run", r["status"] == "needs_confirmation"
              and r["pending"] == {"amount": ["amount"], "identifier": "emp_code"} and one("SELECT count(*) FROM _forensic.test_runs") == runs0, r.get("pending"))
        r, _ = suite_run("--confirmed-by", "A. Reviewer")
        check("a confirmer with no columns runs nothing either", r["status"] == "needs_confirmation" and one("SELECT count(*) FROM _forensic.test_runs") == runs0)

        print("\n--- confirmed: every applicable method runs, one combined reply ---")
        r, out = suite_run(*full)
        by = {f"{e['m']}:{e['col']}": e for bucket in ("ran", "declined", "refused", "errors") for e in r.get(bucket, [])}
        check("completed; 4 planned; one line within the budget",
              r.get("status") == "completed" and r["planned"] == 4 and "\n" not in out.strip() and len(out) <= suite.MAX_SUITE_CHARS, (r.get("status"), len(out)))
        print(f"  combined reply for 4 planned methods: {len(out)} chars (~{len(out) // 4} tokens, ESTIMATE)")
        check("benford ran on the log-uniform amount column", by["benford:amount"]["status"] == "completed", by.get("benford:amount"))
        check("benford declined the 5-value column, with the reason, and the others were unaffected",
              by["benford:small_amt"]["status"] == "declined" and "FEW_DISTINCT_VALUES" in by["benford:small_amt"]["why"]
              and by["duplicate-analysis:emp_code"]["status"] == "completed" and by["fuzzy-entity-match:emp_code"]["status"] == "completed", by.get("benford:small_amt"))
        check("cross-dataset-match is listed as skipped for needing a second table",
              {"method": "cross-dataset-match", "why": "NEEDS_SECOND_TABLE"} in r["skipped"])
        check("all results are about one dataset version, reported once", r["dataset"]["basis"] == "content" and "warn" not in r, r.get("dataset"))
        check("anomalies counts the ANOMALY-classified methods", r["anomalies"] == sum(1 for e in r["ran"] if e["class"] == "ANOMALY"))
        for e in r["ran"]:
            row = None
            cur.execute("SELECT test_name, dataset_id FROM _forensic.test_runs WHERE run_id = %s", (e["run"],))
            row = cur.fetchone()
            check(f"{e['m']}:{e['col']}: its run is recorded for that method and dataset", row == (e["m"], r["dataset"]["id"]), row)
        check("each method that ran left its own run (3 runs; the declined one left none)",
              one("SELECT count(*) FROM _forensic.test_runs") == runs0 + 3)
        cur.execute("SELECT params_json FROM _forensic.audit_log WHERE operation='suite' AND status='success'")
        audit = cur.fetchone()[0]
        check("one suite audit row lists the steps, the runs and the confirmer",
              len(audit["steps"]) == 4 and sorted(audit["runs"]) == sorted(e["run"] for e in r["ran"]) and audit["confirmed_by"] == "A. Reviewer", audit.get("steps"))
        check("no data value appears in the combined reply", not any(v in out for v in raw))
        r2, _ = suite_run(*full)
        strip = lambda d: json.loads(json.dumps(d), object_hook=lambda o: {k: v for k, v in o.items() if k not in ("run", "finding_ids")})
        check("deterministic: same data and arguments give the same reply apart from run and finding ids", strip(r) == strip(r2))

        print("\n--- isolation: one bad step does not stop the others ---")
        r, _ = suite_run("--amount", "nope_col", "--amount", "amount", "--confirmed-by", "A. Reviewer")
        check("a missing column is a refused entry with its code; the real column still ran",
              r["refused"][0]["code"] == "NO_SUCH_COLUMN" and r["ran"][0]["col"] == "amount", r.get("refused"))
        r, _ = suite_run("--identifier", "emp_code", "--confirmed-by", "A. Reviewer")
        check("identifier only: duplicate ran; fuzzy skipped for the missing entity-name role",
              r["ran"][0]["m"] == "duplicate-analysis" and {"method": "fuzzy-entity-match", "why": "NEEDS_ROLE_ENTITY_NAME"} in r["skipped"], r.get("skipped"))
        runs1 = one("SELECT count(*) FROM _forensic.test_runs")
        r, _ = suite_run("--amount", "amount", "--confirmed-by", "A. Reviewer", "--timeout-seconds", "0")
        check("a method that overruns its time is reported as an error entry and the suite still replies",
              r["status"] == "completed" and r["errors"][0]["code"] == "SUITE_METHOD_TIMEOUT", r.get("errors"))

        print("\n--- refusals and limits ---")
        r, _ = suite_run(table="t" * 70)
        check("an unsafe name is refused with a code", r.get("status") == "refused" and r.get("code") == "UNSAFE_IDENTIFIER", r)
        r, _ = suite_run(table="nope")
        check("a missing table is refused, and the refusal is audit-logged",
              r.get("code") == "NO_SUCH_TABLE" and one("SELECT count(*) FROM _forensic.audit_log WHERE operation='suite' AND status='refused'") == 1, r)
        r, _ = suite_run(*full, e={**env, "FORENSIC_STATEMENT_TIMEOUT_MS": "banana"})
        check("a bad timeout setting is BAD_CONFIGURATION", r.get("code") == "BAD_CONFIGURATION", r)
        r, _ = suite_run(table="big_est")
        check("a table estimated over the row limit is declined UNSAFE_TO_RUN before any scan",
              r.get("status") == "declined" and r.get("verdict") == "UNSAFE_TO_RUN" and r["why"] == ["TABLE_TOO_LARGE_TO_PROFILE"], r)
        r, _ = suite_run("--allow-large-profile", table="big_est")
        check("--allow-large-profile lets the profile proceed", r.get("status") == "needs_confirmation", r.get("status"))
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

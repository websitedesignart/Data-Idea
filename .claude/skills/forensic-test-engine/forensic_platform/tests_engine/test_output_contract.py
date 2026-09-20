"""
Tests for what Claude actually receives: run_test.py's default output is the one compact contract
result for every method, every refusal and every error.

    python forensic_platform/tests_engine/test_output_contract.py                  # unit tests
    python forensic_platform/tests_engine/test_output_contract.py --integration    # + scratch database

--integration creates its own scratch database (forensic_test_<hex>), runs the real run_test.py
entry point against it, and always drops it.

What must hold: every pointer in a result (run, finding, dataset, evidence) resolves to a real
record; constant text is a pointer, not repeated; refusals and errors share one shape with a stable
code; results are deterministic; and the previous shapes are still available behind a flag while
callers move over.
"""
import importlib.util
import io
import json
import os
import subprocess
import sys
import uuid
from contextlib import redirect_stdout
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE.parent))

from forensic_platform.core.contract import ContractViolation, MAX_RESULT_CHARS  # noqa: E402

failures = 0


def check(label, ok, detail=""):
    global failures
    if not ok:
        failures += 1
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}{(' - ' + str(detail)) if detail else ''}")


def load_run_test():
    spec = importlib.util.spec_from_file_location("run_test_under_test", ENGINE / "scripts" / "run_test.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def unit_tests():
    import argparse
    print("=== a presentation failure is reported, never printed raw ===")
    rt = load_run_test()
    args = argparse.Namespace(subtest="benford", legacy_output=False)

    def boom():
        raise ContractViolation("too big")

    buf = io.StringIO()
    with redirect_stdout(buf):
        rt._emit(args, {"secret": "123456789012"}, boom)
    out = json.loads(buf.getvalue())
    check("a result that breaks the contract becomes an error result with a code",
          out["status"] == "error" and out["code"] == "RESULT_NOT_PRESENTABLE" and out["method"].startswith("benford@"), out)
    check("the legacy payload is not leaked as a fallback", "123456789012" not in buf.getvalue())
    buf = io.StringIO()
    with redirect_stdout(buf):
        rt._emit(argparse.Namespace(subtest="benford", legacy_output=True), {"a": 1}, boom)
    check("--legacy-output prints the previous shape without touching the contract", json.loads(buf.getvalue()) == {"a": 1})
    from forensic_platform.core import present
    check("an invalid method name still yields a valid refusal", present.refused("Bad Name!", None, "X_Y", "r")["method"] == "engine@0.0.0")

    print("\n=== describe_method: the pointer resolves ===")
    sys.path.insert(0, str(ENGINE / "scripts"))
    import describe_method
    d = describe_method.describe("benford@1.1.0")
    check("a result's `limits` pointer resolves to the registered limitations",
          d["method"] == "benford@1.1.0" and "Not valid for columns" in d["limitations"] and "\n" not in d["limitations"], d.get("method"))
    check("a bare method name works", describe_method.describe("duplicate-analysis")["status"] == "implemented")
    check("an unknown method is refused", describe_method.describe("nope")["status"] == "refused")
    check("a stale version is noted, not silently accepted", "note" in describe_method.describe("benford@0.9.0"))


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
            CREATE TABLE t_num AS SELECT g AS id, round(power(10, random()*4)::numeric, 2) AS amount FROM generate_series(1, 3000) g;
            ALTER TABLE t_num ADD PRIMARY KEY (id);
            CREATE TABLE t_skew AS SELECT g AS id, round(((1 + floor(random()*9)) * power(10, floor(random()*4)) * (1 + random()*0.09))::numeric, 2) AS amount FROM generate_series(1, 3000) g;
            ALTER TABLE t_skew ADD PRIMARY KEY (id);
            CREATE TABLE t_people (id serial PRIMARY KEY, reg text, name text);
            INSERT INTO t_people (reg, name)
              SELECT 'R' || (i % 40), CASE WHEN i % 40 < 8 THEN 'PERSON ' || chr(65 + (i % 7)) || chr(75 + (i % 5)) ELSE 'STAFF ' || i END
              FROM generate_series(1, 300) i;
            CREATE TABLE t_left (id serial PRIMARY KEY, ref text);
            INSERT INTO t_left (ref) SELECT 'K' || i FROM generate_series(1, 120) i;
            CREATE TABLE t_right (id serial PRIMARY KEY, ref text);
            INSERT INTO t_right (ref) SELECT 'K' || i FROM generate_series(1, 100) i;
            CREATE TABLE t_nokey (a text, b numeric);
            INSERT INTO t_nokey VALUES ('x', 1), ('y', 2);
            GRANT SELECT ON ALL TABLES IN SCHEMA public TO forensic_app;
            -- finding ids and run ids must differ, or a swapped id would still 'resolve'
            SELECT setval(pg_get_serial_sequence('_forensic.findings', 'finding_id'), 100);
        ''')
        base_env = {**os.environ, "FORENSIC_MCP_CONFIG": str(cfg_path), "FORENSIC_MASK_SALT": "t" * 40}
        base_env.pop("FORENSIC_LEGACY_OUTPUT", None)

        def run(*args, env=None):
            p = subprocess.run([sys.executable, str(ENGINE / "scripts" / "run_test.py"), "--database", scratch,
                                "--schema", "public", *args], capture_output=True, text=True, env=env or base_env)
            try:
                return json.loads(p.stdout), p.stdout
            except ValueError:
                return {"status": "NOT-JSON", "stderr": p.stderr[-300:]}, p.stdout

        def one(sql_text, *params):
            cur.execute(sql_text, params)
            return cur.fetchone()

        cases = [
            ("benford", ["--subtest", "benford", "--table", "t_skew", "--column", "amount", "--confirmed-by", "A. Reviewer"]),
            ("duplicate-analysis", ["--subtest", "duplicate-analysis", "--table", "t_people", "--column", "reg", "--distinct-of", "name"]),
            ("fuzzy-entity-match", ["--subtest", "fuzzy-entity-match", "--table", "t_people", "--column", "reg", "--distinct-of", "name"]),
            ("cross-dataset-match", ["--subtest", "cross-dataset-match", "--table", "t_left", "--column", "ref",
                                     "--right-table", "t_right", "--right-column", "ref"]),
        ]
        print("\n--- every method: one compact shape, every pointer resolves ---")
        outputs = {}
        for name, args in cases:
            r, out = run(*args)
            outputs[name] = (r, out)
            check(f"{name}: one line, completed, within the {MAX_RESULT_CHARS}-character budget",
                  r.get("status") == "completed" and "\n" not in out.strip() and len(out) <= MAX_RESULT_CHARS, (r.get("status"), len(out)))
            check(f"{name}: `limits` points at the registered method, and describe_method resolves it",
                  r.get("limits", "").startswith(name + "@") and subprocess.run(
                      [sys.executable, str(ENGINE / "scripts" / "describe_method.py"), r.get("limits", "")],
                      capture_output=True, text=True).stdout.count('"limitations"') == 1, r.get("limits"))
            check(f"{name}: no repeated constant text in the result", "limitations" not in out and "query_text" not in out and "Duplication is" not in out)
            run_row = one("SELECT test_name, test_version, dataset_id, records_examined FROM _forensic.test_runs WHERE run_id = %s", r["run"])
            check(f"{name}: `run` is a real test run for this method, version and dataset",
                  run_row is not None and run_row[0] == name and f"{run_row[0]}@{run_row[1]}" == r["limits"]
                  and run_row[2] == r["dataset"]["id"] and run_row[3] == r["scanned"], run_row)
            fid = r["finding_ids"][0]
            frow = one("SELECT classification, run_id FROM _forensic.findings WHERE finding_id = %s", fid)
            check(f"{name}: `finding_ids` resolve, and `class` equals the recorded finding's classification",
                  frow is not None and frow[0] == r["class"] and frow[1] == r["run"], (frow, r.get("class")))
            drow = one("SELECT table_hash, notes FROM _forensic.datasets WHERE dataset_id = %s", r["dataset"]["id"])
            check(f"{name}: dataset version is a real content-fingerprinted one", r["dataset"]["basis"] == "content" and str(drow[0]).startswith("s56:"), drow)
            if name != "benford":
                links = one("SELECT count(*) FROM _forensic.evidence_links WHERE finding_id = %s", fid)[0]
                check(f"{name}: `evidence.links` equals the evidence rows recorded; the key is the primary key",
                      r["evidence"]["links"] == links and r["evidence"]["key"] == ["id"] and links > 0, (r.get("evidence"), links))

        print("\n--- the signals ---")
        r = outputs["benford"][0]
        check("benford on digit-skewed data: ANOMALY with one digit_distribution signal naming the worst digit",
              r["class"] == "ANOMALY" and r["top"][0]["kind"] == "digit_distribution"
              and {"mad", "worst_digit", "observed_pct", "expected_pct"} <= set(r["top"][0]["metrics"]), r.get("top"))
        check("benford: the signal's strength is the MAD (an effect size, not a probability)",
              abs(r["top"][0]["strength"] - r["summary"]["mad"]) < 1e-4 and r["top"][0]["metrics"]["mad"] == r["summary"]["mad"], (r["top"][0]["strength"], r["summary"]["mad"]))
        check("benford: summary carries the statistics and says thresholds are unvalidated",
              r["summary"]["thresholds"] == "unvalidated" and r["summary"]["conformity"] in ("nonconformity", "marginally_acceptable_conformity")
              and r["summary"]["reliable"] is True, r["summary"])
        r, _ = run("--subtest", "benford", "--table", "t_num", "--column", "amount", "--confirmed-by", "A. Reviewer")
        check("benford on Benford-like data: OBSERVATION and no signals", r["class"] == "OBSERVATION" and "top" not in r, r.get("class"))
        r = outputs["duplicate-analysis"][0]
        check("duplicate-analysis: signals are masked references only, strongest first",
              r["class"] == "ANOMALY" and all(t["subject"].startswith("ref:") and len(t["subject"]) == 16 for t in r["top"])
              and [t["strength"] for t in r["top"]] == sorted((t["strength"] for t in r["top"]), reverse=True), r.get("top"))
        check("duplicate-analysis: 5 shown of the total, marked truncated when more exist",
              len(r["top"]) <= 5 and r["signals"] >= len(r["top"]) and (r["signals"] == len(r["top"]) or r.get("top_truncated") is True))
        r = outputs["cross-dataset-match"][0]
        check("cross-dataset-match: orphans on the left only -> ANOMALY, 20 keys, counts in the summary",
              r["class"] == "ANOMALY" and r["summary"]["only_left"] == 20 and r["summary"]["only_right"] == 0
              and r["top"][0]["subject"] == "grp:left_keys" and r["top"][0]["metrics"] == {"count": 20}, (r.get("summary"), r.get("top")))

        print("\n--- smaller than the previous shapes, and the same facts ---")
        legacy_env = {**base_env, "FORENSIC_LEGACY_OUTPUT": "1"}
        total_old = total_new = 0
        for name, args in cases:
            new_r, new_out = outputs[name]
            old_r, old_out = run(*args, env=legacy_env)
            total_old += len(old_out)
            total_new += len(new_out)
            check(f"{name}: shorter than the previous shape ({len(old_out)} -> {len(new_out)} chars)", len(new_out) < len(old_out))
            if name == "benford":
                obs, exp = old_r["digit_observed_pct"], old_r["digit_expected_pct"]
                worst = max(obs, key=lambda d: abs(obs[d] - exp[d]))
                sig = new_r["top"][0]["metrics"]
                check("benford: the reported worst digit is the one that deviates most, with its true percentages",
                      sig["worst_digit"] == int(worst) and abs(sig["observed_pct"] - 100 * obs[worst]) < 0.01
                      and abs(sig["expected_pct"] - 100 * exp[worst]) < 0.01, (sig, worst))
                check("benford: the same MAD and conformity as the previous shape",
                      old_r["mad"] == new_r["summary"]["mad"] and old_r["conformity"].replace(" ", "_") == new_r["summary"]["conformity"])
            if name == "duplicate-analysis":
                check("same facts as the previous shape (flagged keys and rows)",
                      old_r["flagged_keys"] == new_r["summary"]["flagged_keys"] and old_r["flagged_rows"] == new_r["summary"]["flagged_rows"])
                check("the previous shape is still 'success' with its own fields", old_r["status"] == "success" and "top_groups" in old_r)
        print(f"  all four together: {total_old} -> {total_new} chars (~{total_old // 4} -> ~{total_new // 4} tokens, ESTIMATE)")
        r, out = run(*cases[1][1], "--legacy-output")
        check("--legacy-output works as a flag too", r.get("status") == "success" and "\n" in out)

        print("\n--- determinism ---")
        a, _ = run(*cases[1][1])
        b, _ = run(*cases[1][1])
        strip = lambda d: {k: v for k, v in d.items() if k not in ("run", "finding_ids")}
        check("the same data and arguments give the same result apart from the new run and finding ids", strip(a) == strip(b))
        check("...against the same dataset version (no new version for unchanged data)", a["dataset"] == b["dataset"])

        print("\n--- refusals: one shape, a stable code, a reason ---")
        for label, args, code in (
                ("a table with no usable row identity", ["--subtest", "duplicate-analysis", "--table", "t_nokey", "--column", "a"], "NO_ROW_IDENTITY"),
                ("a text column given to benford", ["--subtest", "benford", "--table", "t_people", "--column", "name"], "WRONG_COLUMN_TYPE"),
                ("a missing column", ["--subtest", "duplicate-analysis", "--table", "t_people", "--column", "nope"], "NO_SUCH_COLUMN"),
                ("a missing table", ["--subtest", "benford", "--table", "nope", "--column", "amount"], "NO_SUCH_TABLE"),
                ("an unsafe identifier (over 63 bytes)", ["--subtest", "benford", "--table", "t" * 70, "--column", "amount"], "UNSAFE_IDENTIFIER"),
                ("a legal but awkward name is quoted, not executed", ["--subtest", "benford", "--table", 'x"; DROP TABLE t_num; --', "--column", "amount"], "NO_SUCH_TABLE"),
                ("a missing argument", ["--subtest", "fuzzy-entity-match", "--table", "t_people", "--column", "reg"], "MISSING_ARGUMENT"),
                ("an unimplemented subtest", ["--subtest", "outlier", "--table", "t_num", "--column", "amount"], "NOT_IMPLEMENTED"),
                ("a missing right table", ["--subtest", "cross-dataset-match", "--table", "t_left", "--column", "ref",
                                           "--right-table", "nope", "--right-column", "ref"], "NO_SUCH_TABLE")):
            r, out = run(*args)
            check(f"{label}: refused with code {code}",
                  r.get("status") == "refused" and r.get("code") == code and r.get("reason", "").endswith("Nothing was executed.")
                  and "method" in r and len(out) < 500 and "\n" not in out.strip(), r)
        r, _ = run("--subtest", "benford", "--table", "t_num", "--column", "amount", "--confirmed-by", "A. Reviewer",
                   env={**base_env, "FORENSIC_STATEMENT_TIMEOUT_MS": "banana"})
        check("a bad timeout setting is a refusal with BAD_CONFIGURATION", r.get("status") == "refused" and r.get("code") == "BAD_CONFIGURATION", r)
        check("the injected DROP TABLE never ran", one("SELECT count(*) FROM t_num")[0] == 3000)
        check("a table that does not exist leaves no permanent dataset row",
              one("SELECT count(*) FROM _forensic.datasets WHERE source_table = 'nope'")[0] == 0)
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

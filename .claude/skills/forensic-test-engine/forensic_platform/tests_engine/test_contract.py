"""
Tests for the result contract (core/contract.py).

    python forensic_platform/tests_engine/test_contract.py                  # unit tests only
    python forensic_platform/tests_engine/test_contract.py --integration    # + the four real methods

--integration creates its own uniquely named scratch database (forensic_test_<hex>), runs the
four real methods against it, builds a contract result for each, and compares its size with what
run_test.py prints today. It always drops the database afterwards, and connects only to the
maintenance database and to the scratch database. It needs the project's .mcp.json (found by
walking up from the working directory, or $FORENSIC_MCP_CONFIG).
"""
import dataclasses
import hashlib
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


def rejects(label, fn, must_mention=""):
    from forensic_platform.core.contract import ContractViolation
    try:
        fn()
        check(label, False, "was accepted")
    except ContractViolation as exc:
        check(label, must_mention.lower() in str(exc).lower(), str(exc)[:90])
    except Exception as exc:  # any other exception type is a bug in the contract itself
        check(label, False, f"{type(exc).__name__}: {exc}")


def mask(value) -> str:
    """Test-local stand-in for core.masking: 12 letters from a hash."""
    return "".join(chr(97 + b % 26) for b in hashlib.sha256(str(value).encode()).digest()[:12])


def unit_tests():
    from forensic_platform.core import contract as C
    from forensic_platform.core.contract import (
        Classification, DatasetVersion, EvidenceInfo, MethodRef, MethodResult, RowIdentitySpec,
        Signal, Status, Subject, Verdict)

    M = MethodRef("duplicate-analysis", "1.0.0")
    DS = DatasetVersion(7, "content", "s56:189:7052264672013575444")
    EV = EvidenceInfo(True, RowIdentitySpec(("row_id",), "primary_key"), 14)

    def sig(i, strength):
        return Signal("shared_identifier", strength, Subject.masked(mask(i)), {"rows": 2, "distinct": 2})

    def ok(signals=(), **over):
        kw = dict(method=M, dataset=DS, verdict=Verdict.SUPPORTED, classification=Classification.ANOMALY,
                  records_scanned=189, findings_count=7, summary={"flagged_keys": 7, "flagged_rows": 14},
                  finding_ids=(812,), run_id=41, evidence=EV, signals=list(signals))
        kw.update(over)
        return MethodResult.build(**kw)

    print("=== a valid result: compact, stable, pointer-based ===")
    r = ok([sig(1, 0.4), sig(2, 0.9), sig(3, 0.9)])
    text = r.to_json()
    check("compact JSON (no spaces), method and dataset named", " " not in text and "duplicate-analysis@1.0.0" in text and '"dataset":{"id":7,"basis":"content"}' in text, text[:90])
    check("constant text is a pointer, not repeated", '"limits":"duplicate-analysis@1.0.0"' in text and "SELECT" not in text)
    check("the fingerprint stays out of what Claude sees", "s56" not in text)
    check("evidence says how rows are keyed, never the rows", '"evidence":{"key":["row_id"],"links":14}' in text)
    check("same inputs give byte-identical output", ok([sig(1, 0.4), sig(2, 0.9), sig(3, 0.9)]).to_json() == text)
    check("strongest first; ties broken by subject", [s["strength"] for s in json.loads(text)["top"]] == [0.9, 0.9, 0.4])
    check("a typical result is small", r.estimated_tokens() < 250, f"~{r.estimated_tokens()} tokens (ESTIMATE)")

    print("\n=== size budget ===")
    many = ok([sig(i, 0.5 + i / 100) for i in range(40)])
    d = json.loads(many.to_json())
    check("40 signals -> top 5 kept, total remembered, truncation flagged", len(d["top"]) == 5 and d["signals"] == 40 and d["top_truncated"] is True)
    small = ok([sig(i, 0.5) for i in range(5)], max_chars=650)
    check("build() trims the weakest signals to fit a smaller budget", len(small.to_json()) <= 650 and 0 < len(small.top_signals) < 5, len(small.top_signals))
    rejects("a result that cannot fit even with one signal is refused", lambda: ok([sig(1, 0.5)], max_chars=60), "fit")

    print("\n=== the engine never concludes ===")
    for c in (Classification.REVIEW_REQUIRED, Classification.SUPPORTED_EXCEPTION, Classification.UNRESOLVED,
              Classification.INVESTIGATION_LEAD, Classification.CONCLUSION):
        rejects(f"result classified {c.value} rejected", lambda c=c: ok(classification=c), "only emit")
    rejects("signal classified CONCLUSION rejected", lambda: Signal("x", 0.5, Subject.group("g"), classification=Classification.CONCLUSION), "only emit")
    rejects("ANOMALY with zero findings rejected", lambda: ok(findings_count=0), "at least one finding")

    print("\n=== no raw identifiers ===")
    rejects("a raw string is not a subject", lambda: Signal("x", 0.5, "123412341234"), "not a raw value")
    rejects("Aadhaar-shaped digits cannot be a masked subject", lambda: Subject.masked("123412341234"), "letters")
    rejects("hex is not accepted either", lambda: Subject.masked("0a1b2c3d4e5f"), "letters")
    rejects("wrong-length token rejected", lambda: Subject.masked("abc"), "letters")
    try:
        accepted = str(Subject.masked("abcdefghijkl")) == "ref:abcdefghijkl"
    except C.ContractViolation:
        accepted = False
    check("12 lowercase letters is accepted", accepted)
    rejects("a long digit string cannot pass as a group label", lambda: Subject.group("123412341234"), "not an identifier")
    rejects("an email cannot pass as a group label", lambda: Subject.group("a@b.com"), "short text")
    try:
        accepted = str(Subject.group("March 2024")) == "grp:March 2024"
    except C.ContractViolation:
        accepted = False
    check("a plain category label is fine", accepted)
    for bad in ("ABCDE1234F", "123412341234", "a@b.com", "Ram Kumar", "x" * 40):
        rejects(f"metric value {bad[:12]!r} rejected", lambda bad=bad: Signal("x", 0.5, Subject.row(1), {"v": bad}), "token")
    check("numbers, booleans and lowercase tokens are allowed in metrics",
          Signal("x", 0.5, Subject.row(1), {"n": 3, "f": 0.25, "b": True, "t": "close_conformity"}).metrics["t"] == "close_conformity")
    rejects("NaN metric rejected", lambda: Signal("x", 0.5, Subject.row(1), {"n": float("nan")}), "finite")
    rejects("a metric key that is not snake_case rejected", lambda: Signal("x", 0.5, Subject.row(1), {"Bad Key": 1}), "snake_case")
    rejects("more than 16 scalars rejected", lambda: ok(summary={f"k{i}": i for i in range(17)}), "limit")

    print("\n=== strength is an effect size, not a probability ===")
    for bad in (-0.1, 1.5, float("nan"), True):
        rejects(f"strength {bad!r} rejected", lambda bad=bad: Signal("x", bad, Subject.row(1)), "")
    check("strength is rounded to 4 places", Signal("x", 0.123456789, Subject.row(1)).strength == 0.1235)

    print("\n=== status rules ===")
    rejects("completed without a dataset version rejected", lambda: ok(dataset=None), "dataset version")
    rejects("completed with a non-runnable verdict rejected", lambda: ok(verdict=Verdict.NOT_APPLICABLE), "verdict")
    rejects("SUPPORTED_WITH_WARNING without a reason rejected", lambda: ok(verdict=Verdict.SUPPORTED_WITH_WARNING), "why")
    check("SUPPORTED_WITH_WARNING with reason codes accepted", ok(verdict=Verdict.SUPPORTED_WITH_WARNING, reason_codes=("SMALL_SAMPLE",)).verdict is Verdict.SUPPORTED_WITH_WARNING)
    dec = MethodResult.declined(M, Verdict.NOT_APPLICABLE, ["CONSTRAINED_RANGE"])
    check("a declined result carries verdict + reasons and no findings", dec.status is Status.DECLINED and '"why":["CONSTRAINED_RANGE"]' in dec.to_json() and "limits" not in dec.to_json())
    rejects("declined with a runnable verdict rejected", lambda: MethodResult.declined(M, Verdict.SUPPORTED, ["X_Y"]), "non-runnable")
    rejects("declined without reasons rejected", lambda: MethodResult.declined(M, Verdict.NOT_APPLICABLE, []), "reason_codes")
    ref = MethodResult.refused(M, "NO_ROW_IDENTITY", "Table has no primary key.")
    check("a refusal is short", ref.status is Status.REFUSED and len(ref.to_json()) < 140, len(ref.to_json()))
    rejects("refusal without a code rejected", lambda: MethodResult(method=M, status=Status.REFUSED, reason="x"), "code")
    rejects("over-long reason rejected", lambda: MethodResult.failed(M, "DATABASE_ERROR", "x" * 301), "300")
    rejects("only a completed result may carry findings", lambda: MethodResult(method=M, status=Status.ERROR, code="E_X", reason="r", findings_count=1), "only a completed")

    print("\n=== evidence, dataset, method ===")
    rejects("available evidence must say how rows are keyed", lambda: EvidenceInfo(True), "identified")
    rejects("unavailable evidence cannot have links", lambda: EvidenceInfo(False, links=3), "cannot have links")
    rejects("content basis needs a fingerprint", lambda: DatasetVersion(1, "content"), "fingerprint")
    rejects("unknown basis rejected", lambda: DatasetVersion(1, "guess"), "basis")
    rejects("dataset id 0 rejected", lambda: DatasetVersion(0, "row_count"), "positive")
    check("row_count basis is allowed and reported as such", '"basis":"row_count"' in ok(dataset=DatasetVersion(3, "row_count")).to_json())
    rejects("method id with capitals rejected", lambda: MethodRef("Benford", "1.0.0"), "lowercase")
    rejects("method version must be x.y.z", lambda: MethodRef("benford", "1.0"), "1.0.0")

    print("\n=== immutability ===")
    try:
        r.records_scanned = 1
        check("a result cannot be modified after it is built", False)
    except dataclasses.FrozenInstanceError:
        check("a result cannot be modified after it is built", True)
    try:
        r.summary["x"] = 1
        check("its summary cannot be modified either", False)
    except TypeError:
        check("its summary cannot be modified either", True)


def integration_tests():
    import psycopg2
    from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
    from forensic_platform.core.config import find_mcp_config, load_mcp_config, superuser_dsn
    from forensic_platform.core.contract import (
        Classification, DatasetVersion, EvidenceInfo, MAX_RESULT_CHARS, MethodRef, MethodResult,
        RowIdentitySpec, Signal, Subject, Verdict)
    from forensic_platform.tests_engine import benford, cross_dataset_match, duplicate_analysis, fuzzy_entity_match

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
            CREATE TABLE t_people (id serial PRIMARY KEY, reg text, name text);
            INSERT INTO t_people (reg, name)
              SELECT 'R' || (i % 40), CASE WHEN i % 40 < 8 THEN 'PERSON ' || chr(65 + (i % 7)) || chr(75 + (i % 5)) ELSE 'STAFF ' || i END
              FROM generate_series(1, 300) i;
            CREATE TABLE t_left (id serial PRIMARY KEY, ref text);
            INSERT INTO t_left (ref) SELECT 'K' || i FROM generate_series(1, 120) i;
            CREATE TABLE t_right (id serial PRIMARY KEY, ref text);
            INSERT INTO t_right (ref) SELECT 'K' || i FROM generate_series(1, 100) i;
            GRANT SELECT ON ALL TABLES IN SCHEMA public TO forensic_app;
        ''')
        env = {**os.environ, "FORENSIC_MCP_CONFIG": str(cfg_path), "FORENSIC_MASK_SALT": "t" * 40}

        def current_output(*args):
            p = subprocess.run([sys.executable, str(ENGINE / "scripts" / "run_test.py"), "--database", scratch,
                                "--schema", "public", *args], capture_output=True, text=True, env=env)
            out = json.loads(p.stdout)
            return out, len(p.stdout)

        ds = DatasetVersion(1, "content", "s56:0:0")

        def evidence(res):
            return EvidenceInfo(True, RowIdentitySpec(res.identity.columns, res.identity.kind), len(res.evidence))

        cases = []

        # ---- the four real methods, adapted to the contract (these adapters become the
        # ---- methods' own output in the migration step)
        res = benford.run(cur, "public", "t_num", "amount")
        anomalous = res.reliable_sample_size and res.conformity in ("marginally acceptable conformity", "nonconformity")
        sigs = [Signal("digit_distribution", min(res.mad, 1.0), Subject.group("first_digit"), {"mad": round(res.mad, 5)})] if anomalous else []
        cases.append(("benford", MethodResult.build(
            method=MethodRef("benford", benford.TEST_VERSION), dataset=ds, verdict=Verdict.SUPPORTED,
            classification=Classification.ANOMALY if anomalous else Classification.OBSERVATION,
            records_scanned=res.records_examined, findings_count=len(sigs) or 1 if anomalous else 0,
            summary={"mad": round(res.mad, 5), "chi_square": round(res.chi_square, 2),
                     "conformity": res.conformity.replace(" ", "_"), "reliable": res.reliable_sample_size},
            signals=sigs), ["--subtest", "benford", "--confirmed-by", "tester", "--allow-unsuitable", "--table", "t_num", "--column", "amount"]))

        res = duplicate_analysis.run(cur, "public", "t_people", "reg", distinct_of="name")
        raw_dup_keys = [g["key_value"] for g in res.top_groups]
        sigs = [Signal("shared_identifier", min(1.0, g["row_count"] / res.records_examined), Subject.masked(mask(g["key_value"])),
                       {"rows": g["row_count"], "distinct": g["measure_value"]}) for g in res.top_groups]
        cases.append(("duplicate-analysis", MethodResult.build(
            method=MethodRef("duplicate-analysis", duplicate_analysis.TEST_VERSION), dataset=ds, verdict=Verdict.SUPPORTED,
            classification=Classification.ANOMALY if res.flagged_keys else Classification.OBSERVATION,
            records_scanned=res.records_examined, findings_count=1 if res.flagged_keys else 0,
            summary={"flagged_keys": res.flagged_keys, "flagged_rows": res.flagged_rows, "max_group": res.max_group_size,
                     "keys_examined": res.keys_examined},
            signals=sigs, evidence=evidence(res), finding_ids=(1,), run_id=1),
            ["--subtest", "duplicate-analysis", "--table", "t_people", "--column", "reg", "--distinct-of", "name"]))

        res = fuzzy_entity_match.run(cur, "public", "t_people", "reg", distinct_of="name")
        sigs = [Signal("shared_identifier", min(1.0, g["distinct_entities"] / g["raw_distinct_names"]), Subject.masked(mask(g["key_value"])),
                       {"entities": g["distinct_entities"], "raw_names": g["raw_distinct_names"]}) for g in res.top_groups]
        cases.append(("fuzzy-entity-match", MethodResult.build(
            method=MethodRef("fuzzy-entity-match", fuzzy_entity_match.TEST_VERSION), dataset=ds, verdict=Verdict.SUPPORTED,
            classification=Classification.ANOMALY if res.flagged_keys else Classification.OBSERVATION,
            records_scanned=res.records_examined, findings_count=1 if res.flagged_keys else 0,
            summary={"flagged_keys": res.flagged_keys, "collapsed": res.collapsed_by_spelling, "max_entities": res.max_entities},
            parameters={"threshold": res.threshold}, signals=sigs, evidence=evidence(res), finding_ids=(1,), run_id=1),
            ["--subtest", "fuzzy-entity-match", "--table", "t_people", "--column", "reg", "--distinct-of", "name"]))

        res = cross_dataset_match.run(cur, "public", "t_left", "ref", right_table="t_right", right_column="ref")
        sigs = [Signal("orphan_keys", res.only_left / res.left_distinct, Subject.group("left_keys"), {"only_left": res.only_left})] if res.only_left else []
        cases.append(("cross-dataset-match", MethodResult.build(
            method=MethodRef("cross-dataset-match", cross_dataset_match.TEST_VERSION), dataset=ds, verdict=Verdict.SUPPORTED,
            classification=Classification.ANOMALY if res.only_left else Classification.OBSERVATION,
            records_scanned=res.left_rows, findings_count=1 if res.only_left else 0,
            summary={"left_distinct": res.left_distinct, "right_distinct": res.right_distinct, "in_both": res.in_both,
                     "only_left": res.only_left, "only_right": res.only_right},
            signals=sigs, evidence=evidence(res), finding_ids=(1,), run_id=1),
            ["--subtest", "cross-dataset-match", "--table", "t_left", "--column", "ref", "--right-table", "t_right", "--right-column", "ref"]))

        print("=== the four real methods fit the one contract, and it is smaller ===")
        total_old = total_new = 0
        for name, result, args in cases:
            out, old_len = current_output(*args)
            new_len = len(result.to_json())
            total_old += old_len
            total_new += new_len
            check(f"{name}: valid contract result, within budget", new_len <= MAX_RESULT_CHARS, f"{new_len} chars")
            check(f"{name}: smaller than what run_test.py prints today", out.get("status") == "success" and new_len < old_len,
                  f"{old_len} -> {new_len} chars (~{old_len // 4} -> ~{new_len // 4} tokens, ESTIMATE)")
        print(f"  all four together: {total_old} -> {total_new} chars (~{total_old // 4} -> ~{total_new // 4} tokens, ESTIMATE)")
        printed_today = json.dumps(current_output("--subtest", "duplicate-analysis", "--table", "t_people", "--column", "reg", "--distinct-of", "name")[0].get("top_groups"))
        check("run_test.py no longer prints the raw key values in top_groups (masked since A5)",
              len(raw_dup_keys) > 0 and not any(k in printed_today for k in raw_dup_keys), raw_dup_keys[:3])
        dup_json = cases[1][1].to_json()
        check("the contract's equivalent contains NONE of those raw values", not any(k in dup_json for k in raw_dup_keys), f"{len(raw_dup_keys)} keys checked")
        check("...only masked references", all(str(s.subject).startswith("ref:") for s in cases[1][1].top_signals) and len(cases[1][1].top_signals) > 0)
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

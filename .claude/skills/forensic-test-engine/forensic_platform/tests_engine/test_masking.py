"""
Tests for identifier masking (core/masking.py) and its use in run_test.py output.

    python forensic_platform/tests_engine/test_masking.py                  # unit tests (no database)
    python forensic_platform/tests_engine/test_masking.py --integration    # + scratch-database tests

--integration creates its own scratch database (forensic_test_<hex>), runs the real run_test.py
entry point against it with a test masking key, and always drops the database. It needs the
project's .mcp.json (or $FORENSIC_MCP_CONFIG).

Before this, `top_groups` and `sample_only_*` printed RAW key values (Aadhaar-style numbers included)
straight into Claude's context.
"""
import json
import os
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE.parent))

from forensic_platform.core import masking                                   # noqa: E402
from forensic_platform.core.contract import ContractViolation, Subject       # noqa: E402

failures = 0
SALT = ("k" * 40).encode()
OTHER = ("z" * 40).encode()


def check(label, ok, detail=""):
    global failures
    if not ok:
        failures += 1
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}{(' - ' + str(detail)) if detail else ''}")


def raises(exc, fn, *a, **k):
    try:
        fn(*a, **k)
    except exc:
        return True
    except Exception:
        return False
    return False


def unit_tests():
    saved = os.environ.pop(masking.SALT_ENV, None)
    try:
        _unit()
    finally:
        if saved is not None:
            os.environ[masking.SALT_ENV] = saved


def _unit():
    print("=== the masked token ===")
    t = masking.mask_value("123456789012", SALT)
    check("12 lowercase letters (the contract's masked shape)", len(t) == 12 and t.isalpha() and t.islower(), t)
    check("deterministic for one key", t == masking.mask_value("123456789012", SALT))
    check("a different key gives a different token (keyed, not a plain hash)", t != masking.mask_value("123456789012", OTHER))
    check("different values give different tokens", t != masking.mask_value("123456789013", SALT))
    check("spacing, hyphens and case do not split one identifier into two",
          masking.mask_value("1234 5678 9012", SALT) == t == masking.mask_value("1234-5678-9012", SALT)
          and masking.mask_value("ABCDE1234F", SALT) == masking.mask_value(" abcde1234f ", SALT))
    check("full-width digits normalise to the same token", masking.mask_value("１２３４５６７８９０１２", SALT) == t)
    check("a non-string value is masked by its text (integers, decimals)", masking.mask_value(123456789012, SALT) == t)
    toks = {masking.mask_value(i, SALT) for i in range(20000)}
    check("no collisions across 20,000 sequential identifiers", len(toks) == 20000, len(toks))
    check("the contract accepts it as a masked subject", masking.subject("123456789012", SALT).token == t)
    check("a digit string is never a valid masked subject (letters only)", raises(ContractViolation, Subject.masked, "123456789012"))
    check("a short or non-bytes key is refused", raises(masking.MaskSaltUnavailable, masking.mask_value, "x", b"short")
          and raises(masking.MaskSaltUnavailable, masking.mask_value, "x", "not-bytes-but-a-str-of-sufficient-length!!"))

    print("\n=== what looks sensitive ===")
    for v in ("123456789012", "1234 5678 9012", "ABCDE1234F", "abcde1234f", "SBIN0001234", "9876543210",
              "a@b.co", "12345678901234", 123456789012):
        check(f"sensitive: {v!r}", masking.looks_sensitive(v))
    for v in ("INV-7", "D12", "MCI", "12345678", "Ram Kumar", "2024-05"):
        check(f"not sensitive: {v!r}", not masking.looks_sensitive(v))
    check("column names: aadhaar / bank account / mobile are sensitive",
          all(masking.column_looks_sensitive(c) for c in ("aadhaar_no", "BankAccount", "mobile", "PAN")))
    check("column names: invoice_no / amount are not", not any(masking.column_looks_sensitive(c) for c in ("invoice_no", "amount")))

    print("\n=== protect(): fail-closed ===")
    p = masking.protect(["INV-7", None, "INV-9"], column="invoice_no", salt=SALT)
    check("default is masked, even for a harmless-looking column; None stays None",
          p.mode == "masked" and p.values[1] is None and "INV-7" not in p.values and len(p.values[0]) == 12, p)
    check("the token matches mask_value (stable for cross-run linking)", p.values[0] == masking.mask_value("INV-7", SALT))
    r = masking.protect(["INV-7", "INV-9"], column="invoice_no", salt=SALT, reveal=True)
    check("reveal shows raw values only for a non-sensitive column and non-sensitive values",
          r.mode == "revealed" and r.values == ["INV-7", "INV-9"] and r.note == "")
    r = masking.protect(["INV-7"], column="aadhaar_no", salt=SALT, reveal=True)
    check("reveal refused for a sensitive column name, and says so",
          r.mode == "masked" and r.note == "reveal_refused_sensitive_column" and r.values[0] != "INV-7", r)
    r = masking.protect(["INV-7", "123456789012"], column="ref", salt=SALT, reveal=True)
    check("reveal refused when ANY value is sensitive (one Aadhaar among safe values)",
          r.mode == "masked" and r.note == "reveal_refused_sensitive_values" and "INV-7" not in r.values, r)
    r = masking.protect(["INV-7", "x"], column="ref", salt=None, reveal=True)
    check("no key: values withheld entirely, even when reveal is requested",
          r.mode == "withheld" and r.values == [] and r.note == "no_mask_key", r)
    check("an empty list is fine", masking.protect([], column="c", salt=SALT).values == [])
    check("nothing but tokens appears in a masked result",
          all(v is None or (len(v) == 12 and v.isalpha() and v.islower()) for v in masking.protect(
              ["123456789012", "ABCDE1234F", "a@b.co", "INV-7"], column="x", salt=SALT).values))

    print("\n=== the key ===")
    os.environ[masking.SALT_ENV] = "too short"
    check("an env key under 32 characters is refused, not padded", raises(masking.MaskSaltUnavailable, masking.load_salt))
    os.environ[masking.SALT_ENV] = "e" * 40
    check("a valid env key is used as given", masking.load_salt() == b"e" * 40)
    del os.environ[masking.SALT_ENV]
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        check("without create=False being needed, a missing file with create=False is unavailable",
              raises(masking.MaskSaltUnavailable, masking.load_salt, d, create=False))
        s1 = masking.load_salt(d)
        check("first use creates a random 64-character key file beside the project config",
              (d / masking.SALT_FILE).is_file() and len(s1) == 64, len(s1))
        check("the key is stable across calls", masking.load_salt(d) == s1)
        (d / masking.SALT_FILE).write_text("short", encoding="utf-8")
        check("a corrupt (short) key file is refused and NOT overwritten",
              raises(masking.MaskSaltUnavailable, masking.load_salt, d)
              and (d / masking.SALT_FILE).read_text(encoding="utf-8") == "short")
    with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
        check("two projects get two different keys", masking.load_salt(Path(a)) != masking.load_salt(Path(b)))


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
            CREATE TABLE pay (id serial PRIMARY KEY, aadhaar text, invoice_no text, who text);
            INSERT INTO pay (aadhaar, invoice_no, who) VALUES
              ('123456789012', 'INV-7', 'Ram Kumar'), ('123456789012', 'INV-7', 'Shyam Singh'),
              ('987654321098', 'INV-9', 'Gita Rani'), ('987654321098', 'INV-9', 'Gita Rani');
            CREATE TABLE roll (id serial PRIMARY KEY, aadhaar text, invoice_no text);
            INSERT INTO roll (aadhaar, invoice_no) VALUES ('987654321098', 'INV-9'), ('555566667777', 'INV-1');
            GRANT SELECT ON ALL TABLES IN SCHEMA public TO forensic_app;
        ''')
        # the reveal / withheld semantics below belong to the LEGACY output; the default contract
        # output is tested in its own section at the end
        base_env = {**os.environ, "FORENSIC_MCP_CONFIG": str(cfg_path), "FORENSIC_MASK_SALT": "s" * 40,
                    "FORENSIC_LEGACY_OUTPUT": "1"}
        contract_env = {k: v for k, v in base_env.items() if k != "FORENSIC_LEGACY_OUTPUT"}

        def run(*extra, env=None):
            p = subprocess.run([sys.executable, str(ENGINE / "scripts" / "run_test.py"), "--database", scratch,
                                "--schema", "public", *extra], capture_output=True, text=True, env=env or base_env)
            try:
                return json.loads(p.stdout), p.stdout
            except ValueError:
                return {"status": "NOT-JSON", "stderr": p.stderr[-300:]}, p.stdout

        raw_ids = ("123456789012", "987654321098", "555566667777", "Ram Kumar", "Gita Rani")

        print("\n--- legacy output: duplicate-analysis ---")
        r, out = run("--subtest", "duplicate-analysis", "--table", "pay", "--column", "aadhaar")
        keys = [g["key_value"] for g in r.get("top_groups", [])]
        check("succeeds and flags both Aadhaar numbers", r.get("status") == "success" and r.get("flagged_keys") == 2, r.get("status"))
        check("NO raw identifier anywhere in the printed output", not any(v in out for v in raw_ids))
        check("key values are 12-letter tokens; output says values are masked",
              len(keys) == 2 and all(len(k) == 12 and k.isalpha() for k in keys) and r.get("values") == "masked", (keys, r.get("values")))
        r2, _ = run("--subtest", "duplicate-analysis", "--table", "pay", "--column", "aadhaar")
        check("the same value gets the same token in a later run", [g["key_value"] for g in r2["top_groups"]] == keys)
        r3, _ = run("--subtest", "duplicate-analysis", "--table", "pay", "--column", "aadhaar",
                    env={**base_env, "FORENSIC_MASK_SALT": "t" * 40})
        check("a different project key gives different tokens", not set(keys) & {g["key_value"] for g in r3["top_groups"]})
        r4, out4 = run("--subtest", "duplicate-analysis", "--table", "pay", "--column", "aadhaar", "--reveal-values")
        check("--reveal-values on an Aadhaar column is refused: still masked, with the reason",
              r4.get("values") == "masked" and r4.get("values_note") == "reveal_refused_sensitive_column"
              and not any(v in out4 for v in raw_ids), (r4.get("values"), r4.get("values_note")))
        r5, out5 = run("--subtest", "duplicate-analysis", "--table", "pay", "--column", "invoice_no", "--reveal-values")
        check("--reveal-values on a harmless column shows raw values, and says so",
              r5.get("values") == "revealed" and {g["key_value"] for g in r5["top_groups"]} == {"INV-7", "INV-9"}, r5.get("values"))
        r6, out6 = run("--subtest", "duplicate-analysis", "--table", "pay", "--column", "invoice_no")
        check("without the flag even a harmless column is masked", r6.get("values") == "masked" and "INV-7" not in out6)
        r7, out7 = run("--subtest", "duplicate-analysis", "--table", "pay", "--column", "aadhaar",
                       env={**base_env, "FORENSIC_MASK_SALT": "short"})
        check("no usable key: values are withheld, counts still reported, nothing raw printed",
              r7.get("values") == "withheld" and r7.get("flagged_keys") == 2
              and all("key_value" not in g for g in r7["top_groups"]) and not any(v in out7 for v in raw_ids), r7.get("values"))

        print("\n--- fuzzy-entity-match ---")
        r, out = run("--subtest", "fuzzy-entity-match", "--table", "pay", "--column", "aadhaar", "--distinct-of", "who")
        check("succeeds, flags the shared identifier, prints no raw identifier or name",
              r.get("status") == "success" and r.get("flagged_keys") == 1 and not any(v in out for v in raw_ids), (r.get("status"), r.get("flagged_keys")))
        check("its key value is a token and matches the duplicate-analysis token for the same value",
              r["top_groups"][0]["key_value"] in keys and r.get("values") == "masked")

        print("\n--- cross-dataset-match ---")
        r, out = run("--subtest", "cross-dataset-match", "--table", "pay", "--column", "aadhaar",
                     "--right-table", "roll", "--right-column", "aadhaar")
        check("succeeds and finds one key only on each side",
              r.get("status") == "success" and r.get("only_left") == 1 and r.get("only_right") == 1, (r.get("status"), r.get("only_left")))
        check("samples are tokens; no raw identifier printed",
              not any(v in out for v in raw_ids) and all(len(s) == 12 for s in r["sample_only_left"] + r["sample_only_right"]))
        check("the same value has the same token on both sides of the comparison",
              masking.mask_value("987654321098", b"s" * 40) not in r["sample_only_left"] + r["sample_only_right"]
              and r["sample_only_left"][0] == masking.mask_value("123456789012", b"s" * 40))
        r, out = run("--subtest", "cross-dataset-match", "--table", "pay", "--column", "invoice_no",
                     "--right-table", "roll", "--right-column", "aadhaar", "--reveal-values")
        check("if one side is unsafe to reveal, BOTH sides stay masked",
              r.get("values") == "masked" and "INV-7" not in out and "555566667777" not in out, (r.get("values"), r.get("values_note")))
        r, out = run("--subtest", "cross-dataset-match", "--table", "pay", "--column", "invoice_no",
                     "--right-table", "roll", "--right-column", "invoice_no", "--reveal-values")
        check("both sides harmless and reveal requested: raw values shown", r.get("values") == "revealed" and "INV-7" in out, r.get("values"))

        print("\n--- the default (contract) output ---")
        tok = lambda r: [t["subject"] for t in r.get("top", [])]
        key = b"s" * 40
        want = {"ref:" + masking.mask_value(v, key) for v in ("123456789012", "987654321098")}
        r, out = run("--subtest", "duplicate-analysis", "--table", "pay", "--column", "aadhaar", env=contract_env)
        check("completed; flags both Aadhaar numbers; says values are masked",
              r.get("status") == "completed" and r["summary"]["flagged_keys"] == 2 and r["summary"]["values"] == "masked", r.get("summary"))
        check("subjects are exactly the keyed tokens of the two identifiers", set(tok(r)) == want, tok(r))
        check("no raw identifier or name anywhere in the output", not any(v in out for v in raw_ids))
        r2, out2 = run("--subtest", "duplicate-analysis", "--table", "pay", "--column", "invoice_no", "--reveal-values", env=contract_env)
        check("--reveal-values cannot put raw values into a contract result (even for a harmless column)",
              r2["summary"]["values"] == "masked" and "INV-7" not in out2 and all(s.startswith("ref:") for s in tok(r2)), tok(r2))
        r3, out3 = run("--subtest", "duplicate-analysis", "--table", "pay", "--column", "aadhaar",
                       env={**contract_env, "FORENSIC_MASK_SALT": "short"})
        check("no usable key: subjects are rank labels, values withheld, counts kept, nothing raw",
              r3["summary"]["values"] == "withheld" and r3["summary"]["flagged_keys"] == 2
              and all(s.startswith("grp:key_") for s in tok(r3)) and not any(v in out3 for v in raw_ids), tok(r3))
        r, out = run("--subtest", "fuzzy-entity-match", "--table", "pay", "--column", "aadhaar", "--distinct-of", "who", env=contract_env)
        check("fuzzy: masked subject, no raw identifier or name",
              r.get("status") == "completed" and tok(r) == ["ref:" + masking.mask_value("123456789012", key)]
              and not any(v in out for v in raw_ids), tok(r))
        r, out = run("--subtest", "cross-dataset-match", "--table", "pay", "--column", "aadhaar",
                     "--right-table", "roll", "--right-column", "aadhaar", env=contract_env)
        check("cross-dataset: counts only, no sample values, nothing raw",
              r["summary"]["only_left"] == 1 and r["summary"]["only_right"] == 1 and not any(v in out for v in raw_ids)
              and "sample_only_left" not in out, r.get("summary"))
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

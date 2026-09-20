"""
Tests for the profiler (core/profile.py) and role suggestions / bindings (core/roles.py).

    python forensic_platform/tests_engine/test_profile.py                  # unit tests (no database)
    python forensic_platform/tests_engine/test_profile.py --integration    # + scratch-database tests

--integration creates its own uniquely named scratch database (forensic_test_<hex>) and always drops
it. It needs the project's .mcp.json (or $FORENSIC_MCP_CONFIG) with the admin entry.

What must hold: measurements are exact; no data VALUE is ever returned; a suggestion never binds a
role; only a confirmed binding hands column measurements to a suitability rule set; a sensitive
column is never suggested as an amount or a name.
"""
import json
import sys
import uuid
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE.parent))

from forensic_platform.core.contract import MethodRef, Verdict          # noqa: E402
from forensic_platform.core.profile import ColumnProfile, TableProfile  # noqa: E402
from forensic_platform.core.roles import (Bindings, facts_for, name_tokens, sensitive_columns,  # noqa: E402
                                          suggest_roles)
from forensic_platform.core.suitability import Rule, RuleSet, Threshold, assess, needs_role  # noqa: E402

failures = 0


def check(label, ok, detail=""):
    global failures
    if not ok:
        failures += 1
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}{(' - ' + str(detail)) if detail else ''}")


def col(name, tc, *, non_null=100, distinct=50, ordinal=1, pk=False, fk=None, **metrics):
    dtype = {"numeric": "numeric", "text": "text", "date": "date"}.get(tc, "other")
    c = ColumnProfile(name, dtype, tc, ordinal, non_null=non_null, distinct=distinct, metrics=metrics)
    c.is_pk, c.fk_to = pk, fk
    return c


def table(*cols, rows=100):
    return TableProfile("public", "t", rows, {c.name: c for c in cols})


def unit_tests():
    print("=== column-name tokens ===")
    check("camelCase and separators split into whole words",
          name_tokens("NetPay_Amt-2024") == {"net", "pay", "amt", "2024"}, name_tokens("NetPay_Amt-2024"))
    check("a token is a whole word, not a substring ('payroll' is not 'pay')", "pay" not in name_tokens("payroll"))

    print("\n=== suggestions: evidence, not binding ===")
    t = table(
        col("emp_id", "numeric", non_null=100, distinct=100, ordinal=1, pk=True, n_distinct=100),
        col("employee_name", "text", distinct=90, ordinal=2, len_mean=14.0, numeric_like_share=0.0),
        col("gross_salary", "numeric", ordinal=3, n_distinct=80),
        col("paid_on", "date", ordinal=4, min_date="2024-01-01", max_date="2024-12-31"),
        col("remarks", "text", distinct=3, ordinal=5, len_mean=3.0, numeric_like_share=0.0),
    )
    s = suggest_roles(t)
    check("amount is suggested for the salary column, strong",
          [(x.column, x.support) for x in s["amount"]] == [("gross_salary", "strong")], s["amount"])
    check("a primary key is not suggested as an amount", "emp_id" not in [x.column for x in s["amount"]])
    check("date suggested from its type even when the name says nothing",
          [x.column for x in s["date"]] == ["paid_on"], s["date"])
    check("entity name suggested; free-text remarks is not",
          [x.column for x in s["entity_name"]] == ["employee_name"], s["entity_name"])
    check("identifier suggested from the primary key", [x.column for x in s["identifier"]][:1] == ["emp_id"])
    check("suggestions carry evidence tokens, not values",
          all(isinstance(e, str) and e.islower() for x in s["amount"] for e in x.evidence))
    b = Bindings()
    suggest_roles(t)
    check("computing suggestions binds nothing", b.bound("amount") is None and b.pending("amount") is None)

    print("\n=== a name alone is not enough ===")
    weak = table(col("total_remarks", "text", distinct=5, len_mean=6.0, numeric_like_share=0.0))
    check("a text column named 'total' with non-numeric content is not an amount", suggest_roles(weak)["amount"] == [])
    numtext = table(col("net_pay", "text", numeric_like_share=1.0, distinct=60))
    check("numeric text (e.g. Excel import) is suggested with the numeric_text evidence",
          [(x.column, "numeric_text" in x.evidence) for x in suggest_roles(numtext)["amount"]] == [("net_pay", True)])
    serial = table(col("sno", "numeric", distinct=100, n_distinct=100, integer_share=1.0),
                   col("page", "numeric", distinct=40, n_distinct=40, integer_share=1.0, ordinal=2),
                   col("qty_adj", "numeric", distinct=40, n_distinct=40, integer_share=0.6, ordinal=3))
    check("an unnamed integer-only numeric (serial number, page) is not suggested as an amount; one with decimals is",
          [x.column for x in suggest_roles(serial)["amount"]] == ["qty_adj"], [x.column for x in suggest_roles(serial)["amount"]])
    named = table(col("sgst", "numeric", distinct=60, n_distinct=60, integer_share=1.0),
                  col("service_charge", "numeric", distinct=60, n_distinct=60, integer_share=1.0, ordinal=2))
    check("tax and charge names count as amount evidence even for whole-number values",
          [x.column for x in suggest_roles(named)["amount"]] == ["sgst", "service_charge"], [x.column for x in suggest_roles(named)["amount"]])
    idlike = table(col("mobile_no", "numeric", distinct=100, n_distinct=100, mobile_like_share=1.0,
                       aadhaar_like_share=0.0, ordinal=1))
    check("a 10-digit numeric that looks like a mobile number is not an amount", suggest_roles(idlike)["amount"] == [])

    print("\n=== sensitive columns ===")
    sens = table(
        col("aadhaar_no", "text", ordinal=1, aadhaar_like_share=0.0, numeric_like_share=1.0),
        col("field_x", "text", ordinal=2, pan_like_share=0.98),
        col("contact", "numeric", ordinal=3, mobile_like_share=0.9, aadhaar_like_share=0.0),
        col("bank_account_no", "text", ordinal=4),
        col("net_pay", "numeric", ordinal=5, n_distinct=60),
        col("account_amount", "numeric", ordinal=6, n_distinct=60),   # would be a strong amount if not sensitive
    )
    sc = sensitive_columns(sens)
    check("detected by name (aadhaar, account)", sc.get("aadhaar_no") == "aadhaar" and sc.get("bank_account_no") == "account", sc)
    check("the conservative rule wins: 'account_amount' is sensitive, so it is not an amount",
          sc.get("account_amount") == "account" and [x.column for x in suggest_roles(sens)["amount"]] == ["net_pay"],
          [x.column for x in suggest_roles(sens)["amount"]])
    check("detected by content pattern share even when the name is neutral", sc.get("field_x") == "pan" and sc.get("contact") == "mobile", sc)
    check("an ordinary amount column is not sensitive", "net_pay" not in sc)
    ss = suggest_roles(sens)
    check("a sensitive column is never suggested as amount, name or identifier",
          not any(x.column in sc for r in ("amount", "entity_name", "identifier", "date") for x in ss[r]))
    check("they are suggested as sensitive_id", {x.column for x in ss["sensitive_id"]} == set(sc), ss["sensitive_id"])
    check("below the share threshold it is not flagged by content",
          "f" not in sensitive_columns(table(col("f", "text", pan_like_share=0.5))))

    print("\n=== bindings: only a named human binds ===")
    b = Bindings()
    b.propose("amount", "gross_salary")
    check("propose makes it pending, not bound", b.pending("amount") == "gross_salary" and b.bound("amount") is None)
    for who in ("", "   ", None):
        try:
            b.confirm("amount", "gross_salary", who)
            check(f"confirm refuses confirmed_by={who!r}", False)
        except ValueError:
            check(f"confirm refuses confirmed_by={who!r}", b.bound("amount") is None)
    b.confirm("amount", "gross_salary", "A. Reviewer")
    check("confirm binds, records who, and clears pending",
          b.bound("amount") == "gross_salary" and b.pending("amount") is None and b.confirmed_by("amount") == "A. Reviewer")
    b.propose("amount", "other")
    check("a later proposal does not displace a confirmed binding", b.bound("amount") == "gross_salary" and b.pending("amount") is None)
    for bad in ("nonsense", "AMOUNT", ""):
        try:
            b.propose(bad, "x")
            check(f"unknown role {bad!r} refused", False)
        except ValueError:
            check(f"unknown role {bad!r} refused", True)

    print("\n=== facts_for feeds suitability, and only when confirmed ===")
    rs = RuleSet(MethodRef("probe", "1.0.0"), (
        *needs_role("amount"),
        Rule("FEW_ROWS", "n_eligible", "<", Threshold(300), Verdict.INSUFFICIENT_DATA, "too few eligible values"),
        Rule("NARROW_SPAN", "magnitude_span", "<", Threshold(2), Verdict.NOT_APPLICABLE, "values span too little"),
    ))
    amt = col("gross_salary", "numeric", n_eligible=500, n_distinct=400, magnitude_span=3.5, nonpositive_share=0.0)
    tab = table(amt, rows=500)
    none = Bindings()
    f0 = facts_for(tab, none, rs, "amount")
    check("nothing bound: role facts false and NO column measurements leak", f0 == {"role.amount.bound": False, "role.amount.pending": False}, f0)
    check("nothing bound: verdict is INSUFFICIENT_DATA", assess(rs, f0).verdict is Verdict.INSUFFICIENT_DATA)
    pend = Bindings()
    pend.propose("amount", "gross_salary")
    f1 = facts_for(tab, pend, rs, "amount")
    check("pending only: no column measurements are handed over", "n_eligible" not in f1 and f1["role.amount.pending"] is True, f1)
    check("pending only: REQUIRES_CONFIRMATION", assess(rs, f1).verdict is Verdict.REQUIRES_CONFIRMATION)
    ok = Bindings()
    ok.confirm("amount", "gross_salary", "A. Reviewer")
    f2 = facts_for(tab, ok, rs, "amount")
    check("confirmed: measurements handed over, nothing extra",
          f2 == {"role.amount.bound": True, "role.amount.pending": False, "n_eligible": 500, "magnitude_span": 3.5}, f2)
    check("confirmed and sound data: SUPPORTED", assess(rs, f2).verdict is Verdict.SUPPORTED)
    check("a fact the profile lacks stays absent (reported as not measured)",
          "MISSING_MAGNITUDE_SPAN" in assess(rs, facts_for(table(col("gross_salary", "numeric", n_eligible=500)), ok, rs, "amount")).reason_codes)
    gone = Bindings()
    gone.confirm("amount", "no_such_column", "A. Reviewer")
    check("a bound column that is not in the profile yields no measurements",
          "n_eligible" not in facts_for(tab, gone, rs, "amount"))
    try:
        facts_for(tab, ok, rs, "bogus")
        check("facts_for refuses an unknown role", False)
    except ValueError:
        check("facts_for refuses an unknown role", True)

    print("\n=== digest is small and value-free ===")
    d = tab.digest()
    check("digest is shape only", set(d) == {"table", "rows", "cols", "types", "empty_cols"} and len(json.dumps(d)) < 150, d)


def integration_tests():
    import psycopg2
    from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
    from forensic_platform.core.config import find_mcp_config, superuser_dsn
    from forensic_platform.core.profile import ProfileTooLarge, deepen, profile_table

    try:
        find_mcp_config()
    except Exception as exc:
        print(f"  [SKIP] integration tests need .mcp.json: {exc}")
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
        cur.execute('''
            CREATE TABLE dept (dept_id int PRIMARY KEY);
            INSERT INTO dept VALUES (1),(2);
            CREATE TABLE "Pay Roll" (
                id serial PRIMARY KEY, dept_id int REFERENCES dept, "Net Pay" numeric, "Mobile" bigint,
                who text, paid date, note text, flag boolean);
            INSERT INTO "Pay Roll" (dept_id, "Net Pay", "Mobile", who, paid, note, flag) VALUES
              (1, 100.5, 9876543210, 'Ram Kumar', '2024-01-05', '123456789012', true),
              (1, 200,   9876543211, 'Sita Devi', '2024-02-05', 'ABCDE1234F', false),
              (2, 0,     9876543212, 'Ram Kumar', '2024-03-05', 'a@b.co', true),
              (2, -50,   9876543213, NULL,        NULL,         NULL, NULL),
              (2, 1000,  9876543214, 'Gita',      '2024-04-05', 'ABCD0123456', true),
              (1, NULL,  9876543215, 'Mohan Lal', '2024-05-05', 'x', true);
        ''')
        p = profile_table(cur, "public", "Pay Roll")
        check("row count exact and every column profiled", p.row_count == 6 and len(p.columns) == 8, (p.row_count, list(p.columns)))
        pay = p.column("Net Pay")
        m = pay.metrics
        check("numeric: non-null / distinct exact", pay.non_null == 5 and pay.distinct == 5, (pay.non_null, pay.distinct))
        check("numeric: eligible excludes zero and null (4 of 6)", m["n_eligible"] == 4 and m["n_distinct"] == 4, m)
        check("numeric: min/max absolute value ignore zero", m["min_abs"] == 50.0 and m["max_abs"] == 1000.0, m)
        check("numeric: magnitude span is log10(1000/50)", abs(m["magnitude_span"] - 1.301) < 0.001, m.get("magnitude_span"))
        check("numeric: nonpositive share is 2 of 5", m["nonpositive_share"] == 0.4, m["nonpositive_share"])
        check("numeric: integer share is 4 of 5 (100.5 is not integral)", m["integer_share"] == 0.8, m["integer_share"])
        check("null rate exact", m["null_rate"] == round(1 / 6, 6), m["null_rate"])
        check("primary key and foreign key come from the catalog",
              p.column("id").is_pk and p.column("id").is_unique and p.column("dept_id").fk_to == "dept")
        check("a 10-digit bigint is measured as mobile-shaped", p.column("Mobile").metrics.get("mobile_like_share") == 1.0, p.column("Mobile").metrics)
        w = p.column("who")
        check("text: length stats exact", w.metrics["len_min"] == 4 and w.metrics["len_max"] == 9, w.metrics)
        n = p.column("note").metrics
        check("text: pattern shares over non-null rows (Aadhaar-, PAN-, e-mail-, IFSC-shaped one each of 5)",
              n["aadhaar_like_share"] == 0.2 and n["pan_like_share"] == 0.2 and n["email_like_share"] == 0.2
              and n["ifsc_like_share"] == 0.2, n)
        d = p.column("paid")
        check("date: min and max", d.metrics["min_date"] == "2024-01-05" and d.metrics["max_date"] == "2024-05-05", d.metrics)
        check("boolean column profiled without error", p.column("flag").non_null == 5)

        blob = json.dumps({"digest": p.digest(), "cols": {k: c.metrics for k, c in p.columns.items()}}, default=str)
        check("no data value appears in anything the profile exposes for text columns",
              not any(v in blob for v in ("Ram Kumar", "Sita Devi", "Mohan Lal", "ABCDE1234F", "a@b.co")))

        deepen(cur, p, ["Net Pay", "who"])
        check("deepen: top10_share (only 4 eligible values, all in the top 10 = 1.0); text column untouched",
              m["top10_share"] == 1.0 and "top10_share" not in w.metrics, m.get("top10_share"))

        cur.execute("CREATE TABLE t12 (v int)")
        cur.execute("INSERT INTO t12 SELECT g FROM generate_series(1, 12) g")   # 12 distinct values once each
        p12 = profile_table(cur, "public", "t12")
        deepen(cur, p12, ["v"])
        check("deepen: the ten commonest of 12 equal values hold 10/12 of them",
              abs(p12.column("v").metrics["top10_share"] - round(10 / 12, 6)) < 1e-9, p12.column("v").metrics["top10_share"])

        sug = suggest_roles(p)
        check("real profile: amount, date and sensitive detected",
              [x.column for x in sug["amount"]][:1] == ["Net Pay"] and "paid" in [x.column for x in sug["date"]]
              and "Mobile" in [x.column for x in sug["sensitive_id"]],
              {r: [x.column for x in v] for r, v in sug.items()})

        cur.execute("CREATE TABLE empty_t (a int, b text)")
        e = profile_table(cur, "public", "empty_t")
        check("an empty table profiles without dividing by zero", e.row_count == 0 and e.column("a").metrics["null_rate"] == 0.0)

        cur.execute("CREATE TABLE wide (" + ", ".join(f"c{i} int" for i in range(130)) + ")")
        cur.execute("INSERT INTO wide SELECT " + ", ".join("g" for _ in range(130)) + " FROM generate_series(1,3) g")
        wd = profile_table(cur, "public", "wide")
        check("a 130-column table is profiled in batches, all columns measured",
              len(wd.columns) == 130 and all(c.non_null == 3 for c in wd.columns.values()))

        cur.execute("CREATE TABLE big_est (a int)")
        cur.execute("INSERT INTO big_est SELECT generate_series(1, 50)")
        cur.execute("UPDATE pg_class SET reltuples = 9000000 WHERE oid = 'big_est'::regclass")
        try:
            profile_table(cur, "public", "big_est")
            refused = False
        except ProfileTooLarge:
            refused = True
        check("a table estimated over the row limit is refused unless allowed", refused)
        check("allow_large overrides the limit", profile_table(cur, "public", "big_est", allow_large=True).row_count == 50)

        for bad in ("x'; DROP TABLE dept; --", ""):
            try:
                profile_table(cur, "public", bad)
                ok = False
            except Exception:
                ok = True
            check(f"unsafe table name {bad[:12]!r} is refused, not executed", ok)
        cur.execute("SELECT count(*) FROM dept")
        check("nothing was written by profiling", cur.fetchone()[0] == 2)
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

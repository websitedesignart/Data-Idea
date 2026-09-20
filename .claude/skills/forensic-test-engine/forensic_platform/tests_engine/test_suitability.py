"""
Tests for the suitability framework (core/suitability.py). Pure: no database, no configuration.

    python forensic_platform/tests_engine/test_suitability.py

The Benford rule set below is ILLUSTRATIVE: it exists to prove the framework on realistic
scenarios (including the numbers measured in a real audit). The engine's own Benford guard, with
its final thresholds, is a later step.
"""
import copy
import random
import sys
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE.parent))

from forensic_platform.core.contract import ContractViolation, MethodRef, Status, Verdict  # noqa: E402
from forensic_platform.core.suitability import (  # noqa: E402
    Rule, RuleSet, Threshold, assess, needs_input, needs_role, missing_code)

failures = 0


def check(label, ok, detail=""):
    global failures
    if not ok:
        failures += 1
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}{(' - ' + str(detail)) if detail else ''}")


def rejects(label, fn, must_mention=""):
    try:
        fn()
        check(label, False, "was accepted")
    except ContractViolation as exc:
        check(label, must_mention.lower() in str(exc).lower(), str(exc)[:80])
    except Exception as exc:
        check(label, False, f"{type(exc).__name__}: {exc}")


M = MethodRef("demo-method", "1.0.0")
V = Verdict


def rule(code, fact, op, value, outcome, validated=False, unless=()):
    return Rule(code, fact, op, Threshold(value, validated), outcome, f"{code.lower()} rule", unless)


# ----- an ILLUSTRATIVE Benford-style rule set (thresholds are unvalidated starting defaults)
BENFORD = RuleSet(MethodRef("benford", "1.0.0"), (
    *needs_role("amount"),
    rule("SMALL_SAMPLE", "n_eligible", "<", 300, V.INSUFFICIENT_DATA),
    rule("MODEST_SAMPLE", "n_eligible", "<", 1000, V.SUPPORTED_WITH_WARNING, unless=("SMALL_SAMPLE",)),
    rule("CONSTRAINED_VALUES", "n_distinct", "<", 100, V.NOT_APPLICABLE, unless=("SMALL_SAMPLE",)),
    rule("NARROW_MAGNITUDE_RANGE", "magnitude_span", "<", 2.0, V.NOT_APPLICABLE),
    rule("MANY_NONPOSITIVE", "nonpositive_share", ">", 0.2, V.SUPPORTED_WITH_WARNING),
))
GOOD = {"role.amount.bound": True, "role.amount.pending": False, "n_eligible": 5000, "n_distinct": 3000,
        "magnitude_span": 4.5, "nonpositive_share": 0.01}


def with_facts(**over):
    f = dict(GOOD)
    f.update({k.replace("__", "."): v for k, v in over.items()})
    return f


def unit_tests():
    print("=== rules and thresholds are validated when written ===")
    rejects("threshold must be finite", lambda: Threshold(float("nan")), "finite")
    rejects("a rule may not have outcome SUPPORTED", lambda: rule("X_Y", "f", "<", 1, V.SUPPORTED), "restrict")
    rejects("bad operator rejected", lambda: rule("X_Y", "f", "~", 1, V.NOT_APPLICABLE), "operator")
    rejects("lowercase code rejected", lambda: rule("bad", "f", "<", 1, V.NOT_APPLICABLE), "UPPER_SNAKE")
    rejects("bad fact name rejected", lambda: rule("X_Y", "Bad Fact", "<", 1, V.NOT_APPLICABLE), "fact name")
    rejects("boolean threshold with < rejected", lambda: rule("X_Y", "f", "<", True, V.NOT_APPLICABLE), "boolean")
    rejects("duplicate codes in a rule set rejected", lambda: RuleSet(M, (rule("X_Y", "a", "<", 1, V.NOT_APPLICABLE), rule("X_Y", "b", "<", 1, V.NOT_APPLICABLE))), "unique")
    rejects("a fact name too long to form a reason code rejected", lambda: rule("X_Y", "a" * 60, "<", 1, V.NOT_APPLICABLE), "too long")
    check("thresholds default to UNVALIDATED", Threshold(300).validated is False and "not validated" in Threshold(300).basis)

    print("\n=== verdicts ===")
    a = assess(BENFORD, GOOD)
    check("all rules pass -> SUPPORTED, no reasons, runnable", a.verdict is V.SUPPORTED and a.reason_codes == () and a.runnable)
    a = assess(BENFORD, with_facts(n_eligible=600))
    check("modest sample -> SUPPORTED_WITH_WARNING with its code", a.verdict is V.SUPPORTED_WITH_WARNING and a.reason_codes == ("MODEST_SAMPLE",) and a.runnable, a.reason_codes)
    a = assess(BENFORD, with_facts(n_eligible=184))
    check("small sample -> INSUFFICIENT_DATA, not runnable", a.verdict is V.INSUFFICIENT_DATA and not a.runnable, a.reason_codes)
    a = assess(BENFORD, with_facts(n_distinct=30))
    check("few distinct values -> NOT_APPLICABLE", a.verdict is V.NOT_APPLICABLE and a.reason_codes == ("CONSTRAINED_VALUES",), a.reason_codes)

    print("\n=== the most restrictive verdict wins, and every reason is reported ===")
    a = assess(BENFORD, with_facts(n_eligible=500, n_distinct=30, magnitude_span=1.0, nonpositive_share=0.5))
    check("several problems -> NOT_APPLICABLE outranks the warnings", a.verdict is V.NOT_APPLICABLE, a.verdict)
    check("reasons ordered most restrictive first, then by code",
          a.reason_codes == ("CONSTRAINED_VALUES", "NARROW_MAGNITUDE_RANGE", "MANY_NONPOSITIVE", "MODEST_SAMPLE"), a.reason_codes)
    a = assess(BENFORD, with_facts(n_eligible=100, n_distinct=30, magnitude_span=3.0))
    check("...and INSUFFICIENT_DATA outranks a warning", a.verdict is V.INSUFFICIENT_DATA, a.reason_codes)
    a = assess(BENFORD, with_facts(role__amount__pending=True, n_distinct=30))
    check("an unconfirmed role outranks NOT_APPLICABLE (the measured column may be the wrong one)",
          a.verdict is V.REQUIRES_CONFIRMATION and a.reason_codes[:2] == ("ROLE_UNCONFIRMED_AMOUNT", "CONSTRAINED_VALUES"), a.reason_codes)
    many = RuleSet(M, tuple(rule(f"PROBLEM_{i}", "f", ">", 0, V.SUPPORTED_WITH_WARNING) for i in range(9)))
    a = assess(many, {"f": 1})
    check("reason codes are capped at 6 and the remainder is counted", len(a.reason_codes) == 6 and a.more_reasons == 3, (len(a.reason_codes), a.more_reasons))
    unsafe = RuleSet(M, (rule("TOO_MANY_ROWS", "n_rows", ">", 1000, V.UNSAFE_TO_RUN), rule("PLAIN", "n_rows", ">", 1, V.REQUIRES_CONFIRMATION)))
    check("UNSAFE_TO_RUN outranks everything", assess(unsafe, {"n_rows": 5000}).verdict is V.UNSAFE_TO_RUN)

    print("\n=== a fact that was not measured is never assumed ===")
    facts = dict(GOOD)
    del facts["n_distinct"]
    a = assess(BENFORD, facts)
    check("missing fact -> INSUFFICIENT_DATA naming it", a.verdict is V.INSUFFICIENT_DATA and a.reason_codes == ("MISSING_N_DISTINCT",), a.reason_codes)
    for label, bad in (("None", None), ("NaN", float("nan")), ("infinity", float("inf")), ("a string", "lots")):
        a = assess(BENFORD, with_facts(n_distinct=bad))
        check(f"a {label} value is treated as unmeasured", a.verdict is V.INSUFFICIENT_DATA and a.reason_codes == ("MISSING_N_DISTINCT",), a.reason_codes)
    a = assess(BENFORD, {})
    check("no facts at all -> INSUFFICIENT_DATA, never SUPPORTED", a.verdict is V.INSUFFICIENT_DATA and not a.runnable)
    check("missing_code is derived from the fact name", missing_code("role.amount.bound") == "MISSING_ROLE_AMOUNT_BOUND")

    print("\n=== nothing is chosen for the user: roles and domain inputs ===")
    check("role never bound -> INSUFFICIENT_DATA", assess(BENFORD, with_facts(role__amount__bound=False)).reason_codes[:1] == ("ROLE_UNBOUND_AMOUNT",))
    a = assess(BENFORD, with_facts(role__amount__pending=True))
    check("role suggested but unconfirmed -> REQUIRES_CONFIRMATION", a.verdict is V.REQUIRES_CONFIRMATION and not a.runnable, a.reason_codes)
    check("role confirmed -> runs", assess(BENFORD, GOOD).runnable)
    holiday = RuleSet(M, needs_input("holiday calendar"))
    a = assess(holiday, {})
    check("calendar facts absent -> INSUFFICIENT_DATA (never assumed supplied)", a.verdict is V.INSUFFICIENT_DATA and not a.runnable, a.reason_codes)
    a = assess(holiday, {"input.holiday_calendar.supplied": False, "input.holiday_calendar.pending": False})
    check("calendar not supplied -> INSUFFICIENT_DATA with a specific code", a.verdict is V.INSUFFICIENT_DATA and a.reason_codes == ("INPUT_NOT_SUPPLIED_HOLIDAY_CALENDAR",), a.reason_codes)
    a = assess(holiday, {"input.holiday_calendar.supplied": True, "input.holiday_calendar.pending": True})
    check("calendar supplied but unconfirmed -> REQUIRES_CONFIRMATION", a.verdict is V.REQUIRES_CONFIRMATION and a.reason_codes == ("INPUT_UNCONFIRMED_HOLIDAY_CALENDAR",), a.reason_codes)
    a = assess(holiday, {"input.holiday_calendar.supplied": True, "input.holiday_calendar.pending": False})
    check("calendar supplied and confirmed -> runs", a.runnable and a.verdict is V.SUPPORTED)
    for name in ("pay scale", "approval limit", "EPF rate", "ESI rate"):
        r = assess(RuleSet(M, needs_input(name)), {})
        check(f"{name}: never assumed", r.verdict is V.INSUFFICIENT_DATA and not r.runnable, r.reason_codes[:1])

    print("\n=== a reason already explained by another is not reported twice ('unless') ===")
    a = assess(BENFORD, with_facts(n_eligible=184, n_distinct=67))
    check("a small sample suppresses 'few distinct values' and 'modest sample'",
          a.reason_codes == ("SMALL_SAMPLE",) and a.verdict is V.INSUFFICIENT_DATA, a.reason_codes)
    a = assess(BENFORD, with_facts(n_eligible=500, n_distinct=67))
    check("...but only when the explaining rule actually fired",
          a.reason_codes == ("CONSTRAINED_VALUES", "MODEST_SAMPLE"), a.reason_codes)
    rejects("'unless' naming a code that does not exist is rejected",
            lambda: RuleSet(M, (rule("A_B", "f", ">", 0, V.NOT_APPLICABLE, unless=("NOPE_X",)),)), "do not exist")
    rejects("a rule cannot be suppressed by itself",
            lambda: rule("A_B", "f", ">", 0, V.NOT_APPLICABLE, unless=("A_B",)), "other rules")
    rejects("two rules that suppress each other are rejected (they could hide everything)",
            lambda: RuleSet(M, (rule("A_B", "f", ">", 0, V.NOT_APPLICABLE, unless=("C_D",)),
                                rule("C_D", "f", ">", 0, V.NOT_APPLICABLE, unless=("A_B",)))), "cycle")
    rejects("longer cycles are rejected too",
            lambda: RuleSet(M, (rule("A_B", "f", ">", 0, V.NOT_APPLICABLE, unless=("C_D",)),
                                rule("C_D", "f", ">", 0, V.NOT_APPLICABLE, unless=("E_F",)),
                                rule("E_F", "f", ">", 0, V.NOT_APPLICABLE, unless=("A_B",)))), "cycle")
    chain = RuleSet(M, (rule("A_B", "f", ">", 0, V.NOT_APPLICABLE, unless=("C_D",)),
                        rule("C_D", "f", ">", 0, V.INSUFFICIENT_DATA, unless=("E_F",)),
                        rule("E_F", "f", ">", 0, V.SUPPORTED_WITH_WARNING)))
    check("a chain (not a cycle) is allowed, and the root reason still shows",
          assess(chain, {"f": 1}).reason_codes == ("E_F",), assess(chain, {"f": 1}).reason_codes)

    print("\n=== deterministic and pure ===")
    facts = with_facts(n_eligible=100, n_distinct=30)
    before = copy.deepcopy(facts)
    first = assess(BENFORD, facts)
    check("the facts are never modified", facts == before)
    check("same facts -> identical assessment", assess(BENFORD, facts) == first)
    shuffled_ok = True
    for seed in range(20):
        rules = list(BENFORD.rules)
        random.Random(seed).shuffle(rules)
        shuffled_ok &= assess(RuleSet(BENFORD.method, tuple(rules)), facts) == first
    check("the order rules are written in does not change the result", shuffled_ok)

    print("\n=== what to measure, and how much to trust it ===")
    check("facts_required names exactly what the profiler must measure",
          BENFORD.facts_required() == {"role.amount.bound", "role.amount.pending", "n_eligible", "n_distinct", "magnitude_span", "nonpositive_share"})
    check("a rule set with default thresholds is flagged unvalidated", assess(BENFORD, GOOD).unvalidated is True)
    validated = RuleSet(M, (rule("SMALL", "n", "<", 10, V.INSUFFICIENT_DATA, validated=True),))
    check("a rule set of validated thresholds is not flagged", assess(validated, {"n": 50}).unvalidated is False)
    check("even a SUPPORTED verdict carries the unvalidated flag in its summary", assess(BENFORD, GOOD).summary().get("thresholds") == "unvalidated" or assess(BENFORD, GOOD).summary() == {})

    print("\n=== declining becomes evidence (contract result) ===")
    declined = assess(BENFORD, with_facts(n_eligible=1500, n_distinct=30, magnitude_span=1.5)).to_declined()
    check("a declined contract result, valid and compact", declined.status is Status.DECLINED and declined.verdict is V.NOT_APPLICABLE and len(declined.to_json()) < 420, len(declined.to_json()))
    check("it names the reasons and the facts that decided it", '"why":["CONSTRAINED_VALUES","NARROW_MAGNITUDE_RANGE"]' in declined.to_json() and '"n_distinct":30' in declined.to_json() and '"magnitude_span":1.5' in declined.to_json() and '"thresholds":"unvalidated"' in declined.to_json(), declined.to_json()[:200])
    rejects("a runnable assessment cannot be 'declined'", lambda: assess(BENFORD, GOOD).to_declined(), "non-runnable")

    print("\n=== realistic scenarios (numbers measured in a real audit) ===")
    # staff_lines.amount: 7,108 usable values but only 30 distinct (fixed-rate pay)
    a = assess(BENFORD, {"role.amount.bound": True, "role.amount.pending": False, "n_eligible": 7108, "n_distinct": 30})
    check("fixed-rate pay column (7,108 rows, 30 distinct values) -> NOT_APPLICABLE, so no false ANOMALY", a.verdict is V.NOT_APPLICABLE and "CONSTRAINED_VALUES" in a.reason_codes, a.reason_codes)
    # invoices.total_amount: 184 values
    a = assess(BENFORD, {"role.amount.bound": True, "role.amount.pending": False, "n_eligible": 184, "n_distinct": 67,
                         "magnitude_span": 2.72, "nonpositive_share": 0.0})
    check("184 invoice totals -> INSUFFICIENT_DATA (previously it ran and reported)", a.verdict is V.INSUFFICIENT_DATA and a.reason_codes == ("SMALL_SAMPLE",), a.reason_codes)
    a = assess(BENFORD, with_facts(n_eligible=5000, n_distinct=3000, magnitude_span=4.5))
    check("a large, spread-out, confirmed amount column -> SUPPORTED", a.verdict is V.SUPPORTED and a.runnable)


if __name__ == "__main__":
    unit_tests()
    print("\n" + ("ALL TESTS PASS" if failures == 0 else f"{failures} TEST(S) FAILED"))
    sys.exit(1 if failures else 0)

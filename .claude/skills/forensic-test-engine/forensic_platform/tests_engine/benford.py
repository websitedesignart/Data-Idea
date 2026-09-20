"""
Benford's Law first-digit test.

Methodology adapted from the published statistical procedure in Nigrini,
"Benford's Law: Applications for Forensic Accounting, Auditing, and Fraud
Detection" (2012) — the MAD conformity bands and chi-square/MAD formulas are
standard published statistics, not sourced from any particular software's
implementation. Deterministic: pure SQL aggregation plus closed-form
statistics, no machine learning, no randomness.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from psycopg2 import sql

from ..core.contract import MethodRef, Verdict
from ..core.sqlsafe import ident
from ..core.suitability import Rule, RuleSet, Threshold, needs_role

TEST_NAME = "benford"
TEST_VERSION = "1.1.0"

BENFORD_EXPECTED = {d: math.log10(1 + 1 / d) for d in range(1, 10)}

MIN_RELIABLE_SAMPLE = 300


@dataclass
class BenfordResult:
    records_examined: int
    digit_counts: dict
    digit_observed_pct: dict
    digit_expected_pct: dict
    mad: float
    conformity: str
    chi_square: float
    reliable_sample_size: bool
    query_text: str


# Suitability: should this test run on this column at all? Every threshold below is an UNVALIDATED
# starting default (validated=False): a judgement to be checked against fixtures, not a finding.
_STARTING = "starting default; not validated against fixtures"
_STRUCTURAL = "structural rule, not a tunable threshold"
RULESET = RuleSet(MethodRef(TEST_NAME, TEST_VERSION), (
    *needs_role("amount"),
    Rule("FEW_ELIGIBLE_VALUES", "n_eligible", "<", Threshold(MIN_RELIABLE_SAMPLE, False, "engine minimum, after Nigrini's guidance; not validated"),
         Verdict.INSUFFICIENT_DATA, "too few non-zero values for a reliable first-digit test"),
    Rule("FEW_DISTINCT_VALUES", "n_distinct", "<", Threshold(100, False, _STARTING),
         Verdict.NOT_APPLICABLE, "too few distinct values for a digit distribution", unless=("FEW_ELIGIBLE_VALUES",)),
    Rule("NARROW_MAGNITUDE_SPAN", "magnitude_span", "<", Threshold(2.0, False, _STARTING),
         Verdict.NOT_APPLICABLE, "values span under two orders of magnitude", unless=("FEW_ELIGIBLE_VALUES",)),
    Rule("FIXED_VALUES_DOMINATE", "top10_share", ">", Threshold(0.8, False, _STARTING),
         Verdict.NOT_APPLICABLE, "ten values hold most rows (rate card or fixed amounts)", unless=("FEW_ELIGIBLE_VALUES",)),
    Rule("IDENTIFIER_LIKE_COLUMN", "identifier_like", "==", Threshold(True, True, _STRUCTURAL),
         Verdict.NOT_APPLICABLE, "column looks like an assigned number, not a measured amount"),
    Rule("MANY_ZERO_OR_NEGATIVE", "nonpositive_share", ">", Threshold(0.2, False, _STARTING),
         Verdict.SUPPORTED_WITH_WARNING, "many zero or negative values; absolute values are tested"),
))


def _leading_digit_query(schema: str, table: str, column: str) -> sql.Composable:
    # Names are validated and quoted by psycopg2, never pasted into the SQL text.
    # The FIRST SIGNIFICANT digit: leading zeros are stripped, so 0.0456 counts as a 4 (values below 1
    # were previously read as '0' and silently dropped). NaN and infinity have no digits and drop out.
    digit = ("left(ltrim(regexp_replace(abs(({c})::numeric)::text, '[^0-9]', '', 'g'), '0'), 1)")
    return sql.SQL(
        "SELECT " + digit + " AS digit, count(*) AS n "
        "FROM {t} "
        "WHERE {c} IS NOT NULL AND {c} <> 0 "
        "GROUP BY 1 "
        "HAVING " + digit + " IN ('1','2','3','4','5','6','7','8','9') "
        "ORDER BY 1"
    ).format(c=ident(column), t=ident(schema, table))


def _mad_conformity(mad: float) -> str:
    # Nigrini (2012) MAD conformity bands for the first-digit test.
    if mad < 0.006:
        return "close conformity"
    if mad < 0.012:
        return "acceptable conformity"
    if mad < 0.015:
        return "marginally acceptable conformity"
    return "nonconformity"


def run(cur, schema: str, table: str, column: str) -> BenfordResult:
    composed = _leading_digit_query(schema, table, column)
    query = composed.as_string(cur)  # reproducible query text, stored and reported with the result
    cur.execute(composed)
    rows = cur.fetchall()

    digit_counts = {int(d): int(n) for d, n in rows}
    total = sum(digit_counts.values())
    if total == 0:
        raise ValueError(
            f"No usable (non-null, non-zero) numeric values found in {schema}.{table}.{column}"
        )

    observed_pct = {d: digit_counts.get(d, 0) / total for d in range(1, 10)}
    expected_pct = BENFORD_EXPECTED

    mad = sum(abs(observed_pct[d] - expected_pct[d]) for d in range(1, 10)) / 9
    chi_square = sum(
        ((digit_counts.get(d, 0) - expected_pct[d] * total) ** 2) / (expected_pct[d] * total)
        for d in range(1, 10)
    )

    return BenfordResult(
        records_examined=total,
        digit_counts=digit_counts,
        digit_observed_pct=observed_pct,
        digit_expected_pct=expected_pct,
        mad=mad,
        conformity=_mad_conformity(mad),
        chi_square=chi_square,
        reliable_sample_size=total >= MIN_RELIABLE_SAMPLE,
        query_text=query,
    )

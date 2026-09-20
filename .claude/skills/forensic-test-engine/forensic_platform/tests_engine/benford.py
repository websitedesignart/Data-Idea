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

from ..core.sqlsafe import ident

TEST_NAME = "benford"
TEST_VERSION = "1.0.0"

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


def _leading_digit_query(schema: str, table: str, column: str) -> sql.Composable:
    # Names are validated and quoted by psycopg2, never pasted into the SQL text.
    return sql.SQL(
        "SELECT left(regexp_replace(abs(({c})::numeric)::text, '[^0-9]', '', 'g'), 1) AS digit, "
        "count(*) AS n "
        "FROM {t} "
        "WHERE {c} IS NOT NULL AND {c} <> 0 "
        "GROUP BY 1 "
        "HAVING left(regexp_replace(abs(({c})::numeric)::text, '[^0-9]', '', 'g'), 1) "
        "IN ('1','2','3','4','5','6','7','8','9') "
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

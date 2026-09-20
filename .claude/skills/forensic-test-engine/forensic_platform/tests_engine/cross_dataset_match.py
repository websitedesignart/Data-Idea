"""
Cross-dataset matching / referential completeness.

Answers the question every other test depends on but none of them ask: does the
population under analysis actually tie to its counterpart? Compares the distinct
key values of a left dataset against a right dataset and reports coverage in
both directions.

Typical uses:
  - do practitioner rows reference establishments that exist in the register?
  - do registered establishments have any practitioner rows at all?
  - do this year's registrations appear in last year's?

An orphaned key is a completeness or integrity fact. It is not evidence of
wrongdoing: extracts are routinely partial, and a missing counterpart may simply
mean the row was never exported.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from psycopg2 import sql

from ..core.identity import RowIdentity, resolve_row_identity

TEST_NAME = "cross-dataset-match"
TEST_VERSION = "1.0.0"

DEFAULT_PLACEHOLDERS = [
    "0", "00", "000", "0000", "1", "NIL", "NA", "N/A", "NO", "NONE",
    "-", "--", ".", "XX", "XXX", "NOT AVAILABLE", "NOT APPLICABLE",
]


@dataclass
class CrossMatchResult:
    left: str
    right: str
    left_rows: int
    right_rows: int
    left_distinct: int
    right_distinct: int
    in_both: int
    only_left: int
    only_right: int
    left_coverage_pct: float
    right_coverage_pct: float
    orphan_left_rows: int
    sample_only_left: list = field(default_factory=list)
    sample_only_right: list = field(default_factory=list)
    evidence: list = field(default_factory=list)  # tuples of `identity` column values (left table)
    query_text: str = ""
    identity: RowIdentity | None = None


def _norm(col: str) -> str:
    return f"upper(regexp_replace(btrim({col}::text), '\\s+', ' ', 'g'))"


def run(
    cur,
    schema: str,
    table: str,
    column: str,
    right_table: str,
    right_column: str,
    right_schema: str | None = None,
    exclude_placeholders: bool = True,
    evidence_limit: int = 50000,
    identity: RowIdentity | None = None,
) -> CrossMatchResult:
    # Evidence is linked to the LEFT table's rows (the ones with no counterpart), so that
    # table needs a usable row identity. Resolve first so this fails up front, not after
    # the reconciliation has already been computed. Raises NoRowIdentity.
    identity = identity or resolve_row_identity(cur, schema, table)
    rschema = right_schema or schema
    lkey = _norm(f'"{column}"')
    rkey = _norm(f'"{right_column}"')

    lfilter = f"{lkey} IS NOT NULL AND {lkey} <> ''"
    rfilter = f"{rkey} IS NOT NULL AND {rkey} <> ''"
    params: list = []
    if exclude_placeholders:
        lfilter += f" AND {lkey} <> ALL(%s)"
        rfilter += f" AND {rkey} <> ALL(%s)"

    cur.execute(f'SELECT count(*) FROM "{schema}"."{table}"')
    left_rows = cur.fetchone()[0]
    cur.execute(f'SELECT count(*) FROM "{rschema}"."{right_table}"')
    right_rows = cur.fetchone()[0]

    lp = [DEFAULT_PLACEHOLDERS] if exclude_placeholders else []
    cur.execute(f'SELECT count(DISTINCT {lkey}) FROM "{schema}"."{table}" WHERE {lfilter}', lp)
    left_distinct = cur.fetchone()[0]
    cur.execute(
        f'SELECT count(DISTINCT {rkey}) FROM "{rschema}"."{right_table}" WHERE {rfilter}', lp)
    right_distinct = cur.fetchone()[0]

    query = (
        f'WITH l AS (SELECT DISTINCT {lkey} k FROM "{schema}"."{table}" WHERE {lfilter}),\n'
        f'     r AS (SELECT DISTINCT {rkey} k FROM "{rschema}"."{right_table}" WHERE {rfilter})\n'
        f'SELECT (SELECT count(*) FROM l JOIN r USING (k)),\n'
        f'       (SELECT count(*) FROM l WHERE k NOT IN (SELECT k FROM r)),\n'
        f'       (SELECT count(*) FROM r WHERE k NOT IN (SELECT k FROM l))'
    )
    cur.execute(query, lp + lp if exclude_placeholders else [])
    in_both, only_left, only_right = cur.fetchone()

    cur.execute(
        f'WITH r AS (SELECT DISTINCT {rkey} k FROM "{rschema}"."{right_table}" WHERE {rfilter})\n'
        f'SELECT DISTINCT {lkey} FROM "{schema}"."{table}" WHERE {lfilter} '
        f'AND {lkey} NOT IN (SELECT k FROM r) ORDER BY 1 LIMIT 25', lp + lp if exclude_placeholders else [])
    sample_left = [r[0] for r in cur.fetchall()]

    cur.execute(
        f'WITH l AS (SELECT DISTINCT {lkey} k FROM "{schema}"."{table}" WHERE {lfilter})\n'
        f'SELECT DISTINCT {rkey} FROM "{rschema}"."{right_table}" WHERE {rfilter} '
        f'AND {rkey} NOT IN (SELECT k FROM l) ORDER BY 1 LIMIT 25', lp + lp if exclude_placeholders else [])
    sample_right = [r[0] for r in cur.fetchall()]

    pk = identity.select_list()
    cur.execute(
        sql.SQL(f'WITH r AS (SELECT DISTINCT {rkey} k FROM "{rschema}"."{right_table}" WHERE {rfilter})\nSELECT ')
        + pk
        + sql.SQL(" FROM ") + sql.Identifier(schema, table)
        + sql.SQL(f" WHERE {lfilter} AND {lkey} NOT IN (SELECT k FROM r) ORDER BY ")
        + pk
        + sql.SQL(" LIMIT %s"),
        (lp + lp if exclude_placeholders else []) + [evidence_limit])
    evidence = [tuple(r) for r in cur.fetchall()]

    return CrossMatchResult(
        left=f"{schema}.{table}.{column}",
        right=f"{rschema}.{right_table}.{right_column}",
        left_rows=left_rows,
        right_rows=right_rows,
        left_distinct=left_distinct,
        right_distinct=right_distinct,
        in_both=in_both,
        only_left=only_left,
        only_right=only_right,
        left_coverage_pct=round(100.0 * in_both / left_distinct, 3) if left_distinct else 0.0,
        right_coverage_pct=round(100.0 * in_both / right_distinct, 3) if right_distinct else 0.0,
        orphan_left_rows=len(evidence),
        sample_only_left=sample_left,
        sample_only_right=sample_right,
        evidence=evidence,
        query_text=query,
        identity=identity,
    )

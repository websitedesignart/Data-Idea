"""
Duplicate and shared-identifier analysis.

Two modes, both deterministic pure SQL:

  1. duplicate       - key values appearing on more than `min_occurrences` rows.
                       Classic duplicate detection (e.g. one certificate number
                       issued to several records).

  2. shared_identifier - key values that map to MORE THAN ONE distinct value of a
                       second column (e.g. one practitioner registration number
                       recorded against several different practitioner names, or
                       attached to several distinct establishments).

Normalisation applied for matching only (the source is never altered): trim,
collapse internal whitespace, uppercase. Placeholder tokens ('0', 'NIL', 'NA',
...) are excluded when requested, because a placeholder shared across many rows
is a data-entry artefact, not a shared identifier - verified necessary on the
real registration data, where '0' alone spanned 388 establishments.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from psycopg2 import sql

from ..core.identity import RowIdentity, resolve_row_identity
from ..core.sqlsafe import ident, norm_expr

TEST_NAME = "duplicate-analysis"
TEST_VERSION = "1.0.0"

DEFAULT_PLACEHOLDERS = [
    "0", "00", "000", "0000", "1", "NIL", "NA", "N/A", "NO", "NONE",
    "-", "--", ".", "XX", "XXX", "NOT AVAILABLE", "NOT APPLICABLE",
]


@dataclass
class DuplicateResult:
    mode: str
    records_examined: int
    keys_examined: int
    flagged_keys: int
    flagged_rows: int
    max_group_size: int
    placeholders_excluded_rows: int
    top_groups: list = field(default_factory=list)
    evidence: list = field(default_factory=list)  # tuples of `identity` column values
    query_text: str = ""
    identity: RowIdentity | None = None


def run(
    cur,
    schema: str,
    table: str,
    column: str,
    distinct_of: str | None = None,
    min_occurrences: int = 2,
    exclude_placeholders: bool = True,
    require_digit: bool = False,
    evidence_limit: int = 50000,
    identity: RowIdentity | None = None,
) -> DuplicateResult:
    # Resolve first: a table with no usable row identity must fail up front, not only once
    # something is flagged and evidence is needed. Raises NoRowIdentity.
    identity = identity or resolve_row_identity(cur, schema, table)
    # Every caller-supplied name goes through ident() (validated + quoted), never into SQL text.
    tbl = ident(schema, table)
    key = norm_expr(ident(column))
    mode = "shared_identifier" if distinct_of else "duplicate"

    ph_clause = sql.SQL("")
    params: list = []
    if exclude_placeholders:
        ph_clause = sql.SQL(" AND {} <> ALL(%s)").format(key)
        params.append(DEFAULT_PLACEHOLDERS)
    if require_digit:
        # A registration/certificate number without a single digit is free text in a
        # numeric field ('MCI', 'HOSPITAL', a surname), not an identifier. Structural
        # rule, preferred over an endlessly growing denylist.
        ph_clause += sql.SQL(" AND {} ~ '[0-9]'").format(key)

    cur.execute(sql.SQL("SELECT count(*) FROM {}").format(tbl))
    records_examined = cur.fetchone()[0]

    placeholders_excluded = 0
    if exclude_placeholders:
        cur.execute(
            sql.SQL("SELECT count(*) FROM {t} WHERE {k} = ANY(%s)").format(t=tbl, k=key),
            [DEFAULT_PLACEHOLDERS],
        )
        placeholders_excluded = cur.fetchone()[0]

    base_where = sql.SQL("{k} IS NOT NULL AND {k} <> ''").format(k=key) + ph_clause

    if distinct_of:
        measure = sql.SQL("count(DISTINCT {})").format(norm_expr(ident(distinct_of)))
    else:
        measure = sql.SQL("count(*)")

    composed = sql.SQL(
        "SELECT {k} AS key_value, count(*) AS row_count, {m} AS measure_value\n"
        "FROM {t}\n"
        "WHERE {w}\n"
        "GROUP BY {k}\n"
        "HAVING {m} >= %s\n"
        "ORDER BY {m} DESC, count(*) DESC"
    ).format(k=key, m=measure, t=tbl, w=base_where)
    query = composed.as_string(cur)  # reproducible query text, stored and reported with the result
    cur.execute(composed, params + [min_occurrences])
    groups = cur.fetchall()

    cur.execute(
        sql.SQL("SELECT count(DISTINCT {k}) FROM {t} WHERE {w}").format(k=key, t=tbl, w=base_where),
        params)
    keys_examined = cur.fetchone()[0]

    flagged_keys = len(groups)
    flagged_rows = sum(int(g[1]) for g in groups)
    max_group = max((int(g[2]) for g in groups), default=0)

    top = [
        {"key_value": g[0], "row_count": int(g[1]), "measure_value": int(g[2])}
        for g in groups[:100]
    ]

    evidence: list = []
    if flagged_keys:
        keys = [g[0] for g in groups]
        pk = identity.select_list()
        cur.execute(
            sql.SQL("SELECT {pk} FROM {t} WHERE {k} = ANY(%s) ORDER BY {k}, {pk} LIMIT %s")
            .format(pk=pk, t=tbl, k=key),
            [keys, evidence_limit],
        )
        evidence = [tuple(r) for r in cur.fetchall()]

    return DuplicateResult(
        mode=mode,
        records_examined=records_examined,
        keys_examined=keys_examined,
        flagged_keys=flagged_keys,
        flagged_rows=flagged_rows,
        max_group_size=max_group,
        placeholders_excluded_rows=placeholders_excluded,
        top_groups=top,
        evidence=evidence,
        query_text=query,
        identity=identity,
    )

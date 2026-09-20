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
    evidence: list = field(default_factory=list)
    query_text: str = ""


def _norm(col: str) -> str:
    """SQL normalisation expression, matching the Python analysis exactly."""
    return f"upper(regexp_replace(btrim({col}::text), '\\s+', ' ', 'g'))"


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
) -> DuplicateResult:
    key = _norm(f'"{column}"')
    mode = "shared_identifier" if distinct_of else "duplicate"

    ph_clause = ""
    params: list = []
    if exclude_placeholders:
        ph_clause = f" AND {key} <> ALL(%s)"
        params.append(DEFAULT_PLACEHOLDERS)
    if require_digit:
        # A registration/certificate number without a single digit is free text in a
        # numeric field ('MCI', 'HOSPITAL', a surname), not an identifier. Structural
        # rule, preferred over an endlessly growing denylist.
        ph_clause += " AND {} ~ '[0-9]'".format(key)

    cur.execute(f'SELECT count(*) FROM "{schema}"."{table}"')
    records_examined = cur.fetchone()[0]

    placeholders_excluded = 0
    if exclude_placeholders:
        cur.execute(
            f'SELECT count(*) FROM "{schema}"."{table}" WHERE {key} = ANY(%s)',
            [DEFAULT_PLACEHOLDERS],
        )
        placeholders_excluded = cur.fetchone()[0]

    base_where = f"{key} IS NOT NULL AND {key} <> ''{ph_clause}"

    if distinct_of:
        measure = f'count(DISTINCT {_norm(chr(34) + distinct_of + chr(34))})'
        having = f"{measure} >= %s"
    else:
        measure = "count(*)"
        having = f"{measure} >= %s"

    query = (
        f'SELECT {key} AS key_value, count(*) AS row_count, {measure} AS measure_value\n'
        f'FROM "{schema}"."{table}"\n'
        f'WHERE {base_where}\n'
        f'GROUP BY {key}\n'
        f'HAVING {having}\n'
        f'ORDER BY {measure} DESC, count(*) DESC'
    )
    cur.execute(query, params + [min_occurrences])
    groups = cur.fetchall()

    cur.execute(
        f'SELECT count(DISTINCT {key}) FROM "{schema}"."{table}" WHERE {base_where}', params)
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
        cur.execute(
            f'SELECT _row_no, {key} FROM "{schema}"."{table}" '
            f'WHERE {key} = ANY(%s) ORDER BY {key}, _row_no LIMIT %s',
            [keys, evidence_limit],
        )
        evidence = [(int(r[0]), r[1]) for r in cur.fetchall()]

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
    )

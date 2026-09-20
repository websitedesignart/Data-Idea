"""
Fuzzy entity matching - collapses near-duplicate name variants so that a count
of "distinct entities" is not inflated by spelling.

Why this exists: on real practitioner-registration data, a single registration
number showed 13 "distinct practitioner names" that were all spellings of one
person (e.g. DR ANUPAM KUMAR BHARGAVA / ANUPAMKUMARBHARGAVA /
DR ANUPAM KUKMAR BHARGAVA ... - synthetic names used here). Exact matching
therefore overstates identity conflict, while understating nothing.

Algorithm - deliberately simple, self-contained and auditable rather than
delegated to a database extension or third-party library, so that any reviewer
can read and reproduce it:

  1. canonicalise : uppercase, strip accents-free non-letters to spaces, drop
                    honorifics (DR, SMT, PROF ...), sort the remaining tokens
                    alphabetically, and join. Token sorting makes
                    "BHARGAVA ANUPAM KUMAR" and "ANUPAM KUMAR BHARGAVA" identical.
  2. similarity   : Jaccard overlap of padded 3-grams of the canonical form.
  3. cluster      : single-linkage union-find over all within-group pairs, with
                    inputs sorted first so the output is order-independent and
                    byte-for-byte reproducible.

Deterministic: no randomness, no model, no locale-dependent collation.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

TEST_NAME = "fuzzy-entity-match"
TEST_VERSION = "1.0.0"

HONORIFICS = {
    "DR", "DRS", "SMT", "SHRI", "SRI", "MR", "MRS", "MS", "MISS", "PROF",
    "PROFESSOR", "LATE", "SH", "KM",
}

DEFAULT_THRESHOLD = 0.55
DEFAULT_PLACEHOLDERS = [
    "0", "00", "000", "0000", "1", "NIL", "NA", "N/A", "NO", "NONE",
    "-", "--", ".", "XX", "XXX", "NOT AVAILABLE", "NOT APPLICABLE",
]


@dataclass
class FuzzyResult:
    records_examined: int
    keys_examined: int
    keys_with_multiple_raw: int
    flagged_keys: int
    collapsed_by_spelling: int
    max_entities: int
    threshold: float
    top_groups: list = field(default_factory=list)
    evidence: list = field(default_factory=list)
    query_text: str = ""


def _tokens(name: str) -> list[str]:
    s = re.sub(r"[^A-Za-z]+", " ", str(name).upper())
    tokens = [t for t in s.split() if t and t not in HONORIFICS]
    return tokens or [t for t in s.split() if t]


def canonical(name: str) -> str:
    """Token-sorted form: makes word order irrelevant
    ('BHARGAVA ANUPAM KUMAR' == 'ANUPAM KUMAR BHARGAVA')."""
    return "".join(sorted(_tokens(name)))


def canonical_flat(name: str) -> str:
    """Letters-only form preserving order: makes spacing irrelevant
    ('ANUPAMKUMARBHARGAVA' == 'ANUPAM KUMAR BHARGAVA')."""
    return "".join(_tokens(name))


def trigrams(s: str) -> set[str]:
    padded = f"  {s} "
    return {padded[i:i + 3] for i in range(len(padded) - 2)} if s else set()


def similarity(a: str, b: str) -> float:
    if a == b:
        return 1.0
    ta, tb = trigrams(a), trigrams(b)
    if not ta or not tb:
        return 0.0
    inter = len(ta & tb)
    return inter / (len(ta) + len(tb) - inter)


def name_similarity(a: str, b: str) -> float:
    """Compare two raw names using both canonical forms and take the stronger
    match, so word reordering and lost spacing are each handled."""
    return max(
        similarity(canonical(a), canonical(b)),
        similarity(canonical_flat(a), canonical_flat(b)),
    )


def cluster_names(names: list[str], threshold: float) -> list[list[str]]:
    """Single-linkage clustering. Inputs sorted so results are reproducible."""
    ordered = sorted(set(names))
    parent = list(range(len(ordered)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int) -> None:
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[max(ri, rj)] = min(ri, rj)

    for i in range(len(ordered)):
        for j in range(i + 1, len(ordered)):
            if name_similarity(ordered[i], ordered[j]) >= threshold:
                union(i, j)

    buckets: dict[int, list[str]] = {}
    for idx, name in enumerate(ordered):
        buckets.setdefault(find(idx), []).append(name)
    return [buckets[k] for k in sorted(buckets)]


def _norm_sql(col: str) -> str:
    return f"upper(regexp_replace(btrim({col}::text), '\\s+', ' ', 'g'))"


def run(
    cur,
    schema: str,
    table: str,
    column: str,
    distinct_of: str,
    min_entities: int = 2,
    threshold: float = DEFAULT_THRESHOLD,
    exclude_placeholders: bool = True,
    require_digit: bool = False,
    evidence_limit: int = 50000,
) -> FuzzyResult:
    """`column` is the identifier (e.g. reg_no); `distinct_of` is the name column."""
    key = _norm_sql(f'"{column}"')
    val = _norm_sql(f'"{distinct_of}"')

    params: list = []
    ph = ""
    if exclude_placeholders:
        ph = f" AND {key} <> ALL(%s)"
        params.append(DEFAULT_PLACEHOLDERS)
    if require_digit:
        # See duplicate_analysis: a digitless identifier is free text, not an identifier.
        ph += " AND {} ~ '[0-9]'".format(key)

    cur.execute(f'SELECT count(*) FROM "{schema}"."{table}"')
    records_examined = cur.fetchone()[0]

    query = (
        f'SELECT {key} AS key_value, {val} AS name_value, count(*) AS n\n'
        f'FROM "{schema}"."{table}"\n'
        f'WHERE {key} IS NOT NULL AND {key} <> \'\'{ph}\n'
        f'  AND {val} IS NOT NULL AND {val} <> \'\'\n'
        f'GROUP BY 1, 2'
    )
    cur.execute(query, params)

    by_key: dict[str, list[str]] = {}
    for key_value, name_value, _ in cur.fetchall():
        by_key.setdefault(key_value, []).append(name_value)

    keys_examined = len(by_key)
    multiple_raw = 0
    flagged: list[tuple[str, int, int]] = []
    for key_value, names in by_key.items():
        raw = len(set(names))
        if raw > 1:
            multiple_raw += 1
        else:
            continue
        clusters = cluster_names(names, threshold)
        if len(clusters) >= min_entities:
            flagged.append((key_value, len(clusters), raw))

    flagged.sort(key=lambda t: (-t[1], -t[2], t[0]))
    max_entities = max((f[1] for f in flagged), default=0)

    evidence: list = []
    if flagged:
        keys = [f[0] for f in flagged]
        cur.execute(
            f'SELECT _row_no FROM "{schema}"."{table}" WHERE {key} = ANY(%s) '
            f'ORDER BY _row_no LIMIT %s',
            [keys, evidence_limit],
        )
        evidence = [int(r[0]) for r in cur.fetchall()]

    return FuzzyResult(
        records_examined=records_examined,
        keys_examined=keys_examined,
        keys_with_multiple_raw=multiple_raw,
        flagged_keys=len(flagged),
        collapsed_by_spelling=multiple_raw - len(flagged),
        max_entities=max_entities,
        threshold=threshold,
        top_groups=[
            {"key_value": k, "distinct_entities": c, "raw_distinct_names": r}
            for k, c, r in flagged[:100]
        ],
        evidence=evidence,
        query_text=query,
    )

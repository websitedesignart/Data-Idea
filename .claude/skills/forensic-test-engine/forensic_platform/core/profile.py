"""
Profile a table once: measure what each column IS, so methods and role suggestions do not each
rescan it and Claude never has to read a schema dump.

Read-only. The caller supplies the cursor, so the caller decides which role and session limits
apply (statement timeout, read-only transaction). Nothing here returns a VALUE from the data:
only counts, shares, lengths and ranges. Sensitive-looking patterns (Aadhaar-, PAN-, IFSC-,
mobile-, e-mail-shaped) are measured as a share of rows and never echoed.

The metric names are chosen to match the fact names that suitability rules use, so a profile
answers `RuleSet.facts_required()` directly:

    numeric  n_eligible (non-null, non-zero), n_distinct (among those), min_abs, max_abs,
             magnitude_span (log10 of max_abs / min_abs), nonpositive_share, integer_share,
             top10_share (only after `deepen()`: the share held by the 10 commonest values)
    text     len_min, len_max, len_mean, and a share of rows matching each pattern below
    date     min_date, max_date
    any      non_null, distinct, null_rate, is_unique, is_pk, fk_to

One aggregate scan per batch of columns, so a wide table is not one giant statement. A table
larger than MAX_PROFILE_ROWS is refused unless the caller opts in, since profiling is a full scan.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from psycopg2 import sql

from .sqlsafe import ident

MAX_PROFILE_ROWS = 2_000_000
COLUMNS_PER_SCAN = 60

_NUMERIC = {"smallint", "integer", "bigint", "numeric", "real", "double precision"}
_DIGIT_TEXT = {"bigint", "numeric"}      # can hold a 10-12 digit identifier such as an Aadhaar number
_TEXT = {"text", "character varying", "character"}
_DATE = {"date", "timestamp without time zone", "timestamp with time zone"}
_BOOL = {"boolean"}

# Shapes measured as a share of rows. They describe what a column looks like; values are never returned.
PATTERNS = {
    "digits_only": r"^[0-9]+$",
    "numeric_like": r"^\s*-?[0-9][0-9,]*(\.[0-9]+)?\s*$",
    "date_iso": r"^[0-9]{4}-[0-9]{2}-[0-9]{2}",
    "date_dmy": r"^[0-9]{1,2}[-/.][0-9]{1,2}[-/.][0-9]{2,4}$",
    "date_mon": r"^[A-Za-z]{3,9}[ -][0-9]{2,4}$",
    "aadhaar_like": r"^[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}$",
    "pan_like": r"^[A-Z]{5}[0-9]{4}[A-Z]$",
    "ifsc_like": r"^[A-Z]{4}0[A-Z0-9]{6}$",
    "mobile_like": r"^[6-9][0-9]{9}$",
    "email_like": r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
}
_TEXT_PATTERNS = tuple(PATTERNS)
_DIGIT_PATTERNS = ("aadhaar_like", "mobile_like")   # applied to the text form of bigint/numeric columns


class ProfileTooLarge(RuntimeError):
    """Profiling is a full scan; this table is larger than the allowed size (UNSAFE_TO_RUN)."""


@dataclass
class ColumnProfile:
    name: str
    data_type: str
    type_class: str                      # numeric | text | date | boolean | other
    ordinal: int
    non_null: int = 0
    distinct: int = 0
    metrics: dict[str, Any] = field(default_factory=dict)
    is_pk: bool = False
    fk_to: str | None = None

    @property
    def is_unique(self) -> bool:
        return self.non_null > 0 and self.distinct == self.non_null


@dataclass
class TableProfile:
    schema: str
    table: str
    row_count: int
    columns: dict[str, ColumnProfile]

    def column(self, name: str) -> ColumnProfile:
        return self.columns[name]

    def digest(self) -> dict:
        """Tiny summary for Claude: shape only, no schema dump."""
        classes: dict[str, int] = {}
        for c in self.columns.values():
            classes[c.type_class] = classes.get(c.type_class, 0) + 1
        return {"table": f"{self.schema}.{self.table}", "rows": self.row_count, "cols": len(self.columns),
                "types": dict(sorted(classes.items())),
                "empty_cols": sum(1 for c in self.columns.values() if c.non_null == 0)}


def type_class(data_type: str) -> str:
    if data_type in _NUMERIC:
        return "numeric"
    if data_type in _TEXT:
        return "text"
    if data_type in _DATE:
        return "date"
    if data_type in _BOOL:
        return "boolean"
    return "other"


def _shares(pairs: dict[str, int], denominator: int) -> dict[str, float]:
    return {k: round(v / denominator, 6) for k, v in pairs.items()} if denominator else {k: 0.0 for k in pairs}


def _aggregates(col: ColumnProfile) -> list[tuple[str, sql.Composable]]:
    """(metric, SQL expression) pairs for one column, chosen by its type class."""
    c = ident(col.name)
    out: list[tuple[str, sql.Composable]] = [("non_null", sql.SQL("count({})").format(c))]
    if col.type_class in ("numeric", "text", "date"):
        out.append(("distinct", sql.SQL("count(DISTINCT {})").format(c)))
    if col.type_class == "numeric":
        out += [
            ("n_eligible", sql.SQL("count(*) FILTER (WHERE {c} <> 0)").format(c=c)),
            ("n_distinct", sql.SQL("count(DISTINCT {c}) FILTER (WHERE {c} <> 0)").format(c=c)),
            ("min_abs", sql.SQL("min(abs({c}::numeric)) FILTER (WHERE {c} <> 0 AND {c}::numeric NOT IN ('NaN','Infinity','-Infinity'))").format(c=c)),
            ("max_abs", sql.SQL("max(abs({c}::numeric)) FILTER (WHERE {c}::numeric NOT IN ('NaN','Infinity','-Infinity'))").format(c=c)),
            ("nonpositive", sql.SQL("count(*) FILTER (WHERE {c} <= 0)").format(c=c)),
            ("integral", sql.SQL("count(*) FILTER (WHERE {c}::numeric NOT IN ('NaN','Infinity','-Infinity') AND {c}::numeric = trunc({c}::numeric))").format(c=c)),
        ]
        if col.data_type in _DIGIT_TEXT:
            for name in _DIGIT_PATTERNS:
                out.append((name, sql.SQL("count(*) FILTER (WHERE {c}::text ~ {p})").format(c=c, p=sql.Literal(PATTERNS[name]))))
    elif col.type_class == "text":
        out += [
            ("len_min", sql.SQL("min(length({}))").format(c)),
            ("len_max", sql.SQL("max(length({}))").format(c)),
            ("len_mean", sql.SQL("avg(length({}))").format(c)),
        ]
        for name in _TEXT_PATTERNS:
            out.append((name, sql.SQL("count(*) FILTER (WHERE {c} ~ {p})").format(c=c, p=sql.Literal(PATTERNS[name]))))
    elif col.type_class == "date":
        out += [("min_date", sql.SQL("min({})::text").format(c)), ("max_date", sql.SQL("max({})::text").format(c))]
    return out


def profile_table(cur, schema: str, table: str, *, allow_large: bool = False,
                  columns: list[str] | None = None) -> TableProfile:
    """Measure every column of schema.table (or only `columns`). Read-only; counts and shares only."""
    tbl = ident(schema, table)

    cur.execute("SELECT c.reltuples::bigint FROM pg_class c WHERE c.oid = to_regclass(%s)", (tbl.as_string(cur),))
    row = cur.fetchone()
    estimate = row[0] if row else None
    if not allow_large and estimate is not None and estimate > MAX_PROFILE_ROWS:
        raise ProfileTooLarge(
            f"{schema}.{table} has about {estimate:,} rows; profiling is a full scan and is limited to "
            f"{MAX_PROFILE_ROWS:,} rows unless explicitly allowed.")

    cur.execute("SELECT column_name, data_type, ordinal_position FROM information_schema.columns "
                "WHERE table_schema=%s AND table_name=%s ORDER BY ordinal_position", (schema, table))
    cols = {name: ColumnProfile(name, dtype, type_class(dtype), ordinal) for name, dtype, ordinal in cur.fetchall()
            if columns is None or name in columns}
    cur.execute(sql.SQL("SELECT count(*) FROM {}").format(tbl))
    row_count = cur.fetchone()[0]

    # primary key and foreign keys come from the catalog, not from the data
    cur.execute("SELECT a.attname FROM pg_index i JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum = ANY(i.indkey) "
                "WHERE i.indrelid = to_regclass(%s) AND i.indisprimary", (tbl.as_string(cur),))
    for (name,) in cur.fetchall():
        if name in cols:
            cols[name].is_pk = True
    cur.execute("SELECT a.attname, cf.relname FROM pg_constraint k "
                "JOIN pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = ANY(k.conkey) "
                "JOIN pg_class cf ON cf.oid = k.confrelid "
                "WHERE k.contype = 'f' AND k.conrelid = to_regclass(%s)", (tbl.as_string(cur),))
    for name, target in cur.fetchall():
        if name in cols:
            cols[name].fk_to = target

    names = list(cols)
    for start in range(0, len(names), COLUMNS_PER_SCAN):
        batch = [cols[n] for n in names[start:start + COLUMNS_PER_SCAN]]
        plan = [(col, _aggregates(col)) for col in batch]
        exprs = [expr for _, aggs in plan for _, expr in aggs]
        cur.execute(sql.SQL("SELECT {} FROM {}").format(sql.SQL(", ").join(exprs), tbl))
        values = list(cur.fetchone())
        i = 0
        for col, aggs in plan:
            raw = {}
            for metric, _ in aggs:
                raw[metric] = values[i]
                i += 1
            _finish(col, raw, row_count)
    return TableProfile(schema, table, row_count, cols)


def _finish(col: ColumnProfile, raw: dict[str, Any], row_count: int) -> None:
    """Turn raw aggregates into normalised, JSON-safe metrics (shares rounded for determinism)."""
    col.non_null = int(raw["non_null"] or 0)
    col.distinct = int(raw.get("distinct") or 0)
    m: dict[str, Any] = {"null_rate": round(1 - col.non_null / row_count, 6) if row_count else 0.0}
    if col.type_class == "numeric":
        n_elig = int(raw["n_eligible"] or 0)
        m["n_eligible"] = n_elig
        m["n_distinct"] = int(raw["n_distinct"] or 0)
        mn, mx = raw["min_abs"], raw["max_abs"]
        m["min_abs"] = float(mn) if mn is not None else None
        m["max_abs"] = float(mx) if mx is not None else None
        if mn and mx and float(mn) > 0:
            m["magnitude_span"] = round(math.log10(float(mx) / float(mn)), 4)
        m["nonpositive_share"] = round((raw["nonpositive"] or 0) / col.non_null, 6) if col.non_null else None
        m["integer_share"] = round((raw["integral"] or 0) / col.non_null, 6) if col.non_null else None
        for name in _DIGIT_PATTERNS:
            if name in raw:
                m[name + "_share"] = round((raw[name] or 0) / col.non_null, 6) if col.non_null else 0.0
    elif col.type_class == "text":
        m["len_min"], m["len_max"] = raw["len_min"], raw["len_max"]
        m["len_mean"] = round(float(raw["len_mean"]), 2) if raw["len_mean"] is not None else None
        for name in _TEXT_PATTERNS:
            m[name + "_share"] = round((raw[name] or 0) / col.non_null, 6) if col.non_null else 0.0
    elif col.type_class == "date":
        m["min_date"], m["max_date"] = raw["min_date"], raw["max_date"]
    col.metrics = m


def deepen(cur, profile: TableProfile, columns: list[str]) -> None:
    """Measure the costlier per-column facts, only for the columns that need them.
    Currently `top10_share`: the share of eligible values held by the ten commonest ones (a high
    share means a few fixed values dominate, e.g. a rate card)."""
    tbl = ident(profile.schema, profile.table)
    for name in columns:
        col = profile.column(name)
        if col.type_class != "numeric" or "top10_share" in col.metrics:
            continue
        c = ident(name)
        cur.execute(sql.SQL("SELECT coalesce(sum(n), 0) FROM (SELECT count(*) AS n FROM {t} "
                            "WHERE {c} IS NOT NULL AND {c} <> 0 GROUP BY {c} ORDER BY n DESC LIMIT 10) s").format(t=tbl, c=c))
        top = int(cur.fetchone()[0])
        eligible = col.metrics.get("n_eligible") or 0
        col.metrics["top10_share"] = round(top / eligible, 6) if eligible else None

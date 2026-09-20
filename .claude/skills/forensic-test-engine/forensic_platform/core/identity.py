"""
Row identity: how a finding points back at the exact source rows behind it.

Evidence that cannot name its rows is an unsupported assertion, so every test that
writes evidence links needs a *stable, unique* identity for the rows of the table it
reads. This module decides what that identity is, and refuses when there isn't one.

Resolution order (first match wins, nothing is guessed):

  1. the table's declared PRIMARY KEY, including composite keys
  2. the engine's own `_row_no` column, which Excel ingestion creates, but only when it
     is provably unique and non-null in this table
  3. otherwise: NoRowIdentity. The test is refused rather than linked to rows by a
     physical location (ctid) or a row number that could change between runs.

Storage needs no schema change. `_forensic.evidence_links` already holds a column name
and a value as text:

  single column   -> ("row_id", "42")                       (unchanged from before)
  composite key   -> ('["a","b"]', '["7","x"]')             (JSON arrays, all strings)

Values are always stored as text, so they compare with `column::text = value`.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from psycopg2 import sql

ENGINE_ROW_NO = "_row_no"


class NoRowIdentity(Exception):
    """The table has no usable row identity, so evidence cannot be linked to its rows."""


@dataclass(frozen=True)
class RowIdentity:
    columns: tuple[str, ...]
    kind: str  # "primary_key" | "engine_row_no"

    def select_list(self) -> sql.Composable:
        """The identity columns as a safely quoted, comma-separated SELECT list."""
        return sql.SQL(", ").join(sql.Identifier(c) for c in self.columns)

    def encode(self, values) -> tuple[str, str]:
        """(source_pk_column, source_pk_value) exactly as stored in evidence_links."""
        values = tuple(values)
        if len(values) != len(self.columns):
            raise ValueError(f"identity has {len(self.columns)} column(s), got {len(values)} value(s)")
        if len(self.columns) == 1:
            return self.columns[0], str(values[0])
        return json.dumps(list(self.columns)), json.dumps([str(v) for v in values])

    def describe(self) -> dict:
        """Compact form for tool output."""
        return {"columns": list(self.columns), "kind": self.kind}


def decode(source_pk_column: str, source_pk_value: str) -> dict[str, str]:
    """Inverse of RowIdentity.encode: {column: value-as-text} for one evidence link."""
    if source_pk_column.startswith("["):
        try:
            cols, vals = json.loads(source_pk_column), json.loads(source_pk_value)
        except ValueError:
            cols = vals = None
        if isinstance(cols, list) and isinstance(vals, list) and len(cols) == len(vals):
            return {str(c): str(v) for c, v in zip(cols, vals)}
    return {source_pk_column: source_pk_value}


def resolve_row_identity(cur, schema: str, table: str) -> RowIdentity:
    """Return the identity to use for `schema.table`, or raise NoRowIdentity."""
    qualified = sql.Identifier(schema, table).as_string(cur)

    cur.execute("SELECT to_regclass(%s)", (qualified,))
    if cur.fetchone()[0] is None:
        raise NoRowIdentity(f"Table {schema}.{table} does not exist or is not visible to this role.")

    cur.execute(
        "SELECT a.attname FROM pg_index i "
        "JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey) "
        "WHERE i.indrelid = to_regclass(%s) AND i.indisprimary "
        "ORDER BY array_position(i.indkey::int2[], a.attnum)",
        (qualified,),
    )
    pk = tuple(r[0] for r in cur.fetchall())
    if pk:
        return RowIdentity(pk, "primary_key")

    cur.execute(
        "SELECT 1 FROM information_schema.columns "
        "WHERE table_schema = %s AND table_name = %s AND column_name = %s",
        (schema, table, ENGINE_ROW_NO),
    )
    if cur.fetchone():
        col = sql.Identifier(ENGINE_ROW_NO)
        cur.execute(
            sql.SQL("SELECT count(*), count(DISTINCT {c}), count(*) FILTER (WHERE {c} IS NULL) FROM {t}")
            .format(c=col, t=sql.Identifier(schema, table))
        )
        total, distinct, nulls = cur.fetchone()
        if nulls == 0 and distinct == total:
            return RowIdentity((ENGINE_ROW_NO,), "engine_row_no")
        raise NoRowIdentity(
            f"{schema}.{table} has a '{ENGINE_ROW_NO}' column but it is not a unique identity "
            f"({total} rows, {distinct} distinct values, {nulls} NULL), so evidence cannot "
            f"be linked to exact rows."
        )

    raise NoRowIdentity(
        f"{schema}.{table} has no primary key and no '{ENGINE_ROW_NO}' column. Evidence must "
        f"point at exact rows, so the test was not run. Declare a primary key on the table, or "
        f"import it through the engine's ingestion, which assigns '{ENGINE_ROW_NO}'."
    )

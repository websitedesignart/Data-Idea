"""
Safe SQL identifiers.

Schema, table and column names arrive from the command line, i.e. from a user or from an
LLM. They must never be pasted into SQL text: a name containing a quote and a semicolon
would otherwise run extra statements as the engine's role (which can write to the
append-only evidence tables). Every name is therefore

  1. checked by `check_identifier` for the few things quoting cannot fix, and
  2. rendered by psycopg2's `sql.Identifier`, which quotes and escapes correctly.

Quotes, spaces, mixed case, reserved words and non-ASCII are all fine once quoted. What is
refused, with a clear reason rather than guessed at:

  - empty names
  - a NUL character (PostgreSQL cannot represent it)
  - more than 63 bytes: PostgreSQL silently TRUNCATES longer identifiers, which could make
    a query hit a different column than the one that was asked for
  - a percent sign: psycopg2 treats it as a parameter marker in any statement that also
    passes parameters, so it cannot be embedded safely
"""
from __future__ import annotations

from psycopg2 import sql

MAX_IDENTIFIER_BYTES = 63


class UnsafeIdentifier(ValueError):
    """A caller-supplied schema/table/column name that cannot be used safely."""


def check_identifier(name, what: str = "identifier") -> str:
    if not isinstance(name, str) or name == "":
        raise UnsafeIdentifier(f"{what} must be a non-empty name.")
    if "\x00" in name:
        raise UnsafeIdentifier(f"{what} contains a NUL character.")
    if len(name.encode("utf-8")) > MAX_IDENTIFIER_BYTES:
        raise UnsafeIdentifier(
            f"{what} is longer than {MAX_IDENTIFIER_BYTES} bytes; PostgreSQL would silently "
            f"truncate it and could query a different object.")
    if "%" in name:
        raise UnsafeIdentifier(f"{what} contains '%', which cannot be embedded safely in a parameterised query.")
    return name


def ident(*names: str) -> sql.Identifier:
    """A validated, correctly quoted identifier; several parts give schema.table style names."""
    for n in names:
        check_identifier(n)
    return sql.Identifier(*names)


def table_exists(cur, schema: str, table: str) -> bool:
    """True if schema.table exists and is visible to this role (catalog lookup, no data read)."""
    cur.execute("SELECT to_regclass(%s)", (ident(schema, table).as_string(cur),))
    return cur.fetchone()[0] is not None


def norm_expr(column: sql.Composable) -> sql.Composable:
    """The matching normalisation used by every test: trim, collapse whitespace, uppercase.
    Applied for matching only; the source value is never altered."""
    return sql.SQL("upper(regexp_replace(btrim({}::text), '\\s+', ' ', 'g'))").format(column)

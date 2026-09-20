"""
The engine's analysis connection, and what happens when a query goes wrong.

Every session is opened with a statement timeout and a lock timeout, so a runaway query is
cancelled and a blocked one gives up instead of waiting forever. Both are set as connection
options (per session; nothing in the database is changed) and are configurable:

  FORENSIC_STATEMENT_TIMEOUT_MS   default 60000   longest any single statement may run
  FORENSIC_LOCK_TIMEOUT_MS        default 5000    longest to wait for a lock

A value of 0 disables that limit (PostgreSQL's meaning), which is not recommended on data you
do not own. `idle_in_transaction_session_timeout` is deliberately not set: tests do CPU-bound
Python work (e.g. fuzzy clustering) between queries while the transaction is open, and a
timeout there would kill healthy runs.
"""
from __future__ import annotations

import os
from contextlib import contextmanager

import psycopg2

from .config import forensic_dsn

ENV_STATEMENT_TIMEOUT = "FORENSIC_STATEMENT_TIMEOUT_MS"
ENV_LOCK_TIMEOUT = "FORENSIC_LOCK_TIMEOUT_MS"
DEFAULT_STATEMENT_TIMEOUT_MS = 60_000
DEFAULT_LOCK_TIMEOUT_MS = 5_000
MAX_TIMEOUT_MS = 2_147_483_647  # PostgreSQL stores these as a 32-bit integer of milliseconds


class InvalidTimeout(RuntimeError):
    """A timeout setting that is not a usable number of milliseconds."""


def _read_ms(env: str, default: int) -> int:
    raw = os.environ.get(env)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw.strip())
    except ValueError:
        raise InvalidTimeout(f"{env} must be a whole number of milliseconds, got {raw!r}.") from None
    if not 0 <= value <= MAX_TIMEOUT_MS:
        raise InvalidTimeout(f"{env} must be between 0 and {MAX_TIMEOUT_MS} milliseconds, got {value}.")
    return value


def timeouts() -> dict:
    """The effective limits for this process. Raises InvalidTimeout on a bad setting."""
    return {
        "statement_timeout_ms": _read_ms(ENV_STATEMENT_TIMEOUT, DEFAULT_STATEMENT_TIMEOUT_MS),
        "lock_timeout_ms": _read_ms(ENV_LOCK_TIMEOUT, DEFAULT_LOCK_TIMEOUT_MS),
    }


@contextmanager
def connect(database: str):
    t = timeouts()  # validated integers, so safe to place in the options string
    conn = psycopg2.connect(
        forensic_dsn(database),
        options=f"-c statement_timeout={t['statement_timeout_ms']} -c lock_timeout={t['lock_timeout_ms']}",
    )
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def describe_db_error(exc: BaseException) -> tuple[str, str]:
    """A short, stable (code, reason) for a database failure, instead of a traceback or a
    dump of the failing SQL. The codes are safe to branch on."""
    pgcode = getattr(exc, "pgcode", None)
    t = timeouts()
    if pgcode == "57014":
        return ("STATEMENT_TIMEOUT",
                f"A query was cancelled after exceeding the {t['statement_timeout_ms']} ms statement "
                f"timeout (or was cancelled manually). Nothing was recorded as a result. Narrow the "
                f"test, or raise {ENV_STATEMENT_TIMEOUT} if the data is legitimately that large.")
    if pgcode == "55P03":
        return ("LOCK_TIMEOUT",
                f"Another session holds a lock this test needs; gave up after {t['lock_timeout_ms']} ms. "
                f"Nothing was recorded as a result. Try again later, or raise {ENV_LOCK_TIMEOUT}.")
    first_line = (str(exc).strip().splitlines() or [""])[0][:200]
    return "DATABASE_ERROR", first_line

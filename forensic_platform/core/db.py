from contextlib import contextmanager

import psycopg2

from .config import forensic_dsn


@contextmanager
def connect(database: str):
    conn = psycopg2.connect(forensic_dsn(database))
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

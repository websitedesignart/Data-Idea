"""
Creates a synthetic fixture table with two columns of KNOWN, deliberately
seeded properties, used to validate that forensic tests recover the expected
result rather than merely running without error:

  - conforming_amount: log-uniform over [1, 100000], seed=42 -> should closely
    follow Benford's Law (expected conformity: close/acceptable).
  - fabricated_amount: values clustered in 480-499 (just under a $500 approval
    threshold, seed=43) -> should NOT follow Benford's Law (expected: heavy
    concentration on leading digit 4, nonconformity).

Loaded via the postgres superuser (fixture/source data creation is an
ingestion-time action, not something the least-privilege forensic_app role
should be able to do — by design it has no CREATE/INSERT on public).
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

import psycopg2

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MCP_CONFIG_PATH = PROJECT_ROOT / ".mcp.json"

N_ROWS = 2000


def superuser_dsn(database: str) -> str:
    cfg = json.loads(MCP_CONFIG_PATH.read_text(encoding="utf-8"))
    base = cfg["mcpServers"]["local-postgres-cluster"]["args"][-1]
    prefix = base.rsplit("/", 1)[0]
    return f"{prefix}/{database}"


def generate_rows() -> list[tuple[float, float]]:
    rng_conforming = random.Random(42)
    rng_fabricated = random.Random(43)
    rows = []
    for _ in range(N_ROWS):
        # log-uniform over [1, 100000] -> naturally Benford-conforming
        conforming = round(10 ** rng_conforming.uniform(0, 5), 2)
        # clustered just under a 500 threshold -> not Benford-conforming
        fabricated = round(rng_fabricated.uniform(480, 499.99), 2)
        rows.append((conforming, fabricated))
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True)
    args = parser.parse_args()

    conn = psycopg2.connect(superuser_dsn(args.database))
    conn.autocommit = True
    cur = conn.cursor()

    cur.execute("DROP TABLE IF EXISTS public.forensic_fixture_amounts")
    cur.execute(
        "CREATE TABLE public.forensic_fixture_amounts ("
        "id SERIAL PRIMARY KEY, conforming_amount NUMERIC, fabricated_amount NUMERIC)"
    )
    rows = generate_rows()
    cur.executemany(
        "INSERT INTO public.forensic_fixture_amounts (conforming_amount, fabricated_amount) VALUES (%s, %s)",
        rows,
    )
    print(f"Loaded {len(rows)} rows into public.forensic_fixture_amounts (database={args.database})")
    cur.close()
    conn.close()


if __name__ == "__main__":
    main()

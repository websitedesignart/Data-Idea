"""
Creates a new, isolated PostgreSQL case database and registers a matching MCP
entry, following the project's one-database-per-dump convention.

Usage:
    .venv\\Scripts\\python.exe forensic_platform\\scripts\\create_case_db.py --database my_case_db

Idempotent: if the database already exists it is left untouched.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import psycopg2
from psycopg2 import sql
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from forensic_platform.core.config import find_mcp_config, superuser_dsn  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--database", required=True)
    args = ap.parse_args()

    conn = psycopg2.connect(superuser_dsn("postgres"))
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (args.database,))
            if cur.fetchone():
                print(f"database '{args.database}' already exists - left untouched")
            else:
                cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(args.database)))
                print(f"created database '{args.database}'")
    finally:
        conn.close()

    config_path = find_mcp_config()
    cfg = json.loads(config_path.read_text(encoding="utf-8"))
    entry = f"local-postgres-cluster-{args.database}"
    if entry in cfg["mcpServers"]:
        print(f"{entry} already present in .mcp.json")
    else:
        cfg["mcpServers"][entry] = {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-postgres", superuser_dsn(args.database)],
        }
        config_path.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
        print(f"added {entry} to .mcp.json (available after session restart)")


if __name__ == "__main__":
    main()

"""
One-time (idempotent) setup of the forensic evidence/audit layer in a target database.

Usage:
    .venv\\Scripts\\python.exe forensic_platform\\scripts\\bootstrap.py --database demo

Connects as the postgres superuser (credentials come from .mcp.json, the same
source the rest of the project already uses), creates the forensic_app role
if it doesn't exist yet, writes its connection string into .mcp.json as a new
MCP server entry, then applies forensic_platform/sql/001_bootstrap.sql.
"""
import argparse
import json
import secrets
from pathlib import Path

import psycopg2
from psycopg2 import sql

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MCP_CONFIG_PATH = PROJECT_ROOT / ".mcp.json"
BOOTSTRAP_SQL_PATH = PROJECT_ROOT / "forensic_platform" / "sql" / "001_bootstrap.sql"


def load_superuser_dsn(mcp_config: dict) -> str:
    args = mcp_config["mcpServers"]["local-postgres-cluster"]["args"]
    return args[-1]


def build_dsn(base_dsn: str, database: str) -> str:
    prefix = base_dsn.rsplit("/", 1)[0]
    return f"{prefix}/{database}"


def ensure_forensic_role(cursor) -> None:
    cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", ("forensic_app",))
    if cursor.fetchone():
        print("forensic_app role already exists, leaving password unchanged")
        return None
    password = secrets.token_urlsafe(24)
    cursor.execute(
        sql.SQL("CREATE ROLE forensic_app LOGIN PASSWORD {}").format(sql.Literal(password))
    )
    print("created forensic_app role")
    return password


def register_mcp_entry(mcp_config: dict, database: str, dsn_with_password: str) -> None:
    entry_name = f"local-postgres-cluster-{database}-forensic"
    if entry_name in mcp_config["mcpServers"]:
        print(f"{entry_name} already present in .mcp.json, leaving as-is")
        return
    mcp_config["mcpServers"][entry_name] = {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-postgres", dsn_with_password],
    }
    MCP_CONFIG_PATH.write_text(json.dumps(mcp_config, indent=2) + "\n", encoding="utf-8")
    print(f"added {entry_name} to .mcp.json")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True, help="Target database name, e.g. demo")
    parser.add_argument(
        "--grant-schema", action="append", default=[],
        help="Additional source schema to grant read-only access on (repeatable). "
             "Source data is never made writable to forensic_app.",
    )
    args = parser.parse_args()

    mcp_config = json.loads(MCP_CONFIG_PATH.read_text(encoding="utf-8"))
    superuser_dsn = build_dsn(load_superuser_dsn(mcp_config), args.database)

    conn = psycopg2.connect(superuser_dsn)
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            new_password = ensure_forensic_role(cur)

        bootstrap_sql = BOOTSTRAP_SQL_PATH.read_text(encoding="utf-8")
        with conn.cursor() as cur:
            cur.execute(bootstrap_sql)
        print(f"applied {BOOTSTRAP_SQL_PATH.name} to database '{args.database}'")

        # Read-only grants on source schemas. SELECT only - never INSERT/UPDATE/DELETE,
        # so imported evidence stays immutable to the analysis role.
        for schema in args.grant_schema:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM information_schema.schemata WHERE schema_name = %s", (schema,))
                if not cur.fetchone():
                    print(f"WARNING: schema '{schema}' does not exist - skipped")
                    continue
                cur.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO forensic_app")
                            .format(sql.Identifier(schema)))
                cur.execute(sql.SQL("GRANT SELECT ON ALL TABLES IN SCHEMA {} TO forensic_app")
                            .format(sql.Identifier(schema)))
                cur.execute(sql.SQL(
                    "ALTER DEFAULT PRIVILEGES IN SCHEMA {} GRANT SELECT ON TABLES TO forensic_app")
                    .format(sql.Identifier(schema)))
                print(f"granted read-only access on schema '{schema}' to forensic_app")

        if new_password is not None:
            prefix, rest = superuser_dsn.split("://", 1)
            userinfo, hostpart = rest.split("@", 1)
            forensic_dsn = f"{prefix}://forensic_app:{new_password}@{hostpart}"
            register_mcp_entry(mcp_config, args.database, forensic_dsn)
    finally:
        conn.close()


if __name__ == "__main__":
    main()

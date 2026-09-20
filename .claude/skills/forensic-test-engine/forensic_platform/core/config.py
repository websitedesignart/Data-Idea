import json
import os
from pathlib import Path

ENV_VAR = "FORENSIC_MCP_CONFIG"


def find_mcp_config() -> Path:
    """Locate the .mcp.json of the project the engine is being used in.

    The engine ships inside a skill folder and is copied into arbitrary projects,
    so it must never look for config relative to its own location. Resolution
    order, first match wins - there is deliberately no silent fallback, because
    guessing a database is how a test ends up running against the wrong case:

      1. $FORENSIC_MCP_CONFIG, if set (explicit path to a .mcp.json)
      2. a .mcp.json in the current working directory or any parent of it
    """
    explicit = os.environ.get(ENV_VAR)
    if explicit:
        path = Path(explicit)
        if not path.is_file():
            raise RuntimeError(f"{ENV_VAR} points to '{explicit}', which is not a file.")
        return path

    here = Path.cwd().resolve()
    for folder in [here, *here.parents]:
        candidate = folder / ".mcp.json"
        if candidate.is_file():
            return candidate

    raise RuntimeError(
        "No .mcp.json found in the current directory or any parent. Run from inside your "
        f"project, or set {ENV_VAR} to the path of your .mcp.json "
        "(see .mcp.json.example for the format)."
    )


def load_mcp_config() -> dict:
    return json.loads(find_mcp_config().read_text(encoding="utf-8"))


def superuser_dsn(database: str = "postgres") -> str:
    """DSN of the cluster admin, taken from the project's `local-postgres-cluster` entry.

    Used only by one-time setup scripts (create database, bootstrap, ingest). Analysis
    itself always runs as the least-privilege forensic_app role.
    """
    cfg = load_mcp_config()
    servers = cfg.get("mcpServers", {})
    if "local-postgres-cluster" not in servers:
        raise RuntimeError(
            "No 'local-postgres-cluster' entry in .mcp.json - it holds the admin "
            "connection setup scripts need. See .mcp.json.example."
        )
    base = servers["local-postgres-cluster"]["args"][-1]
    return f"{base.rsplit('/', 1)[0]}/{database}"


def forensic_dsn(database: str) -> str:
    """Resolve the forensic_app DSN for a database.

    forensic_app is a cluster-level role, so if no per-database entry exists we
    reuse the credentials from any existing forensic entry and retarget the
    database. This keeps one credential for the analysis role across all cases.
    """
    cfg = load_mcp_config()
    key = f"local-postgres-cluster-{database}-forensic"
    if key in cfg["mcpServers"]:
        return cfg["mcpServers"][key]["args"][-1]

    for name, entry in cfg["mcpServers"].items():
        if name.endswith("-forensic"):
            dsn = entry["args"][-1]
            prefix, rest = dsn.split("://", 1)
            userinfo, hostpart = rest.split("@", 1)
            host = hostpart.rsplit("/", 1)[0]
            return f"{prefix}://{userinfo}@{host}/{database}"

    raise RuntimeError(
        f"No forensic_app credentials found in .mcp.json. "
        f"Run forensic_platform/scripts/bootstrap.py --database {database} first."
    )

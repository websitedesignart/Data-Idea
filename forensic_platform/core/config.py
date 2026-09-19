import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MCP_CONFIG_PATH = PROJECT_ROOT / ".mcp.json"


def load_mcp_config() -> dict:
    return json.loads(MCP_CONFIG_PATH.read_text(encoding="utf-8"))


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

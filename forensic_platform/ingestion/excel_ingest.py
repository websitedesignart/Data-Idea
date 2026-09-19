"""
Ingests an Excel workbook into a case database as immutable source tables.

Forensic decisions, all deliberate:
  - every column is loaded as TEXT so the exact source representation is
    preserved; no silent type coercion can alter a value before analysis
  - column names are normalised to snake_case, and the original -> normalised
    mapping is recorded as part of the ingestion manifest, so no rename is silent
  - a content fingerprint is computed per table during load (sum of per-row
    SHA-256 digests, modulo 2^256): order-independent, and unlike XOR it does
    not cancel out duplicate rows - which are exactly what we test for
  - the source workbook is hashed and never modified

Usage:
    .venv\\Scripts\\python.exe forensic_platform\\ingestion\\excel_ingest.py \\
        --source "D:\\path\\file.xlsx" --database my_case_db
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import psycopg2
from psycopg2 import sql

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from forensic_platform.core.hashing import column_signature  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MCP_CONFIG_PATH = PROJECT_ROOT / ".mcp.json"
MODULUS = 1 << 256


def superuser_dsn(database: str) -> str:
    cfg = json.loads(MCP_CONFIG_PATH.read_text(encoding="utf-8"))
    base = cfg["mcpServers"]["local-postgres-cluster"]["args"][-1]
    return f"{base.rsplit('/', 1)[0]}/{database}"


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def norm_ident(name: str) -> str:
    s = str(name).strip().lower()
    s = re.sub(r"[^\w]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    if not s:
        s = "col"
    if s[0].isdigit():
        s = f"c_{s}"
    return s[:63]


def norm_table(sheet: str) -> str:
    return norm_ident(sheet)


NULL_SENTINEL = "\x00"  # distinguishes a blank cell from a genuine empty string


def row_digest(values: list) -> int:
    canon = "\x1f".join(NULL_SENTINEL if v is None else str(v) for v in values)
    return int(hashlib.sha256(canon.encode("utf-8")).hexdigest(), 16)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True)
    ap.add_argument("--database", required=True)
    args = ap.parse_args()

    source = Path(args.source)
    started = datetime.now(timezone.utc)
    src_hash = file_sha256(source)

    print(f"source     : {source}")
    print(f"sha256     : {src_hash}")
    print(f"database   : {args.database}\n")

    sheets = pd.read_excel(source, sheet_name=None, dtype=object)
    conn = psycopg2.connect(superuser_dsn(args.database))
    conn.autocommit = False
    manifest = {
        "source_file": str(source),
        "source_sha256": src_hash,
        "source_size_bytes": source.stat().st_size,
        "ingested_at_utc": started.isoformat(),
        "transformations": [
            "all columns stored as TEXT (no type coercion)",
            "column names normalised to snake_case (original names recorded below)",
            "blank cells stored as SQL NULL",
        ],
        "tables": [],
    }

    try:
        with conn.cursor() as cur:
            cur.execute("CREATE SCHEMA IF NOT EXISTS source")
            for sheet, df in sheets.items():
                table = norm_table(sheet)
                cols = [norm_ident(c) for c in df.columns]
                # guard against collisions after normalisation
                seen: dict[str, int] = {}
                final_cols = []
                for c in cols:
                    if c in seen:
                        seen[c] += 1
                        c = f"{c}_{seen[c]}"
                    else:
                        seen[c] = 0
                    final_cols.append(c)

                cur.execute(sql.SQL("DROP TABLE IF EXISTS source.{}").format(sql.Identifier(table)))
                cur.execute(sql.SQL("CREATE TABLE source.{} ({}, _row_no BIGINT)").format(
                    sql.Identifier(table),
                    sql.SQL(", ").join(
                        sql.SQL("{} TEXT").format(sql.Identifier(c)) for c in final_cols
                    ),
                ))

                buf = io.StringIO()
                writer = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\n")
                acc = 0
                for i, rec in enumerate(df.itertuples(index=False, name=None), start=1):
                    vals = [None if (v is None or (isinstance(v, float) and pd.isna(v)))
                            else str(v) for v in rec]
                    acc = (acc + row_digest(vals)) % MODULUS
                    writer.writerow(["" if v is None else v for v in vals] + [i])
                buf.seek(0)

                copy_cols = sql.SQL(", ").join(
                    sql.Identifier(c) for c in final_cols + ["_row_no"])
                # FORCE_NULL is required: with QUOTE_ALL every value is quoted, and
                # Postgres treats a *quoted* empty string as a real empty string, so
                # `NULL ''` alone would silently turn every blank cell into ''.
                force_null = sql.SQL(", ").join(sql.Identifier(c) for c in final_cols)
                cur.copy_expert(
                    sql.SQL("COPY source.{} ({}) FROM STDIN "
                            "WITH (FORMAT csv, NULL '', FORCE_NULL ({}))")
                    .format(sql.Identifier(table), copy_cols, force_null).as_string(cur),
                    buf,
                )
                cur.execute(sql.SQL("SELECT count(*) FROM source.{}").format(sql.Identifier(table)))
                loaded = cur.fetchone()[0]

                content_fp = format(acc, "064x")
                status = "OK" if loaded == len(df) else "ROW COUNT MISMATCH"
                print(f"  {table:<32} rows={loaded:>6} (source {len(df)})  {status}  fp={content_fp[:16]}...")
                if loaded != len(df):
                    raise RuntimeError(
                        f"row count mismatch for {table}: loaded {loaded}, source {len(df)}")

                manifest["tables"].append({
                    "sheet": sheet,
                    "table": f"source.{table}",
                    "row_count": loaded,
                    "content_fingerprint": content_fp,
                    "column_mapping": dict(zip([str(c) for c in df.columns], final_cols)),
                })

                # Acquisition-time registration: the fingerprint is fixed once, here,
                # so later test runs verify cheaply instead of rescanning the table.
                cur.execute(
                    "SELECT to_regclass('_forensic.datasets') IS NOT NULL")
                if cur.fetchone()[0]:
                    col_sig = column_signature([(c, "text") for c in final_cols])
                    cur.execute(
                        "INSERT INTO _forensic.datasets "
                        "(source_schema, source_table, row_count, column_hash, table_hash, "
                        " imported_by, notes) VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING dataset_id",
                        ("source", table, loaded, col_sig, content_fp, "excel_ingest.py",
                         f"sheet={sheet!r} from {source.name} (sha256 {src_hash[:16]}...)"),
                    )
                    manifest["tables"][-1]["dataset_id"] = cur.fetchone()[0]
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    out = PROJECT_ROOT / "clinical_establishment_registration" / "output" / \
        f"ingestion_manifest_{started.strftime('%Y%m%d_%H%M%S')}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"\nmanifest: {out}")


if __name__ == "__main__":
    main()

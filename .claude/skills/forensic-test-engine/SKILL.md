---
name: forensic-test-engine
description: Runs a registered, deterministic forensic subtest (benford, duplicate-analysis, fuzzy-entity-match, cross-dataset-match, etc.) against a table/column in a case database and reports the recorded, auditable result. Use whenever the user asks to run a forensic test, check for fraud indicators, test Benford's Law, find duplicate or shared identifiers, or look for anomalies in imported case data.
argument-hint: "<subtest> <database> <schema> <table> <column>"
allowed-tools: Bash, Read, Grep, Glob
---

This skill is the only sanctioned way to produce a forensic finding. It never
computes anything itself. It dispatches to the engine's `run_test.py`, which
validates required fields, runs the deterministic SQL/Python test, and writes the
result to the `_forensic` evidence tables and audit log. Never write ad hoc SQL or
pandas code as a substitute for a registered subtest, and never state a statistic or
conclusion that didn't come back from that script's JSON output.

## Finding the engine

The engine is the `forensic_platform` folder that sits **next to this SKILL.md**, so it
travels with the skill into whichever project uses it. Locate `run_test.py` at, in order:

1. `<project>/.claude/skills/forensic-test-engine/forensic_platform/scripts/run_test.py`
2. `~/.claude/skills/forensic-test-engine/forensic_platform/scripts/run_test.py`

If neither exists, stop and tell the user the skill folder is incomplete. Don't hunt
elsewhere or recreate the engine.

Run every command **from the project root**, because the engine reads database
connection details from that project's own `.mcp.json` (or from the path in
`FORENSIC_MCP_CONFIG`). If no `.mcp.json` is found, the engine says so and stops. Don't
work around it by inventing a connection string.

## Python

Use the project's own interpreter if it has one (`.venv\Scripts\python.exe` on Windows,
`.venv/bin/python` elsewhere), otherwise `python`. The engine needs `pandas`, `openpyxl`,
`psycopg2` and `pyyaml`, listed in `requirements.txt` next to this file. If an import
fails, report which package is missing and stop. Don't install anything without asking.

## Available subtests

Read `forensic_platform/registry/test_registry.yaml` (next to this file) for the current
subtests and their status (`implemented`, `not_implemented`, or `extensible`). The
registry is the source of truth, so always read it rather than relying on this text.
If the user asks for a subtest whose status is not `implemented`, say so plainly and do
not attempt a manual equivalent.

Subtest-specific arguments for `run_test.py`:
- `benford`: numeric `--column` only.
- `duplicate-analysis`: optional `--distinct-of <col>` (shared-identifier mode),
  `--min-occurrences N`, `--require-digit`, `--include-placeholders`.
- `fuzzy-entity-match`: required `--distinct-of <name col>`, optional
  `--threshold 0.55`, `--min-occurrences N`, `--require-digit`.
- `cross-dataset-match`: required `--right-table` and `--right-column`,
  optional `--right-schema`.

## Workflow

1. Identify the target: database, schema, table, and column(s) the subtest needs. If any of this is ambiguous, inspect the schema (a read-only database connection for that case, or `information_schema`). Never guess a name.
2. Look up the subtest's `required_fields` and `limitations` in the registry so you can explain what the test needs and doesn't cover.
3. Run it from the project root:
   ```
   <python> <engine>/forensic_platform/scripts/run_test.py --database <db> --subtest <subtest> --schema <schema> --table <table> --column <column>
   ```
4. Parse the JSON response:
   - `"status": "refused"`: the engine declined to run (unimplemented subtest, missing column, wrong type). Report the exact reason. This is not an error to work around; it's the engine correctly refusing to guess.
   - `"status": "error"`: something failed during execution. Report the `code` and `reason`; do not fabricate a result. If the code is `STATEMENT_TIMEOUT` or `LOCK_TIMEOUT`, the engine protected the database by cancelling the query. Tell the user and ask before retrying. Never raise the `FORENSIC_*_TIMEOUT_MS` limits yourself.
   - `"status": "success"`: report the finding(s) exactly as returned. Cite `run_id` and `finding_id`, quote the statistics verbatim, state the finding's classification (OBSERVATION, ANOMALY, etc.), and include the `limitations` text.
5. Never upgrade a finding's classification yourself. An `ANOMALY` is a structural or statistical fact about the data, not evidence of fraud. Say so explicitly if the user's framing implies otherwise. Classification changes toward `INVESTIGATION LEAD` or `CONCLUSION` require human review, which is not yet built.

## First-time setup in a new project

Setup (creating a case database, importing an Excel file, creating the least-privilege role)
is a one-time task done by the user with the scripts in `forensic_platform/scripts/` and
`forensic_platform/ingestion/`. These change the database, so run them only when the user
asks, and show the command first.

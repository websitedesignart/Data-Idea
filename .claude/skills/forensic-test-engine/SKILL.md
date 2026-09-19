---
name: forensic-test-engine
description: Runs a registered, deterministic forensic subtest (benford, duplicate-analysis, gap-sequence, round-number, outlier, etc.) against a table/column in a case database and reports the recorded, auditable result. Use whenever the user asks to run a forensic test, check for fraud indicators, test Benford's Law, or look for anomalies in imported case data.
argument-hint: "<subtest> <database> <schema> <table> <column>"
allowed-tools: Bash, Read, Grep
---

This skill is the only sanctioned way to produce a forensic finding. It never
computes anything itself — it dispatches to `forensic_platform/scripts/run_test.py`,
which is the single entry point that validates required fields, runs the
deterministic SQL/Python test, and writes the result to the `_forensic`
evidence tables and audit log. Never write ad hoc SQL or pandas code as a
substitute for a registered subtest, and never state a statistic or
conclusion that didn't come back from this script's JSON output.

## Available subtests

Read `forensic_platform/registry/test_registry.yaml` to see current subtests
and their status (`implemented`, `not_implemented`, or `extensible`). The
registry is the source of truth - always read it rather than relying on this
text. Currently implemented: `benford`, `duplicate-analysis`,
`fuzzy-entity-match` and `cross-dataset-match`; the rest are registered
placeholders. If the user asks for a subtest whose status is not
`implemented`, say so plainly and do not attempt a manual equivalent.

Subtest-specific arguments for `run_test.py`:
- `duplicate-analysis`: optional `--distinct-of <col>` (shared-identifier mode),
  `--min-occurrences N`, `--require-digit`, `--include-placeholders`.
- `fuzzy-entity-match`: required `--distinct-of <name col>`, optional
  `--threshold 0.55`, `--min-occurrences N`, `--require-digit`.
- `cross-dataset-match`: required `--right-table` and `--right-column`,
  optional `--right-schema`.

## Workflow

1. Identify the target: database, schema, table, and column(s) the subtest needs. If any of this is ambiguous, inspect the relevant `local-postgres-cluster-<database>` MCP connection (read-only) to find the right table/column — never guess a name.
2. Look up the subtest's `required_fields` and `limitations` in the registry so you can explain what the test needs and doesn't cover.
3. Run it:
   ```
   .venv\Scripts\python.exe forensic_platform\scripts\run_test.py --database <db> --subtest <subtest> --schema <schema> --table <table> --column <column>
   ```
4. Parse the JSON response:
   - `"status": "refused"` — the engine declined to run (unimplemented subtest, missing column, wrong type). Report the exact reason. This is not an error to work around; it's the engine correctly refusing to guess.
   - `"status": "error"` — something failed during execution. Report the error text; do not fabricate a result.
   - `"status": "success"` — report the finding(s) exactly as returned: cite `run_id` and `finding_id`, quote the statistics (e.g. `mad`, `chi_square`, `conformity`) verbatim, state the finding's classification (OBSERVATION, ANOMALY, etc.), and include the `limitations` text.
5. Never upgrade a finding's classification yourself. An `ANOMALY` is a statistical fact about the distribution, not evidence of fraud — say so explicitly if the user's framing implies otherwise. Classification changes toward `INVESTIGATION LEAD` or `CONCLUSION` require the human-review workflow (not yet built).

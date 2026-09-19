# Data-Idea

An evidence-first forensic data-analysis engine for fraud and anomaly detection, driven by
Claude Code. The idea behind it is IDEA-style audit analytics: every record gets tested, and
every result can be reproduced. No proprietary IDEA code or algorithms are used.

**The core rule:** Claude never calculates a forensic statistic. Deterministic Python and SQL
compute everything. Claude chooses which registered test to run, runs it, and explains the
result. Every result is written to an append-only evidence store with an audit trail.

## What it does

| Subtest | What it finds | Status |
|---|---|---|
| `benford` | Leading-digit distribution vs Benford's Law (Nigrini MAD bands, chi-square) | implemented |
| `duplicate-analysis` | Duplicate identifiers, and one identifier shared across many distinct values (e.g. one registration number used by many names or establishments) | implemented |
| `fuzzy-entity-match` | Spelling variants collapsed before counting distinct entities, so identity conflicts aren't inflated by typos | implemented |
| `cross-dataset-match` | Reconciliation and referential completeness between two datasets | implemented |
| `gap-sequence`, `round-number`, `outlier`, `split-transaction`, `threshold-proximity`, `vendor-analysis`, `employee-vendor-match`, `duplicate-payment`, `journal-entry`, `date-time-anomaly`, `velocity-analysis` | — | registered, not yet implemented |
| `custom-test` | Investigator-defined tests. They must be registered before they can run | extension point |

If a subtest isn't implemented, or a required column is missing or the wrong type, the engine
**refuses** and says exactly why. It never guesses.

## Evidence model

Each case gets its own PostgreSQL database with two schemas:

- `source` — imported data. Every column is stored as TEXT so values are kept exactly as they
  were. The engine can only read it.
- `_forensic` — `datasets`, `test_runs`, `findings`, `evidence_links` and `audit_log`. All are
  append-only except the reviewer fields on `findings`.

Each source table gets a content fingerprint when it's imported. Every finding links to the
exact source rows behind it. Findings are classified `OBSERVATION` or `ANOMALY` and nothing
higher: **an anomaly is a structural fact about the data, not evidence of wrongdoing.**

## Setup

Requires Python 3.11+, PostgreSQL 14+ and Node.js (for the MCP servers).

```
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
copy .mcp.json.example .mcp.json        # then set your own postgres password
```

Then set up a case:

```
.venv\Scripts\python.exe forensic_platform\scripts\create_case_db.py --database my_case_db
.venv\Scripts\python.exe forensic_platform\ingestion\excel_ingest.py --source "path\to\data.xlsx" --database my_case_db
.venv\Scripts\python.exe forensic_platform\scripts\bootstrap.py --database my_case_db --grant-schema source
```

Restart Claude Code so it picks up the new MCP entries. After that, ask for a forensic test in
plain language and the `forensic-test-engine` skill will send it to
`forensic_platform/scripts/run_test.py`.

## Verifying the engine

```
.venv\Scripts\python.exe forensic_platform\tests_engine\test_fuzzy_entity_match.py
.venv\Scripts\python.exe forensic_platform\fixtures\synthetic_seed.py --database my_case_db
```

The fixture builds a column that follows Benford's Law and one that deliberately doesn't. The
test should pass the first and flag the second.

## Never commit case data

`.gitignore` blocks credentials (`.mcp.json`), spreadsheets, outputs and case folders. The
engine is meant to be reused across cases, so the evidence always stays with the case and never
goes into this repository.

## Known limitations

- Windows-first: the setup commands and the skill use `.venv\Scripts\python.exe`.
- Credentials still come from `.mcp.json`. Moving them to an OS credential store is planned.
- Can't be installed as a Claude Code plugin yet. For now, clone the repo and use it as your
  project.

# Changelog

## [0.2.0] - 2026-09-20
- The engine now lives inside the skill folder (`.claude/skills/forensic-test-engine/forensic_platform/`),
  so copying that one folder into any project installs everything. The repo is skill-only, with
  no plugin manifest.
- Config is resolved from the *current project's* `.mcp.json` (searched upward from the working
  directory) or `FORENSIC_MCP_CONFIG`, never from the engine's own location. A missing config
  now returns a JSON `refused` result instead of a traceback.
- `excel_ingest.py` writes its manifest to `--output-dir` (default `./output`) instead of a
  hardcoded case folder.
- `verify_bootstrap.py` takes `--database` instead of assuming a database named `demo`.
- `requirements.txt` moved into the skill folder; `requirements-pdf.txt` added as an optional
  extra for the PDF and scan fallback.
- Verified end to end from a throwaway project with only the skill folder: setup scripts,
  Excel ingestion, Benford, duplicate, fuzzy and refusal paths all pass.

## [0.1.0] - 2026-09-19
- Repository repurposed as the forensic engine. The earlier code-review plugin is removed. It
  reviewed software diffs rather than data, and Claude Code's built-in `/code-review`
  already does that job. Its history is still in git (commits `449e3aa`, `c684941`).
- Added the `forensic_platform` engine: an append-only `_forensic` evidence schema, a
  least-privilege `forensic_app` role, and a test registry that refuses unregistered or
  unimplemented tests.
- Added subtests `benford`, `duplicate-analysis`, `fuzzy-entity-match` and
  `cross-dataset-match`. Each one writes record-level evidence links.
- Added Excel ingestion. Every column is stored as TEXT, blank cells become NULL (via
  `FORCE_NULL`), and each table gets a content fingerprint when it's imported.
- Added the `forensic-test-engine` Claude Code skill.

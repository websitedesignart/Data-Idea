# Changelog

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

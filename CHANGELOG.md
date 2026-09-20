# Changelog

## [Unreleased]
- **A profiler and role suggestions** (`core/profile.py`, `core/roles.py`, no new libraries). A
  table is measured once (one aggregate scan per batch of 60 columns) for exactly the facts
  suitability rules ask for: eligible and distinct counts, magnitude span, nonpositive and integer
  share, null rate, primary and foreign keys from the catalog, and the share of rows shaped like
  an Aadhaar number, PAN, IFSC, mobile number or e-mail. Only counts, shares and ranges leave the
  profiler, never a data value. It is read-only, runs in the caller's session (so the statement
  timeout applies), and refuses a table estimated over 2,000,000 rows unless explicitly allowed.
- Roles are suggestions, bindings and facts, kept apart. A suggestion carries evidence tokens and a
  strong/medium/weak label (a count of corroborating evidence, not a probability) and binds
  nothing. Only `Bindings.confirm(role, column, confirmed_by)` binds, and it needs a named person.
  `facts_for()` hands a rule set column measurements only for a confirmed column, because for an
  unconfirmed one they may describe the wrong column. A column that looks sensitive (by name or by
  pattern share) is never suggested as an amount, name or identifier, and is flagged for masking.
- Measured read-only against a real payroll-invoicing database in a session forced read-only: all
  12 tables profiled in about 1 s in total (largest, 7,234 rows and 30 columns, under 1 s), and its
  write counters were unchanged afterwards. That run showed page and serial-number columns being
  suggested as amounts, so an unnamed whole-number column is now no longer suggested, and tax and
  charge names count as amount evidence.
- New `tests_engine/test_profile.py` (65 checks: unit tests plus a scratch database). Eleven
  deliberate weakenings were tried and the first pass missed two (a sensitive column also suggested
  as an amount, and a wrong top-10 share); tests were added, and all twelve are now caught.
- **A suitability framework: should this method run on this data at all?**
  (`core/suitability.py`, standard library only.) A method declares rules over named, *measured*
  facts, and the pure function `assess()` returns one of `SUPPORTED`, `SUPPORTED_WITH_WARNING`,
  `INSUFFICIENT_DATA`, `NOT_APPLICABLE`, `REQUIRES_CONFIRMATION` or `UNSAFE_TO_RUN`, plus reason
  codes. The most restrictive verdict wins. It is not wired into `run_test.py` yet; the Benford
  guard that uses it is a later step.
- Enforced structurally: a fact that was not measured is never assumed (it yields
  `INSUFFICIENT_DATA`); a required role or domain input (holiday calendar, pay scale, approval
  limit, ...) that was never supplied is `INSUFFICIENT_DATA`, and one supplied but not yet
  confirmed by a human is `REQUIRES_CONFIRMATION`, so the engine cannot choose one itself; every
  threshold carries `validated` (default false) and its basis, and an assessment reports when it
  rested on unvalidated defaults; declining is recorded as a contract result, so "considered and
  declined, and why" is itself evidence; `facts_required()` tells the profiler exactly what to
  measure. A rule can say `unless=` another reason already explains it (a small sample makes
  "few distinct values" meaningless), and rule sets whose `unless` chains form a cycle are
  rejected because they could suppress every reason and silently return `SUPPORTED`.
- Judged read-only against a real payroll-invoicing database, assuming a human had confirmed each
  money-like column (70 columns): none would be `SUPPORTED`. 57 are `INSUFFICIENT_DATA` (under 300
  rows) and 13 salary-line columns are `NOT_APPLICABLE` (22 to 34 distinct values across about
  7,100 rows), which are exactly the columns where the previous Benford test ran and reported a
  nonconformity. The thresholds in that run were illustrative, not final.
- New `tests_engine/test_suitability.py` (57 checks, no database needed). Ten deliberate
  weakenings of the framework were each caught; the first attempt exposed that the `unless` cycle
  protection had no test, which was then added.
- **A single result contract for every method** (`core/contract.py`, standard library only). The
  four methods each printed a differently shaped, pretty-printed result that repeated constant
  text and, in `top_groups`, printed **raw key values**. The contract is one compact shape
  (`MethodResult`) carrying counts, a few top `Signal`s and pointers: dataset version and its
  basis, method version, finding ids, and how evidence is keyed (never the rows). Constant text
  is referenced (`limits`), not repeated. Methods are not migrated to it yet; that is a later
  step, so `run_test.py` output is unchanged for now.
- Rules are enforced when a result is built, not documented: the engine may only emit
  OBSERVATION or ANOMALY (review states and conclusions are human-only and rejected); a signal's
  subject cannot be a raw string (only a masked reference of 12 letters, a group label or a row
  index, so a digit-based identifier can never pass as one); metrics hold numbers, booleans and
  short lowercase tokens only; `strength` is an effect size in [0, 1], not a probability; a
  completed result must name its dataset version; a size budget of 2,000 characters is enforced
  and `build()` trims the weakest signals to fit. Shape checks cannot prove a value is not
  sensitive; masking (a later step) and review remain responsible for that.
- Measured against the four real methods on synthetic tables: 7,650 characters printed today
  become 2,633 in the contract (about 1,912 to 658 tokens, ESTIMATE), and the raw key values
  `run_test.py` prints today do not appear in it at all.
- New `tests_engine/test_contract.py` (71 checks: 60 unit with no database, 11 integration). Seven
  deliberate weakenings of the validator were each caught by it.
- **Dataset versions are now defined by content, not row count.** Before, any table not imported
  by our own Excel ingestion was versioned by row count alone: a table whose *values* changed but
  whose row count did not was silently treated as the same dataset, so findings could cite a
  version they were not computed on. A version is now the table's content fingerprint
  (`s56:<rows>:<sum of SHA-256-based row hashes>`, computed in SQL) plus its column layout.
  Unchanged content reuses the version, rewriting rows with identical content does not create a
  new one (order-independent), any edit, insert or delete does, and returning to earlier content
  maps back to the earlier version. The fingerprint is a change detector, not tamper-proofing.
- If the fingerprint cannot be computed within the statement timeout, the run falls back to the
  weaker row-count basis and **records that it did** (`table_hash` NULL and a note in
  `datasets.notes`). It never claims a content-verified version it did not verify. Hashes
  recorded by other algorithms (Excel ingestion's) are never trusted for reuse.
- Sessions now pin `DateStyle`, `IntervalStyle`, `TimeZone` and `extra_float_digits`. Measured:
  the same two rows gave four different fingerprints under different session settings, so
  without this the same data could look changed. No schema migration.
- Measured on real tables, read-only: all 12 tables of a real payroll-invoicing database fingerprint in 0.10 s in
  total (largest, 7,234 rows, 64 ms), and a 64,096-row table in 0.2 s; every fingerprint was
  repeatable.
- New `tests_engine/test_dataset_version.py` (14 checks). Run against the previous engine, 8 of
  them fail.
- **Timeouts.** Every analysis session now has a statement timeout (default 60 s) and a lock
  timeout (default 5 s), so a runaway query is cancelled and a blocked one gives up. Set per
  session through connection options, so nothing in the database changes. Configure with
  `FORENSIC_STATEMENT_TIMEOUT_MS` and `FORENSIC_LOCK_TIMEOUT_MS`; `0` disables a limit; invalid
  values are refused up front. Measured in a scratch database: a runaway query that used to
  run 23 s is cancelled at ~1 s, and a query on a locked table that used to block forever gives
  up in ~1 s. `idle_in_transaction_session_timeout` is deliberately not set, since tests do
  CPU-bound work (e.g. fuzzy clustering) inside an open transaction.
- **A failing test now returns a compact error, not a traceback.** Before, a failure inside a
  test printed a ~2,000-character traceback: the audit-log write ran inside the transaction
  PostgreSQL had already aborted, and failed too. A savepoint now lets the engine roll back
  just the test, keep the dataset registration and write the failure to the audit log. Errors
  return `{"status":"error","code":...,"reason":...}` (~290 characters) with the codes
  `STATEMENT_TIMEOUT`, `LOCK_TIMEOUT`, `DATABASE_ERROR` or `TEST_ERROR`. Failures outside the
  test call (registration, evidence writes, a dropped connection) are reported the same way and
  logged in a fresh transaction.
- The skill now tells Claude to report a timeout and ask before retrying, and never to raise the
  limits itself.
- New `tests_engine/test_timeouts.py` (31 checks). Run against the previous engine version, 15
  of them fail.
- **Security: caller-supplied names can no longer run extra SQL.** Schema, table and column
  names (from a user or an LLM) were pasted into SQL text at 30+ sites, some with no quoting at
  all. Verified exploitable: a crafted `--table` inserted a forged row into the append-only
  `audit_log` while the engine reported "refused". Every name now goes through
  `core/sqlsafe.py` (`ident()`), which validates it and lets psycopg2 quote it.
- Names that cannot be made safe are refused with a reason instead of guessed at: empty, NUL,
  over 63 bytes (PostgreSQL silently truncates longer identifiers and could hit a different
  column), and any containing `%`.
- Legal but awkward names now work. Before, a table with a quote or space in its name crashed
  the engine, and `benford` never quoted its column at all, so mixed-case columns failed.
- `--right-table`, `--right-column` and `--right-schema` were never validated. They are now
  checked for existence and refused cleanly. A table that does not exist is refused for every
  subtest, not only the evidence-writing ones.
- Refusals for unsafe names are audit-logged, since an attempt is evidence too.
- The three copies of the text-normalisation expression are now one (`sqlsafe.norm_expr`).
- Query results are unchanged: 12 read-only comparisons against values recorded before the
  change all match on real data.
- New `tests_engine/test_identifier_safety.py` (35 checks). Run against the previous engine
  version, 18 of them fail.

- **Evidence now identifies rows by primary key, not `_row_no`.** Before, `duplicate-analysis`,
  `fuzzy-entity-match` and `cross-dataset-match` selected a `_row_no` column that only exists in
  tables our own Excel ingestion created. On any native table they failed, and
  `cross-dataset-match` failed unconditionally, at exactly the point where something was
  flagged. New `core/identity.py` resolves a row identity in this order: the declared primary
  key (composite keys supported), else `_row_no` if it is provably unique and non-null, else the
  test is **refused**. Nothing is guessed from `ctid` or row position.
- No schema migration. A single key is stored exactly as before, so existing evidence is
  unchanged. A composite key stores JSON arrays in the same two `evidence_links` text columns
  (`core.identity.decode` reverses it).
- The identity check runs before dataset registration, so a refusal leaves no permanent row in
  the append-only `datasets` table.
- Tool output for these three tests gains `evidence_identity` (~15 tokens).
- New `tests_engine/test_row_identity.py`: unit tests, plus `--integration`, which creates and
  drops its own scratch database.

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

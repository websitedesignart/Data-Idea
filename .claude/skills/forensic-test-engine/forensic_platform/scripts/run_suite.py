"""
Run every applicable method on one table and print ONE combined, compact result.

    python forensic_platform/scripts/run_suite.py --database <db> --schema <schema> --table <table> \\
        --amount <col> [--amount <col2>] --identifier <col> --entity-name <col> --confirmed-by "<name>"

Nothing is guessed. A method runs only for a column a named person confirmed for the role it needs
(`--confirmed-by` is that person's name; pass only a name the user gave you). Without a
confirmation nothing runs: the table is profiled once and the reply PROPOSES columns per role, with
what supports each proposal, for the user to confirm.

Every method still runs through run_test.py, so each keeps its own guards, its own recorded run and
finding, and its own audit row. One method refusing, declining, failing or timing out never stops
the others. The suite adds one audit row listing what it ran.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import psycopg2

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from forensic_platform.core import present, suite  # noqa: E402
from forensic_platform.core.config import forensic_dsn  # noqa: E402
from forensic_platform.core.db import connect, describe_db_error, timeouts  # noqa: E402
from forensic_platform.core.profile import ProfileTooLarge, profile_table  # noqa: E402
from forensic_platform.core.roles import suggest_roles, sensitive_columns  # noqa: E402
from forensic_platform.core.sqlsafe import UnsafeIdentifier, check_identifier, table_exists  # noqa: E402
from forensic_platform.tests_engine import base  # noqa: E402

ACTOR = "forensic-test-engine skill (suite)"
RUN_TEST = Path(__file__).resolve().parent / "run_test.py"


def _out(payload: dict) -> None:
    print(json.dumps(payload, separators=(",", ":")))


def _refused(code: str, reason: str) -> None:
    _out(present.refused(suite.SUITE_ID, suite.SUITE_VERSION, code, f"{reason} Nothing was executed."))


def run_step(cmd: list[str], timeout: int) -> tuple[dict | None, str, str]:
    """Run one method through run_test.py. (result, error_code, error_reason); a result of None
    means it did not produce a usable one. Never echoes stderr: it can carry data."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "SUITE_METHOD_TIMEOUT", f"the method did not finish within {timeout} seconds and was stopped."
    try:
        result = json.loads(p.stdout)
    except ValueError:
        return None, "SUITE_BAD_OUTPUT", "the method did not return a usable result."
    if not isinstance(result, dict) or "status" not in result:
        return None, "SUITE_BAD_OUTPUT", "the method returned an unexpected shape."
    return result, "", ""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True)
    parser.add_argument("--schema", required=True)
    parser.add_argument("--table", required=True)
    parser.add_argument("--amount", action="append", default=[], help="a column confirmed as an amount (repeatable)")
    parser.add_argument("--identifier", default=None, help="the column confirmed as the identifier / key")
    parser.add_argument("--entity-name", default=None, help="the column confirmed as the entity's name")
    parser.add_argument("--confirmed-by", default=None,
                        help="name of the person who confirmed the columns; without it nothing runs")
    parser.add_argument("--allow-large-profile", action="store_true",
                        help="profile a table estimated over the row limit (a full scan; the timeout still applies)")
    parser.add_argument("--timeout-seconds", type=int, default=300, help="per method")
    args = parser.parse_args()

    try:
        for what, value in [("--schema", args.schema), ("--table", args.table), ("--identifier", args.identifier),
                            ("--entity-name", args.entity_name), *[("--amount", a) for a in args.amount]]:
            if value is not None:
                check_identifier(value, what)
    except UnsafeIdentifier as exc:
        _refused("UNSAFE_IDENTIFIER", str(exc))
        return
    try:
        forensic_dsn(args.database)
        timeouts()
    except RuntimeError as exc:
        _refused("BAD_CONFIGURATION", str(exc))
        return

    try:
        _run(args)
    except psycopg2.Error as exc:
        code, reason = describe_db_error(exc)
        _out(present.failed(suite.SUITE_ID, suite.SUITE_VERSION, code, reason))


def _run(args) -> None:
    target = f"{args.schema}.{args.table}"
    plan = suite.plan_steps(amounts=args.amount, identifier=args.identifier, entity_name=args.entity_name,
                            confirmed_by=args.confirmed_by)
    with connect(args.database) as conn:
        cur = conn.cursor()
        if not table_exists(cur, args.schema, args.table):
            reason = f"Table {target} does not exist or is not visible to this role."
            base.log_audit(cur, ACTOR, "suite", None, __file__, vars(args), "refused", error_text=reason)
            _refused("NO_SUCH_TABLE", reason)
            return

        if not plan.steps:
            # Nothing can run: profile once and PROPOSE columns for the user to confirm.
            try:
                profile = profile_table(cur, args.schema, args.table, allow_large=args.allow_large_profile)
            except ProfileTooLarge as exc:
                base.log_audit(cur, ACTOR, "suite", None, __file__, vars(args), "declined", error_text="TABLE_TOO_LARGE_TO_PROFILE")
                _out({"method": suite.SUITE_REF, "status": "declined", "verdict": "UNSAFE_TO_RUN",
                      "why": ["TABLE_TOO_LARGE_TO_PROFILE"], "table": target, "reason": str(exc)[:200],
                      "next": "confirm the columns yourself and pass them, or add --allow-large-profile"})
                return
            digest = profile.digest()
            reply = {"method": suite.SUITE_REF, "status": "needs_confirmation", "table": target,
                     "profile": {k: digest[k] for k in ("rows", "cols", "types", "empty_cols")},
                     "propose": suite.proposals(suggest_roles(profile), sensitive_columns(profile))}
            pending = {role: value for role, value in (("amount", args.amount or None), ("identifier", args.identifier),
                                                       ("entity_name", args.entity_name)) if value}
            if pending:
                reply["pending"] = pending
            reply["next"] = ("ask the user to confirm the column for each role, then rerun with --amount, --identifier, "
                             "--entity-name and --confirmed-by <their name>")
            base.log_audit(cur, ACTOR, "suite", None, __file__, vars(args), "declined", error_text="NEEDS_CONFIRMATION")
            _out(reply)
            return

    # Each method is its own run_test.py process and its own transaction, so run them after the
    # connection above is closed.
    entries = []
    for step in plan.steps:
        cmd = [sys.executable, str(RUN_TEST), "--database", args.database, "--schema", args.schema,
               "--table", args.table, "--subtest", step.method, "--column", step.column, *step.extra]
        result, code, reason = run_step(cmd, args.timeout_seconds)
        entries.append(suite.summarise_step(step, result) if result is not None else suite.error_entry(step, code, reason))

    combined = suite.fold(entries, plan.skipped, table=target, confirmed_by=args.confirmed_by.strip())
    runs = [e["run"] for e in entries if "run" in e]
    with connect(args.database) as conn:
        base.log_audit(conn.cursor(), ACTOR, "suite", None, __file__,
                       {**vars(args), "steps": [s.label for s in plan.steps], "runs": runs,
                        "statuses": {f"{e['m']}:{e['col']}": e.get("status") for e in entries}}, "success")
    try:
        _out(suite.fit(combined))
    except ValueError as exc:
        _out(present.failed(suite.SUITE_ID, suite.SUITE_VERSION, "RESULT_NOT_PRESENTABLE",
                            f"the methods ran and were recorded (runs {runs[:20]}) but the combined result is too large: {exc}"))


if __name__ == "__main__":
    main()

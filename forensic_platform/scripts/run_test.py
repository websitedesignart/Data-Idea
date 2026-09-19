"""
The single entry point through which a forensic subtest is ever executed.
This is what the forensic-test-engine skill calls — it never lets an LLM
compute a result itself; it only ever reports what this script writes.

Usage:
    .venv\\Scripts\\python.exe forensic_platform\\scripts\\run_test.py \\
        --database demo --subtest benford --schema public --table transactions --column amount

Prints a single JSON object (the recorded test_runs row plus any findings) to
stdout. Every invocation writes an audit_log row, success or failure.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from forensic_platform.core.db import connect
from forensic_platform.tests_engine import base
from forensic_platform.tests_engine import benford
from forensic_platform.tests_engine import duplicate_analysis
from forensic_platform.tests_engine import fuzzy_entity_match
from forensic_platform.tests_engine import cross_dataset_match

ACTOR = "forensic-test-engine skill"

DISPATCH = {
    "benford": benford,
    "duplicate-analysis": duplicate_analysis,
    "fuzzy-entity-match": fuzzy_entity_match,
    "cross-dataset-match": cross_dataset_match,
}


def _finish_duplicate_analysis(cur, args, entry, module, dataset_id, result) -> None:
    """Record a duplicate-analysis run, its finding, and its record-level evidence."""
    fields = [args.column] + ([args.distinct_of] if args.distinct_of else [])
    limitations = entry["limitations"]
    truncated = len(result.evidence) >= args.evidence_limit
    if truncated:
        limitations += (f" Evidence links truncated at {args.evidence_limit} rows for this run; "
                        f"the flagged group counts are complete but the linked rows are not.")

    run_id = base.record_test_run(
        cur,
        test_name=module.TEST_NAME,
        test_version=module.TEST_VERSION,
        dataset_id=dataset_id,
        fields_used=fields,
        params={
            "schema": args.schema, "table": args.table, "column": args.column,
            "distinct_of": args.distinct_of, "mode": result.mode,
            "min_occurrences": args.min_occurrences,
            "exclude_placeholders": not args.include_placeholders,
            "require_digit": args.require_digit,
            "label": args.label,
        },
        records_examined=result.records_examined,
        result_count=result.flagged_keys,
        query_text=result.query_text,
        limitations=limitations,
        status="success",
    )

    target = f"{args.schema}.{args.table}.{args.column}"
    if result.flagged_keys == 0:
        classification = "OBSERVATION"
        desc = (f"No values of {target} met the duplication criteria "
                f"(mode={result.mode}, min_occurrences={args.min_occurrences}).")
    elif result.mode == "shared_identifier":
        classification = "ANOMALY"
        desc = (f"{result.flagged_keys} distinct values of {target} are each associated with "
                f"{args.min_occurrences}+ distinct values of '{args.distinct_of}' "
                f"(max {result.max_group_size}), spanning {result.flagged_rows} rows of "
                f"{result.records_examined} examined. A shared identifier is a structural "
                f"fact about the data, not evidence of wrongdoing.")
    else:
        classification = "ANOMALY"
        desc = (f"{result.flagged_keys} distinct values of {target} appear on "
                f"{args.min_occurrences}+ rows (max {result.max_group_size}), "
                f"covering {result.flagged_rows} rows of {result.records_examined} examined. "
                f"Duplication is a structural fact about the data, not evidence of wrongdoing.")

    finding_id = base.record_finding(cur, run_id, classification, desc)
    linked = base.record_evidence_links(
        cur, finding_id, args.schema, args.table, "_row_no",
        [row_no for row_no, _ in result.evidence],
    )

    base.log_audit(cur, ACTOR, f"run:{args.subtest}", dataset_id, __file__, vars(args), "success")

    print(json.dumps({
        "status": "success",
        "run_id": run_id,
        "dataset_id": dataset_id,
        "finding_ids": [finding_id],
        "classification": classification,
        "test_name": module.TEST_NAME,
        "test_version": module.TEST_VERSION,
        "mode": result.mode,
        "records_examined": result.records_examined,
        "keys_examined": result.keys_examined,
        "flagged_keys": result.flagged_keys,
        "flagged_rows": result.flagged_rows,
        "max_group_size": result.max_group_size,
        "placeholders_excluded_rows": result.placeholders_excluded_rows,
        "evidence_links_written": linked,
        "evidence_truncated": truncated,
        "top_groups": result.top_groups[:15],
        "limitations": limitations,
        "query_text": result.query_text,
    }, indent=2, default=str))


def _finish_fuzzy_entity_match(cur, args, entry, module, dataset_id, result) -> None:
    """Record a fuzzy-entity-match run: how many identifiers still resolve to
    multiple entities once spelling variants are collapsed."""
    limitations = entry["limitations"]
    truncated = len(result.evidence) >= args.evidence_limit
    if truncated:
        limitations += (f" Evidence links truncated at {args.evidence_limit} rows; "
                        f"group counts are complete but linked rows are not.")

    run_id = base.record_test_run(
        cur,
        test_name=module.TEST_NAME,
        test_version=module.TEST_VERSION,
        dataset_id=dataset_id,
        fields_used=[args.column, args.distinct_of],
        params={
            "schema": args.schema, "table": args.table, "column": args.column,
            "distinct_of": args.distinct_of, "min_entities": args.min_occurrences,
            "threshold": args.threshold,
            "exclude_placeholders": not args.include_placeholders,
            "require_digit": args.require_digit,
            "label": args.label,
        },
        records_examined=result.records_examined,
        result_count=result.flagged_keys,
        query_text=result.query_text,
        limitations=limitations,
        status="success",
    )

    target = f"{args.schema}.{args.table}.{args.column}"
    if result.flagged_keys == 0:
        classification = "OBSERVATION"
        desc = (f"After collapsing spelling variants (threshold {args.threshold}), no value of "
                f"{target} resolves to {args.min_occurrences}+ distinct entities of "
                f"'{args.distinct_of}'. All apparent conflicts were spelling variance.")
    else:
        classification = "ANOMALY"
        desc = (f"{result.flagged_keys} values of {target} still resolve to "
                f"{args.min_occurrences}+ distinct entities of '{args.distinct_of}' after "
                f"collapsing spelling variants at threshold {args.threshold} "
                f"(max {result.max_entities}). {result.collapsed_by_spelling} of "
                f"{result.keys_with_multiple_raw} identifiers with multiple raw name strings "
                f"were explained by spelling variance alone. A shared identifier is a "
                f"structural fact about the data, not evidence of wrongdoing.")

    finding_id = base.record_finding(cur, run_id, classification, desc)
    linked = base.record_evidence_links(
        cur, finding_id, args.schema, args.table, "_row_no", result.evidence)

    base.log_audit(cur, ACTOR, f"run:{args.subtest}", dataset_id, __file__, vars(args), "success")

    print(json.dumps({
        "status": "success",
        "run_id": run_id,
        "dataset_id": dataset_id,
        "finding_ids": [finding_id],
        "classification": classification,
        "test_name": module.TEST_NAME,
        "test_version": module.TEST_VERSION,
        "threshold": result.threshold,
        "records_examined": result.records_examined,
        "keys_examined": result.keys_examined,
        "keys_with_multiple_raw_names": result.keys_with_multiple_raw,
        "flagged_keys": result.flagged_keys,
        "collapsed_by_spelling": result.collapsed_by_spelling,
        "max_entities": result.max_entities,
        "evidence_links_written": linked,
        "evidence_truncated": truncated,
        "top_groups": result.top_groups[:15],
        "limitations": limitations,
    }, indent=2, default=str))


def _finish_cross_dataset_match(cur, args, entry, module, dataset_id, result) -> None:
    """Record a reconciliation run between two datasets."""
    limitations = entry["limitations"]
    truncated = len(result.evidence) >= args.evidence_limit
    if truncated:
        limitations += (f" Evidence links truncated at {args.evidence_limit} orphan rows; "
                        f"counts are complete but linked rows are not.")

    run_id = base.record_test_run(
        cur,
        test_name=module.TEST_NAME,
        test_version=module.TEST_VERSION,
        dataset_id=dataset_id,
        fields_used=[args.column, f"{args.right_table}.{args.right_column}"],
        params={
            "left": result.left, "right": result.right,
            "exclude_placeholders": not args.include_placeholders,
            "label": args.label,
        },
        records_examined=result.left_rows,
        result_count=result.only_left,
        query_text=result.query_text,
        limitations=limitations,
        status="success",
    )

    if result.only_left == 0 and result.only_right == 0:
        classification = "OBSERVATION"
        desc = (f"{result.left} and {result.right} reconcile exactly: "
                f"{result.in_both} distinct keys present in both, none unmatched either way.")
    else:
        classification = "ANOMALY" if result.only_left else "OBSERVATION"
        desc = (f"Reconciliation of {result.left} against {result.right}: "
                f"{result.in_both} keys in both, {result.only_left} only on the left "
                f"({result.left_coverage_pct}% left coverage), {result.only_right} only on the "
                f"right ({result.right_coverage_pct}% right coverage). Unmatched keys are a "
                f"completeness/integrity fact about these two extracts, not evidence of "
                f"wrongdoing.")

    finding_id = base.record_finding(cur, run_id, classification, desc)
    linked = base.record_evidence_links(
        cur, finding_id, args.schema, args.table, "_row_no", result.evidence)

    base.log_audit(cur, ACTOR, f"run:{args.subtest}", dataset_id, __file__, vars(args), "success")

    print(json.dumps({
        "status": "success",
        "run_id": run_id,
        "finding_ids": [finding_id],
        "classification": classification,
        "left": result.left, "right": result.right,
        "left_rows": result.left_rows, "right_rows": result.right_rows,
        "left_distinct": result.left_distinct, "right_distinct": result.right_distinct,
        "in_both": result.in_both,
        "only_left": result.only_left, "only_right": result.only_right,
        "left_coverage_pct": result.left_coverage_pct,
        "right_coverage_pct": result.right_coverage_pct,
        "sample_only_left": result.sample_only_left[:10],
        "sample_only_right": result.sample_only_right[:10],
        "evidence_links_written": linked,
        "limitations": limitations,
    }, indent=2, default=str))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True)
    parser.add_argument("--subtest", required=True)
    parser.add_argument("--schema", required=True)
    parser.add_argument("--table", required=True)
    parser.add_argument("--column", required=True, help="Column to test (test-specific meaning)")
    parser.add_argument("--distinct-of", default=None,
                        help="duplicate-analysis: switch to shared-identifier mode against this column")
    parser.add_argument("--min-occurrences", type=int, default=2)
    parser.add_argument("--include-placeholders", action="store_true",
                        help="Do NOT exclude placeholder tokens such as 0/NIL/NA")
    parser.add_argument("--right-table", default=None,
                        help="cross-dataset-match: table to reconcile against")
    parser.add_argument("--right-column", default=None,
                        help="cross-dataset-match: key column in the right table")
    parser.add_argument("--right-schema", default=None,
                        help="cross-dataset-match: schema of the right table (defaults to --schema)")
    parser.add_argument("--require-digit", action="store_true",
                        help="Treat identifier values containing no digit (e.g. 'MCI', "
                             "'HOSPITAL', a surname) as free text and exclude them")
    parser.add_argument("--evidence-limit", type=int, default=50000)
    parser.add_argument("--threshold", type=float, default=0.55,
                        help="fuzzy-entity-match: similarity threshold for treating two "
                             "names as the same entity")
    parser.add_argument("--label", default=None, help="Optional human label for this run")
    args = parser.parse_args()

    entry = base.get_test_entry(args.subtest)
    if entry.get("status") != "implemented":
        print(json.dumps({
            "status": "refused",
            "reason": f"Subtest '{args.subtest}' is registered as '{entry.get('status')}', not implemented. "
                      f"Nothing was executed.",
        }))
        return

    with connect(args.database) as conn:
        cur = conn.cursor()
        dataset_id = base.get_or_register_dataset(cur, args.schema, args.table, ACTOR)

        data_type = base.column_info(cur, args.schema, args.table, args.column)
        if data_type is None:
            base.log_audit(
                cur, ACTOR, f"run:{args.subtest}", dataset_id, __file__,
                vars(args), "refused",
                error_text=f"Column '{args.column}' does not exist on {args.schema}.{args.table}",
            )
            print(json.dumps({
                "status": "refused",
                "reason": f"Column '{args.column}' does not exist on {args.schema}.{args.table}. Nothing was executed.",
            }))
            return

        if args.subtest == "benford" and data_type not in (
            "smallint", "integer", "bigint", "numeric", "real", "double precision",
        ):
            base.log_audit(
                cur, ACTOR, f"run:{args.subtest}", dataset_id, __file__,
                vars(args), "refused",
                error_text=f"Column '{args.column}' is type '{data_type}', not numeric",
            )
            print(json.dumps({
                "status": "refused",
                "reason": f"benford requires a numeric column; '{args.column}' is '{data_type}'. Nothing was executed.",
            }))
            return

        if args.distinct_of:
            dtype = base.column_info(cur, args.schema, args.table, args.distinct_of)
            if dtype is None:
                base.log_audit(
                    cur, ACTOR, f"run:{args.subtest}", dataset_id, __file__,
                    vars(args), "refused",
                    error_text=f"Column '{args.distinct_of}' does not exist on {args.schema}.{args.table}",
                )
                print(json.dumps({
                    "status": "refused",
                    "reason": f"--distinct-of column '{args.distinct_of}' does not exist on "
                              f"{args.schema}.{args.table}. Nothing was executed.",
                }))
                return

        module = DISPATCH[args.subtest]
        try:
            if args.subtest == "cross-dataset-match":
                if not (args.right_table and args.right_column):
                    print(json.dumps({
                        "status": "refused",
                        "reason": "cross-dataset-match requires --right-table and "
                                  "--right-column. Nothing was executed.",
                    }))
                    return
                result = module.run(
                    cur, args.schema, args.table, args.column,
                    right_table=args.right_table,
                    right_column=args.right_column,
                    right_schema=args.right_schema,
                    exclude_placeholders=not args.include_placeholders,
                    evidence_limit=args.evidence_limit,
                )
            elif args.subtest == "fuzzy-entity-match":
                if not args.distinct_of:
                    print(json.dumps({
                        "status": "refused",
                        "reason": "fuzzy-entity-match requires --distinct-of (the name column). "
                                  "Nothing was executed.",
                    }))
                    return
                result = module.run(
                    cur, args.schema, args.table, args.column,
                    distinct_of=args.distinct_of,
                    min_entities=args.min_occurrences,
                    threshold=args.threshold,
                    exclude_placeholders=not args.include_placeholders,
                    require_digit=args.require_digit,
                    evidence_limit=args.evidence_limit,
                )
            elif args.subtest == "duplicate-analysis":
                result = module.run(
                    cur, args.schema, args.table, args.column,
                    distinct_of=args.distinct_of,
                    min_occurrences=args.min_occurrences,
                    exclude_placeholders=not args.include_placeholders,
                    require_digit=args.require_digit,
                    evidence_limit=args.evidence_limit,
                )
            else:
                result = module.run(cur, args.schema, args.table, args.column)
        except Exception as exc:
            base.log_audit(
                cur, ACTOR, f"run:{args.subtest}", dataset_id, __file__,
                vars(args), "error", error_text=str(exc),
            )
            print(json.dumps({"status": "error", "reason": str(exc)}))
            return

        if args.subtest == "duplicate-analysis":
            _finish_duplicate_analysis(cur, args, entry, module, dataset_id, result)
            return
        if args.subtest == "fuzzy-entity-match":
            _finish_fuzzy_entity_match(cur, args, entry, module, dataset_id, result)
            return
        if args.subtest == "cross-dataset-match":
            _finish_cross_dataset_match(cur, args, entry, module, dataset_id, result)
            return

        run_id = base.record_test_run(
            cur,
            test_name=module.TEST_NAME,
            test_version=module.TEST_VERSION,
            dataset_id=dataset_id,
            fields_used=[args.column],
            params={"schema": args.schema, "table": args.table, "column": args.column},
            records_examined=result.records_examined,
            result_count=len(result.digit_counts),
            query_text=result.query_text,
            limitations=entry["limitations"],
            status="success",
        )

        findings = []
        if not result.reliable_sample_size:
            desc = (
                f"Only {result.records_examined} usable values in {args.schema}.{args.table}.{args.column} "
                f"(Nigrini's guidance recommends >= {benford.MIN_RELIABLE_SAMPLE} for a reliable first-digit test). "
                f"MAD/chi-square are reported but should not be relied on."
            )
            findings.append(base.record_finding(cur, run_id, "OBSERVATION", desc))
        elif result.conformity in ("marginally acceptable conformity", "nonconformity"):
            desc = (
                f"First-digit distribution of {args.schema}.{args.table}.{args.column} shows "
                f"{result.conformity} with Benford's Law (MAD={result.mad:.5f}, chi-square={result.chi_square:.2f}, "
                f"n={result.records_examined}). This is a statistical anomaly, not evidence of fraud on its own."
            )
            findings.append(base.record_finding(cur, run_id, "ANOMALY", desc))
        else:
            desc = (
                f"First-digit distribution of {args.schema}.{args.table}.{args.column} shows "
                f"{result.conformity} with Benford's Law (MAD={result.mad:.5f}, n={result.records_examined})."
            )
            findings.append(base.record_finding(cur, run_id, "OBSERVATION", desc))

        base.log_audit(cur, ACTOR, f"run:{args.subtest}", dataset_id, __file__, vars(args), "success")

        print(json.dumps({
            "status": "success",
            "run_id": run_id,
            "dataset_id": dataset_id,
            "test_name": module.TEST_NAME,
            "test_version": module.TEST_VERSION,
            "records_examined": result.records_examined,
            "digit_counts": result.digit_counts,
            "digit_observed_pct": {str(k): round(v, 5) for k, v in result.digit_observed_pct.items()},
            "digit_expected_pct": {str(k): round(v, 5) for k, v in result.digit_expected_pct.items()},
            "mad": round(result.mad, 5),
            "chi_square": round(result.chi_square, 3),
            "conformity": result.conformity,
            "reliable_sample_size": result.reliable_sample_size,
            "finding_ids": findings,
            "limitations": entry["limitations"],
            "query_text": result.query_text,
        }, indent=2))


if __name__ == "__main__":
    main()

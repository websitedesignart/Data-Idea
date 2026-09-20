"""
Suite: plan which methods to run on a table, and fold their results into one compact reply.

Pure logic, no database and no subprocess, so it can be tested exhaustively. `scripts/run_suite.py`
does the running; every method still runs through `run_test.py`, so every method keeps its own
guards, recording and audit trail. The suite adds nothing that could bypass them.

Nothing is chosen for the user:

  * A method runs only for a column a NAMED PERSON confirmed for the role it needs (amount,
    identifier, entity_name). The engine may PROPOSE columns from what the profiler measured, but a
    proposal is never a binding and nothing runs on it.
  * A method whose role has no confirmed column is listed as skipped with the reason, not guessed at.
  * One method failing, declining or timing out never stops the others.
"""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Any, Mapping

SUITE_ID = "suite"
SUITE_VERSION = "1.0.0"
SUITE_REF = f"{SUITE_ID}@{SUITE_VERSION}"
MAX_SUITE_CHARS = 6000          # ~1,500 tokens (ESTIMATE, chars / 4) for the whole combined reply
MAX_AMOUNT_COLUMNS = 8
TOP_PER_METHOD = 2
PROPOSALS_PER_ROLE = 3

NEEDS_SECOND_TABLE = "NEEDS_SECOND_TABLE"


@dataclass(frozen=True)
class Step:
    method: str
    column: str
    extra: tuple[str, ...] = ()
    by: str | None = None            # the entity-name column of a shared-identifier check

    @property
    def label(self) -> str:
        return f"{self.method}:{self.column}"


@dataclass(frozen=True)
class Plan:
    steps: tuple[Step, ...]
    skipped: tuple[dict, ...]        # {"method", "why"[, "n"]}


def plan_steps(*, amounts: list[str], identifier: str | None, entity_name: str | None,
               confirmed_by: str | None) -> Plan:
    """The steps that CONFIRMED bindings allow, and why the others do not run."""
    if not (confirmed_by and confirmed_by.strip()):
        return Plan((), ())
    steps: list[Step] = []
    skipped: list[dict] = []

    unique_amounts = list(dict.fromkeys(amounts))
    for col in unique_amounts[:MAX_AMOUNT_COLUMNS]:
        steps.append(Step("benford", col, ("--confirmed-by", confirmed_by.strip())))
    if len(unique_amounts) > MAX_AMOUNT_COLUMNS:
        skipped.append({"method": "benford", "why": "TOO_MANY_AMOUNT_COLUMNS",
                        "n": len(unique_amounts) - MAX_AMOUNT_COLUMNS})
    if not unique_amounts:
        skipped.append({"method": "benford", "why": "NEEDS_ROLE_AMOUNT"})

    if identifier:
        steps.append(Step("duplicate-analysis", identifier, ("--distinct-of", entity_name) if entity_name else (), entity_name))
        if entity_name:
            steps.append(Step("fuzzy-entity-match", identifier, ("--distinct-of", entity_name), entity_name))
        else:
            skipped.append({"method": "fuzzy-entity-match", "why": "NEEDS_ROLE_ENTITY_NAME"})
    else:
        skipped.append({"method": "duplicate-analysis", "why": "NEEDS_ROLE_IDENTIFIER"})
        skipped.append({"method": "fuzzy-entity-match", "why": "NEEDS_ROLE_IDENTIFIER"})
    skipped.append({"method": "cross-dataset-match", "why": NEEDS_SECOND_TABLE})
    return Plan(tuple(steps), tuple(skipped))


# ------------------------------------------------------------------------------ folding
def summarise_step(step: Step, result: Mapping[str, Any]) -> dict:
    """One method's contract result, reduced for the combined reply. Only fields the method's own
    contract result already carries; the entry adds the column names (metadata, never values)."""
    entry: dict[str, Any] = {"m": step.method, "col": step.column}
    if step.by:
        entry["by"] = step.by
    for key in ("status", "verdict", "why", "code", "reason", "class", "scanned", "summary", "signals"):
        if key in result:
            entry[key] = result[key]
    if result.get("top"):
        entry["top"] = list(result["top"])[:TOP_PER_METHOD]
    for key in ("run", "finding_ids"):
        if key in result:
            entry[key] = result[key]
    if result.get("evidence"):
        entry["links"] = result["evidence"].get("links")
    if result.get("dataset"):
        entry["dataset"] = result["dataset"]
    return entry


def error_entry(step: Step, code: str, reason: str) -> dict:
    entry = {"m": step.method, "col": step.column, "status": "error", "code": code, "reason": reason[:200]}
    if step.by:
        entry["by"] = step.by
    return entry


_BUCKET = {"completed": "ran", "declined": "declined", "refused": "refused", "error": "errors"}


def fold(entries: list[dict], skipped: tuple[dict, ...] | list[dict], *, table: str, confirmed_by: str) -> dict:
    """One combined result. Deterministic: entries keep plan order."""
    buckets: dict[str, list[dict]] = {"ran": [], "declined": [], "refused": [], "errors": []}
    for e in entries:
        buckets[_BUCKET.get(e.get("status"), "errors")].append(e)
    versions = {(e["dataset"]["id"], e["dataset"]["basis"]) for e in entries if e.get("dataset")}
    out: dict[str, Any] = {"method": SUITE_REF, "status": "completed", "table": table, "confirmed_by": confirmed_by}
    if len(versions) == 1:
        (vid, basis), = versions
        out["dataset"] = {"id": vid, "basis": basis}
    elif versions:
        # the table changed while the suite was running: the results are not about one dataset
        out["dataset_versions"] = sorted(v[0] for v in versions)
        out["warn"] = ["DATASET_CHANGED_DURING_SUITE"]
    out["planned"] = len(entries)
    out["anomalies"] = sum(1 for e in buckets["ran"] if e.get("class") == "ANOMALY")
    for name, items in buckets.items():
        if items:
            out[name] = items
    if skipped:
        out["skipped"] = list(skipped)
    return out


def size(result: Mapping[str, Any]) -> int:
    return len(json.dumps(result, separators=(",", ":"), ensure_ascii=True))


def fit(result: dict, max_chars: int = MAX_SUITE_CHARS) -> dict:
    """Trim to the budget without dropping any method or verdict: first the extra signals (`top`),
    then per-method summaries, weakest information first, last method first. Marks what was trimmed.
    Works on a copy: the caller's result is never modified."""
    result = copy.deepcopy(result)
    for field in ("top", "summary"):
        if size(result) <= max_chars:
            break
        trimmed = False
        for bucket in ("ran", "declined", "refused", "errors"):
            for entry in reversed(result.get(bucket, [])):
                if field in entry:
                    del entry[field]
                    trimmed = True
                    if size(result) <= max_chars:
                        break
            if size(result) <= max_chars:
                break
        if trimmed:
            result.setdefault("trimmed", []).append(field)
    if size(result) > max_chars:
        raise ValueError(f"the combined result is {size(result)} characters even after trimming (limit {max_chars}).")
    return result


def proposals(suggestions: Mapping[str, list], sensitive: Mapping[str, str]) -> dict:
    """What the profiler would propose per role. Proposals only: they bind nothing."""
    out: dict[str, Any] = {}
    for role in ("amount", "identifier", "entity_name"):
        items = [{"column": s.column, "support": s.support} for s in suggestions.get(role, [])[:PROPOSALS_PER_ROLE]]
        if items:
            out[role] = items
    if sensitive:
        names = sorted(sensitive)
        out["sensitive"] = {"n": len(names), "columns": names[:5]}
    return out

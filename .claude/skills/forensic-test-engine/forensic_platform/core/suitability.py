"""
Suitability: should this method run on this data at all?

A method declares a `RuleSet`: rules over named, MEASURED facts. `assess()` is a pure function
that turns the facts into one of the contract's verdicts plus reason codes:

    SUPPORTED              run it
    SUPPORTED_WITH_WARNING run it; the warning travels with the result
    INSUFFICIENT_DATA      not enough measured data, or a required input was never supplied
    NOT_APPLICABLE         the data cannot meaningfully be tested this way
    REQUIRES_CONFIRMATION  a human must confirm a role binding or a domain input first
    UNSAFE_TO_RUN          running it would be unsafe (cost, memory)

The most restrictive triggered verdict wins, in that order (UNSAFE_TO_RUN first).

Principles, each enforced here rather than left to the caller:

  * A fact that was not measured is never assumed. A rule that needs it yields INSUFFICIENT_DATA.
  * Nothing is chosen for the user. A required role or domain input (holiday calendar, pay scale,
    approval limit, ...) that was never supplied is INSUFFICIENT_DATA; one that was supplied but
    not yet confirmed by a human is REQUIRES_CONFIRMATION.
  * Every threshold says whether it has been validated and on what basis. Starting defaults are
    marked unvalidated, and an assessment reports when its verdict rested on any.
  * Declining is recorded, not silent: `Assessment.to_declined()` produces a contract result, so
    "considered and declined, and why" is itself evidence.

Facts are a flat mapping of names to numbers or booleans. The profiler measures them and the
binding layer supplies the `role.<name>.bound|pending` and `input.<name>.supplied|pending` facts.
`RuleSet.facts_required()` tells the profiler exactly what to measure, so nothing more is scanned.
"""
from __future__ import annotations

import math
import operator
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .contract import ContractViolation, MethodRef, MethodResult, Verdict, MAX_REASON_CODES

_OPS = {"<": operator.lt, "<=": operator.le, ">": operator.gt, ">=": operator.ge,
        "==": operator.eq, "!=": operator.ne}
_CODE = re.compile(r"^[A-Z][A-Z0-9_]{1,40}$")
_FACT = re.compile(r"^[a-z][a-z0-9_.]{0,63}$")

# Most restrictive first. Confirmation outranks NOT_APPLICABLE: if the column itself has not been
# confirmed, its measurements may describe the wrong column, so resolve that before judging it.
SEVERITY = {
    Verdict.UNSAFE_TO_RUN: 5,
    Verdict.REQUIRES_CONFIRMATION: 4,
    Verdict.NOT_APPLICABLE: 3,
    Verdict.INSUFFICIENT_DATA: 2,
    Verdict.SUPPORTED_WITH_WARNING: 1,
    Verdict.SUPPORTED: 0,
}
RUNNABLE = {Verdict.SUPPORTED, Verdict.SUPPORTED_WITH_WARNING}


@dataclass(frozen=True)
class Threshold:
    """A threshold, and how much to trust it. Defaults are honest: unvalidated."""
    value: float | int | bool
    validated: bool = False
    basis: str = "starting default; not validated against fixtures"

    def __post_init__(self):
        if not isinstance(self.value, bool) and not (isinstance(self.value, (int, float)) and math.isfinite(self.value)):
            raise ContractViolation("a threshold must be a finite number or a boolean.")
        if not self.basis or len(self.basis) > 200:
            raise ContractViolation("a threshold needs a basis of at most 200 characters.")


@dataclass(frozen=True)
class Rule:
    """Triggers when `fact <op> threshold` is TRUE, i.e. describe the problem, not the pass."""
    code: str
    fact: str
    op: str
    threshold: Threshold
    outcome: Verdict
    why: str
    # Codes of rules that, when triggered, already explain this one. Then this rule is not
    # reported. Example: a small sample makes "few distinct values" meaningless, so the honest
    # verdict is INSUFFICIENT_DATA, not NOT_APPLICABLE.
    unless: tuple[str, ...] = ()

    def __post_init__(self):
        object.__setattr__(self, "unless", tuple(self.unless))
        if not all(_CODE.match(u or "") and u != self.code for u in self.unless):
            raise ContractViolation("'unless' must list other rules' UPPER_SNAKE_CASE codes.")
        if not _CODE.match(self.code or ""):
            raise ContractViolation(f"rule code {self.code!r} must be UPPER_SNAKE_CASE, at most 41 characters.")
        if not _FACT.match(self.fact or ""):
            raise ContractViolation(f"fact name {self.fact!r} must be lowercase letters, digits, '_' and '.'.")
        if self.op not in _OPS:
            raise ContractViolation(f"operator {self.op!r} must be one of {sorted(_OPS)}.")
        if not isinstance(self.outcome, Verdict) or self.outcome is Verdict.SUPPORTED:
            raise ContractViolation("a rule must restrict: its outcome cannot be SUPPORTED.")
        if isinstance(self.threshold.value, bool) and self.op not in ("==", "!="):
            raise ContractViolation("a boolean threshold only supports == and !=.")
        if not self.why or len(self.why) > 120:
            raise ContractViolation("a rule needs a one-line reason of at most 120 characters.")
        if not _CODE.match(missing_code(self.fact)):
            raise ContractViolation(f"fact name {self.fact!r} is too long to form a reason code.")


def missing_code(fact: str) -> str:
    return "MISSING_" + re.sub(r"[^A-Z0-9]+", "_", fact.upper()).strip("_")


_STRUCTURAL = Threshold(False, True, "structural requirement, not a tunable threshold")
_PENDING = Threshold(True, True, "structural requirement, not a tunable threshold")


def needs_role(role: str) -> tuple[Rule, Rule]:
    """The method needs a semantic role (amount, date, ...) that a human has confirmed."""
    name = re.sub(r"[^a-z0-9]+", "_", role.lower()).strip("_")
    up = name.upper()
    return (
        Rule(f"ROLE_UNBOUND_{up}", f"role.{name}.bound", "==", _STRUCTURAL, Verdict.INSUFFICIENT_DATA,
             f"no column is bound to the {name} role"),
        Rule(f"ROLE_UNCONFIRMED_{up}", f"role.{name}.pending", "==", _PENDING, Verdict.REQUIRES_CONFIRMATION,
             f"the {name} role is suggested but not yet confirmed by a human"),
    )


def needs_input(name: str) -> tuple[Rule, Rule]:
    """The method needs a domain input (holiday calendar, pay scale, approval limit, ...) that the
    user supplied and confirmed. The engine never picks one."""
    n = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    up = n.upper()
    return (
        Rule(f"INPUT_NOT_SUPPLIED_{up}", f"input.{n}.supplied", "==", _STRUCTURAL, Verdict.INSUFFICIENT_DATA,
             f"the {n} was not supplied"),
        Rule(f"INPUT_UNCONFIRMED_{up}", f"input.{n}.pending", "==", _PENDING, Verdict.REQUIRES_CONFIRMATION,
             f"the {n} was supplied but not yet confirmed by a human"),
    )


@dataclass(frozen=True)
class RuleSet:
    method: MethodRef
    rules: tuple[Rule, ...]

    def __post_init__(self):
        object.__setattr__(self, "rules", tuple(self.rules))
        codes = [r.code for r in self.rules]
        if len(codes) != len(set(codes)):
            raise ContractViolation("rule codes must be unique within a rule set.")
        unknown = {u for r in self.rules for u in r.unless} - set(codes)
        if unknown:
            raise ContractViolation(f"'unless' refers to rule codes that do not exist: {sorted(unknown)}.")
        # Rules that suppress each other could hide every reason and silently yield SUPPORTED.
        graph = {r.code: r.unless for r in self.rules}
        done: set[str] = set()

        def visit(code: str, path: tuple[str, ...]) -> None:
            if code in path:
                raise ContractViolation(f"'unless' forms a cycle: {' -> '.join(path + (code,))}.")
            if code in done:
                return
            for nxt in graph[code]:
                visit(nxt, path + (code,))
            done.add(code)

        for code in graph:
            visit(code, ())

    def facts_required(self) -> frozenset[str]:
        """Exactly the facts the profiler must measure for this method."""
        return frozenset(r.fact for r in self.rules)


@dataclass(frozen=True)
class Triggered:
    code: str
    fact: str
    value: Any            # the measured value, or None if it was not measured
    outcome: Verdict
    validated: bool
    why: str


@dataclass(frozen=True)
class Assessment:
    method: MethodRef
    verdict: Verdict
    reason_codes: tuple[str, ...]      # at most 6, most restrictive first
    more_reasons: int                  # triggered reasons beyond those listed
    triggered: tuple[Triggered, ...]   # full provenance, most restrictive first
    unvalidated: bool                  # True if any threshold consulted is unvalidated

    @property
    def runnable(self) -> bool:
        return self.verdict in RUNNABLE

    def summary(self) -> dict:
        """Small scalars for a contract result: the facts that decided it, and validation status."""
        out: dict[str, Any] = {}
        if self.unvalidated:
            out["thresholds"] = "unvalidated"
        if self.more_reasons:
            out["more_reasons"] = self.more_reasons
        for t in self.triggered:
            if t.value is not None and not isinstance(t.value, str):
                key = re.sub(r"[^a-z0-9]+", "_", t.fact).strip("_")[:32]
                out.setdefault(key, round(t.value, 4) if isinstance(t.value, float) else t.value)
            if len(out) >= 12:
                break
        return out

    def to_declined(self) -> MethodResult:
        """The contract result for a method that will not run: 'considered and declined, and why'."""
        if self.runnable:
            raise ContractViolation("only a non-runnable assessment can be turned into a declined result.")
        return MethodResult.declined(self.method, self.verdict, list(self.reason_codes), summary=self.summary())


def assess(ruleset: RuleSet, facts: Mapping[str, Any]) -> Assessment:
    """Pure and deterministic: the same facts and rules always give the same assessment, whatever
    the order of the rules. The facts are never modified."""
    triggered: list[Triggered] = []
    for rule in ruleset.rules:
        value = facts.get(rule.fact)
        measured = value is not None and not (isinstance(value, float) and not math.isfinite(value))
        if not measured:
            # Never assume a fact that was not measured.
            triggered.append(Triggered(missing_code(rule.fact), rule.fact, None, Verdict.INSUFFICIENT_DATA,
                                       True, f"{rule.fact} was not measured"))
            continue
        try:
            hit = _OPS[rule.op](value, rule.threshold.value)
        except TypeError:
            triggered.append(Triggered(missing_code(rule.fact), rule.fact, None, Verdict.INSUFFICIENT_DATA,
                                       True, f"{rule.fact} has an unusable value"))
            continue
        if hit:
            triggered.append(Triggered(rule.code, rule.fact, value, rule.outcome, rule.threshold.validated, rule.why))

    # Drop reasons already explained by another triggered reason (see Rule.unless).
    fired = {t.code for t in triggered}
    suppressed = {r.code for r in ruleset.rules if fired & set(r.unless)}
    triggered = [t for t in triggered if t.code not in suppressed]

    # de-duplicate by code, then most restrictive first, then by code: fully deterministic
    unique = {t.code: t for t in triggered}
    ordered = sorted(unique.values(), key=lambda t: (-SEVERITY[t.outcome], t.code))
    verdict = ordered[0].outcome if ordered else Verdict.SUPPORTED
    codes = [t.code for t in ordered]
    return Assessment(
        method=ruleset.method,
        verdict=verdict,
        reason_codes=tuple(codes[:MAX_REASON_CODES]),
        more_reasons=max(0, len(codes) - MAX_REASON_CODES),
        triggered=tuple(ordered),
        unvalidated=any(not r.threshold.validated for r in ruleset.rules),
    )

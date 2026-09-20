"""
Roles: which column plays which part (amount, date, entity name, identifier, ...).

Three separate things, kept apart on purpose:

  * SUGGESTIONS  `suggest_roles(profile)`: evidence-backed guesses from column names and measured
                 characteristics. A suggestion binds nothing. Its `support` label (strong / medium /
                 weak) counts corroborating evidence; it is not a probability.
  * BINDINGS     `Bindings`: which column a role is tied to. A role is either pending (proposed) or
                 bound (a named human confirmed it). Only `confirm()` binds, and it needs a
                 non-empty `confirmed_by`. There is no path from a suggestion to a binding.
  * FACTS        `facts_for()`: turns a profile and bindings into the flat facts a suitability
                 RuleSet asks for, and nothing else. Column measurements are handed over only for
                 a CONFIRMED column, because for an unconfirmed one they may describe the wrong
                 column.

Sensitive-looking columns are detected by `sensitive_columns()` so the masking step can hide them
before anything reaches Claude. Detection uses names and pattern shares, never values.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .profile import ColumnProfile, TableProfile
from .suitability import RuleSet

ROLES = ("amount", "date", "entity_name", "identifier", "sensitive_id")

_TOKENS = {
    "amount": {"amount", "amt", "salary", "sal", "pay", "wage", "wages", "gross", "net", "total", "price",
               "value", "payment", "cost", "fee", "fees", "deduction", "epf", "esi", "gpf", "bonus", "allowance",
               "tax", "gst", "cgst", "sgst", "igst", "charge", "charges", "tds", "balance", "paid", "due"},
    "date": {"date", "dt", "dob", "doj", "period", "month", "year", "day", "timestamp", "time"},
    "entity_name": {"name", "employee", "vendor", "beneficiary", "payee", "supplier", "party", "holder", "firm"},
    "identifier": {"id", "no", "number", "code", "ref", "reference", "uid", "key", "serial", "sr"},
    "sensitive_id": {"aadhaar", "aadhar", "uidai", "pan", "ifsc", "account", "acct", "mobile", "phone",
                     "email", "passport", "voter", "licence", "license"},
}
# name-token sets are matched against whole tokens; 'pay' must not match 'payroll' as a substring.

_SENSITIVE_PATTERN = {"aadhaar_like": "aadhaar", "pan_like": "pan", "ifsc_like": "ifsc",
                      "mobile_like": "mobile", "email_like": "email"}
_SENSITIVE_SHARE = 0.8        # a column where this share of rows has the shape is treated as that kind
_SENSITIVE_NAME_KIND = {"aadhaar": "aadhaar", "aadhar": "aadhaar", "uidai": "aadhaar", "pan": "pan",
                        "ifsc": "ifsc", "account": "account", "acct": "account", "mobile": "mobile",
                        "phone": "mobile", "email": "email", "passport": "passport", "voter": "voter",
                        "licence": "licence", "license": "licence"}
_NUMERIC_TEXT_SHARE = 0.95
_DATE_TEXT_SHARE = 0.95


def name_tokens(name: str) -> set[str]:
    """Lowercase whole-word tokens of a column name: split on non-alphanumerics and camelCase."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return {t for t in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if t}


@dataclass(frozen=True)
class Suggestion:
    role: str
    column: str
    support: str                      # strong | medium | weak
    evidence: tuple[str, ...]         # short lowercase tokens: why


def _label(evidence: list[str]) -> str:
    return "strong" if len(evidence) >= 3 else "medium" if len(evidence) == 2 else "weak"


def _amount(col: ColumnProfile, tokens: set[str]) -> list[str]:
    ev: list[str] = []
    if tokens & _TOKENS["amount"]:
        ev.append("name")
    if col.type_class == "numeric":
        ev.append("numeric_type")
        m = col.metrics
        if "name" not in ev and m.get("integer_share") == 1.0:
            return []                                   # whole numbers with no money-like name: a counter, page or code
        if m.get("n_distinct", 0) >= 20 and not col.is_pk and not col.is_unique:
            ev.append("varied_values")
        if m.get("aadhaar_like_share", 0) >= _SENSITIVE_SHARE or m.get("mobile_like_share", 0) >= _SENSITIVE_SHARE:
            return []                                   # a number that looks like an identifier, not a money value
    elif col.type_class == "text" and col.metrics.get("numeric_like_share", 0) >= _NUMERIC_TEXT_SHARE and col.non_null:
        ev.append("numeric_text")
    else:
        return []
    return ev if len(ev) >= 2 else []


def _date(col: ColumnProfile, tokens: set[str]) -> list[str]:
    ev: list[str] = []
    if tokens & _TOKENS["date"]:
        ev.append("name")
    if col.type_class == "date":
        ev.append("date_type")
        if col.metrics.get("min_date") != col.metrics.get("max_date"):
            ev.append("has_range")
    elif col.type_class == "text" and col.non_null:
        m = col.metrics
        if max(m.get("date_iso_share", 0), m.get("date_dmy_share", 0), m.get("date_mon_share", 0)) >= _DATE_TEXT_SHARE:
            ev.append("date_text")
    else:
        return []
    return ev if "date_type" in ev or "date_text" in ev else []


def _entity_name(col: ColumnProfile, tokens: set[str]) -> list[str]:
    if col.type_class != "text" or not col.non_null:
        return []
    m = col.metrics
    ev: list[str] = []
    if tokens & _TOKENS["entity_name"]:
        ev.append("name")
    if m.get("numeric_like_share", 0) < 0.1 and (m.get("len_mean") or 0) >= 5:
        ev.append("wordlike_text")
    if col.distinct > 1 and col.distinct / col.non_null > 0.3:
        ev.append("many_distinct")
    return ev if "name" in ev or len(ev) >= 2 else []


def _identifier(col: ColumnProfile, tokens: set[str]) -> list[str]:
    ev: list[str] = []
    if tokens & _TOKENS["identifier"]:
        ev.append("name")
    if col.is_pk:
        ev.append("primary_key")
    if col.is_unique and col.non_null >= 2:
        ev.append("unique")
    if col.fk_to:
        ev.append("foreign_key")
    return ev if ("name" in ev and len(ev) >= 2) or "primary_key" in ev or "foreign_key" in ev else []


def sensitive_columns(profile: TableProfile) -> dict[str, str]:
    """Columns that look like personal or financial identifiers -> kind. Names and pattern shares
    only. The masking step hides these before anything reaches Claude."""
    out: dict[str, str] = {}
    for col in profile.columns.values():
        kind = None
        for tok in name_tokens(col.name):
            if tok in _SENSITIVE_NAME_KIND:
                kind = _SENSITIVE_NAME_KIND[tok]
                break
        if kind is None:
            for pat, k in _SENSITIVE_PATTERN.items():
                if col.metrics.get(pat + "_share", 0) >= _SENSITIVE_SHARE and col.non_null:
                    kind = k
                    break
        if kind is not None:
            out[col.name] = kind
    return out


_DETECTORS = {"amount": _amount, "date": _date, "entity_name": _entity_name, "identifier": _identifier}


def suggest_roles(profile: TableProfile) -> dict[str, list[Suggestion]]:
    """Role -> suggestions, strongest first (then column order). Suggestions bind nothing."""
    sensitive = sensitive_columns(profile)
    out: dict[str, list[Suggestion]] = {r: [] for r in ROLES}
    for col in profile.columns.values():
        tokens = name_tokens(col.name)
        if col.name in sensitive:
            out["sensitive_id"].append(Suggestion("sensitive_id", col.name, "strong", (sensitive[col.name],)))
            continue                                     # never also suggested as amount or name
        for role, detect in _DETECTORS.items():
            ev = detect(col, tokens)
            if ev:
                out[role].append(Suggestion(role, col.name, _label(ev), tuple(ev)))
    rank = {"strong": 0, "medium": 1, "weak": 2}
    order = {n: i for i, n in enumerate(profile.columns)}
    for role in out:
        out[role].sort(key=lambda s: (rank[s.support], order[s.column]))
    return out


@dataclass
class Bindings:
    """Which column each role is tied to. Pending = proposed; bound = a named human confirmed it."""
    _pending: dict[str, str] = field(default_factory=dict)
    _bound: dict[str, tuple[str, str]] = field(default_factory=dict)

    def propose(self, role: str, column: str) -> None:
        _check_role(role)
        if role not in self._bound:
            self._pending[role] = column

    def confirm(self, role: str, column: str, confirmed_by: str) -> None:
        _check_role(role)
        if not isinstance(confirmed_by, str) or not confirmed_by.strip():
            raise ValueError("a role binding must be confirmed by a named person (confirmed_by).")
        self._bound[role] = (column, confirmed_by.strip())
        self._pending.pop(role, None)

    def bound(self, role: str) -> str | None:
        b = self._bound.get(role)
        return b[0] if b else None

    def pending(self, role: str) -> str | None:
        return self._pending.get(role)

    def confirmed_by(self, role: str) -> str | None:
        b = self._bound.get(role)
        return b[1] if b else None


def _check_role(role: str) -> None:
    if role not in ROLES:
        raise ValueError(f"unknown role {role!r}; roles are {list(ROLES)}.")


_ROLE_FACT = re.compile(r"^role\.([a-z_]+)\.(bound|pending)$")
_COLUMN_FACTS = ("n_eligible", "n_distinct", "min_abs", "max_abs", "magnitude_span", "nonpositive_share",
                 "integer_share", "top10_share", "null_rate", "non_null", "distinct")


def facts_for(profile: TableProfile, bindings: Bindings, ruleset: RuleSet, role: str) -> dict:
    """The flat facts `ruleset` asks for, about the column bound to `role`. Only facts the rule set
    names are returned. Column measurements come only from a CONFIRMED binding; an absent fact is
    left absent (never guessed), so `assess()` reports it as not measured."""
    _check_role(role)
    wanted = ruleset.facts_required()
    facts: dict = {}
    for fact in wanted:
        m = _ROLE_FACT.match(fact)
        if m:
            r, kind = m.groups()
            facts[fact] = (bindings.bound(r) is not None) if kind == "bound" else (bindings.pending(r) is not None)
    if "n_rows" in wanted:
        facts["n_rows"] = profile.row_count
    column = bindings.bound(role)
    if column is not None and column in profile.columns:
        col = profile.columns[column]
        values = {**col.metrics, "non_null": col.non_null, "distinct": col.distinct}
        for fact in wanted:
            if fact in _COLUMN_FACTS and values.get(fact) is not None:
                facts[fact] = values[fact]
    return facts

"""
The result contract: the one shape every forensic method returns.

Three ideas, each enforced structurally rather than by convention:

  1. COMPACT FOR CLAUDE, COMPLETE FOR EVIDENCE. A result carries counts, a few top signals and
     pointers (dataset version, method version, finding ids, how evidence is keyed). It never
     carries rows, and constant text (limitations, SQL) is referenced, not repeated. A hard size
     budget is checked, and `build()` trims the weakest signals to fit it.

  2. THE ENGINE NEVER CONCLUDES. Engine results may only be OBSERVATION or ANOMALY. Review states
     and conclusions (REVIEW_REQUIRED, SUPPORTED_EXCEPTION, UNRESOLVED, INVESTIGATION_LEAD,
     CONCLUSION) exist in the vocabulary but are human-only, and validation rejects them.

  3. NO RAW IDENTIFIERS. A signal's subject is a `Subject`, which can only be a masked reference,
     a group label or a row index. A raw string is not accepted, and free-form values cannot
     appear in metrics (numbers, booleans and short lowercase tokens only). Shape checks cannot
     prove a value is not sensitive; `core.masking` (the only sanctioned way to make a masked
     Subject) and review remain responsible for that.

`strength` is a method-defined effect size in [0, 1]: how large the departure is. It is NOT a
probability and NOT a fraud likelihood, and strengths of different methods are not comparable
until scoring calibrates them.
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field, fields
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

CONTRACT_VERSION = "1.0"
MAX_TOP_SIGNALS = 5
MAX_RESULT_CHARS = 2000        # ~500 tokens (ESTIMATE, chars / 4) per method result
MAX_REASON_CHARS = 300
MAX_SCALARS = 16
MAX_REASON_CODES = 6


class ContractViolation(ValueError):
    """A result that breaks the contract. Raised when a result is built, never at the consumer."""


class Status(str, Enum):
    COMPLETED = "completed"
    DECLINED = "declined"    # suitability decided not to run it (see verdict + reason_codes)
    REFUSED = "refused"      # a precondition failed (bad name, missing table, no row identity, ...)
    ERROR = "error"          # something failed while running


class Verdict(str, Enum):
    SUPPORTED = "SUPPORTED"
    SUPPORTED_WITH_WARNING = "SUPPORTED_WITH_WARNING"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNSAFE_TO_RUN = "UNSAFE_TO_RUN"
    REQUIRES_CONFIRMATION = "REQUIRES_CONFIRMATION"


RUNNABLE_VERDICTS = {Verdict.SUPPORTED, Verdict.SUPPORTED_WITH_WARNING}


class Classification(str, Enum):
    OBSERVATION = "OBSERVATION"
    ANOMALY = "ANOMALY"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    SUPPORTED_EXCEPTION = "SUPPORTED_EXCEPTION"
    UNRESOLVED = "UNRESOLVED"
    INVESTIGATION_LEAD = "INVESTIGATION_LEAD"
    CONCLUSION = "CONCLUSION"


ENGINE_CLASSIFICATIONS = {Classification.OBSERVATION, Classification.ANOMALY}

_KEY = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_TOKEN = re.compile(r"^[a-z][a-z0-9_]{0,31}$")          # enumerated string values in scalars
_CODE = re.compile(r"^[A-Z][A-Z0-9_]{1,40}$")
_METHOD_ID = re.compile(r"^[a-z][a-z0-9-]{1,40}$")
_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
# Letters only: a masked reference can never equal a digit-based identifier (Aadhaar, account
# numbers, PAN), even by accident. (A hex alphabet would accept a 12-digit number.)
_MASKED = re.compile(r"^[a-z]{12}$")
_GROUP = re.compile(r"^[A-Za-z0-9_. -]{1,40}$")
_LOOKS_LIKE_ID = re.compile(r"^\d{8,}$")


def _fail(msg: str):
    raise ContractViolation(msg)


def _number(value, what: str) -> float | int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail(f"{what} must be a number, got {type(value).__name__}.")
    if isinstance(value, float) and not math.isfinite(value):
        _fail(f"{what} must be finite.")
    return value


def _scalars(values: Mapping[str, Any], what: str) -> Mapping[str, Any]:
    if not isinstance(values, Mapping):
        _fail(f"{what} must be a mapping.")
    if len(values) > MAX_SCALARS:
        _fail(f"{what} has {len(values)} entries; the limit is {MAX_SCALARS}.")
    out = {}
    for k, v in values.items():
        if not isinstance(k, str) or not _KEY.match(k):
            _fail(f"{what} key {k!r} must be lowercase snake_case, up to 32 characters.")
        if isinstance(v, bool):
            out[k] = v
        elif isinstance(v, (int, float)):
            out[k] = _number(v, f"{what}[{k}]")
        elif isinstance(v, str):
            # Only short lowercase tokens (an enumeration such as 'close_conformity'). Digits-first,
            # uppercase, spaces, '@' and long strings, i.e. what raw identifiers look like, are refused.
            if not _TOKEN.match(v):
                _fail(f"{what}[{k}] string values must be short lowercase tokens; got {v[:12]!r}.")
            out[k] = v
        else:
            _fail(f"{what}[{k}] must be a number, boolean or token, got {type(v).__name__}.")
    return MappingProxyType(dict(sorted(out.items())))


# --------------------------------------------------------------------------- references
@dataclass(frozen=True)
class MethodRef:
    id: str
    version: str

    def __post_init__(self):
        if not _METHOD_ID.match(self.id or ""):
            _fail(f"method id {self.id!r} must be lowercase letters, digits and hyphens.")
        if not _VERSION.match(self.version or ""):
            _fail(f"method version {self.version!r} must look like 1.0.0.")

    @property
    def ref(self) -> str:
        """Pointer to the method's registered limitations, instead of repeating their text."""
        return f"{self.id}@{self.version}"


@dataclass(frozen=True)
class DatasetVersion:
    dataset_id: int
    basis: str                       # "content" (fingerprinted) | "row_count" (weaker; see datasets.notes)
    fingerprint: str | None = None   # kept for the evidence store; not sent to Claude

    def __post_init__(self):
        if isinstance(self.dataset_id, bool) or not isinstance(self.dataset_id, int) or self.dataset_id < 1:
            _fail("dataset_id must be a positive integer.")
        if self.basis not in ("content", "row_count"):
            _fail(f"dataset basis must be 'content' or 'row_count', got {self.basis!r}.")
        if self.basis == "content" and not self.fingerprint:
            _fail("a content-basis dataset version needs its fingerprint.")


@dataclass(frozen=True)
class RowIdentitySpec:
    columns: tuple[str, ...]
    kind: str                        # "primary_key" | "engine_row_no"

    def __post_init__(self):
        if not self.columns or not all(isinstance(c, str) and c for c in self.columns):
            _fail("a row identity needs at least one column name.")
        if self.kind not in ("primary_key", "engine_row_no"):
            _fail(f"row identity kind must be 'primary_key' or 'engine_row_no', got {self.kind!r}.")
        object.__setattr__(self, "columns", tuple(self.columns))


@dataclass(frozen=True)
class EvidenceInfo:
    """How the full evidence behind a result can be retrieved. The rows themselves are never here."""
    available: bool
    identity: RowIdentitySpec | None = None
    links: int = 0
    truncated: bool = False

    def __post_init__(self):
        if self.links < 0:
            _fail("evidence links cannot be negative.")
        if self.available and self.identity is None:
            _fail("available evidence must say how its rows are identified.")
        if not self.available and (self.links or self.truncated):
            _fail("evidence that is not available cannot have links.")


# ------------------------------------------------------------------------------- subjects
@dataclass(frozen=True)
class Subject:
    """What a signal is about. Deliberately NOT a string: there is no way to put a raw
    identifier here. Build one with the factories below."""
    kind: str        # "ref" (masked identifier) | "grp" (a category label) | "row" (row index)
    token: str

    def __post_init__(self):
        if self.kind == "ref":
            if not _MASKED.match(self.token):
                _fail("a masked subject must be 12 lowercase letters (an encoded keyed hash).")
        elif self.kind == "grp":
            if not _GROUP.match(self.token) or _LOOKS_LIKE_ID.match(self.token):
                _fail(f"a group label must be short text, not an identifier; got {self.token[:12]!r}.")
        elif self.kind == "row":
            if not self.token.isdigit() or len(self.token) > 12:
                _fail("a row subject must be a row index.")
        else:
            _fail(f"unknown subject kind {self.kind!r}.")

    @classmethod
    def masked(cls, encoded_keyed_hash: str) -> "Subject":
        """Only `core.masking` should call this, with an HMAC of the identifier encoded as 12
        lowercase letters."""
        return cls("ref", encoded_keyed_hash)

    @classmethod
    def group(cls, label: str) -> "Subject":
        return cls("grp", label)

    @classmethod
    def row(cls, index: int) -> "Subject":
        return cls("row", str(index))

    def __str__(self) -> str:
        return f"{self.kind}:{self.token}"


@dataclass(frozen=True)
class Signal:
    kind: str                         # method-defined, e.g. "shared_identifier"
    strength: float                   # effect size in [0, 1]; NOT a probability
    subject: Subject
    metrics: Mapping[str, Any] = field(default_factory=dict)
    classification: Classification = Classification.ANOMALY

    def __post_init__(self):
        if not _KEY.match(self.kind or ""):
            _fail(f"signal kind {self.kind!r} must be lowercase snake_case.")
        s = _number(self.strength, "strength")
        if not 0.0 <= s <= 1.0:
            _fail(f"strength must be within [0, 1], got {s}.")
        if not isinstance(self.subject, Subject):
            _fail("a signal's subject must be a Subject (masked reference, group label or row index), not a raw value.")
        object.__setattr__(self, "strength", round(float(s), 4))
        object.__setattr__(self, "metrics", _scalars(self.metrics, "signal metrics"))
        if not isinstance(self.classification, Classification):
            object.__setattr__(self, "classification", Classification(self.classification))
        if self.classification not in ENGINE_CLASSIFICATIONS:
            _fail(f"the engine may only emit OBSERVATION or ANOMALY, not {self.classification.value}.")

    def to_dict(self) -> dict:
        d = {"kind": self.kind, "strength": self.strength, "subject": str(self.subject)}
        if self.metrics:
            d["metrics"] = dict(self.metrics)
        if self.classification is not Classification.ANOMALY:
            d["class"] = self.classification.value
        return d


# -------------------------------------------------------------------------------- result
@dataclass(frozen=True)
class MethodResult:
    method: MethodRef
    status: Status
    dataset: DatasetVersion | None = None
    verdict: Verdict | None = None
    reason_codes: tuple[str, ...] = ()
    code: str | None = None                   # refused / error: a stable code
    reason: str | None = None                 # refused / error: one actionable sentence
    records_scanned: int = 0
    findings_count: int = 0
    classification: Classification | None = None
    summary: Mapping[str, Any] = field(default_factory=dict)
    parameters: Mapping[str, Any] = field(default_factory=dict)
    top_signals: tuple[Signal, ...] = ()
    signals_total: int = 0
    finding_ids: tuple[int, ...] = ()
    run_id: int | None = None
    evidence: EvidenceInfo = EvidenceInfo(False)

    def __post_init__(self):
        for name, enum in (("status", Status), ("verdict", Verdict), ("classification", Classification)):
            v = getattr(self, name)
            if v is not None and not isinstance(v, enum):
                object.__setattr__(self, name, enum(v))
        object.__setattr__(self, "summary", _scalars(self.summary, "summary"))
        object.__setattr__(self, "parameters", _scalars(self.parameters, "parameters"))
        object.__setattr__(self, "reason_codes", tuple(self.reason_codes))
        object.__setattr__(self, "top_signals", tuple(self.top_signals))
        object.__setattr__(self, "finding_ids", tuple(self.finding_ids))
        self._validate()

    def _validate(self) -> None:
        if self.classification is not None and self.classification not in ENGINE_CLASSIFICATIONS:
            _fail(f"the engine may only emit OBSERVATION or ANOMALY, not {self.classification.value}.")
        if len(self.reason_codes) > MAX_REASON_CODES or not all(_CODE.match(c) for c in self.reason_codes):
            _fail("reason codes must be UPPER_SNAKE_CASE, at most 6.")
        if not isinstance(self.records_scanned, int) or self.records_scanned < 0 or \
                not isinstance(self.findings_count, int) or self.findings_count < 0:
            _fail("records_scanned and findings_count must be non-negative integers.")
        if len(self.top_signals) > MAX_TOP_SIGNALS:
            _fail(f"at most {MAX_TOP_SIGNALS} top signals; use MethodResult.build() to trim.")
        if not len(self.top_signals) <= self.signals_total:
            _fail("signals_total cannot be smaller than the signals shown.")

        if self.status is Status.COMPLETED:
            if self.dataset is None:
                _fail("a completed result must name the dataset version it was computed on.")
            if self.verdict not in RUNNABLE_VERDICTS:
                _fail("a completed result needs verdict SUPPORTED or SUPPORTED_WITH_WARNING.")
            if self.verdict is Verdict.SUPPORTED_WITH_WARNING and not self.reason_codes:
                _fail("SUPPORTED_WITH_WARNING must say why (reason_codes).")
            if self.classification is None:
                _fail("a completed result must carry OBSERVATION or ANOMALY.")
            if self.code or self.reason:
                _fail("a completed result has no error code or reason.")
        elif self.status is Status.DECLINED:
            if self.verdict is None or self.verdict in RUNNABLE_VERDICTS:
                _fail("a declined result needs a non-runnable verdict (INSUFFICIENT_DATA, NOT_APPLICABLE, UNSAFE_TO_RUN or REQUIRES_CONFIRMATION).")
            if not self.reason_codes:
                _fail("a declined result must say why (reason_codes).")
        else:  # refused / error
            if not self.code or not _CODE.match(self.code):
                _fail("a refused or error result needs an UPPER_SNAKE_CASE code.")
            if not self.reason or len(self.reason) > MAX_REASON_CHARS:
                _fail(f"a refused or error result needs a reason of at most {MAX_REASON_CHARS} characters.")
        if self.status is not Status.COMPLETED and (self.top_signals or self.findings_count or self.finding_ids):
            _fail("only a completed result can carry signals or findings.")
        if self.status is Status.COMPLETED and self.findings_count == 0 and self.signals_total:
            _fail("a result with signals must count at least one finding.")
        if self.status is Status.COMPLETED and self.classification is Classification.ANOMALY \
                and self.findings_count == 0:
            _fail("an ANOMALY needs at least one finding; with none, the result is an OBSERVATION.")

    # ---- construction helpers ------------------------------------------------------
    @classmethod
    def build(cls, *, signals: list[Signal] = (), max_top: int = MAX_TOP_SIGNALS,
              max_chars: int = MAX_RESULT_CHARS, **kwargs) -> "MethodResult":
        """A completed result. Sorts signals (strongest first, ties by subject), keeps the top few,
        and trims the weakest until the compact JSON fits the size budget. Deterministic."""
        ordered = sorted(signals, key=lambda s: (-s.strength, str(s.subject), s.kind))
        keep = min(max_top, MAX_TOP_SIGNALS, len(ordered))
        while True:
            result = cls(status=Status.COMPLETED, top_signals=tuple(ordered[:keep]),
                         signals_total=len(ordered), **kwargs)
            if len(result.to_json()) <= max_chars:
                return result
            if keep <= 1:
                _fail(f"a result must fit {max_chars} characters; this one is {len(result.to_json())} even with one signal.")
            keep -= 1

    @classmethod
    def declined(cls, method: MethodRef, verdict: Verdict, reason_codes: list[str], **kwargs) -> "MethodResult":
        return cls(method=method, status=Status.DECLINED, verdict=verdict, reason_codes=tuple(reason_codes), **kwargs)

    @classmethod
    def refused(cls, method: MethodRef, code: str, reason: str) -> "MethodResult":
        return cls(method=method, status=Status.REFUSED, code=code, reason=reason)

    @classmethod
    def failed(cls, method: MethodRef, code: str, reason: str) -> "MethodResult":
        return cls(method=method, status=Status.ERROR, code=code, reason=reason)

    # ---- serialisation ---------------------------------------------------------------
    def to_dict(self) -> dict:
        """The compact form sent to Claude: empty and default fields are omitted, keys are in a
        fixed order, and constant text is a pointer (`limits`), never repeated."""
        d: dict = {"method": self.method.ref, "status": self.status.value}
        if self.verdict is not None:
            d["verdict"] = self.verdict.value
        if self.reason_codes:
            d["why"] = list(self.reason_codes)
        if self.code:
            d["code"] = self.code
        if self.reason:
            d["reason"] = self.reason
        if self.dataset is not None:
            d["dataset"] = {"id": self.dataset.dataset_id, "basis": self.dataset.basis}
        if self.status is Status.COMPLETED:
            d["scanned"] = self.records_scanned
            d["findings"] = self.findings_count
            d["class"] = self.classification.value
        if self.summary:
            d["summary"] = dict(self.summary)
        if self.parameters:
            d["params"] = dict(self.parameters)
        if self.top_signals:
            d["top"] = [s.to_dict() for s in self.top_signals]
            d["signals"] = self.signals_total
            if self.signals_total > len(self.top_signals):
                d["top_truncated"] = True
        if self.finding_ids:
            d["finding_ids"] = list(self.finding_ids)
        if self.run_id is not None:
            d["run"] = self.run_id
        if self.evidence.available:
            e = {"key": list(self.evidence.identity.columns), "links": self.evidence.links}
            if self.evidence.truncated:
                e["truncated"] = True
            d["evidence"] = e
        if self.status is Status.COMPLETED:
            d["limits"] = self.method.ref
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), ensure_ascii=True)

    def estimated_tokens(self) -> int:
        """ESTIMATE (characters / 4), not a measured token count."""
        return math.ceil(len(self.to_json()) / 4)


def result_keys() -> list[str]:
    """The fields of a MethodResult, for documentation and tests."""
    return [f.name for f in fields(MethodResult)]

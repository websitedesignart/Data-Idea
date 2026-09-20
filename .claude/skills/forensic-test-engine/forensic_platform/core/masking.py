"""
Masking: nothing identifying reaches Claude unless a human asked for it and it is safe to show.

A masked reference is a keyed hash (HMAC-SHA256) of the normalised value, encoded as 12 lowercase
letters (the shape `contract.Subject.masked` requires; letters only, so a digit identifier can
never be mistaken for one). It is:

  * stable    the same value gets the same token in every run of the same project, so groups can
              be followed across findings without ever showing the value;
  * keyed     the key is a per-project secret. An unkeyed hash of a 12-digit Aadhaar number can be
              brute-forced in minutes, so an unkeyed hash is not masking;
  * one-way   nothing here maps a token back. To see a row, use its evidence link (row identity)
              in the database, locally.

Fail-closed:
  * `protect()` masks every value by default. `reveal=True` shows raw values only when neither the
    column name nor any value looks sensitive (Aadhaar-, PAN-, IFSC-, mobile-, e-mail-shaped, or a
    long digit string such as an account number). A request that cannot be honoured safely is
    masked and says so.
  * With no salt available, values are WITHHELD entirely (counts still reported), never printed.

The key lives in `$FORENSIC_MASK_SALT`, or a `.forensic_mask_salt` file created next to the
project's `.mcp.json` on first use. Losing it changes future tokens (old ones stop matching), so
back it up with the project. It is a secret: never commit it.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .contract import Subject
from .profile import PATTERNS
from .roles import _SENSITIVE_NAME_KIND, name_tokens

SALT_ENV = "FORENSIC_MASK_SALT"
SALT_FILE = ".forensic_mask_salt"
MIN_SALT_CHARS = 32
_VERSION = b"forensic-mask-v1:"
_SENSITIVE_SHAPES = ("aadhaar_like", "pan_like", "ifsc_like", "mobile_like", "email_like")
_LONG_DIGITS = 9            # a digit string this long (account, card, Aadhaar) is treated as sensitive
_SEPARATORS = re.compile(r"[\s\-]+")


class MaskSaltUnavailable(RuntimeError):
    """No usable masking key. Callers must withhold values, never fall back to printing them."""


def load_salt(config_dir: Path | None = None, *, create: bool = True) -> bytes:
    """The project's masking key: $FORENSIC_MASK_SALT, else `.forensic_mask_salt` beside .mcp.json."""
    env = os.environ.get(SALT_ENV)
    if env is not None:
        if len(env) < MIN_SALT_CHARS:
            raise MaskSaltUnavailable(f"{SALT_ENV} must be at least {MIN_SALT_CHARS} characters.")
        return env.encode("utf-8")
    if config_dir is None:
        from .config import find_mcp_config
        try:
            config_dir = find_mcp_config().parent
        except RuntimeError as exc:
            raise MaskSaltUnavailable("no project found to hold a masking key.") from exc
    path = Path(config_dir) / SALT_FILE
    if path.is_file():
        text = path.read_text(encoding="utf-8").strip()
        if len(text) < MIN_SALT_CHARS:
            raise MaskSaltUnavailable(f"{path.name} is too short to be a masking key; not overwriting it.")
        return text.encode("utf-8")
    if not create:
        raise MaskSaltUnavailable(f"{path.name} does not exist.")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)   # O_EXCL: never overwrite a key
    except FileExistsError:
        return load_salt(config_dir, create=False)                        # lost a race; use the winner's key
    except OSError as exc:
        raise MaskSaltUnavailable(f"cannot create {path.name}: {exc.strerror}") from exc
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(secrets.token_hex(32))
    return load_salt(config_dir, create=False)


def normalise(value: Any) -> str:
    """Case, width, spacing and hyphen differences must not split one identifier into two tokens."""
    return _SEPARATORS.sub("", unicodedata.normalize("NFKC", str(value))).casefold()


def mask_value(value: Any, salt: bytes) -> str:
    """12 lowercase letters: a keyed hash of the normalised value. Deterministic per key."""
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < MIN_SALT_CHARS:
        raise MaskSaltUnavailable("a masking key of at least 32 bytes is required.")
    digest = hmac.new(bytes(salt), _VERSION + normalise(value).encode("utf-8"), hashlib.sha256).digest()
    n = int.from_bytes(digest[:8], "big")
    letters = []
    for _ in range(12):
        n, r = divmod(n, 26)
        letters.append(chr(ord("a") + r))
    return "".join(letters)


def subject(value: Any, salt: bytes) -> Subject:
    """The contract Subject for an identifier: the only sanctioned way to make a masked one."""
    return Subject.masked(mask_value(value, salt))


def looks_sensitive(value: Any) -> bool:
    """Shape test on one value. Errs towards True: an identifier is masked unless clearly safe."""
    text = str(value).strip()
    compact = _SEPARATORS.sub("", text)
    if compact.isdigit() and len(compact) >= _LONG_DIGITS:
        return True
    return any(re.match(PATTERNS[p], text) or re.match(PATTERNS[p], text.upper()) for p in _SENSITIVE_SHAPES)


def column_looks_sensitive(column: str) -> bool:
    return bool(name_tokens(column) & set(_SENSITIVE_NAME_KIND))


@dataclass(frozen=True)
class Protected:
    values: list            # tokens, raw values (only if revealed), or empty (withheld)
    mode: str               # masked | revealed | withheld
    note: str = ""          # why a request was not honoured, as a short lowercase token


def protect(values: Iterable[Any], *, column: str, salt: bytes | None, reveal: bool = False) -> Protected:
    """Prepare identifier values for output to Claude. None stays None (absence is not an identifier)."""
    items = list(values)
    if salt is None:
        return Protected([], "withheld", "no_mask_key")
    note = ""
    if reveal:
        if column_looks_sensitive(column):
            note = "reveal_refused_sensitive_column"
        elif any(v is not None and looks_sensitive(v) for v in items):
            note = "reveal_refused_sensitive_values"
        else:
            return Protected(items, "revealed")
    return Protected([None if v is None else mask_value(v, salt) for v in items], "masked", note)

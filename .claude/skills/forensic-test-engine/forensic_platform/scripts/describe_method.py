"""
Print a method's registered description and limitations, given the `limits` pointer from a result
(e.g. `benford@1.1.0`) or just the method name. No database is touched.

    python forensic_platform/scripts/describe_method.py benford@1.1.0

Results carry only this pointer instead of repeating the limitations text every run. Read it once per
method and quote it when reporting a finding.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from forensic_platform.tests_engine import base  # noqa: E402


def describe(ref: str) -> dict:
    name, _, version = ref.partition("@")
    try:
        entry = base.get_test_entry(name)
    except ValueError as exc:
        return {"status": "refused", "reason": str(exc)}
    out = {"method": f"{name}@{entry.get('version')}", "status": entry.get("status"),
           "algorithm": " ".join(str(entry.get("algorithm", "")).split()),
           "limitations": " ".join(str(entry.get("limitations", "")).split())}
    if version and version != entry.get("version"):
        out["note"] = f"asked for version {version}; the registry holds {entry.get('version')}."
    return out


def main() -> None:
    if len(sys.argv) != 2:
        print(json.dumps({"status": "refused", "reason": "usage: describe_method.py <method>[@version]"}))
        sys.exit(2)
    print(json.dumps(describe(sys.argv[1]), separators=(",", ":")))


if __name__ == "__main__":
    main()

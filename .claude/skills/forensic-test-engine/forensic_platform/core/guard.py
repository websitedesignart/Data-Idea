"""
Guard: decide whether a method should run on a column, before it runs.

Glue between the profiler (measure), the role bindings (a named human confirmed the column plays
this part) and suitability (the method's own rules). It answers one question and returns an
`Assessment`; the caller declines or runs.

  * Not confirmed  -> REQUIRES_CONFIRMATION, and the table is NOT scanned: an unconfirmed column's
                      measurements would not be used anyway.
  * Confirmed      -> the column alone is profiled (never the whole table), then assessed.

`confirmed_by` is a claim by the caller. The engine cannot verify who typed it, so it records the
name (the run is audit-logged with it) and relies on the skill to pass only a name the user gave.
"""
from __future__ import annotations

from .profile import TableProfile, deepen, profile_table
from .roles import Bindings, facts_for
from .suitability import Assessment, RuleSet, assess


def assess_column(cur, ruleset: RuleSet, schema: str, table: str, column: str, *,
                  role: str, confirmed_by: str | None) -> Assessment:
    bindings = Bindings()
    if confirmed_by and confirmed_by.strip():
        bindings.confirm(role, column, confirmed_by)
        # One column, so a full-scan profile is no heavier than the test itself; the statement
        # timeout of the caller's session still applies.
        profile = profile_table(cur, schema, table, allow_large=True, columns=[column])
        if "top10_share" in ruleset.facts_required():
            deepen(cur, profile, [column])
    else:
        bindings.propose(role, column)
        profile = None
    if profile is None:
        profile = TableProfile(schema, table, 0, {})
    return assess(ruleset, facts_for(profile, bindings, ruleset, role))

# Changelog

## [1.0.1] - 2026-09-10
- Fix: `/review` now actually runs in the `code-reviewer` subagent. The skill declared
  `agent: code-reviewer` without `context: fork`, so it ran inline in the main session and the
  subagent was never spawned.

## [1.0.0] - 2026-09-06
- Initial release: `code-reviewer` agent and `/review` skill.

# Code Review Agent

A Claude Code plugin that reviews diffs, PRs, or file sets for correctness bugs, security issues, and unnecessary complexity. Install it once and use `/review` in any project.

## What's included

- **`code-reviewer` agent** — a subagent that reads the actual diff/files, verifies each finding against real code, and classifies issues as CONFIRMED or PLAUSIBLE.
- **`/review` skill** — resolves a target (uncommitted changes, a branch, a PR number, or a path) and hands it to the `code-reviewer` agent.

## Install into any project

```
/plugin marketplace add websitedesignart/Data-Idea
/plugin install code-review@data-idea
```

Then, in any project:

```
/review
/review 123          # review PR #123 (uses gh CLI if available)
/review main          # diff against the main branch
/review src/utils.py  # review a file directly
```

## Local development

```
claude --plugin-dir /path/to/Data-Idea
```

## Structure

```
.claude-plugin/
  plugin.json        # plugin manifest
  marketplace.json    # marketplace catalog (this repo is both plugin + marketplace)
agents/
  code-reviewer.md    # the review subagent
skills/
  review/SKILL.md      # the /review slash command
```

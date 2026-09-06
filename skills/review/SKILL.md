---
name: review
description: Review the current git diff, a specific branch/commit, a PR, or a given file/path for correctness, security, and simplification issues. Invoke when the user asks to review code, check a diff, or review a PR before merging.
argument-hint: "[diff|branch|PR#|path]"
arguments: [target]
allowed-tools: Read, Grep, Glob, Bash
agent: code-reviewer
---

Determine the review target from `$target`:

- No argument: review uncommitted changes (`git status` + `git diff`, and `git diff --staged`). If there are none, review the diff of the current branch against its merge base with the default branch.
- A number (e.g. `123`): treat it as a PR — use `gh pr diff $target` if the `gh` CLI is available and authenticated; otherwise fetch and diff the PR's branch directly with git.
- A branch or commit-ish: run `git diff` against it.
- A file or directory path: review that path's current content directly (no diff needed).

Hand the resolved diff or file content to the `code-reviewer` agent for analysis. Report its findings to the user exactly as returned — most severe first, each with file:line, summary, failure scenario, and suggested fix. If the target can't be resolved (e.g. no git repo, no changes, invalid PR number), say so instead of guessing at a target.

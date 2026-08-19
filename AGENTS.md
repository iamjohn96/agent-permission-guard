# Agent Permission Guard working rules

## Scope

This repository contains Agent Permission Guard. Keep changes limited to the requested milestone. Do not modify unrelated repositories or files.

## Allowed without additional approval

- Read and search this repository.
- Edit local source, tests, and documentation within the approved task.
- Run tests, type checks, builds, and safe diagnostics.
- Produce diffs and summarize results.

## Approval required before execution

- `git push`, remote repository mutations, or deployment.
- Package installation, dependency addition/removal, or broad upgrades.
- Reading `.env`, tokens, keys, credentials, or signing material.
- External API write requests or user-data operations.
- Database migrations against a persistent database, data deletion, resets, or destructive commands.
- Changes to authentication, authorization, approval bypass behavior, or production policy semantics.
- Running unknown or external scripts and MCP server commands.
- Changes outside this repository or outside the requested scope.

Approval requests must state the action, reason, affected resources, risk, rollback, and exact command or payload.

Never print or persist secret values. If a secret appears necessary, report only its name and why it is needed, then stop.

Final reports must include changed files, reasons, verification, failures or unverified items, remaining risks, and rollback guidance.

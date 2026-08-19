# Agent Permission Guard

Firewall and audit layer for AI agents.

Agent Permission Guard is an MCP gateway that sits between an MCP client and server. The current implementation is a local CLI enforcement point with deterministic policy evaluation, risk scoring, and a local SQLite audit trail.

> [!WARNING]
> Agent Permission Guard `0.1.x` is a developer alpha. Test policies with non-production tools and data before placing it in front of credentials, destructive actions, or irreversible external side effects.

## Install from source

The CLI is not published to the npm registry yet. Build it from a local checkout:

```sh
git clone https://github.com/iamjohn96/agent-permission-guard.git
cd agent-permission-guard
npm ci
npm run build
node dist/src/cli/main.js init
```

Check the local setup and a trusted upstream command without starting that command:

```sh
node dist/src/cli/main.js doctor -- node
```

`doctor` checks the supported Node.js version, policy syntax, audit database path, localhost dashboard port, and whether the optional upstream command is executable. It never runs the upstream command.

Start the proxy with the trusted upstream MCP server command:

```sh
node dist/src/cli/main.js proxy \
  --policy ./.apg/policy.yaml \
  --audit-db ./.apg/audit.sqlite \
  --dashboard-port 47831 \
  -- <upstream-command> [args...]
```

APG prints a tokenized localhost dashboard URL to stderr. Open that exact URL to review approvals, inspect the audit trail, and edit the active policy.

## Current milestone

- Proxy `tools/list` from an upstream MCP server.
- Initialize a private starter policy with `apg init` without overwriting existing policy files.
- Diagnose the local runtime, policy, audit path, dashboard port, and upstream executable with `apg doctor` without executing the upstream command.
- Forward allowed `tools/call` requests.
- Stop denied calls before they reach the upstream server.
- Support modern MCP `2026-07-28` and legacy `2025-11-25` clients through the official SDK.
- Keep stdout reserved for MCP JSON-RPC messages.
- Parse versioned YAML policies with a fail-closed schema.
- Evaluate deterministic Allow / Ask / Deny rules.
- Escalate high-risk Allow decisions to Ask without heuristic auto-denial.
- Enforce policy decisions on live MCP tool calls.
- Persist redacted call metadata, decisions, outcomes, and a tamper-evident audit-event hash chain in SQLite.
- Fail closed before tool execution if the required policy or pre-execution audit write is unavailable.
- Hold Ask requests for one-time human approval in a local web dashboard.
- Expire or cancel pending approvals without calling the upstream tool.
- Protect the dashboard API with loopback-only binding, exact origin/host checks, and an ephemeral bearer token.
- Review recent redacted tool calls and audit-chain integrity in the dashboard.
- Validate, atomically save, and immediately activate YAML policy changes from the dashboard.
- Detect stale editor revisions or external file changes instead of overwriting them.
- Record dashboard policy-change attempts in the same audit trail.

See [`apg.example.yaml`](./apg.example.yaml) for the current policy format.

## Development

The project targets Node.js 24 LTS.

```sh
npm run typecheck
npm test
npm run build
```

The normal test suite is fully local. A separate opt-in compatibility check uses pinned versions of the official Everything and Filesystem reference servers:

```sh
APG_REAL_MCP_E2E=1 npm test -- test/integration/official-servers.test.ts
```

That command allows `npx` to download and execute the two reviewed reference packages. Run it only in a disposable development environment after approving external package execution. The Filesystem server is restricted to a test-created temporary directory.

The compatibility test pins the npm-published versions `@modelcontextprotocol/server-everything@2026.8.18` and `@modelcontextprotocol/server-filesystem@2026.7.10` rather than following `latest`.

Only run upstream commands that you trust and have explicitly reviewed.

The source-build examples use `node dist/src/cli/main.js`. After the package is published or installed as a CLI, use the shorter equivalents:

```sh
apg init
apg doctor -- <upstream-command>
apg proxy --policy ./.apg/policy.yaml --audit-db ./.apg/audit.sqlite -- <upstream-command> [args...]
```

`apg init` defaults to `./.apg` and accepts `--directory <path>`. It creates `policy.yaml` with private file permissions and refuses to overwrite an existing policy. The audit database is created only when the proxy first starts.

After startup, APG prints a secure local dashboard URL to stderr. Open that exact URL to review pending requests. Its token is held only for the running process and the current browser session. Use `--dashboard-port 0` when the operating system should choose a free loopback port.

The policy and audit database are mandatory. Missing or invalid policy input and database initialization failures stop startup. Arguments are stored as bounded, redacted previews; tool result bodies are not retained. Secret-derived raw values are not included in request hashes.

## Enforcement behavior

| Effective decision | Current behavior |
| --- | --- |
| Allow | Write the decision and pre-execution event, call the upstream tool, then record the outcome. |
| Ask | Wait for one-time dashboard approval. Approved calls proceed; denied, expired, or cancelled calls never reach upstream. |
| Deny | Record the denial and return a safe error without calling upstream. |

Approval requests use the policy's `approval_ttl_seconds`. A decision is consumed once and cannot be replayed.

Dashboard policy updates are security-sensitive. APG validates the complete YAML document before writing, checks that the editor and on-disk revisions are current, atomically replaces the policy file with mode `0600`, and applies it only to new tool calls. Existing in-flight calls keep the decision already recorded for them.

## Product shape

The MVP is a **local security gateway with a CLI runtime and a localhost web dashboard**:

- The CLI/background process is the enforcement point between an MCP client and server.
- The browser dashboard provides human approval, recent audit history, integrity status, and policy editing.
- It is not a hosted SaaS web app and not a native mobile app.
- A native desktop tray wrapper may be added later for installation and notifications, while the local gateway remains the security boundary.

The intended product path is:

1. Local developer preview: CLI, YAML policy, local audit database, localhost dashboard.
2. Installable desktop product: signed macOS/Windows packages, tray notifications, managed local service.
3. Team product: optional self-hosted control plane for policy distribution and audit aggregation; enforcement remains local.
4. Enterprise product: agent identity, delegated permissions, SSO/RBAC, signed policies, and external SIEM export with telemetry opt-in.

## Open-source scope

This repository is licensed under the [Apache License 2.0](./LICENSE). The open-source scope includes the local MCP gateway, policy and risk engines, approval dashboard, SQLite audit logger, and local developer tooling contained in this repository.

Potential future hosted control-plane services, managed policy distribution, enterprise identity, SSO/RBAC, and commercial support may be developed as separate products and are not included merely by being described on the roadmap.

Apache-2.0 permits commercial use, modification, distribution, and hosted use of the code in this repository, subject to its license terms. It does not reserve hosted use exclusively for the project owner.

See [CONTRIBUTING.md](./CONTRIBUTING.md) before submitting changes. Report suspected vulnerabilities privately as described in [SECURITY.md](./SECURITY.md).

## Current limitations

- Audit history currently shows the 50 most recent calls and does not yet provide search, pagination, retention controls, or export.
- External edits to the active policy are not hot-reloaded. APG refuses to overwrite them; restart the process after reviewing an external change.
- The approval token is process-local and the server only binds to `127.0.0.1`, but a fully packaged desktop product should additionally use OS-level process identity and secure local credential storage.
- The hash chain detects event-content changes, reordering, and interior deletion. It is not yet externally anchored or signed, so tail truncation or full database replacement requires a future external checkpoint to detect.
- If a tool executes successfully and the post-execution outcome write then fails, the gateway cannot undo that external side effect. The durable pre-execution event still records that execution was released.
- Node.js 24 LTS is the target runtime; development may also work on newer supported Node versions listed in `package.json`.

## License

Apache License 2.0. See [LICENSE](./LICENSE).

# Agent Permission Guard for macOS — Personal Product Plan

Status: product architecture accepted; M0 local API contract hardening implemented locally
Scope: personal Free and Pro only; Team and Enterprise are explicitly deferred

## Product decision

Keep the security enforcement engine open source and cross-platform. Build a separate macOS menu bar companion that makes the local engine easy to install, understand, and approve.

```text
Codex / MCP client
        |
        v
Open-source APG CLI (security boundary)
        |
        +---- MCP server
        |
        +---- private localhost API
                    ^
                    |
             macOS menu bar app
```

The macOS app is not a second firewall. If the app is closed, the CLI must continue enforcing Allow, Ask, and Deny. An Ask request may wait or expire, but it must never bypass the CLI.

## Target user

The first user is an individual developer who runs Codex or another local MCP client on a Mac and wants to know:

- What is my agent trying to do?
- Is this action safe?
- Can I approve or deny it quickly?
- What did the agent do earlier?

The first paid value is convenience and clarity for this individual, not organizational governance.

## Free and Pro boundary

### Free and open source

- macOS and Linux CLI runtime
- MCP proxy and Allow / Ask / Deny enforcement
- Local risk scoring
- YAML policy
- Local browser dashboard
- Recent local audit history and integrity check
- Manual installation and MCP configuration guides
- No account and no external telemetry

### macOS Free companion

- Menu bar status: protected, stopped, or attention needed
- Open the existing local dashboard
- Show whether the CLI and state file are detected
- Local setup checklist
- No account required

### macOS Pro

- Native approval notifications
- Approve or deny from the menu bar
- Search and filter local audit history
- Multiple local agent profiles
- Launch-at-login and health warnings
- Policy presets with a clear preview before applying
- Local export of an audit report

Core enforcement and Deny rules must not become paid features. Pro sells a better personal workflow, not basic safety.

## macOS v0.1 acceptance criteria

The first app build is a technical companion preview, before payments:

1. Runs as a SwiftUI menu bar app.
2. Reads one user-selected APG dashboard state file.
3. Shows Connected, Waiting for approval, or Offline.
4. Lists pending approval requests without reading SQLite directly.
5. Approves or denies exactly one pending request through the localhost API.
6. Opens the full browser dashboard for audit and policy work.
7. Shows a local notification when a new approval appears.
8. Keeps the dashboard bearer token only in memory.
9. Sends no telemetry and works without an account.
10. Never starts an unknown MCP command or edits Codex configuration automatically.

Payments, licensing, multiple profiles, native policy editing, and audit search are not part of v0.1.

## Technical architecture

### Repository

Create a separate repository, suggested name `agent-permission-guard-macos`. Keep the Apache-2.0 CLI in the current public repository. The commercial app repository can remain private while the product model is tested.

### Native stack

- Swift 6 and SwiftUI
- `MenuBarExtra` for the menu bar interface
- `URLSession` for the loopback API
- `UserNotifications` for approval alerts
- Apple Security framework only when licensing data later requires Keychain storage
- XCTest for state parsing, API behavior, and approval state transitions

The first build should not add third-party Swift packages.

### Connection contract

The CLI remains the source of truth. The app:

1. Watches the configured `dashboard.json` path.
2. Validates version, loopback URL, PID, and start time.
3. Extracts the bearer token into memory.
4. Calls only the matching `127.0.0.1` origin.
5. Uses the existing approval and audit HTTP endpoints.
6. Discards the token when the state file disappears, changes owner process, or becomes invalid.

The app must not log the URL, bearer token, request headers, or raw sensitive tool arguments.

### Distribution

Start with a signed and notarized direct-download app. Do not target the Mac App Store initially because process discovery, local file access, and managing a separately installed CLI are a poor fit for a strict application sandbox.

The v0.1 preview may require the npm CLI to be installed already. Bundling a Node runtime and CLI helper should be evaluated only after the companion workflow is validated.

## Personal monetization experiment

Do not add payment to the first technical preview. Validate repeated use first.

Suggested sequence:

1. Free preview: confirm that users keep the app running and respond to approvals.
2. Pro trial: enable native notifications, native approval, and audit search for 14 days.
3. Paid launch hypothesis: USD 8–12 monthly or USD 79–99 yearly.
4. Measure activation, approvals handled, seven-day retention, trial conversion, and cancellation reasons locally where possible.

Selecting or integrating a payment/licensing provider is a separate security and billing decision and requires explicit approval. Team billing, shared accounts, hosted audit storage, SSO, and RBAC are out of scope.

## Milestones

### M0 — Contract hardening

- Document the local dashboard API and strict state validation for a native client.
- Provide an authenticated read-only health endpoint with a non-secret dashboard `instance_id`.
- Add integration tests for origin-less native authorization, instance matching, stale credentials, and state-file rotation.

### M1 — Native technical preview

- Create the separate SwiftUI menu bar project.
- Implement state discovery, connection status, pending approvals, decisions, and notifications.
- Test against a locally running APG fixture.

### M2 — Personal usability

- Guided setup and clearer risk explanations.
- Multiple local profiles.
- Native audit search and filters through supported CLI APIs.
- Signed and notarized preview distribution.

### M3 — Pro validation

- Add a local entitlement boundary and trial UX.
- Select a payment and licensing approach after explicit approval.
- Publish pricing only after testing with early users.

## Architecture check

Jonny should approve these decisions before implementation:

1. The macOS app is a companion; the CLI stays the security boundary.
2. The app lives in a separate repository.
3. v0.1 has no payment, account, telemetry, or third-party dependency.
4. Direct signed distribution is preferred over the Mac App Store initially.
5. Team and Enterprise code is deferred.
6. M0 contract hardening happens before creating the SwiftUI project.

# ADR-001: Interception Boundaries

Status: accepted by Jonny on 2026-08-31
Scope: current MCP firewall and the Install Guard module

## Decision

Agent Permission Guard is an enforcement gateway only for execution paths that are explicitly routed through it. The current CLI reliably governs MCP tool calls between one MCP client and one MCP server. It must not claim to protect shell commands, direct GitHub requests, browser actions, or arbitrary API calls unless those actions use an APG-controlled adapter.

```text
MCP client -> APG MCP gateway -> MCP server        enforced today

Agent -> direct shell / browser / API / GitHub     not intercepted today
Agent -> APG adapter -> target execution path      possible future enforcement
```

Brand integration and execution-path integration are separate decisions. A feature can share the APG name, policy language, approval experience, risk explanation, and audit format without pretending that the MCP proxy observes an unrelated execution path.

## Coverage matrix

| Execution path | Current coverage | Required enforcement point | Fail-safe rule |
| --- | --- | --- | --- |
| MCP `tools/call` routed through APG | Enforced | Existing MCP STDIO gateway | Policy/audit/approval failure blocks execution |
| MCP call connected directly to a server | Not covered | Client configuration must route through APG | Clearly report unprotected configuration |
| Shell command | Not covered | Dedicated shell runner or agent/IDE integration | Never imply observation of a direct shell |
| `npm`, `npx`, `pip`, or other installers | Not covered | Install-specific runner or tool adapter | Analyze first; execution requires the adapter |
| GitHub operation through an MCP server behind APG | Enforced as an MCP tool call | Existing gateway plus tool policy | Deny or Ask before the upstream call |
| Direct `git`, `gh`, or GitHub API operation | Not covered | Git wrapper, agent integration, or API proxy | No audit claim without routed execution |
| Browser automation through an MCP server behind APG | Enforced as an MCP tool call | Existing gateway | Evaluate before forwarding |
| Direct browser interaction | Not covered | Browser extension, managed browser, or agent integration | Treat as outside the security boundary |
| Direct external API call | Not covered | HTTP proxy/SDK wrapper or agent integration | Do not market as covered |
| Local file access through an MCP server behind APG | Enforced as an MCP tool call | Existing gateway | Apply policy before forwarding |
| Direct process file-system access | Not covered | OS sandbox or controlled runner | APG cannot retroactively prevent it |

## Trust boundary

APG protects a routed request before it reaches the upstream tool. It does not sandbox the upstream server after approval. Once an allowed or approved tool starts, that process may perform broader child operations than its tool name suggests. Policy therefore needs trusted server provenance, bounded arguments, and audit evidence, while high-risk execution may eventually require an OS sandbox.

The audit log proves what APG observed and decided. It does not prove that no unobserved path was used. Product language should say “protected through APG” rather than “all agent activity protected.”

## Install Guard integration decision

Install Guard will begin inside APG, not as a separate product or repository. It will reuse only the APG components that fit the install workflow. Its execution adapter remains separate from the MCP gateway because the two paths intercept different protocols.

Shared APG components:

- Allow / Ask / Deny decision vocabulary
- human approval service and one-time decisions
- audit event model and integrity guarantees
- common risk bands, reason-code conventions, and plain-language explanations
- privacy-first local operation and fail-closed behavior

Install-specific components:

- npm/npx command parsing and exact target resolution
- package metadata collection and normalization
- install-specific risk signals
- dry-run and execution runner
- post-execution verification

This is a modular connection, not a merge of every Install Guard idea into the MCP gateway. Components should be extracted into shared interfaces only when both execution paths genuinely need them.

Initial scope:

- npm and npx only
- analysis/dry-run before execution
- exact package identity and version fixed at approval time
- Allow once and Deny decisions first
- optional persistent allowance scoped by package, version, and project only after the model is validated
- risk reasons include registry provenance, publisher, package age, download anomaly, install scripts, repository provenance, advisories, and possible typosquatting
- metadata source, observation time, and uncertainty shown to the user
- missing or contradictory metadata results in Ask or Deny, never silent Allow
- audit records analysis, decision, actual command, exit result, relevant file effects, and observed child processes where the adapter can collect them

Proposed flow:

```text
Agent or developer
        |
        v
Install Guard adapter
        |
        +-> resolve exact package/version
        +-> collect metadata and explain risk
        +-> Core Policy + Install Override
        +-> Allow / Ask / Deny
        +-> execute only inside the adapter
        +-> verify and audit the result
```

The first implementation must not monkey-patch a user's global shell, silently replace `npm`, or claim to block direct installer commands. A deliberately invoked runner is the safest v0 path. IDE and agent integrations can follow after the workflow proves useful.

## Explicit non-goal

ContextGate is not part of this project or roadmap. If explored later, it will start in a separate Work with its own requirements and architecture boundary.

## Product loop

The shared APG product loop is:

```text
Observe -> Explain -> Authorize -> Execute -> Verify / Audit
```

Each adapter must implement every stage or explicitly declare which stage it cannot provide.

## Consequences

Positive:

- Security claims match technical reality.
- The existing MCP gateway remains small and stable.
- New adapters can reuse policy, approval, risk, and audit concepts.
- Install Guard can be tested without prematurely building an enterprise platform.

Trade-offs:

- Users must deliberately route activity through APG.
- Coverage is fragmented until client and runner integrations exist.
- Verifying child effects is harder than authorizing a top-level command.
- A common policy schema needs domain-specific overrides rather than one universal list of tool names.

## Accepted architecture decisions

1. APG only claims enforcement for explicitly routed paths.
2. Direct shell, browser, GitHub, API, and file-system actions are currently outside coverage.
3. Install Guard is an APG module, not a separate product or repository at v0.
4. Install Guard starts as a deliberately invoked npm/npx runner, separate from the MCP proxy execution path.
5. APG and Install Guard share only policy, approval, audit, risk conventions, and other proven reusable components.
6. ContextGate is excluded and requires a separate Work if revisited.

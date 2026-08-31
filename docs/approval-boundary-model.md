# Approval Boundary Model

Status: proposed product-policy model
Source: JonnyLab AI Development Approval Boundary Policy

## Product principle

APG follows this principle:

> Automate execution. Gate consequences.

Routine, local, reversible work should not create approval fatigue. Human approval belongs at a boundary where an action can affect production, external systems, sensitive data, money, permissions, or irreversible state.

This development policy informs APG's product model, but it does not automatically change the current runtime policy format or enforcement behavior.

## Two-layer policy

```text
Core Policy
  + Product / domain override
  + Local user override (may become stricter)
  = Effective decision
```

### Core Policy

The shared baseline classifies consequences across all APG adapters:

- local versus production
- reversible versus destructive
- internal versus external side effects
- public/internal data versus user/sensitive data
- no cost versus recurring or uncertain cost
- existing permission versus privilege expansion
- test/simulation versus real execution

### Product or domain override

Each product adds a short rule set for risks unique to its execution path. Examples:

- MCP Firewall: untrusted server, sensitive arguments, destructive tool, external side effect
- Install Guard: package provenance, lifecycle scripts, advisories, typosquatting, version substitution

An override may raise a risk level or require approval. It must never weaken a non-overridable Core Deny rule.

### Local user override

An individual may make policy stricter for a project or machine. In the first personal product, local overrides must not silently weaken built-in safety floors. Any future weakening mechanism requires an explicit architecture and UX review.

## Risk classes and runtime mapping

JonnyLab's development workflow uses four operational classes. APG's enforcement result remains three-valued.

| Development class | Meaning | APG runtime mapping |
| --- | --- | --- |
| GREEN | Local, reversible, testable, no meaningful external consequence | Allow |
| YELLOW | Reversible project-level change; execute and report | Allow plus audit and explanation |
| ORANGE | Meaningful consequence; approval before execution | Ask |
| RED | Explicit human control or prohibited action | Ask or Deny, selected by non-overridable policy |

RED is not automatically Ask. Actions that should never occur in the configured scope—such as deleting a repository or pushing directly to a protected branch—should be Deny. Actions that are legitimate but consequential—such as an approved production deployment—may be Ask.

## Decision precedence

When multiple rules apply, APG chooses the most restrictive result:

```text
Deny > Ask > Allow
```

Additional rules:

1. Uncertainty increases the approval level.
2. Missing required policy, audit, approval, or risk evidence fails closed.
3. A safe-looking tool name cannot reduce risk inferred from trusted policy context.
4. Approval is scoped to the exact action shown to the human and is consumed once.
5. The executed target must match the approved target; changed package versions, arguments, recipients, or environments require a new decision.
6. An adapter may only claim an audit record for activity it actually observed.

## Boundary dimensions

Every adapter should normalize enough context to answer:

- What action is requested?
- Which resource and environment will it affect?
- Is the effect reversible?
- Does it cross a machine, organization, or network boundary?
- Does it involve user or sensitive data?
- Does it expand credentials or permissions?
- Can it create cost or an external commitment?
- What evidence supports the risk assessment?
- What exactly will be executed after approval?

The product should explain the consequence in plain language and show reason codes as supporting detail, not make users interpret a score alone.

## Learning boundary

A learning checkpoint is different from a safety approval. It explains:

1. what was built
2. where data moves
3. the important abstraction
4. failure behavior
5. the security boundary
6. what the user must understand

Learning checkpoints do not grant execution authority and should not interrupt routine safe implementation. They are appropriate at architecture acceptance, a new adapter boundary, or a material change in data flow.

## Evidence before approval

Before asking a human to authorize a consequential action, an adapter should complete every safe check available:

```text
Analyze -> Validate -> Test / Dry-run -> Explain diff and impact
        -> Human decision -> Real side effect -> Verify / Audit
```

An approval prompt should include the proposed action, affected resource, evidence, worst credible failure, rollback, and exact execution target. Secret values must never appear in the prompt or audit record.

## APG project override

For development of Agent Permission Guard itself:

- repository reading, scoped local edits, tests, builds, and documentation are autonomous
- dependency changes require approval before execution
- authentication, authorization, approval bypass, or production policy semantic changes require approval
- secret or credential access is never implicit
- git push, publishing, deployment, external writes, destructive data operations, and out-of-scope file changes require approval
- where this project override and the general JonnyLab policy differ, the stricter boundary applies

## Deferred implementation choices

This document intentionally does not decide:

- a new runtime policy schema version
- permanent approvals or policy exceptions
- remote policy distribution
- team roles, identity, SSO, or RBAC
- hosted audit storage
- payment or licensing enforcement
- ContextGate or context/data-broker enforcement

Those choices require separate product evidence and architecture acceptance.

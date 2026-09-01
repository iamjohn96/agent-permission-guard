# Current State

## Current Milestone

macOS M0 — Local API Contract Hardening: complete locally.

The local dashboard state and authenticated health API now share a random non-secret `instance_id`. This lets a future native companion reject stale state, PID reuse, and responses from an older connection generation without changing API version 1.

## Completed

- IG0: strict npm/npx parsing, offline metadata fixtures, deterministic risk and policy evaluation
- IG1: one-time approval, dashboard representation, and tamper-evident audit integration using fake runners
- IG2: anonymous read-only HTTPS npm registry metadata adapter with bounded transport and memory-only cache
- IG2.5: `apg inspect npm|npx <package-spec>` analysis-only CLI
- IG3 foundation:
  - exact resolved package/version execution identity
  - registry tarball URL, SHA-512 integrity, and executable-bin evidence
  - canonical executable, arguments, working directory, timeout, and pre-state plan hash
  - mandatory one-time Ask for every proposed local install execution
  - fake-runner outcomes for timeout, cancellation, verification failure, and audit failure contracts
  - read-only precondition and post-execution verification helpers
  - controlled `shell: false` runner with private npm config/HOME/cache, captured PATH, bounded redacted output, timeout, cancellation, and process-group termination
  - explicit `apg install npm|npx` CLI with local one-time approval dashboard and non-success exit behavior
  - exact version and approved SHA-512 integrity verification from npm lockfiles
  - isolated real npm acceptance for `yaml@2.9.0` with lifecycle scripts disabled, exact-save enabled, verified lockfile integrity, and a valid audit hash chain
- Release R0:
  - local version and lockfile updated to `0.2.0`
  - package dry-run confirmed 56 intended files, including compiled Install Guard CLI and dashboard assets
- macOS M0:
  - additive version-1 `instance_id` in private dashboard state
  - authenticated health response bound to the same dashboard instance
  - strict loopback URL, credential, query, path, port, token, and UUID validation
  - state cleanup identity includes URL, PID, start time, and instance ID
  - native rotation, token lifetime, SQLite, redirect, and fail-closed contracts documented
  - stale-token and same-PID replacement integration coverage

## In Progress

- No active M0 implementation work remains.

## Remaining

- Decide whether to accept the POSIX-only preview or design a Windows runner separately.
- Start M1 native technical preview in the separate macOS repository only after a new Architecture Check and approval.

## Important Architecture

- APG protects only actions explicitly routed through an APG adapter.
- Install Guard is an APG module but its execution path remains separate from the MCP proxy.
- An install approval is one-time and bound to the complete immutable execution-plan hash.
- Direct npm/npx commands remain outside APG coverage.
- ContextGate is outside this repository and roadmap.
- The future macOS app is a client of the local API; the CLI remains the enforcement boundary.
- State `instance_id` and authenticated health matching establish freshness. PID and start time are diagnostic only.

## Important Decisions

- Real local execution always requires Ask, even when package risk evaluation is otherwise Allow.
- Execution requires fresh resolved metadata, an exact version, HTTPS registry/tarball URLs, and SHA-512 integrity evidence.
- npx requires one deterministic executable binary; ambiguous packages fail closed.
- Project `.npmrc` files are rejected by presence only; their contents are not read.
- The current milestone does not claim OS sandboxing, complete child-effect observation, or automatic rollback.
- State version and API version remain 1 because `instance_id` is an additive field; new native clients must require it.

## Known Issues

- Exact identity currently covers the approved top-level package, not the complete transitive dependency graph.
- File verification is limited to package manifests and npm lockfiles.
- The npm runner has one successful isolated real-package acceptance; npx remains validated only with controlled test executables and has not executed downloaded package code.
- Output redaction is bounded and pattern-based, so it cannot guarantee detection of arbitrary unlabeled secrets.
- The controlled runner preview currently rejects Windows.
- npm performs dependency metadata and tarball requests itself after approval; APG does not act as an HTTP proxy for each transitive request.
- npm public version is `0.2.0`, including IG2 and IG3.
- M0 does not provide OS-level process attestation. A malicious process running as the same user may read the private state file and bearer token.

## Tests

- Current full local suite: 128 passed, 2 skipped on 2026-09-02.
- IG3 coverage includes execution plan, plan tamper, parser bypass, fake executable process execution, registry adapter, dashboard approval, timeout, cancellation, output redaction, terminal audit failure, and exact integrity verification.
- Manual npm acceptance: `yaml@2.9.0`, `--ignore-scripts --save-exact`, exit code 0, verification `verified`, matching approved SHA-512 integrity, valid nine-event audit hash chain. The same temporary audit database also contains the earlier approval-expired attempt.
- Release package dry-run: `agent-permission-guard@0.2.0`, 56 files, 61,727 bytes compressed, scripts disabled, and no registry access. Public registry verification confirmed version `0.2.0` after publish.
- M0 focused suite: 30 passed across dashboard authorization, private state, and STDIO proxy rotation tests.
- M0 coverage includes instance matching, foreign origin rejection, origin-less native authorization, stale credential rejection, strict state URL validation, and same-URL/same-PID replacement safety.
- Default tests must remain network-free; live registry or installation checks are opt-in and approval-gated.

## Do Not Change

- Do not merge the Install Guard runner into the MCP proxy path.
- Do not read `.npmrc`, `.env`, tokens, keys, credentials, or signing material.
- Do not add dependencies, run real installs, access a live registry, publish, push, or migrate the database without approval.
- Do not claim protection for direct npm/npx commands.

## Current Risks

- A future lifecycle script or npx executable can perform effects outside the working directory without an OS sandbox.
- Post-execution audit failure cannot undo a completed local side effect.
- Automatic rollback cannot reliably reverse lifecycle scripts, child processes, cache changes, or external requests.
- Native clients must invalidate in-flight work on state rotation; server-side instance matching cannot cancel stale client responses by itself.

## Next Recommended Task

Start a fresh Work for M1 native technical preview in a separate macOS repository. Real npx acceptance remains a later independent approval because it executes downloaded package code directly.

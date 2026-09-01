# Architecture Decisions

## IG3 uses an immutable execution-plan identity

Date: 2026-09-01

Context: A request such as `yaml@latest` cannot safely authorize a later mutable execution.

Decision: Resolve the top-level package to an exact version and bind package integrity, runner executable, argument array, options, working directory, metadata time, and pre-state hashes into one canonical `InstallExecutionPlan` SHA-256 hash.

Alternatives: Approve the original request string; compare only package/version immediately before execution.

Reason: The plan hash makes approval scope explicit and detects changes between analysis, approval, and future execution.

Trade-offs: This does not pin the full transitive dependency graph and adds precondition checks.

Revisit If: A lockfile preview can reliably bind the complete dependency graph before approval.

## Every real local install execution requires Ask

Date: 2026-09-01

Context: Package risk may be low while installation still changes project state or executes code.

Decision: Install Guard execution upgrades Allow to one-time Ask with `local_install_execution`. Deny remains Deny. Unresolved execution evidence also becomes Deny.

Alternatives: Treat explicit CLI invocation as sufficient authority; auto-run low-risk packages.

Reason: Local dependency and file changes are a consequence boundary distinct from package reputation.

Trade-offs: Adds one approval interaction for every controlled execution preview.

Revisit If: The product later adds a separately accepted, tightly scoped persistent allowance model.

## Real process execution was separately approval-gated

Date: 2026-09-01

Context: IG3 foundation can be tested without installing or executing third-party packages.

Decision: Planning, approval, audit, result, and verification contracts were implemented with fake runners first. After explicit approval on 2026-09-01, connect a controlled POSIX runner and `apg install` CLI. Do not perform a real package installation acceptance test without another explicit approval.

Alternatives: Add and manually exercise the runner in the same change.

Reason: Process execution introduces credential, filesystem, lifecycle-script, cancellation, output, and rollback risks that deserve an isolated review.

Trade-offs: Automated validation continues to use only fake executables. A separately approved isolated `yaml@2.9.0` npm acceptance subsequently completed with lifecycle scripts disabled, exact lockfile integrity verified, and the audit hash chain valid; this does not authorize or validate real npx execution.

Revisit If: Isolated real npm acceptance exposes incompatibilities or a Windows runner is required.

## Approved artifact integrity is verified after npm installation

Date: 2026-09-01

Context: An exact version alone does not prove that the artifact observed after installation matches the artifact approved from registry metadata.

Decision: Bind the registry SHA-512 integrity into the execution-plan hash and require the resulting npm lockfile entry to contain both the exact version and approved integrity. A mismatch is `verification_failed` even when npm exits zero.

Alternatives: Verify only version; trust npm exit status; pre-download and independently install a local tarball.

Reason: This detects version-preserving artifact substitution without changing manifest semantics to a local tarball dependency.

Trade-offs: Verification is post-execution and therefore cannot prevent lifecycle code from running before a mismatch is detected.

Revisit If: A pre-execution, independently verified artifact staging design can preserve normal npm lockfile and manifest behavior.

## Credential-free public registry execution preview

Date: 2026-09-01

Context: npm configuration may contain registry tokens, certificates, proxy settings, or script-shell changes.

Decision: Authenticated registries are out of scope. Reject a project `.npmrc` by presence without reading it. A future runner must use controlled empty npm configuration, private HOME/cache paths, and an allowlisted environment.

Alternatives: Reuse the user's npm configuration; parse and selectively redact `.npmrc`.

Reason: Avoid implicit credential access and configuration-driven substitution.

Trade-offs: Private registries and projects requiring custom npm configuration are unsupported.

Revisit If: A separate credential-handling architecture is approved.

## Deterministic npx binary selection

Date: 2026-09-01

Context: An npx package can expose multiple binaries, and its executable code is a stronger consequence than installation alone.

Decision: Bind one binary name from registry metadata. Prefer the package basename; otherwise accept only a single declared binary. Reject ambiguity and the legacy `--ignore-existing` option.

Alternatives: Let npx infer a binary at execution time; accept arbitrary pass-through command arguments.

Reason: The approved command must identify the code entry point exactly.

Trade-offs: Some multi-binary packages are unsupported in v0.

Revisit If: The CLI adds an explicitly parsed and approved `--bin` option.

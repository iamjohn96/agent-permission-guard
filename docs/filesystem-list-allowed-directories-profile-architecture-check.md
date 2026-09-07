# Filesystem `list_allowed_directories` Exact Identity Architecture Check

Status: accepted by Jonny on 2026-09-07. The network-free implementation and pinned-package acceptance
checkpoint are committed and pushed at `8502e64`. The dedicated opt-in acceptance first failed closed on
wire-schema drift, then passed after binding the captured pinned-runtime draft-07 schema.

Date: 2026-09-07

## Decision summary

The first production MCP identity profile should cover only the Filesystem server tool
`list_allowed_directories`.

The profile can provide `adapter_action_exact` for the request because the reviewed tool has no action
parameters. Exactness binds the configured APG server label, tool name, profile identity, empty argument
set, and reviewed input-schema fingerprint. It does not bind the directories returned by the tool, prove
the upstream executable or publisher, or prove that the server's allowed-directory state is fixed.

Activation must be explicit with a CLI profile ID. An explicitly selected profile is fail-closed for its
covered tool: missing tools, schema drift, unexpected arguments, request metadata, or projection failure
must block before upstream `tools/call`. The profile must not change the risk or policy decision, grant an
Allow result, or affect other tools.

Recommended built-in profile ID:

```text
filesystem.list-allowed-directories.v1
```

The ID intentionally avoids `official`, `verified`, or publisher wording. APG currently knows only the
configured server boundary, not the identity of the launched binary.

## Why this tool is the first profile

The pinned `@modelcontextprotocol/server-filesystem@2026.7.10` source registers
`list_allowed_directories` with an empty input schema and a read-only annotation. The handler returns the
server's current allowed directories. This gives APG a narrow way to validate real profile activation,
schema drift handling, zero-field exact identity, approval display, and portable receipts without putting
file contents or request paths into identity evidence.

This is still a privacy-relevant read. The result can disclose absolute local paths to the MCP client or
model. Read-only does not mean consequence-free, and the annotation is not trusted policy evidence.

Reviewed upstream references:

- https://github.com/modelcontextprotocol/servers/blob/2026.7.10/src/filesystem/index.ts
- https://github.com/modelcontextprotocol/servers/blob/main/src/filesystem/README.md

## Claim boundary

When the profile succeeds, APG may claim:

- this request entered the APG MCP gateway
- the user explicitly activated profile `filesystem.list-allowed-directories.v1`
- the requested operation was exactly `list_allowed_directories`
- arguments were absent or an empty plain object
- no unknown argument, MCP request `_meta`, or task metadata was accepted
- the startup-observed input schema matched the reviewed profile fingerprint
- policy evaluation, approval when required, dispatch, and receipts used the same immutable request

APG must not claim:

- that the process is the official Filesystem server or was published by the MCP project
- that the configured command, package, binary, or dependency graph was authenticated
- that the server implementation still behaves like the reviewed source
- that the returned directory list is public, constant, complete, or safe to disclose
- that the returned directories were part of the approved request identity
- that the server cannot read or write those directories through another tool
- that MCP Roots cannot change the server's allowed-directory state
- that direct MCP connections which bypass APG are protected
- that a portable unsigned receipt authenticates its issuer

The exact claim is therefore **exact zero-parameter adapter action identity**, not executable provenance,
state identity, result identity, or effect containment.

## Product and execution boundary

### In scope

- one APG-shipped, immutable profile definition
- zero-field complete-profile support in the common identity machinery
- explicit CLI activation with `--identity-profile filesystem.list-allowed-directories.v1`
- profile lookup before any upstream process launch
- post-connect startup preflight against the upstream `tools/list` snapshot
- exact-required behavior only for `list_allowed_directories` while the profile is active
- existing Dashboard and receipt 1.1 identity presentation
- network-free synthetic and fixture tests
- one separately approved real compatibility test against the already pinned package version

### Out of scope

- policy-schema changes or user-authored profiles
- automatic profile selection from tool name, command text, schema, annotations, or server metadata
- changing the configured server ID from `local-upstream`
- executable, package publisher, lockfile, signature, or build provenance
- output-path hashing, persistence, redaction, or result commitments
- new filesystem read/write permissions
- handling other Filesystem tools
- MCP Roots enforcement or allowed-directory pinning
- dependencies, database migrations, signing keys, external anchors, or cloud services

## Activation and trust model

### Explicit activation

The CLI should accept exactly one optional built-in profile selector before the upstream separator:

```text
apg proxy ... --identity-profile filesystem.list-allowed-directories.v1 -- <upstream-command>
```

The selector is configuration, not evidence that the upstream command is genuine. Automatic selection is
forbidden because a malicious or unrelated server can advertise the same tool name and schema.

An unknown, duplicate, malformed, or unavailable profile ID must fail argument/configuration validation
before the audit database is opened or the upstream process starts.

The current `local-upstream` server ID remains unchanged. Adding a user-selected server ID could alter
existing policy matching and receipt identity, so it needs a separate compatibility review.

### Required exactness

Selecting this profile means exact identity is required for its covered tool. A profile mismatch must not
silently downgrade and then pass through existing policy. Human approval cannot repair missing identity
evidence.

Calls to other tools exposed by the same server remain `structural_only` and follow existing policy. The
profile must never strengthen or weaken their decision.

No profile is selected by default, so existing users retain current structural identity and policy
behavior.

### Server provenance

Receipt evidence continues to say:

```text
server_provenance_assurance: configured_label_only
```

The profile manifest digest proves which APG profile contract was used. It does not prove source code,
package contents, command arguments, publisher identity, or the running binary.

## Exact profile contract

The profile is equivalent to:

```text
id: filesystem.list-allowed-directories.v1
version: 1
server_id: local-upstream
tool: list_allowed_directories
parameter_coverage: complete_action_parameters
fields: {}
omitted_categories: []
expected_input_schema_digest: <captured reviewed runtime digest>
```

Rules:

- omitted `arguments` and `arguments: {}` are the same empty parameter set
- any argument key is rejected, even if its value is `null` or `undefined`
- a non-plain arguments value is rejected
- request `_meta` and task metadata are rejected
- schema absence or mismatch is rejected
- profile failure is sanitized and must not echo input, schema, paths, or command data
- the safe-claim list is empty
- the action digest still binds profile ID/version/manifest digest, configured server ID, operation,
  parameter coverage, observed schema digest, and the empty typed claim list

The common profile constructor currently rejects zero fields. It may be relaxed only for
`complete_action_parameters`. A `declared_subset` profile must continue to define at least one safe field
and one omitted category; this prevents a no-information partial profile from looking useful.

## Schema evidence and pinned-version acceptance

The reviewed TypeScript source declares `inputSchema: {}`, but the MCP SDK may serialize the advertised
schema into a richer JSON Schema object. The production profile must bind the exact bounded
`tools/list` schema observed from the pinned runtime rather than guessing that wire representation from
source.

The first approved run observed this public wire schema from
`@modelcontextprotocol/server-filesystem@2026.7.10`:

```json
{"type":"object","properties":{},"$schema":"http://json-schema.org/draft-07/schema#"}
```

The prior network-free fixture used the SDK 2.x draft 2020-12 marker. Exact preflight rejected that drift
before downstream service or tool dispatch, after which the fixture was corrected to the captured pinned
runtime value. No matching rule was weakened.

Implementation proceeds in two approval-separated parts within this milestone:

1. Build the disabled/profile-selection path and all network-free tests using an explicit checked-in
   fixture.
2. After separate approval, launch the pinned package in an isolated temporary environment, capture only
   its public `tools/list` entry for `list_allowed_directories`, confirm the expected digest, and call only
   that read-only tool.

If the pinned runtime schema differs from the reviewed fixture, the profile stays unaccepted and the
implementation is corrected through normal review. The test must not follow `latest`.

The real acceptance can require npm registry access, package download, and external package execution if
the package is not already available. Those are independent approval boundaries and must be disclosed in
the approval request. No installation into this repository is permitted.

## Startup preflight and process lifetime

The gateway currently connects to the upstream and obtains one `tools/list` snapshot before serving the
downstream client. With the profile active, startup preflight must verify:

- the target tool exists exactly once
- its observed input schema is within APG resource limits
- its schema digest matches the profile
- the profile can produce exact identity for an empty synthetic request

If preflight fails, APG closes the upstream transport and exits before serving a client or forwarding any
tool call. Starting the server process is unavoidable before its tool schema is known, so preflight does
not claim zero startup side effects.

The accepted schema snapshot is bound for that upstream process lifetime. APG currently does not refresh
tools dynamically. Supporting upstream tool-list changes would require another review; it must not be
silently added here.

## State, permission, failure, and data review

### State

- built-in registry: immutable in-process data loaded at startup
- selected profile ID: parsed CLI configuration for one APG process
- schema evidence: bounded startup `tools/list` snapshot and digest held in memory
- request: one cloned, deeply frozen zero-argument snapshot
- receipts: existing audit events and receipt 1.1 evidence; no schema migration
- allowed directories: upstream server state, not copied into APG identity evidence

MCP Roots can replace the server's allowed directories during runtime. That changes the result of
`list_allowed_directories`, not the semantics of the zero-parameter request. APG must not represent the
receipt as proof of which directories were returned.

### Permission

- the user explicitly chooses whether to activate the built-in profile
- the profile does not grant tool permission or lower risk
- the existing policy independently returns Allow, Ask, or Deny
- a Deny remains Deny
- Ask still requires the existing one-time action-bound approval
- profile failure blocks the covered tool before dispatch
- direct MCP access outside APG remains outside protection

### Failure

| Failure | Required behavior |
| --- | --- |
| unknown profile ID | fail before database open and upstream start |
| target tool missing | close upstream and fail gateway startup |
| duplicate target tool | close upstream and fail gateway startup |
| schema absent, oversized, or mismatched | close upstream and fail gateway startup |
| unexpected arguments, `_meta`, or task | block before policy/upstream dispatch; no downgrade |
| identity invariant failure | no dispatch; sanitized failure |
| policy Deny | preserve existing deny path |
| approval denied, expired, or cancelled | preserve existing no-forward behavior |
| authorization audit failure | no dispatch |
| upstream call failure | existing failed outcome; no automatic retry |
| completion audit failure after dispatch | do not retry; retain incomplete/audit-failed semantics |
| result contains private paths | return to requesting MCP client as normal, but do not persist body in receipts |

Profile rejection should be represented as a controlled APG tool error rather than crashing the full
gateway after startup. Startup preflight failures remain startup errors.

### Data

```text
CLI profile ID
  -> built-in registry lookup
  -> start configured upstream
  -> bounded tools/list snapshot
  -> schema digest + preflight
  -> downstream zero-argument tools/call
  -> frozen empty request + exact identity
  -> unchanged policy/approval/audit
  -> one upstream tools/call
  -> raw result returned to MCP client
  -> bounded outcome metadata only in audit/receipt
```

No path, returned directory, command argument, environment value, token, `.env`, `.npmrc`, credential,
or raw result body is added to portable identity evidence.

## Policy, risk, and approval behavior

Identity assurance and authorization remain independent.

- upstream `readOnlyHint` is recorded/handled only under existing behavior and never authenticates safety
- the profile does not inject an Allow decision
- exact identity does not reduce the tool's risk score
- existing policy rules continue to decide Allow, Ask, or Deny
- when Ask applies, the Dashboard shows the exact profile and an empty parameter set before approval
- approval binds the exact action digest and cannot be reused for another profile, operation, or schema

Because the result may disclose local paths, users who want confirmation for this read should configure
Ask through the existing policy. Adding a mandatory Ask rule belongs to policy design, not the identity
profile.

## UX copy

When active and preflight succeeds:

```text
Identity profile: filesystem.list-allowed-directories.v1
Identity: Exact adapter action
Parameters: None
Server provenance: Configured label only
Result may disclose current allowed directory paths.
Protected only when this MCP call is routed through APG.
```

When the request violates the profile:

```text
Blocked: the request did not match the required reviewed identity profile.
No upstream tool call was made.
```

The UI must not display “Official server verified,” “safe,” “fixed permissions,” or “result verified.”

## Test strategy

All default tests remain network-free.

### Profile definition

- a zero-field `complete_action_parameters` profile is accepted
- a zero-field `declared_subset` profile remains rejected
- profile manifest and action digest are deterministic
- empty safe claims and complete coverage verify in receipt schema 1.1

### Request exactness

- omitted arguments and `{}` produce identical exact identity
- every added key prevents exact identity and blocks dispatch
- non-object arguments prevent exact identity
- `_meta` and task metadata prevent exact identity
- request mutation after preparation cannot affect dispatch

### Selection and preflight

- absent selector preserves existing structural behavior
- the known selector activates only the target tool
- unknown selector fails before database open and upstream spawn
- target tool missing or duplicated fails startup and closes the fake upstream
- matching fixture schema succeeds
- one schema mutation fails startup
- oversized or cyclic-like invalid schema input is bounded and rejected safely
- other tools remain structural and preserve existing policy behavior

### Authorization and audit

- exact identity never changes an existing Allow, Ask, or Deny decision
- Ask approval view contains profile evidence and no paths
- approval cannot be replayed after profile/schema/action changes
- authorization evidence failure remains pre-dispatch fail-closed
- completion audit failure never retries an already executed tool

### Privacy

- fixture paths and returned path samples do not enter authorization or outcome receipt identity evidence
- errors contain reason codes only
- raw tool result bodies remain absent from persisted receipt projection
- direct-bypass and configured-label-only limitations remain visible

### Separately approved real acceptance

- use `@modelcontextprotocol/server-filesystem@2026.7.10`, never `latest`
- use the dedicated `filesystem-identity-acceptance.test.ts`; do not run the broader official-server file
- use a newly created private temporary directory as the sole command-line allowed directory
- use an absolute discovered `npx` path through a fixed-package wrapper
- use a private temporary npm cache, prefix, HOME, TMPDIR, working directory, and empty user/global npm configs
- forward no credential, proxy, custom registry, Node option, or user configuration environment values
- disable lifecycle scripts, audit, funding messages, and update notifications
- do not read project files, user files, `.npmrc`, `.env`, tokens, keys, or credentials
- perform `tools/list`, verify the target schema, and invoke only `list_allowed_directories`
- assert exact profile evidence and a valid audit chain
- assert the result refers only to the disposable directory
- assert no disposable path is persisted in tool-call rows, receipt events, or the exported receipt
- remove the temporary workspace after the test; report whether npm cache cleanup is complete

The acceptance test does not prove package provenance or absence of package startup side effects.

## Risk register and minimization

| Risk | Preventive mitigation | Detection/recovery | Residual risk |
| --- | --- | --- | --- |
| malicious server mimics tool/schema | explicit activation; no automatic matching; configured-label-only claim | receipt exposes weak provenance | same-shape malicious implementation remains possible |
| profile changes policy outcome | identity and authorization remain separate; no risk reduction | Allow/Ask/Deny regression matrix | internal integration defect remains possible |
| silent downgrade bypasses exactness | active profile is exact-required for covered tool | blocked reason and no-forward test | availability loss on benign drift |
| schema drift | pinned version, exact startup digest, closed arguments | fail startup and require reviewed update | behavior can drift without schema change |
| private directory disclosure | no arguments/paths in identity; no raw result persistence; visible warning | receipt privacy fixtures | result still reaches the MCP client/model by design |
| dynamic MCP Roots change scope | exact claim excludes result and server state | visible limitation; process-lifetime snapshot | allowed scope can change between calls |
| startup has side effects | validate selector before spawn; preflight before serving/calling | close transport on failure | upstream startup code is not sandboxed |
| result mistaken for permission attestation | wording says current server-reported list only | UX and receipt assertions | downstream consumers may ignore limitation |
| profile used with arbitrary command | explicit configured-only provenance; no official claim | profile ID and server label in receipt | command identity is unverified |
| data leaks through errors/logs | bounded reason codes; no schema/value echo | secret/path fixtures and scanners | unforeseen runtime/library diagnostics |
| direct APG bypass | repeated routed-boundary warning | documentation and receipt label | APG cannot detect every direct connection |
| real acceptance executes package code | pinned package; isolated temp; separate approval | record version, command, result, cleanup | npm/package supply-chain and startup risk remain |

Release-blocking mitigations are explicit activation, target-only exact-required behavior, startup schema
preflight, closed zero-argument validation, no policy lowering, no result persistence, honest server
provenance, and network-free default tests.

## Alternatives considered

### Automatically recognize the Filesystem server

Rejected. Tool names, schemas, annotations, and command strings do not authenticate the process.

### Bind returned directories into the action receipt

Rejected for this milestone. Absolute paths are private and often low entropy, so even hashing them can
enable guessing. Results also occur after authorization and can change through MCP Roots.

### Add the first path-bearing read tool instead

Deferred. A path profile needs canonical path semantics, relative/absolute scope, symlink behavior,
working-root identity, path privacy, and result-effect review. The zero-parameter tool is a smaller trust
step.

### Treat read-only annotation as sufficient assurance

Rejected. Annotations are upstream-controlled hints. Identity exactness must come from APG's trusted
profile, and authorization remains policy-controlled.

### Add a user-selected server ID now

Deferred. It could change existing policy matching and receipt compatibility. The profile ID provides
the needed explicit assignment without that additional behavior change.

## Implementation boundary requiring approval

After this Architecture Check is accepted, the next implementation is limited to:

1. allow zero fields only for complete built-in profiles
2. add the immutable built-in registry entry
3. add and document the explicit `--identity-profile` CLI option
4. validate selector configuration before opening the database or starting the upstream
5. add startup tool/schema preflight and target-only exact-required enforcement
6. add Dashboard/error copy without claiming server provenance or output verification
7. add only network-free fixtures and tests
8. update repository state and architecture documentation

This approval would not authorize:

- starting or calling the real Filesystem MCP server
- npm registry access or package download
- dependency changes
- policy-schema or database migrations
- reading credentials or private configuration
- git commit, push, npm publish, or deployment

The separately approved real acceptance must state whether package execution, registry access, and
download are each expected before it runs.

## Acceptance criteria

- the production profile is never auto-selected
- an unknown profile fails before upstream start
- the active profile fails closed only for its covered tool
- empty and omitted arguments are exact; every extra field or request metadata is blocked
- startup schema drift blocks before downstream service or tool dispatch
- exact identity does not lower risk or change Allow/Ask/Deny
- other tools and no-profile use preserve existing behavior
- no returned path or raw result body enters portable evidence
- receipts say configured-label-only and never claim an official binary
- no default test uses the network or executes an external package
- no dependency, database migration, secret access, or external write is needed

## Decision checkpoint

Accepted decision: implement only the network-free scope above and keep the real pinned-package
acceptance as a separate explicit approval inside the same milestone.

Completed evidence: the approved pinned-package acceptance used a private temporary npm environment,
captured the public draft-07 target schema after an initial fail-closed mismatch, invoked only
`list_allowed_directories`, verified `adapter_action_exact` portable evidence and the local audit chain,
confirmed returned paths were not persisted, and removed the temporary workspace and cache.

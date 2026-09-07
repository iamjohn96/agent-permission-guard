# Exact MCP Identity Architecture Check

Status: accepted by Jonny on 2026-09-07. Shared identity machinery and synthetic network-free profiles
were committed and pushed at `f9da468`; no production MCP profile or production policy-semantic change
is included.

Date: 2026-09-07

## Decision summary

APG should add exact MCP action identity only through versioned, trusted adapter profiles. It must not
hash arbitrary MCP arguments, infer safety from an upstream JSON Schema, or allow an interceptor to
self-declare a stronger receipt assurance.

The recommended guarantee is **exact adapter action identity**, not exact wire bytes and not complete
downstream effects. APG may issue that guarantee only when a reviewed profile binds every
behavior-determining request field into a typed canonical projection and confirms that no unknown or
unbound behavior-determining field exists. Unknown tools remain `structural_only`.

This architecture deliberately leaves signing, server-binary provenance, secret commitments, user-defined
projection languages, and external anchors out of scope.

## Problem

ER1 portable MCP receipts currently bind the configured server ID and tool name. They omit arbitrary
arguments because those values can contain tokens, message bodies, personal data, private paths, or other
secrets. The resulting `structural_only` label is honest, but it cannot prove that the parameters approved
were the parameters APG dispatched.

The unsafe shortcut is to redact arbitrary input and hash what remains. Key-name redaction is lossy and
can miss positional, nested, mislabeled, or encoded secrets. Hashing a secret or low-entropy sensitive
value can also enable offline guessing. A digest of a redacted object proves only the redacted object, not
the omitted value.

Exact identity also requires a time-of-check/time-of-use guarantee. Today APG clones and freezes
`params.arguments` for policy evaluation, but the gateway forwards the original `request.params` object.
An exact design must dispatch the same immutable snapshot that produced the identity.

## Required claims and non-claims

When the exact profile succeeds, APG may claim:

- the call entered the named APG MCP boundary
- APG selected the named trusted identity profile and version
- all behavior-determining request fields defined by that profile were type-checked and bound
- the safe canonical action projection produced the recorded digest
- the exact immutable request snapshot associated with that projection was forwarded once
- the decision, one-time approval when required, and receipt refer to the same action identity

APG must still not claim:

- that the configured server label authenticates a server binary, publisher, or organization
- that upstream self-reported server metadata or input schema is trusted provenance
- that credentials, principals, or accounts were verified unless a later identity architecture does so
- that an MCP server or child process was sandboxed
- that all downstream filesystem, network, or external-system effects were observed
- that direct calls which bypass APG were protected
- that an unsigned receipt authenticates its issuer

## Exactness vocabulary

Exactness must describe both the canonicalization result and its coverage. A digest can be exact for an
incomplete projection, so those concepts cannot be collapsed into one label.

Recommended receipt identity levels:

| Identity assurance | Meaning |
| --- | --- |
| `structural_only` | binds adapter, configured server ID, and operation only |
| `adapter_scoped` | binds a reviewed safe subset, but one or more behavior-determining fields are unbound or unknown |
| `adapter_action_exact` | binds every behavior-determining request field recognized by a trusted profile |
| `execution_plan_exact` | binds a separately validated immutable execution plan, as Install Guard does |

Every projected identity also records a coverage classification:

| Coverage | Meaning |
| --- | --- |
| `none` | no parameter field is bound |
| `declared_subset` | named safe claims are bound, but the action is not complete |
| `complete_action_parameters` | every behavior-determining parameter is bound; transport-only fields are absent or proven non-semantic by the profile |

`adapter_action_exact` is valid only with `complete_action_parameters`. If an omitted credential can
select the account, tenant, target, permissions, or behavior, exact identity is not available.

The phrase "exact MCP identity" therefore means exactness within the APG adapter's reviewed semantic
model. It does not mean byte-for-byte identity, server provenance, or complete effect identity.

## Trust model

### Trusted inputs

- the immutable request snapshot created at the APG gateway boundary
- APG's locally loaded and validated policy
- APG-shipped identity profile code and its fixed profile manifest
- APG canonicalization and receipt code

### Untrusted inputs

- MCP client arguments
- upstream tool names, annotations, descriptions, server metadata, and JSON Schema
- field names that merely resemble public or secret data
- policy-authored arbitrary selectors or transforms
- assurance values supplied by a generic interceptor
- receipt fields presented back to the verifier

The upstream input schema may be recorded as a bounded observation and compared with a profile's
expected schema fingerprint. It must not decide which fields are safe to disclose or which fields are
behavior-determining.

## Proposed architecture

```text
MCP tools/call
  -> clone and deep-freeze one complete request snapshot
  -> trusted Identity Authority selects a built-in profile
  -> profile validates types, keys, limits, and semantic coverage
  -> typed safe projection + profile evidence
  -> policy and risk evaluation
  -> audit begin + Authorization Receipt
  -> one-time approval over the same safe projection when required
  -> dispatch reconstructed only from the frozen snapshot
  -> observed result + Outcome Receipt
```

### 1. Prepared request snapshot

The gateway creates one `PreparedToolCall` containing:

- configured server ID
- tool name
- cloned and deeply frozen arguments
- bounded observed tool-schema digest, when available
- the trusted identity result

The gateway must reconstruct the upstream `tools/call` payload from this snapshot. It must not forward
the original mutable request object. Arrays keep semantic order; object keys use APG canonical ordering.
The snapshot is created once, before policy evaluation, and is the only dispatch source.

### 2. Identity Authority

A centralized `IdentityAuthority` owns profile selection and assurance assignment. Policy evaluators and
generic interceptors may consume an identity result, but cannot create an exact-assurance result.

The authority is responsible for:

- matching an explicit trusted profile assignment to configured server ID and tool name
- checking profile ID, profile version, and expected operation
- invoking the pure profile on the immutable snapshot
- enforcing input and output resource limits
- rejecting unknown keys, invalid types, lossy normalization, and profile/schema mismatch
- returning a runtime-authenticated result that the approval and receipt paths share

A TypeScript type alone is not a security boundary. Exact assurance should be represented by an opaque
runtime value created only by the authority, and the audit recorder must validate its invariants before
recording it. The current caller-controlled `ReceiptContext.identityAssurance` must not be able to elevate
generic input to `adapter_action_exact`.

### 3. Built-in versioned profiles

The first release supports only reviewed APG-shipped profiles. A profile is identified by a stable ID and
integer version and contains code, not user-authored field expressions.

Each profile declares:

- configured operation(s) it supports
- accepted top-level and nested keys
- required and optional types
- which fields determine action behavior
- canonical normalization for each field
- which safe labels and values may be disclosed to the approval UI and receipt
- whether any field is transport-only and why it cannot affect target or behavior
- maximum string, array, map, and nesting sizes
- optional expected upstream schema fingerprint

Profiles must use closed typed constructors such as tagged public string, enum, integer, boolean, ordered
list, and explicitly scoped resource reference. They must not return arbitrary argument objects.

User-defined profiles are deferred. A selector language would itself become a data-loss and policy-bypass
surface and needs a separate architecture review.

### 4. Identity result

Conceptually, a successful result contains:

```text
profile:
  id
  version
  profile_manifest_digest
server:
  configured_id
  provenance_assurance: configured_label_only
operation
projection:
  format
  safe_claims
  digest
coverage:
  parameter_coverage
  behavior_fields_complete
  omitted_categories
  observed_schema_digest?
```

The projection digest binds tagged types, profile identity, configured server ID, operation, and safe
canonical claims. Type tags prevent values such as string `"1"`, integer `1`, and boolean `true` from
colliding. Profile ID/version and profile manifest digest prevent cross-profile substitution. The
manifest digest identifies the declared profile contract; it does not attest to source code or a binary.

`omitted_categories` uses profile-defined public labels only. It must not copy arbitrary input paths,
field names, values, or value hashes into portable evidence.

### 5. Secret and private-data boundary

The initial exact profile contract does not support secret commitments. Specifically:

- no raw secret is included
- no unkeyed or publicly salted secret hash is included
- no general redaction output is used as identity material
- no environment variable, `.env`, `.npmrc`, token, key, cookie, or credential file is read
- no absolute home path is exported
- a credential-bearing argument that can change principal, scope, target, or behavior prevents exact
  assurance

Tools are best suited to exact profiles when credentials are managed outside call arguments and the call
contains a small typed action description. A future selective-disclosure or keyed-commitment design is a
separate cryptographic and key-custody decision.

The existing `redactForAudit` remains a bounded display/audit safeguard. It is not evidence that arbitrary
arguments are safe, complete, or exact.

### 6. Policy assignment and enforcement

Profile selection must be explicit in validated local policy or an equally trusted APG configuration. A
conceptual rule may select a built-in profile and optionally require its assurance:

```text
server + tool -> built-in profile ID/version
require_identity_assurance -> adapter_action_exact
```

The exact syntax and policy schema change belong to implementation review. Local policy may require a
stronger identity but may not redefine profile field safety or weaken a built-in safety rule.

Default compatibility behavior:

- no assigned profile: preserve `structural_only` and existing policy behavior
- profile produces a reviewed partial projection: `adapter_scoped`
- exact profile succeeds: `adapter_action_exact`
- profile fails and exactness is not required: fall back visibly to `structural_only`, never partial exact
- profile fails and exactness is required: Deny; human approval cannot repair missing identity evidence

The Dashboard must show the profile and coverage before approval. It must never show a green "Exact"
state when the result is partial, downgraded, unknown, or based only on upstream schema.

### 7. Approval identity

The approval prompt and Authorization Receipt use the same immutable identity result. Exact-profile
approval displays only profile-approved safe claims, the configured server/tool, profile version, coverage,
and limitations. It does not display the general redacted arguments object as the authoritative identity.

Approval remains one-time and action-bound. A changed behavior field produces a different digest and a
new approval. A profile change, version change, schema mismatch, unknown field, or downgrade also requires
fresh evaluation and cannot reuse an existing approval.

### 8. Receipt compatibility

The richer identity should use receipt schema `1.1` while continuing to verify existing `1.0` receipts.
A version-1.1 verifier accepts both explicitly supported variants; an older verifier safely rejects 1.1
rather than interpreting unknown exactness semantics.

Version 1.1 should add a strict identity evidence object rather than overload `intentDigest`:

- profile ID/version and profile manifest digest
- server provenance assurance
- parameter coverage
- safe disclosure claims or a bounded safe summary
- omitted public categories
- observed schema digest when used only as drift evidence

No SQLite schema migration is expected. New receipt-finalization event details can carry the additive
evidence, but implementation must stop for a separate migration Architecture Check if that assumption
fails.

Existing version-1.0 MCP receipts remain `structural_only`; they must not be retroactively upgraded.

## State and data flow

- Profile registry: immutable APG code/data loaded at process start
- Profile assignment: validated local policy/configuration
- Request data: cloned and frozen in memory for one call
- Safe projection: immutable in memory; bounded evidence persisted with authorization events
- Raw arguments: continue through the gateway only as needed for the routed call; never enter portable
  identity evidence by default
- Receipt export: read-only database projection, no network, no secret lookup
- Verifier: offline, strict version and resource limits, no profile code execution from receipt input

The verifier validates recorded profile evidence and receipt digests. It must never dynamically load a
profile named by an untrusted receipt.

## Failure model

| Failure | Runtime behavior | Evidence behavior |
| --- | --- | --- |
| unknown tool/profile | existing policy may proceed | `structural_only` |
| profile ID/version unavailable | Deny if exact required; otherwise visible downgrade | record reason code, no exact claim |
| unexpected field or type | same as profile failure | no ignored-field exactness |
| input/schema exceeds limits | fail profile without echoing input | bounded reason code only |
| observed schema mismatch | Deny if exact required; otherwise visible downgrade | bind observed mismatch status, not schema text |
| projection throws | fail closed for required exactness | sanitized error code, no raw value |
| assurance invariant fails | no dispatch | pre-dispatch audit failure |
| authorization evidence write fails | no dispatch | existing failed-pre-dispatch semantics |
| request snapshot cannot reconstruct | no dispatch | explicit precondition failure |
| request mutation attempted | no dispatch | identity mismatch/tamper reason |
| post-dispatch audit failure | do not retry action | existing incomplete/audit-failed semantics |

There is no automatic retry after profile or identity failure, because a retry with downgraded assurance
could bypass a policy requirement.

## Observability and UX

Every approval and receipt view should show:

- Protected through APG MCP gateway
- configured server ID and tool name
- Identity: Exact adapter action / Safe subset / Structure only
- profile ID and version when present
- safe action summary and parameter coverage
- server provenance: Configured label only
- Direct MCP connections and other bypasses are not protected
- Downstream server and child effects are not fully observed

Suggested failure copy:

> APG could not establish exact action identity because the tool input did not match a reviewed profile.
> This call was not treated as exact.

When policy requires exact identity:

> Blocked: exact action identity is required, but APG could not bind every behavior-determining parameter.

## Alternatives considered

### Hash every redacted argument

Rejected. Redaction is incomplete and lossy, omitted values remain unbound, and sensitive hashes can be
guessable.

### Trust MCP JSON Schema annotations

Rejected. Schema and annotations are upstream-controlled, can be stale or malicious, and do not reliably
identify secrets or behavior semantics.

### Let users define arbitrary projection paths

Deferred. It is flexible but lets configuration accidentally disclose secrets or ignore action-relevant
fields while claiming exactness.

### Bind raw arguments only in the local database

Rejected for this milestone. It increases secret retention and still does not create privacy-safe portable
evidence.

### Add a keyed or zero-knowledge secret commitment now

Deferred. It introduces key custody, verifier trust, rotation, guessing-resistance, and cryptographic
review requirements before the non-secret identity model is proven.

### Built-in trusted profiles with explicit assignment

Recommended. It creates a small reviewable trust base, preserves structural fallback for unknown tools,
and makes exact claims opt-in and testable.

## Security test strategy

### Canonical identity

- equivalent semantic input produces identical bytes and digest
- each bound-field mutation changes the digest
- string/number/boolean/null and absent/present values cannot collide
- object key order is irrelevant; array order changes identity unless the profile declares set semantics
- Unicode normalization is explicit and collision-tested; no implicit case folding
- profile ID, version, profile manifest digest, server ID, and operation mutations change identity
- normalization never resolves files, follows symlinks, reads environment state, or uses a network

### Completeness and downgrade

- unknown top-level and nested fields prevent exact assurance
- optional absent versus present values follow explicit profile semantics
- schema/profile drift prevents exact assurance
- profile exceptions and resource-limit failures cannot produce exact assurance
- a required-exact policy denies instead of falling back
- a non-required policy records a visible structural downgrade
- an untrusted interceptor cannot construct or persist exact assurance

### Privacy

- raw and encoded token, password, authorization, cookie, private path, message-body, and personal-data
  fixtures do not appear in receipts, approval views, errors, logs, or projection digests as unsupported
  low-entropy hashes
- changing an intentionally omitted secret does not change a partial digest, and the receipt explicitly
  reports that coverage is not exact
- arbitrary field names are not copied into omitted-category output
- projection output passes both an allowlist validator and a forbidden-content scanner as defense in depth

### Approval-to-dispatch binding

- gateway dispatches only the frozen prepared snapshot, never original request params
- mutation after preparation cannot change the forwarded call
- changed profile, schema digest, or projection after approval invalidates the authorization
- approval cannot be replayed for another action, server, operation, profile, or digest
- cancellation before dispatch preserves no-forward behavior
- audit authorization failure remains fail closed

### Receipt and compatibility

- existing schema-1.0 receipts continue to verify as originally labeled
- schema-1.0 evidence cannot be relabeled as `adapter_action_exact`
- schema-1.1 unknown fields, malformed coverage, and invalid exact/coverage combinations fail verification
- older verifiers reject schema 1.1 safely
- cross-profile, cross-server, cross-operation, and cross-action substitution fail
- tests remain network-free and do not invoke real MCP servers or external services

## Risk register and mitigations

| Risk | Mitigation | Residual risk |
| --- | --- | --- |
| profile omits a behavior field | closed schemas, reject unknown keys, completeness tests, exact opt-in only | reviewer can misunderstand tool semantics |
| profile leaks private data | typed allowlist constructors, no arbitrary output, forbidden fixtures/scanner | safe metadata can still be identifying |
| normalization collision | tagged canonical values, minimal normalization, adversarial vectors | implementation bugs remain possible |
| schema or server drift | observed schema digest and versioned profile mismatch handling | a malicious server can preserve schema while changing behavior |
| server identity spoofing | label guarantee as configured-only; do not claim binary provenance | same label may launch different code |
| approval/dispatch mismatch | one immutable snapshot and dispatch reconstruction | compromised APG process remains out of scope |
| assurance spoof by internal caller | centralized authority, opaque runtime result, recorder invariant checks | in-process compromise remains out of scope |
| secret-bearing tools cannot be exact | explicit partial/structural label; require external credential design later | fewer tools qualify initially |
| approval fatigue after downgrade | exactness requirement is policy-selectable, not global | users may accept structural calls without reading limitations |
| direct MCP bypass | repeat routed-boundary warning in receipt and UI | APG cannot detect every bypass |
| downstream effects exceed tool semantics | preserve unobserved-effects warning; later sandbox/adapter verification | action identity is not effect containment |
| receipt schema fragmentation | one minor-version union and golden compatibility fixtures | long-term migration complexity grows |

Release-blocking mitigations are: immutable snapshot dispatch, centralized assurance authority, unknown-field
rejection, privacy allowlist, honest coverage labeling, schema-1.0 compatibility, and required-exact
fail-closed behavior.

## Implementation boundary requiring next approval

The accepted first implementation is limited to the common identity machinery and controlled test
profiles:

- immutable `PreparedToolCall` dispatch path
- centralized `IdentityAuthority`
- built-in profile interface and closed projection constructors
- exact/partial/structural invariants
- receipt schema 1.1 compatibility without database migration
- approval projection plumbing
- fully synthetic, network-free test profiles and fixtures
- documentation and Dashboard labels

It should not yet ship a production profile for GitHub, filesystem, email, browser, database, or another
third-party MCP server. Each production profile needs its own small review of tool semantics, sensitive
fields, and consequence boundary before activation.

Separate approval remains required for:

- production MCP identity profiles
- runtime policy-schema or production enforcement semantic changes
- any database migration or dependency change
- secret commitments or credential/principal identity
- server executable provenance, code signing, or attestation
- signing keys, Keychain/Secure Enclave, external anchors, or cloud services

## Acceptance criteria

- Exact assurance can originate only from the trusted identity authority.
- The forwarded arguments are reconstructed from the exact frozen snapshot used for identity.
- Unknown or behavior-relevant omitted fields make exact assurance impossible.
- No arbitrary argument, raw secret, sensitive hash, private path, or upstream description enters the
  portable identity projection.
- Approval and receipts use the same profile result and make coverage visible.
- Exact-required policy failure is Deny, not Ask or silent downgrade.
- Existing generic MCP calls retain structural behavior unless a profile is explicitly assigned.
- Existing receipt schema 1.0 remains verifiable and is never upgraded retroactively.
- No database migration, dependency, network request, secret access, or external write is needed.

## Decision checkpoint

Accepted decision: built-in, explicitly assigned, versioned identity profiles are the only path to
`adapter_action_exact`. The first implementation contains shared machinery and synthetic test profiles
only. Unknown and production tools remain structural until their individual profiles pass a focused
privacy and semantic review.

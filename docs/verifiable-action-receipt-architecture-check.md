# Verifiable Action Receipt Architecture Check

Status: ER0 approved; ER1 portable unsigned evidence implemented locally. No signing key, database
migration, or external anchor is approved by this document.

Date: 2026-09-07

## Objective

Extend APG's existing exact-action approval and hash-linked audit evidence into a portable action receipt
without claiming that APG observes or contains effects outside its interception boundary.

The product goal is:

> Make AI-agent actions enforceable before execution—and verifiable afterward.

The receipt must cover allowed, approval-gated, denied, expired, cancelled, failed, and incomplete actions.
It must never imply that an unobserved direct command or downstream side effect was protected by APG.

## Product position

APG remains an action authorization and evidence layer. It does not become:

- a credential vault or agent identity provider
- a general endpoint detection and response product
- a confidential-compute or runtime-attestation platform
- a cloud audit service
- an OS sandbox

APG's narrow differentiator is the combination of:

1. an explicit enforcement adapter
2. a canonical action or immutable execution-plan identity
3. deterministic policy and risk evaluation outside the model
4. one-time human approval where required
5. bounded result observation and verification
6. portable evidence that states exactly what APG did and did not establish

## Existing foundation

The current implementation already provides:

- a redacted request hash for MCP calls
- an immutable Install Guard `planHash`
- exact top-level package/version/integrity, executable, arguments, working directory, and pre-state
  identity for controlled installs
- policy decision, matched rule, reason codes, and risk evidence
- one-time approval lifecycle events
- bounded execution and verification summaries
- a global SHA-256 event chain using `previous_hash` and `event_hash`

This foundation detects accidental corruption and selective edits that do not recompute the chain. It is
not independent proof against an actor who can rewrite the database and recompute every hash. No current
APG claim should describe the local hash chain alone as third-party-verifiable cryptographic proof.

## Claim boundary

### APG may claim

- APG evaluated the represented action through the named adapter.
- The recorded decision followed the identified policy evidence.
- A one-time local approval was requested and resolved as recorded.
- The action identity did or did not match its approved plan at APG's precondition checks.
- APG dispatched the represented action when an execution-start record exists.
- APG observed the represented process result and bounded postcondition verification when an outcome
  record exists.
- The receipt is internally consistent at its declared assurance level.

### APG must not claim

- The action was protected if it bypassed an APG adapter.
- Every child process, filesystem effect, network request, or external-system mutation was observed.
- A local dashboard approval identifies a particular human unless a separate identity provider proves it.
- A successful process result proves the action had no harmful side effects.
- A recovery reference guarantees rollback.
- A software signature proves the exact APG source or runtime was trustworthy.
- A local hash chain cannot be rewritten by an attacker with complete database and process control.

## Threat model

### In scope

- accidental or partial audit-record modification
- receipt truncation, field deletion, field replacement, and cross-action substitution
- action mutation between approval and dispatch
- policy ambiguity caused by recording only a schema version or rule name
- replay of one approval for another action
- confusion between authorization evidence and execution-result evidence
- crash or audit-storage failure between dispatch and terminal outcome
- disclosure of sensitive arguments through exported evidence
- verifier confusion across receipt types or schema versions
- signing-key rotation and revoked-key interpretation at future signed levels

### Out of scope for the initial receipt architecture

- compromised operating-system kernel, root account, or APG process
- proof of exact APG source-to-runtime correspondence
- containment of lifecycle scripts, npx code, MCP servers, or their child effects
- discovery of direct commands that never enter an APG adapter
- independent wall-clock accuracy without a trusted timestamp or external anchor
- hosted organization identity, RBAC, or cloud retention
- automatic rollback of arbitrary local or external side effects

## Receipt family

One action produces up to two separately verifiable records.

### Authorization Receipt

Finalized before dispatch. It records:

- canonical redacted intent identity
- adapter and coverage boundary
- exact policy content digest and policy schema version
- evaluator identity
- risk decision and explanation
- approval requirement and resolution
- immutable execution-plan hash when applicable
- precondition result

If the required authorization record cannot be durably finalized, APG fails closed and does not dispatch.
A denied, expired, or cancelled action has an Authorization Receipt and no Outcome Receipt.

### Outcome Receipt

Finalized after dispatch. It records:

- the Authorization Receipt digest it extends
- execution-start evidence
- bounded observed result
- bounded postcondition verification
- terminal status
- recovery capability and optional reference
- unobserved-effect statement

An Outcome Receipt proves what APG recorded about its own dispatch and observations. It does not prove
complete containment or complete downstream effect coverage.

## Assurance levels

Every exported receipt must declare one of these values. The UI and CLI must use the matching label.

| Level | Product label | Guarantee | Permitted wording |
|---|---|---|---|
| `linked_local` | Local Integrity Receipt | Hash-linked local evidence only | "Local chain verified" |
| `portable_unsigned` | Portable Evidence Receipt | Deterministic self-contained evidence; no issuer authentication | "Receipt structure and digests verified" |
| `signed_local` | Signed Action Receipt | Trusted key signed the exact typed payload bytes | "Signature verified for trusted issuer key" |
| `anchored` | Anchored Action Receipt | Signed receipt or batch root has an independently verifiable inclusion/consistency proof | "Signature and anchor verified" |

`Cryptographic Execution Receipt` is reserved for `signed_local` or `anchored`. APG must not apply that
label to the current local hash chain or to `portable_unsigned` exports.

## Logical receipt schema

The schema below is conceptual. Exact JSON field names and limits require approval with ER1.

```text
schema:
  name
  major_version
  minor_version
receipt:
  id
  type: authorization | outcome
  issued_at
  assurance_level
action:
  id
  adapter
  adapter_version
  operation
  identity_assurance: structural_only | adapter_scoped | execution_plan_exact
  intent_digest
  intent_disclosure
  execution_plan_hash?
coverage:
  routed_through_apg
  boundary
  observed
  not_observed
policy:
  schema_version
  content_digest
  matched_rule_id?
  evaluator_name
  evaluator_version
decision:
  base
  effective
  reason_codes
  risk_score
  risk_band
approval:
  required
  request_id?
  outcome?
  requested_at?
  decided_at?
  expires_at?
  principal_assurance
execution:
  authorization_receipt_digest?
  started_at?
  terminal_status?
  completed_at?
  observed_result?
  verification?
recovery:
  capability: none | manual | bounded_automatic
  reference?
chain:
  chain_id
  first_sequence
  last_sequence
  previous_hash
  terminal_hash
issuer:
  software_name
  software_version
  build_identity_assurance
  key_id?
limitations:
  direct_bypass_unprotected
  unobserved_effects
  clock_assurance
```

All arrays have deterministic ordering rules or retain a documented semantic order. Unknown major
versions fail verification. Unknown minor fields may be ignored only after the signed or digested payload
bytes have been verified.

## Canonicalization and envelope

The existing APG canonical JSON implementation remains valid for the current database chain, but it must
not be silently relabeled as RFC 8785 compliant without conformance tests.

Recommended evolution:

1. ER1 freezes `apg-canonical-json-v1` with cross-platform golden byte fixtures.
2. Exported payloads use UTF-8, reject duplicate keys, reject non-finite numbers, and impose strict size,
   depth, string, and collection limits.
3. A future signed receipt uses a DSSE-style envelope so the signature binds the exact payload bytes and
   authenticated payload type, avoiding signature verification over reparsed JSON semantics.
4. The payload type is fixed, for example
   `application/vnd.jonnylab.apg.action-receipt.v1+json`.
5. Verifiers accept an explicit algorithm allowlist and trust policy. A `key_id` is only a lookup hint,
   never proof that a key is trusted.

RFC 8785 JSON Canonicalization Scheme, DSSE, and the in-toto statement/envelope separation are design
references, not claims of current conformance.

## Policy identity

The policy YAML field `version: 1` identifies the schema, not the exact policy that made a decision.

For each new action, APG should:

1. parse and validate the policy
2. convert the validated policy object into the versioned canonical representation
3. compute `policy.content_digest`
4. pass that digest with the decision into the audit recorder
5. include both the schema version and content digest in the Authorization Receipt

The receipt must not include an absolute policy path. A user-facing source label may include only an
explicit safe name or basename. Policy contents are not exported by default.

## Actor and approver identity

Current APG approval proves possession of the local dashboard capability; it does not prove a person's
identity. The schema therefore uses an assurance value rather than a free-form human name:

- `local_dashboard_session`
- `local_cli_session`
- `external_identity_verified` reserved for a separately approved identity integration
- `unknown`

Current APG must not emit `external_identity_verified`. Adding accounts, SSO, certificates, or remote
approval identity is outside ER1 and requires a separate security/privacy architecture.

## Privacy and disclosure

Receipt generation follows redaction-before-digest for exported intent evidence.

- Never export raw secrets, authorization headers, tokens, `.env`, `.npmrc`, or complete sensitive tool
  arguments.
- Do not publish an unsalted hash of a secret or other low-entropy sensitive value; it can enable offline
  guessing.
- A digest of the redacted representation proves only that representation, not the removed secret value.
- Store byte counts, categories, and bounded verification facts instead of stdout/stderr.
- Absolute home-directory paths are local-only by default. Portable receipts use a scoped label and a
  separately hashed canonical resource identity only when the value is safe.
- External anchoring, if ever approved, submits only a signed receipt digest or batch root and minimal
  inclusion metadata, never the receipt payload by default.
- Receipt export is explicit. No automatic cloud upload or telemetry is introduced.

A future selective-disclosure commitment needs a separately reviewed construction. ER1 must not invent a
custom commitment scheme.

## Durable lifecycle and failure semantics

Recommended state sequence:

```text
evaluated
  -> approval_pending?
  -> authorization_terminal
  -> authorization_receipt_finalized
  -> execution_start_recorded
  -> dispatch
  -> observed_result
  -> outcome_receipt_finalized
```

Rules:

- Required authorization evidence is committed before dispatch. Failure is fail-closed.
- `execution_start_recorded` is committed before process spawn or upstream forwarding.
- A terminal Outcome Receipt is never fabricated from an absent observation.
- If an execution-start record has no terminal record, receipt projection reports `incomplete` and does
  not guess whether dispatch or an external effect completed.
- Automatic startup mutation to `outcome_unknown_after_interruption` is deferred until APG has an
  exclusive-writer/session-ownership mechanism; otherwise one process could misclassify another active
  process that shares the database.
- A post-dispatch audit failure returns `audit_failed`, never retries the action, and leaves the action
  visibly incomplete.
- Recovery cannot retroactively determine arbitrary external effects.
- Export verification distinguishes invalid, incomplete, unsigned, signed-untrusted, and fully verified
  outcomes.

This is a journaled evidence model, not a transaction around external side effects.

## Signing-provider boundary

No signing key is created in ER0 or ER1.

A future `ReceiptSigner` interface must separate:

- payload construction
- signing operation
- public-key and key-ID lookup
- trust policy
- key rotation and revocation evidence
- optional timestamp or external inclusion proof

The algorithm is not selected by untrusted receipt data. The verifier's trust configuration chooses the
allowed key and algorithm. Software keys, macOS Keychain/Secure Enclave integration, hardware-backed
keys, and keyless/OIDC signing have different guarantees and require separate approval.

A signature proves control of the signing key. Without runtime attestation, it does not prove that the
expected APG source or uncompromised APG binary produced the payload.

## Anchoring boundary

External transparency is deferred.

If revisited, APG should batch receipt digests into a Merkle root and anchor only the root. This reduces
payload disclosure and external requests. Enforcement remains local and must not wait for an external
anchor. Offline roots queue locally and receive an `unanchored` status until inclusion and consistency
proofs are verified.

Using a public transparency service, hosted identity, or recurring paid resource is a new external-service
and privacy decision. It requires explicit approval and a retention/deletion analysis.

## Storage, API, and UX boundary

- SQLite remains the local audit source for ER1.
- The native app never reads SQLite directly.
- Receipt projection uses an APG CLI command or authenticated localhost API added under a separate
  approved implementation scope.
- A portable receipt is written only to a user-selected path.
- Default receipt output contains no raw stdout/stderr or secrets.
- Direct npm/npx, shell, browser, and API actions outside an adapter remain absent from receipts.
- Every receipt view displays its assurance level and coverage limitation before a green success label.

Proposed future CLI shape:

```text
apg receipt export <action-id> [--audit-db <audit.sqlite>] --output <path>
apg receipt verify <path>
```

ER1 implements only these unsigned commands. Trust-key selection remains outside the approved scope.

## Backward compatibility and migration

ER1 should avoid a database migration if additive audit-event details can carry policy digest, evaluator
identity, coverage, and receipt-schema data for new actions.

Historical actions lack required evidence and must export, if supported, as `legacy_incomplete`. APG must
not synthesize policy digests, actor identity, timestamps, signatures, or stronger assurance after the
fact.

If ER1 evidence cannot be projected reliably from existing tables and additive events, stop and propose a
separate migration Architecture Check. Do not overload existing columns with changed semantics.

## Risk register and mitigations

| Risk | Impact | Required mitigation | Residual risk |
|---|---|---|---|
| Product overlap with OneCLI or endpoint tools | weak differentiation | position APG around exact adapter action identity and portable evidence, not vault/EDR breadth | competitors can add similar receipts |
| Cryptographic overclaim | trust loss | assurance-level vocabulary; reserve cryptographic wording for signed/anchored levels | users may still misunderstand marketing shorthand |
| Direct-path bypass | false protection belief | `routed_through_apg`, boundary text, and direct-bypass warning in every receipt/UI | APG cannot discover all bypasses |
| Complete-effect overclaim | unsafe conclusions | separate dispatch/observed result from unobserved effects; never claim containment | downstream effects remain unknown |
| Rewritable local chain | forged history | label current chain local-only; later trusted signature and optional anchor | compromised signer can forge future receipts |
| Signing-key compromise | false issuer evidence | key IDs, explicit trust store, rotation/revocation records, no automatic key generation | past signatures remain dependent on key custody evidence |
| Policy ambiguity | unverifiable decision | digest exact validated policy content plus schema/evaluator identity | verifier still must decide whether policy was appropriate |
| Generic MCP identity/privacy conflict | weak action binding or secret leakage | expose `structural_only`; require adapter-safe typed projection before claiming exact parameter identity | unknown tools remain structural-only |
| Weak approver identity | false human attribution | assurance enum; no human name claim without verified identity integration | local capability can be used by another same-user process |
| Sensitive argument leakage | privacy/security incident | redaction before export; strict safe projection; no low-entropy secret hashes | structured metadata may still be identifying |
| Post-execution audit failure | side effect without terminal evidence | durable pre-dispatch record, no retry, incomplete status, startup recovery marker | final external effect cannot always be reconstructed |
| Crash between start record and dispatch | false possible-execution inference | status means "dispatch may have occurred" unless positive observation exists | ambiguity is unavoidable at crash boundary |
| Schema/type confusion | verifier accepts altered meaning | typed envelope, major version rejection, strict parser, golden fixtures | implementation bugs remain possible |
| Algorithm confusion | signature bypass | verifier-selected allowlist; untrusted payload cannot choose trust | trust-store compromise remains out of scope |
| Anchor privacy/cost/availability | data disclosure or blocked local work | digest-only opt-in batching; local enforcement never depends on anchor | timing and volume metadata may leak |
| Historical evidence upgrade | misleading retroactive trust | export legacy data as incomplete and unsigned | old actions cannot gain missing evidence |
| Rollback illusion | unsafe recovery assumptions | capability enum and bounded reference; explicit no-guarantee statement | manual recovery may still fail |
| Database migration | persistent-data risk | ER1 additive events first; separate gate if migration becomes necessary | event projection can be more complex |

## Risk treatment priority and release gates

ER1 must treat the following as release-blocking rather than follow-up work:

1. **Authorization durability:** a required Authorization Receipt is durably committed before dispatch,
   and failure to commit prevents execution.
2. **Identity binding:** the receipt digest binds the exact validated policy object used for evaluation,
   action identity, adapter, approval resolution, and immutable execution plan where applicable.
3. **Honest incompleteness:** a crash, missing terminal event, or post-dispatch audit failure can produce
   only an incomplete or unknown outcome, never a synthesized success.
4. **Privacy-safe export:** a denylist test and an allowlisted projection prevent raw arguments, output,
   credentials, private paths, and low-entropy secret digests from entering portable evidence.
5. **Verifier independence:** verification works offline from exported bytes and rejects field mutation,
   cross-action substitution, unknown major versions, malformed encodings, and excess resource use.
6. **Claim accuracy:** UI, CLI, documentation, and fixtures call ER1 `portable_unsigned`; none use signed,
   attested, tamper-proof, or cryptographic-execution wording.
7. **Boundary visibility:** every successful verification still shows that direct bypasses and unobserved
   downstream effects remain outside APG coverage.

For generic MCP tools, gate 2 means a truthful `structural_only` identity until the adapter has a reviewed
safe projection. ER1 must not hash or export arbitrary parameter values merely to claim exact identity.

Signing, external anchoring, verified human identity, and stronger runtime assurance reduce different
risks, but they cannot compensate for a failure in these seven controls. They remain later defense-in-depth
layers rather than ER1 release blockers.

## Alternatives

### A. Rename the current audit chain as cryptographic receipts

Rejected. It is fast but overstates resistance to a database owner who can recompute the chain.

### B. ER1 portable unsigned evidence first

Recommended. It establishes schema, policy identity, lifecycle semantics, privacy, export, and verification
before introducing key custody. It has useful local and support value while keeping claims narrow.

### C. Add local signing immediately

Deferred. It mixes receipt semantics with cross-platform key storage, trust distribution, rotation, and
revocation. Those decisions deserve a separate architecture gate.

### D. Start with a public transparency service

Rejected for the initial milestone. It introduces external writes, metadata disclosure, retention,
availability, identity, and possible recurring cost before local receipt semantics are proven.

## Recommended ER1 implementation scope

The approved ER1 implementation is limited to:

- versioned Authorization and Outcome Receipt schemas
- exact validated-policy digest for new actions
- explicit adapter, coverage, and limitation fields
- deterministic portable unsigned export from new audit records
- offline verifier for schema, digests, event range, receipt links, and completeness
- legacy-incomplete handling
- incomplete projection for started-without-terminal actions without unsafe automatic database mutation
- MCP and Install Guard fixtures covering Allow, Ask, Deny, expiry, cancellation, completion, execution
  error, verification failure, and audit failure
- no new dependency if the standard-library implementation remains small and reviewable
- no signing key, external anchor, cloud service, identity provider, telemetry, or native SQLite access

## ER1 acceptance criteria

- Equivalent inputs generate identical payload bytes on supported platforms.
- Any covered-field mutation fails verification.
- A receipt from another action cannot substitute for the referenced authorization or outcome.
- Authorization evidence is durable before an approved action can dispatch.
- Missing terminal evidence is reported as incomplete, never completed or denied.
- Policy schema version and exact policy content digest are distinct and verified.
- No exported fixture contains a secret, raw sensitive argument, full stdout/stderr, home-directory path,
  dashboard token, or complete dashboard URL.
- Every receipt states adapter coverage and unobserved effects.
- Direct npm/npx bypass remains explicitly outside APG coverage.
- Current audit-chain verification continues to pass.
- Existing default tests remain network-free.

## Test strategy

### Unit

- canonical byte golden vectors, Unicode, key ordering, arrays, number boundaries, and size/depth limits
- policy digest stability and semantic change detection
- redaction-before-digest and forbidden-field checks
- receipt schema strictness and major/minor version behavior
- authorization/outcome linking and cross-action substitution rejection
- mutation, truncation, reordering, and missing-event detection
- assurance-label and claim-language mapping
- legacy-incomplete projection

### Integration

- MCP Allow, Ask-approved, Ask-denied, expired, cancelled, upstream error, and audit failure
- Install Guard completed, timeout, cancellation, verification failure, and post-execution audit failure
- plan mutation after approval
- started-without-terminal projection after a controlled restart
- localhost API authorization if receipt projection is later exposed to the macOS app

### Negative security tests

- forged policy digest, rule ID, plan hash, outcome link, chain endpoint, and assurance level
- injected unknown major version and duplicate JSON keys
- receipt-provided algorithm or key ID attempting to override verifier trust
- sensitive low-entropy value appearing raw or as an unsupported digest
- direct npm/npx action incorrectly represented as protected

## Approval boundaries

Separate approval is required before:

- ER1 source or test implementation
- any database schema migration
- any dependency addition
- any signing-key creation, import, storage, rotation, or deletion
- macOS Keychain or Secure Enclave integration
- account, SSO, certificate, or approver-identity integration
- external transparency log or hosted verifier integration
- automatic receipt upload, telemetry, or recurring-cost resource
- public marketing that uses `cryptographic`, `attested`, or `tamper-proof`

## Decision checkpoint

Recommended decision: approve ER1 only as a portable unsigned evidence milestone. Validate the receipt
schema, lifecycle, privacy, and offline verifier before selecting a signing provider. Keep the public
product phrase "verifiable evidence" and expose the precise assurance level in technical UI and output.

## References

- RFC 8785, JSON Canonicalization Scheme: <https://www.rfc-editor.org/rfc/rfc8785.html>
- DSSE specification: <https://github.com/secure-systems-lab/dsse>
- in-toto Attestation Framework: <https://github.com/in-toto/attestation>
- Sigstore Rekor transparency model: <https://docs.sigstore.dev/logging/overview/>
- SLSA provenance model: <https://slsa.dev/spec/v1.2/>

# Graph Genesis v11 exact predeclared manifest architecture check

Status: approved for network-free implementation and verification only.
Baseline: `c97d2811ae65a0e2c0028ea2c9a8030bc14ef892`.

## Reason for the checkpoint

The v10 explicit `--save-prod` correction made npm's production dependency save type explicit, but the live v10
acceptance still reached a base-only root manifest and quarantined at the exact manifest predicate. APG owns the
fresh workspace before npm is allowed to start. The minimal correction is to create the declared exact intent before
the child exists, rather than to accept a base-only result or grant APG a second post-npm rewrite authority.

Both Graph Genesis workspace initializers now create the same exclusive `0600` canonical UTF-8 `package.json` bytes:

```json
{"dependencies":{"@modelcontextprotocol/server-filesystem":"2026.7.10"},"name":"apg-graph-genesis","private":true,"version":"0.0.0"}
```

The final newline is part of the canonical byte sequence. `package-lock.json` remains an npm-owned post-state
output and is not an initial protected file.

## Descriptor-bound workspace identity

Every protected initial file records its name, device, inode, `0600` mode, byte size and SHA-256 of bytes read from
its descriptor. The initial tree digest captures the workspace's file bytes and metadata; the separate descriptor
records are included in the workspace binding, which changes containment evidence, the hardened plan, execution
capsule and Dashboard execution envelope.

Before spawn, the workspace authority opens each protected path with macOS `O_NOFOLLOW` and verifies
path-to-descriptor identity, regular file/no-link/no-hardlink status, device, inode, mode, size and content digest
both before and after the read. The post-state authority repeats the same descriptor-bound check both before
inventory/semantic validation and again immediately before evidence issuance. A replacement, mode drift, in-place
mutation, or semantically identical JSON rewrite with different bytes is rejected fail-closed as protected-file
identity drift. A legacy base-only manifest is likewise rejected before it can be mistaken for a valid post-state.

This is a bounded user-space check, not a kernel-held immutable snapshot: a same-user actor could still perform a
transient rewrite outside the observed descriptor/read windows. Exclusive creation, expected-byte capture,
`O_NOFOLLOW`, descriptor checks at both boundaries, and fail-closed handling reduce that remaining TOCTOU surface
without adding a new mutation authority or relaxing the existing containment boundary.

The exact success path leaves the protected initial manifest byte-for-byte intact and adds only the exact expected
lockfile. The separate semantic post-state predicate remains in place as a defense in depth check.

## Unchanged controls and fresh-identity rule

The fixed npm sequence remains exactly:

```text
--save-exact --save-prod --maxsockets=4 --ignore-scripts
```

This checkpoint does not change the target, registry route, broker limits, no-queue/no-retry behavior, containment,
cleanup, terminal semantics, audit/receipt/DB schema, dependencies, approval logic or parser. Because the initial
workspace binding changes, prior containment evidence, plans, capsules and Dashboard approvals cannot authorize a
new run.

## Verification and remaining boundary

Network-free tests cover the two canonical initializers, exclusive mode and descriptor fields, identity propagation,
legacy base-only rejection, in-place mutation, replacement, same-semantic byte rewrite, post-state rejection and
the unchanged exact success path. Type checking, the focused Graph Genesis test set and the full regression must
remain free of real npm, Dashboard, DNS/HTTPS, product DB, candidate, evidence and quarantine access.

No live run is established by this checkpoint. A future acceptance requires review of this build, fresh private
inputs, an exact command authorization and a new Dashboard `Approve once` decision; it must not reuse v1-v10
workspace, containment, plan, approval, candidate, evidence or quarantine state.

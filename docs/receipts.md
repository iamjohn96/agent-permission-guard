# Portable Action Receipts

APG can export locally recorded actions as deterministic portable evidence. Version 1 receipts are
unsigned: they verify their structure, digests, Authorization/Outcome link, and embedded local event
proofs, but they do not authenticate an issuer or provide runtime attestation.

## Export

Find the action UUID in the local Dashboard under **Audit history**, then choose a new output path:

```sh
apg receipt export <action-id> \
  --audit-db ./.apg/audit.sqlite \
  --output ./action.apg-receipt.json
```

APG verifies the complete local audit chain before export. It creates the receipt with private file
permissions and refuses to overwrite an existing file. The audit database is opened read-only, and
export does not contact a network service.

SQLite may create or retain its normal `-wal` or `-shm` coordination sidecars while a WAL-mode database
is opened. Receipt export does not write audit rows, run migrations, or modify the main database bytes.

Historical actions without receipt finalization events export as `LEGACY_INCOMPLETE`. An authorized
action with an execution-start record but no terminal Outcome Receipt exports as `INCOMPLETE`; APG does
not guess whether an external effect completed.

## Verify offline

```sh
apg receipt verify ./action.apg-receipt.json
```

The verifier applies file-size and nesting limits, requires canonical encoding, rejects unknown major
versions, recomputes receipt and event hashes, and checks that an Outcome Receipt extends the exact
Authorization Receipt for the same action.

`VERIFIED_UNSIGNED` means only:

- the exported structure and digests are internally consistent
- the receipt event proofs match the represented action
- the exporter reported a valid local hash chain at export time

It does not mean:

- a trusted person or organization signed the receipt
- the local database owner could not rewrite and recompute the full chain
- actions that bypassed an APG adapter were protected
- every child process, network request, or downstream side effect was observed
- recovery or rollback is guaranteed

Do not describe version 1 exports as signed, attested, tamper-proof, or a Cryptographic Execution
Receipt. Those labels require a separately approved signing or anchoring design.

## Privacy boundary

Portable evidence uses an allowlisted projection. It does not contain raw stdout/stderr, complete MCP
arguments, dashboard credentials, policy contents, or absolute working-directory paths. Install Guard
receipts bind the exact approved execution plan by its existing plan hash and disclose only the exact
package identity needed to understand the action.

Generic MCP receipts currently use `structural_only` identity because APG cannot safely assume which
arbitrary tool parameters contain secrets. APG now has common support for explicitly registered,
versioned safe profiles, but ships no production MCP profile. Unknown and production tools therefore
remain structural today.

A profile-bearing receipt uses schema 1.1 and declares one of these identities:

- `adapter_scoped`: exact digest of a reviewed safe subset, with omitted behavior clearly declared
- `adapter_action_exact`: every behavior-determining parameter accepted and bound by the profile

Profile evidence includes only typed, allowlisted safe claims, the profile manifest digest, coverage, and
configured-label server assurance. It never treats general redaction output or an upstream JSON Schema as
proof that arguments are safe. Existing schema-1.0 receipts continue to verify without being upgraded.
A signature would not remove these privacy or coverage limitations.

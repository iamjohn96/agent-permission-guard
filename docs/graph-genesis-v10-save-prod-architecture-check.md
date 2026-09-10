# Graph Genesis v10 explicit save-prod architecture check

Status: approved for network-free implementation and verification only.
Baseline: `ae52adbd5a861834aed35df52bde827edb3740e0`.

## Supplied v9 finding and source-level cause

The approved v9 bounded diagnostic classified the quarantined root manifest without exposing its path, bytes or
metadata: base fields were exact, while the top-level keyset and dependencies container were missing or invalid and
the target specification was absent. The v9 terminal record, quarantine and all prior evidence remain unchanged.
This is not a successful action and does not establish a candidate.

For npm 11.16.0, `--package-lock-only` builds and saves a lock-only ideal tree. The baseline launch supplied no
explicit save type. In Arborist's explicit-add save path, the no-save-type branch updates only dependency containers
that already exist; the APG-created initial manifest intentionally has none. `--save-prod` fixes the npm save type to
the production dependency container. Together with existing `--save-exact`, its expected target declaration is the
exact version `2026.7.10`.

## Fixed launch and identity boundary

The launch is now exactly ordered:

```text
--package-lock-only --save-exact --save-prod --maxsockets=4 --ignore-scripts
```

`--save-prod` occurs once, immediately after `--save-exact` and before the existing one-time
`--maxsockets=4` cap. It does not change the target, registry route, containment, broker limits, no-queue/no-retry
behavior, lifecycle denial, or post-state expected manifest. It asks npm—not APG—to make the already permitted
owned-workspace manifest write explicit.

The canonical launch argument vector is part of the launch digest. The hardened plan reconstructs that exact vector;
its launch digest feeds the plan hash and private execution capsule, and the execution envelope binds both plan and
launch digest. Removing, changing, duplicating or moving `--save-prod` therefore fails pre-spawn validation or changes
the envelope hash, so no earlier Dashboard approval can authorize this launch.

## Alternatives rejected

- Accepting the dependencies-free manifest would break the direct correspondence between the manifest's declared
  intent and the exact one-target lock root required by the candidate compiler.
- Having APG rewrite `package.json` after npm would create a second mutation authority and require new race,
  durability, audit and recovery semantics. It is not a minimal correction.

No audit, receipt or DB schema, dependency, approval or parser behavior changes in this checkpoint.

## Verification and remaining boundary

Network-free tests require exact argument occurrence and position, plan rejection for missing/changed/duplicate/moved
variants, launch and envelope hash invalidation, and retention of both the exact-dependencies success manifest and
the `manifest_rejected` result for a base-only manifest. Build and all default tests must remain free of live npm,
Dashboard, DNS/HTTPS, product DB, candidate and evidence access.

The changed launch has not been run. A later acceptance requires review of this build, fresh private inputs, an exact
command authorization and a new Dashboard `Approve once` decision. It must not reuse v1-v9 approvals, paths,
workspaces, candidates, audit state or conclusions.

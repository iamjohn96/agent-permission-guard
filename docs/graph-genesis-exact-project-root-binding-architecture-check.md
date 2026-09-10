# Graph Genesis Exact Project Root Binding Architecture Check

Status: implemented network-free on 2026-09-10. Baseline: clean `804a7c5`.

## Decision

The fixed Graph Genesis npm launch now supplies exactly one `--prefix=<workspace>` option.
The npm project root, the protected `package.json`, the generated workspace-root
`package-lock.json`, and every post-state inspection therefore refer to the same directory.

The prior nested `--prefix=<workspace>/prefix` configuration selected a different npm
project root from the one bound into Graph Genesis workspace validation. It could leave
the workspace-root lockfile absent after an otherwise successful child exit. The correction
removes that nested directory from both initializers and from both post-state inventories.

## Closed launch and path predicate

The exact launch retains its fixed target, `--package-lock-only`, `--save-exact`,
`--save-prod`, `--maxsockets=4`, `--ignore-scripts`, registry route, cache/config/log
locations, containment profile, environment and working directory. It contains one prefix
argument at its fixed position, whose value is precisely the authenticated workspace root.

The plan authorities reconstruct that complete launch and compare it canonically. A missing,
changed, duplicate, reordered, or nested legacy prefix is rejected before dispatch. A newly
created `prefix/` top-level directory is also rejected by initial workspace revalidation and
post-state inventory checks. The workspace-root `package.json` remains a protected descriptor-
bound canonical manifest, and the required `package-lock.json` remains root-relative.

## Identity propagation and retained limits

The corrected launch naturally changes the launch digest. That digest remains bound into the
plan, execution capsule and Dashboard execution envelope, so prior approvals cannot match a
corrected plan. No audit, receipt, database, dependency, approval or parser schema changed.

The containment profile still grants filesystem access only to the authenticated workspace and
runtime tree. The inventories retain their rejection of `node_modules`, archives, symlinks,
unexpected files and executable regular files. No queue, retry, download, package install,
lifecycle execution or candidate materialization path was added.

## Network-free verification

The related Graph Genesis unit regression passed **107/107**. It uses synthetic workspaces,
inert child doubles and local fixtures only. The test set covers
the exact root prefix, each malformed prefix variant, nested-prefix inventory rejection,
protected-manifest binding, workspace-root lockfile validation, `node_modules` rejection and
launch/envelope digest divergence.

No npm child, Dashboard, DNS/HTTPS, live execution, product database, candidate, quarantine,
prior v1-v11 evidence, dependency change, commit or push was used.

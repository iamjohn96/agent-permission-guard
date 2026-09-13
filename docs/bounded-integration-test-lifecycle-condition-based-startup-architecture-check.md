# Bounded Integration Test Lifecycle & Condition-based Startup Architecture Check

## Status and authority

**Implemented test-only, network-free correction.** The user approved changes only to the stdio integration test,
the preflight-cancellation unit test, one new test fixture, this document, and `PROJECT_STATE.md`. The three
pre-existing V2 implementation/test work items and their prior V2 content are preserved; `PROJECT_STATE.md` is
intentionally extended under this approval. Production source, timeout/behavior/security semantics,
dependencies, schemas, live routes, real npm/public-network/DNS/HTTPS work, product DB, candidate/evidence/quarantine,
commit, and push are outside this authority.

## Observed test-lifecycle problem

Independent evidence showed inconsistent full-suite failures in unchanged stdio Dashboard announcement/state/policy
tests and the platform preflight-cancellation harness. A standalone exact Ask case could fail with Dashboard URL not
announced, so ordering alone was not sufficient to explain it. The prior helper created an announcement timeout
promise before `client.connect()` and observed it only later; a timeout rejection could therefore be handled after
connection awaits. Generic client and state-rotation paths also used independent wall-clock polling bounds, while the
preflight cancellation test repeatedly ran host-specific production preparation under a 20-second test cap.

This is a test-harness lifecycle diagnosis, not proof of a production Dashboard, preflight, or V2 defect. The
working hypothesis remains that test process startup/resource timing exposed lifecycle gaps; no product causation or
purely environmental explanation is claimed.

## Test-only design

`BoundedTestLifecycle` is a test fixture owner with one monotonic deadline per case. It:

- registers cleanup before `connect()` or fixture-child activity;
- attaches a promise rejection observer synchronously before awaiting connection work;
- aborts at the one deadline, reaps registered resources in reverse order, and makes close idempotent;
- exposes at most eight redacted `{ label, code }` diagnostics, never raw stderr, URL, token, path, or child output.

The Dashboard helper now owns client and stderr-listener cleanup before negotiation, observes dashboard readiness
before `connect()`, and uses a test-only 10-second condition deadline. One valid complete loopback tokenized
announcement establishes readiness. Malformed or additional announcements observed while draining that same bounded
readiness buffer before settlement, and stderr end/error before readiness, fail closed; later connection-lifetime
stderr is outside this test helper's observation window because it detaches on settlement/close. Diagnostics retain
only fixed codes. Its startup deadline is
disarmed only after both connection and announcement readiness while the owner retains cleanup responsibility.
Generic gateway connections likewise disarm their startup owner only after connection. State rotation shares one
25-second monotonic condition deadline inside a 30-second test cap rather than combining independent polling
timeouts.

The platform production-preflight cancellation loop is preserved through a fixed local subprocess fixture. One
compiled child per `runtime`, `workspace`, `containment`, `audit`, and `cleanup` boundary installs only its own
phase-local prototype spy, owns its own `AbortController`, executes the compiled preflight entry, completes its
normal production cleanup, and exits. The child sends its parent only a bounded closed projection of the existing
fail-closed report fields: status, execution/plan closure flags, cleanup outcome, three unattempted external checks,
and the cancellation failure code. No raw report, path, hash, child output, or shared `process.execArgv` mutation
crosses the boundary. The parent verifies that projection and terminal child exit before it can report `childClosed`.
The fixture receives an empty environment and does not attempt public DNS, registry, npm, or package execution.
Those five compiled-production cases retain the exact `darwin`/`arm64`/Node `v26.3.1` guard from the original
test. Generic lifecycle adversarial cases remain cross-platform. The child owner has a 20-second operation deadline;
each guarded Vitest case has a 25-second cap, leaving a bounded five-second cleanup margin. A deterministic fixture
test proves the operation deadline is smaller and that registered cleanup completes before a failed operation returns.

## Verification

- The initial red contract failed typecheck because the old inert fixture did not export a phase or accept a phase
  argument. A first green run then exposed a test-only completion diagnostic mismatch and after-hook replay of an
  expected cleanup error; both were corrected without changing production source.
- Direct local typecheck and build passed after the correction. The preflight lifecycle file passed 10/10 on the
  exact guarded host: the five original compiled phase boundaries plus immediate rejection observation, monotonic
  deadline, aggregate cleanup failure, no false `childClosed` result, and the teardown-margin/cleanup ordering test.
  There were no platform skips on this host; on other hosts only the five guarded production-phase cases skip.
- The stdio proxy file passed 28/28 under the JSON reporter. Earlier text-reporter runs emitted progress without a
  final visible summary, so the JSON result was used as the authoritative count; no test process remained afterward.
- The final one-worker network-free suite passed 480 tests with 3 skipped across 102 passing suites under the
  30-second test limit.

These results verify the revised test harness and its fixed local resources. They do not authorize or demonstrate
production behavior, real external effects, product DB access, candidate processing, or a live Dashboard run.

## Residual risks and rollback

Startup timing can still vary on a loaded host; bounded test deadlines convert it into owned abort/cleanup instead
of late unhandled promise paths, but do not establish host scheduling guarantees. The fixture verifies existing
compiled preflight cancellation boundaries, not a production success, live action, or external effect. Revert only
the five files authorized for this test-only change to roll it back; preserved V2 content remains outside this
correction. No external durable state was changed.

## Next decision

Do not extend this test-only work into production source, production timeout/behavior/security changes, or the
existing V2 dirty files. Any such work needs a new exact approval and independent architecture check.

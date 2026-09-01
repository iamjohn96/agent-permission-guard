# Local API Contract for Native Clients

Status: v1 local contract for the Agent Permission Guard macOS companion

## Discovery

Start the proxy with an explicit private state path:

```sh
apg proxy \
  --policy ./.apg/policy.yaml \
  --audit-db ./.apg/audit.sqlite \
  --dashboard-state ./.apg/dashboard.json \
  -- <trusted-upstream-command> [args...]
```

The state document has this shape:

```json
{
  "version": 1,
  "url": "http://127.0.0.1:47831/#token=REDACTED",
  "pid": 12345,
  "started_at": "2026-08-25T00:00:00.000Z",
  "instance_id": "8d9fbd52-5314-4ef7-a728-51c4fa1cb96e"
}
```

`instance_id` is a random, non-secret identity for one dashboard server lifetime. It is additive to state version 1 so existing URL readers can ignore it. A new native client must require it and match it against authenticated health before reporting Connected. PID and `started_at` are diagnostic only and must never authorize a connection because PIDs can be reused.

The native client must reject an unsupported version, a non-loopback URL, a missing token, an invalid PID, an invalid instance UUID, or a state file that is not private. On macOS it must use `lstat`, reject symlinks and non-regular files, require the current user's ownership, reject group/other permission bits, bound the file size before reading, and parse the complete document before use.

The URL must use `http`, host `127.0.0.1`, an explicit non-zero port, path `/`, no embedded username/password, no query, and exactly one `token` fragment field containing a base64url token. Unknown additive JSON fields may be ignored when `version` remains supported.

## Authentication and request rules

- Connect only to the exact `http://127.0.0.1:<port>` origin found in the state file.
- Send the fragment token as `Authorization: Bearer <token>`.
- Never send the token in a query parameter, request body, analytics event, crash report, or log.
- Native requests may omit the `Origin` header.
- If `Origin` is sent, the gateway accepts only the exact dashboard origin.
- The gateway requires the bearer token for every `/api/` route, including health.
- Do not follow redirects to another host or origin.
- A custom native-client header is not an identity or authorization mechanism and is not required in v1.

Browser clients continue to send the exact localhost `Origin`. A foreign origin is rejected even when it presents a valid token.

## Endpoints

### Health

`GET /api/health`

```json
{
  "status": "ok",
  "api_version": 1,
  "instance_id": "8d9fbd52-5314-4ef7-a728-51c4fa1cb96e"
}
```

The response contains no token, file path, command, PID, policy, audit data, or user data. The client must compare `instance_id` with the state document before accepting the connection.

### Pending approvals

`GET /api/approvals`

Returns the same redacted pending approval representation used by the local browser dashboard.

Approval objects may include an additive `kind` field. `kind: "install"` identifies an Install Guard request; absence of the field retains the existing MCP tool-call meaning. Native clients must ignore unknown future fields. API version 1 is unchanged because this field is optional and backward-compatible.

### Decide once

`POST /api/approvals/<request-id>/approve`  
`POST /api/approvals/<request-id>/deny`

An approval can be consumed only once. A missing or already consumed request returns `404`; an expired request returns `409`.

### Recent audit and policy

`GET /api/audit?limit=<1-100>`  
`GET /api/policy`

The native v0.1 app may use audit for display and policy only to open the existing browser workflow. Native policy writes are deferred.

## Failure behavior

- `401`: discard the connection and reload state; never retry an old token indefinitely.
- `403`: reject the endpoint because the origin contract was violated.
- Connection refused or missing state: show Offline without weakening CLI enforcement.
- State replacement: cancel in-flight polling, clear the previous token, and reconnect from the new state.
- State removal: clear all connection data from memory.
- Health instance mismatch: clear the token, show Offline, and wait for a fresh state event.

## State rotation algorithm

1. Treat each observed state-file identity as a monotonically increasing in-memory connection generation.
2. On replacement or removal, invalidate the current generation and discard its token before processing another response.
3. Parse and validate the replacement into a new candidate without reusing any previous field.
4. Call authenticated health on the exact candidate origin with redirects disabled.
5. Promote the candidate to Connected only when API version and `instance_id` match.
6. Before applying any asynchronous response, verify that its generation is still current; otherwise discard it.
7. Never fall back to an earlier state after a replacement fails validation.

Closing or disconnecting the native app does not change enforcement. Pending Ask requests remain controlled by the CLI and resolve only through approval, denial, expiry, cancellation, or gateway shutdown.

## Persistence boundary

The native app must not read the audit SQLite database directly. SQLite schema, locking, migration, and redaction are internal APG details. The localhost API is the only supported native read/decision contract. The bearer token remains memory-only and must not enter logs, preferences, Keychain, crash reports, analytics, or notification payloads.

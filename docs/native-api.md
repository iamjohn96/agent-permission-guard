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
  "started_at": "2026-08-25T00:00:00.000Z"
}
```

The native client must reject an unsupported version, a non-loopback URL, a missing token, an invalid PID, or a state file that is not private. It should treat replacement of the file as a complete credential rotation and discard the previous token immediately.

## Authentication and request rules

- Connect only to the exact `http://127.0.0.1:<port>` origin found in the state file.
- Send the fragment token as `Authorization: Bearer <token>`.
- Never send the token in a query parameter, request body, analytics event, crash report, or log.
- Native requests may omit the `Origin` header.
- If `Origin` is sent, the gateway accepts only the exact dashboard origin.
- The gateway requires the bearer token for every `/api/` route, including health.
- Do not follow redirects to another host or origin.

Browser clients continue to send the exact localhost `Origin`. A foreign origin is rejected even when it presents a valid token.

## Endpoints

### Health

`GET /api/health`

```json
{
  "status": "ok",
  "api_version": 1
}
```

The response contains no token, file path, command, PID, policy, audit data, or user data.

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

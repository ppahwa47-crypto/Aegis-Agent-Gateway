# API

All protected requests use `Authorization: Bearer <credential>`. Tokens in URL parameters are never accepted. Browser-origin requests are disabled. Control-plane and MCP bodies are limited to 256 KiB. The gateway accepts one JSON-RPC request per POST; batches are unsupported.

| Method/path | Credential | Purpose |
|---|---|---|
| `POST /admin/grants` | Admin bearer | Issue an initial grant and agent JWT |
| `POST /v1/delegate` | Active agent JWT | Issue a child with inherited context and subset rights |
| `POST /v1/revoke` | Active agent JWT | Revoke self or an owned descendant |
| `POST /admin/revoke` | Admin bearer | Revoke any known grant |
| `GET /admin/audit` | Admin bearer | Export ordered chain records |
| `POST /mcp` | Active agent JWT | MCP initialization, discovery, ping, and tool calls |
| `GET /mcp` | None | Returns 405; server streaming is unsupported |
| `GET /healthz` | None | Process liveness |
| `GET /metrics` | None | Low-cardinality counters/histogram; restrict at a production edge |

## Issue a root grant

The trusted issuer asserts the user/tenant/task context. This API is not a public self-service login or OAuth flow.

```json
{
  "agent": "support-agent",
  "user": "alice",
  "tenant": "acme",
  "task": "support-review",
  "ttl_seconds": 300,
  "capabilities": [
    {"tool": "docs.read", "resource": "tenants/acme/projects/alpha/docs/welcome", "destination": ""},
    {"tool": "tickets.create", "resource": "tenants/acme/projects/alpha/tickets/incident", "destination": ""},
    {"tool": "exports.upload", "resource": "tenants/acme/projects/alpha/exports/report", "destination": "vault://acme/alpha"}
  ]
}
```

HTTP 201 returns `grant`, `access_token`, and `token_type`. Store the token outside source control. `client/provision.py` supplies the broader demo fixture, including the injection/confidential/secret documents.

## Initialize and call tools

Use `Content-Type: application/json` and `Accept: application/json, text/event-stream`. Subsequent requests can include `MCP-Protocol-Version: 2025-11-25`. The server is stateless and issues no `Mcp-Session-Id`; authorization is checked on every POST.

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2025-11-25",
    "capabilities": {},
    "clientInfo": {"name": "portfolio-demo", "version": "1.0.0"}
  }
}
```

Send `notifications/initialized` without `id` for HTTP 202. Discovery lists only tool types present in the caller's grant. A tool call requires a stable `Idempotency-Key` header of 8–100 ASCII letters/digits/underscores/hyphens:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "docs.read",
    "arguments": {"resource": "tenants/acme/projects/alpha/docs/welcome"}
  }
}
```

Return values contain MCP text content and `structuredContent`. Mutation results persist in the tool's Redis receipt. A same-key, same-payload retry returns that object; a changed payload or unknown pending outcome returns HTTP 409. A cached result does not bypass expiry, revocation, policy, or integrity checks.

| Tool | Required argument fields | Local effect |
|---|---|---|
| `docs.read` | `resource` | Read synthetic `welcome`, `injection`, `confidential`, or `secret` fixture |
| `tickets.create` | `resource`, `title`, `body` | Persist synthetic ticket in an authorized tenant/project namespace |
| `exports.upload` | `resource`, `destination`, `content` | Persist synthetic public report to the matching local vault |

Additional input fields are rejected. Resource IDs are exact, canonical lowercase paths. The deployment policy registers tenants `acme`/`bravo` and projects `alpha`/`beta`; a grant still needs each exact resource.

## Delegate and revoke

```json
{
  "agent": "reader-child",
  "ttl_seconds": 120,
  "capabilities": [
    {"tool": "docs.read", "resource": "tenants/acme/projects/alpha/docs/welcome", "destination": ""}
  ]
}
```

POST to `/v1/delegate` using the parent JWT. User, tenant, task, parent ID, and depth are assigned server-side. Requested expiry beyond the parent's expiry is rejected rather than silently widened or clamped.

```json
{"grant_id": "ID_FROM_ISSUE_RESPONSE"}
```

POST to `/v1/revoke` or `/admin/revoke`. HTTP 200 acknowledges the authoritative revocation update. Already-dispatched writes are not cancelled atomically; see the threat model.

## Policy decisions

OPA receives only the grant, extracted capability, and DLP booleans. It does not receive raw tool content. Decisions include `allow`, a stable `reason`, and `policy: "aegis/v1"`; missing/invalid policy responses fail closed. Audit records reference that policy identifier. Policy edits should include a reviewed version change and regression tests; the gateway rejects an unexpected policy identifier.

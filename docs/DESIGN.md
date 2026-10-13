# Design

## Authorization path

1. Reject browser origins. Validate the inbound token's fixed EdDSA header, signature, issuer, audience, subject, issue time, expiry, and grant binding.
2. Load the leaf and every ancestor from authoritative shared state. Reject expired/revoked nodes, cycles, depth inconsistencies, or an invalid attenuation edge. Never cache an active decision.
3. Validate the tool name and strict JSON input schema. Extract the canonical resource and optional destination.
4. Inspect inputs and request an OPA decision. Independently require the exact capability and enforce DLP in Go, so an accidentally permissive policy cannot expand issued rights.
5. Fetch authenticated tool discovery. Compare the complete supported descriptor with the reviewed registry. A mismatched or extended unsupported descriptor fails closed.
6. Recheck ancestry and atomically reserve the grant-scoped retry key. Reject a changed request or a pending/uncertain attempt.
7. Write an authorized-intent audit event before dispatch. Mint a separate audience-specific credential bound to this invocation, and call a statically configured backend with redirects disabled.
8. The backend validates its audience, invocation binding, ancestry, exact capability, and input data. Its own receipt reservation makes the synthetic persisted ticket/export operation idempotent.
9. Inspect the returned content. Persist the outcome audit and completed gateway receipt. Recheck ancestry before returning the result. A cached retry still traverses policy, integrity, audit, DLP, and revocation checks.

There is no user-controlled backend URL, DNS resolution of a requested export destination, redirect traversal, or inbound credential forwarding. The export destination selects only a reviewed local vault namespace.

## Delegation invariant

Let a grant be `G = (agent, user, tenant, task, capabilities, expiry, parent, depth)`.

For every child `C` of parent `P`:

```text
C.user = P.user
C.tenant = P.tenant
C.task = P.task
C.capabilities ⊆ P.capabilities
C.expiry ≤ P.expiry
C.parent = P.id
C.depth = P.depth + 1 ≤ 8
```

The agent name may change to identify a child workload. Capabilities are indivisible triples, so subsets compose transitively: every descendant capability was present in the root. Equal permissions are allowed; "only shrink" means no increase, not mandatory removal on every edge. Empty grants, wildcard resources, and arbitrary destinations cannot be issued.

The server fixes parent and inherited fields rather than accepting them from delegation callers. Authoritative ancestry is revalidated on use, so a descendant cannot retain access merely by possessing an unexpired token after an ancestor is revoked.

## Credential separation

| Credential | Holder | Audience / authority | Lifetime |
|---|---|---|---|
| Bootstrap admin bearer | Trusted harness/operator | Grant issuance and administrative revocation | Static local-development credential |
| Agent JWT | Scoped agent | `urn:aegis:gateway` | At most 300 seconds |
| Tool invocation JWT | Gateway-to-one-tool request | `urn:aegis:tool:<tool-name>` | At most ten seconds and never beyond grant expiry |
| Public Ed25519 key | All tool runtimes | Signature verification only | Until explicit rotation |
| Redis tool credential | One tool runtime | Read grants; own receipt namespace | Static local-development credential |
| PostgreSQL application credential | Gateway | SELECT/INSERT audit only | Static local-development credential |

Tool tokens contain no API-provider secret. They are minted independently, and never accept a caller-selected audience. The tool checks both arguments and retry-key binding so an intercepted invocation token cannot authorize a different operation. Tokens, authorization headers, and raw tool payloads are not audit fields or trace attributes.

## State and audit

Redis stores grant JSON under `grant:<id>`. Grants have a ten-minute TTL, exceeding the maximum valid descendant/token lifetime. Revocation preserves that TTL. Gateway and tool receipts are separate namespaces, use atomic Lua transitions, and remain durable for reconciliation and synthetic object storage.

PostgreSQL serializes chain appends with a transaction advisory lock. Each event hash is SHA-256 of `previous_hash + newline + canonical_event_JSON`. The event text preserves serialization bytes. The application role has only SELECT and INSERT permissions. Audit contains identities, exact resources/destinations, argument digests, decision/reason, policy version, and request key; it excludes raw argument/output content. Digests can still reveal low-entropy values through guessing.

The global chain lock favors clarity and correctness over maximum throughput. A larger deployment should consider per-tenant chains, external head anchoring, partition retention, and separate control-plane credentials.

## Failure behavior

| Failure | Behavior |
|---|---|
| Invalid/expired/revoked credential | HTTP 401; no tool dispatch |
| Permission, destination, data, or integrity denial | HTTP 403 |
| Unsupported schema/body/protocol | HTTP 400/415 |
| Changed or pending retry | HTTP 409 |
| OPA/audit/state failure | HTTP 503 or a fail-closed state-dependent authentication error |
| Backend timeout/invalid response | HTTP 502, outcome marked unknown; no automatic mutation replay |
| Output contains a supported secret | Result withheld; completed external side effects cannot be rolled back |

Tracing currently covers inbound HTTP requests. Prometheus counters and latency buckets have no tenant/user labels, limiting cardinality and identity exposure. OTLP is sent to an internal collector with a debug exporter; connect a retained tracing backend for operational use.

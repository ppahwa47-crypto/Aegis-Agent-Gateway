# Threat model

The model may make a malicious choice. The gateway must still reject a request outside the caller's capability and deployment boundary.

## Actors and trust

The agent and all retrieved document content are untrusted. An attacker can induce arbitrary supported tool requests, alter arguments, retry requests, attempt delegation, and use a stolen agent token until it expires or its ancestry is revoked.

The bootstrap administrator, issuer private key, reviewed registry/policies, Docker host, Redis, PostgreSQL, and gateway binary are trusted. The synthetic tool runtimes are trusted to enforce their adapters and shared-state checks. Tools receive no private signing key or admin credential. Their Redis accounts are restricted to reading grants and their own receipt namespace.

The trusted evaluation harness has an administrator credential. Its attack cases use scoped tokens; it is not an untrusted arbitrary-code sandbox. `client/agent.py` and the `agent` container have no administrator credential.

## Boundaries

| Attack | Enforcement point | Expected outcome |
|---|---|---|
| Document tells agent to export to an attacker | Exact destination capability + local-only vault adapter | Denied before dispatch |
| Cross-tenant or cross-project resource | Canonical resource syntax + exact tuple + OPA | Denied |
| Child asks for write rights absent from parent | Tuple subset and inherited context | Delegation denied |
| Grandparent revoked; leaf retries cached result | Live ancestor traversal before cache access | Denied |
| Agent token sent straight to a tool | Ed25519 verification and distinct tool audience | Unauthorized |
| Internal token reused with changed arguments/key | Digest and retry-key binding | Denied |
| Tool description/input schema changes | Pinned descriptor comparison before invocation | Denied |
| Secret in supported input or tool output | Deterministic nested-string scanner | Denied for supported patterns |
| Agent bypasses gateway using a tool port | Docker networks; no published tool ports | Connection fails |
| Agent attempts arbitrary internet egress | Internal agent network | Connection fails in the tested container deployment |
| Tool tries to issue grants | Directional Redis ACL and command restrictions | Redis rejects the write |
| Application tries to change audit history | Restricted PostgreSQL role + triggers | Database rejects mutation |
| OPA/Redis/audit unavailable | No successful authorization fallback | Request fails closed |

## Limits that matter

- This is a bearer-token system. A stolen, still-active agent token can exercise its issued rights. It is not proof-of-possession identity or an external user authentication system. The trusted issuer asserts the initiating user; production should bind it to a verified IdP subject.
- Native development mode exposes tools on loopback and does not restrict other host processes' egress. Network isolation claims apply to the Compose agent container and a trusted host.
- DLP covers the documented patterns, strings, and one base64 layer. It does not infer arbitrary confidential facts, track information flow, understand images/files, or reliably catch obfuscation, paraphrase, chunking, compression, encryption, or marker removal. Content labels are advisory detection inputs, not an unforgeable taint system.
- A descriptor pin detects discovery changes. It cannot attest that a compromised runtime's behavior matches its descriptor. A compromised tool can disclose data it already holds through its permitted channels. Runtime attestation and per-tenant tool processes are further work.
- There is a race between the final active-grant check and committing a side effect. Revocation is not a linearizable distributed cancellation protocol. Tool credentials last at most ten seconds; every tool checks ancestry and the gateway rechecks before releasing results. A write already executing may complete after revocation, and output blocking cannot undo a completed write.
- Pending receipts remain unresolved after an uncertain failure. They are not automatically replayed or deleted. Receipts persist without TTL in deployed Redis; retention/reconciliation needs operational tooling. AOF `appendfsync always` helps durability, but simultaneous infrastructure loss can still invalidate exactly-once assumptions. No global exactly-once claim is made.
- Audit hash chains reveal changes relative to a trusted earlier head. A database administrator can replace a chain or disable protections. Anchor the head outside the database to detect rollback or full-history replacement.
- HTTP and static bootstrap administration are for isolated local development. A production edge needs TLS, a proper OAuth/IdP flow, key rotation/KMS, workload identities/mTLS, quotas, admission controls, backup/recovery, and externally reviewed operational policy. Liveness `/healthz` does not certify dependency readiness.

These limits are interview discussion points and engineering boundaries. The project demonstrates enforceable controls for the stated attack model, rather than universal prevention of prompt injection.

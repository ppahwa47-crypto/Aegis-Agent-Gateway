# Demo and resume guide

Lead with the enforceable boundary: **"The agent can obey a malicious instruction and still cannot perform an unauthorized tool action."** Avoid describing this as a prompt that tells the model to behave safely.

## Five-minute demonstration

1. Show the architecture and the exact tuple for one project's document, ticket, and approved vault resource.
2. Run the evaluation. Point to the malicious document being read successfully, followed by the external upload and other-tenant ticket being denied.
3. Show a legitimate support ticket completing, and its same-key retry returning the identical ticket object.
4. Delegate read access to a child, then a grandchild. Show the child cannot delegate write access or another project's resource.
5. Revoke an ancestor and retry the grandchild's already-cached read. The request fails before the cached content is released.
6. Show the verified audit head, policy decision reason, measured timings, and separate container network checks.

The standalone `agent.py` demo makes the unsafe model choice explicit. Use `evaluate.py` to demonstrate all controls, including the administrator's revocation step. Explain which process is trusted and which holds only the scoped token.

## Resume bullets

Use measured numbers only from a run you can reproduce. Suitable wording after the observed local verification:

- Built a Go zero-trust gateway for MCP tool access with Ed25519 audience-bound credentials, OPA authorization, strict tool-schema integrity checks, and input/output data inspection.
- Implemented monotonic delegated permissions across eight levels, live ancestor revocation, and idempotent retry enforcement; validated cross-tenant isolation and escalation rejection with integration and randomized invariant tests.
- Created a Python adversarial evaluation harness with 28 passing synthetic scenarios and zero successful unauthorized actions in the defined corpus; added PostgreSQL audit chaining, Redis ACL isolation, OTLP tracing, and a Docker/CI deployment.

After running full Compose/CI yourself, you can add the measured deployed p95 overhead, explicit hardware/sample count, and verified network/persistence outcomes. Do not present the local in-memory latency as a production figure or the finite corpus as a universal security guarantee.

## Interview topics

Be ready to explain why exact permission tuples avoid Cartesian recombination; why a session ID is not identity; why backend credentials differ from caller credentials; why expiry alone does not handle ancestor revocation; and why retry reservations must survive an uncertain write.

Discuss the distributed revocation race, limits of regex DLP, trusted-tool assumptions, the audit chain's need for an external anchor, and the performance cost of synchronous audit and per-call discovery. These tradeoffs demonstrate engineering judgment.

## Work toward 2027

There is no guaranteed project that will distinguish every resume in 2027. This one can stand out through evidence and depth. The highest-value follow-up work is external OAuth/IdP integration, workload mTLS, an actual model adapter, a broader public attack corpus, concurrent revocation experiments, and a published benchmark with CI artifacts.

Add a short recorded demo, an architecture image rendered from the Mermaid diagram, a clear README, and a passing public Actions run. Keep the explanation focused on behavior and measurable controls rather than the number of frameworks used.

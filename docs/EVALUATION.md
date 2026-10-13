# Evaluation methodology

`client/evaluate.py` sends a deterministic corpus of adversarial and legitimate requests. It deliberately follows an instruction from the malicious retrieved document. A model is unnecessary for proving the enforcement boundary: the tool choice is already malicious, so the gateway must reject it independently of the model.

The corpus is synthetic, finite, and not a general prompt-injection benchmark. Successful blocking rates do not establish resistance to unseen DLP evasions or all attacker strategies.

## Metrics

| Metric | Definition |
|---|---|
| Unauthorized-action success rate | Attack/isolation cases returning any HTTP success ÷ attack/isolation cases |
| Legitimate task completion rate | Legitimate cases matching their expected HTTP response ÷ legitimate cases |
| False block rate | Legitimate cases failing their expectation ÷ legitimate cases |
| Cross-tenant isolation rate | Defined cross-tenant cases denied as expected ÷ cross-tenant cases |
| p95 gateway overhead | Nearest-rank p95 of server time before response headers minus cumulative downstream discovery/call HTTP duration |
| p95 client round trip | Nearest-rank p95 of wall-clock client request duration for fresh authorized reads |
| Revocation acknowledgement | Duration of the administrative revoke request |
| Observed revocation after acknowledgement | Time from revoke acknowledgement to a sequential rejected leaf retry |

The overhead excludes backend HTTP time and includes gateway credential construction, authorization, schema validation, OPA, Redis, audit, and result checks. Downstream HTTP timing includes response reading/decoding. The latency histogram covers all MCP requests, while the reported read benchmark uses fresh keys and excludes denied cases. It is not a throughput/load test.

Completion is case-level for a scripted workflow, not a measured success rate over probabilistic LLM runs. Revocation timing is one observation; it is not a worst-case bound, concurrency guarantee, or proof of distributed linearizability.

## Corpus

The 28 cases cover successful reads, retrieving an injected document, unauthorized external upload, cross-tenant tickets, cross-project reads, traversal, schema extension, unknown tools, raw/base64 secrets, synthetic SSN input, secret output, confidential read/write, approved exports, ticket retries, changed retries, valid nested delegation, child escalation, descendant revocation, cached retries after revocation, and reverse cross-tenant isolation.

The Go tests add token tampering/audience/expiry checks, downstream invocation binding, tool-description drift, dependency failures, malformed ancestry, fifty concurrent retry reservations, and 500 randomized nested attenuation trials. Fuzzing exercises malformed token parsing.

In Compose, six network probes attempt connections to the document/ticket/export servers, Redis, PostgreSQL, and an external IP from the `agents` network. A DNS failure or connection failure is recorded as blocked. These probes supplement the reviewed network topology; they do not enumerate every possible egress route.

## Reproduce

```sh
docker compose --profile verify run --build --rm verify
docker compose --profile demo run --rm demo
```

The default benchmark uses 50 reads. Override the demo command for a larger bounded sample:

```sh
docker compose --profile demo run --rm demo python /app/client/evaluate.py \
  --url http://gateway:8080 --admin-file /run/secrets/admin_token \
  --report /reports/evaluation.json --deployment compose --network-check --samples 200
```

`all_passed` requires every case and requested network probe to pass. Dependency/configuration failures fail the evaluation; they are not scored as successful security blocks. Each evaluation issues new short-lived grants, appends audit records, verifies the complete exported chain, and exits nonzero on a failed case.

Publish the raw report, stack mode, OS/hardware, sample count, commit SHA, and whether the run used real OPA/Redis/PostgreSQL. Keep local-memory timings separate from deployed timings. Preserve a trusted audit head outside the database when testing rollback protection.

## Additional experiments for a stronger portfolio

- Compare 1/4/8-deep delegation under increasing concurrency and report latency percentiles and errors.
- Stress revocation during writes; distinguish post-acknowledgement admission, result release, and already-running side effects.
- Expand the attack corpus with unseen obfuscation, marker stripping, and chunked exfiltration; report scanner failures alongside successes.
- Inject OPA, Redis, database, and backend outages; inspect unknown outcomes and demonstrate reconciliation rather than blind replay.
- Add a real model adapter, measure end-to-end task completion, and retain this deterministic corpus as the security regression suite.

These experiments are extensions, not results claimed by the checked-in local report.

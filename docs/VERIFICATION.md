# Verification record

Observed on **13 October 2026**, Windows/AMD64, using Go **1.27.2**, Python **3.13.7**, and OPA **1.9.0**. These are local results, not a deployed production benchmark.

| Check | Observed result |
|---|---|
| `go build ./cmd/aegis` | Passed |
| `go test ./...` | 45 tests/subtests passed; two real Redis/PostgreSQL tests skipped without their integration environment |
| `go vet ./...` | Passed |
| `opa test policies -v` | 9/9 passed using the real OPA executable |
| Token parser fuzz, five-second requested duration | Passed; approximately 1.64 million executions in the observed run |
| Python syntax checks | Passed for evaluation, provisioning, and agent clients |
| In-memory evaluation | 28/28 scenarios passed; audit chain verified |
| Live OPA + in-memory state/audit/tools | 28/28 scenarios passed; audit chain verified |
| Separate scoped agent demo | Retrieved injected instruction; attempted upload was denied |
| YAML and configuration inspection | Parsed all YAML; inspected 12 services, secret paths, internal networks, and published ports |
| Docker Compose runtime, Redis/PostgreSQL integration, and network probes | Not run here: Docker is unavailable |
| Local Go race detector | Not completed: installed MinGW compiler lacks 64-bit support |
| GitHub Actions | Configured, not executed/published from this workspace |

The [live-OPA report](evidence/local-opa-evaluation.json) records the final local evaluation. Fresh authorized reads used **50 samples**:

| Metric | Local live-OPA value |
|---|---:|
| Unauthorized-action success rate in the defined corpus | 0% |
| Legitimate case completion | 100% |
| False block rate in the defined corpus | 0% |
| Cross-tenant isolation in the defined cases | 100% |
| p95 gateway overhead | 3.205 ms |
| p95 client round trip | 29.831 ms |
| Revocation request acknowledgement | 11.407 ms |
| Sequential rejected retry observed after acknowledgement | 16.108 ms |

Timings are one uncontrolled local run. The machine was also running compilation/verification tasks; no load, hardware-normalized performance, or worst-case revocation claim is made. The initial pure in-memory run also passed, but its timings are not substituted for real OPA or persistence measurements.

To establish the remaining deployment evidence, run the Compose `verify` and `demo` profiles, publish the generated report/Actions artifacts, and update this record with the commit and environment. YAML inspection does not substitute for `docker compose config` or execution.

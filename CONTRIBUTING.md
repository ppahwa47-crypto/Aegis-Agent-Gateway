# Contributing

Use Go 1.24+ and Python 3.10+. Keep permission tuples exact and delegation monotonic. Never add an implicit production fallback when a dependency is unavailable.

Run `gofmt`, `go vet ./...`, `go test ./...`, `opa test policies -v`, and the relevant Python evaluation. Changes to credential, retry, or revocation semantics should include an adversarial regression case. Compose integration checks cover actual Redis/PostgreSQL behavior and should pass before a deployment change is considered verified.

Use synthetic secrets and data only. Do not commit `secrets`, `.local`, `.tools`, tokens, or raw production payloads. Policy/descriptor changes need explicit review and corresponding version/test updates.

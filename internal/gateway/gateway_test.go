package gateway_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aegis-agent/gateway/internal/audit"
	"github.com/aegis-agent/gateway/internal/gateway"
	"github.com/aegis-agent/gateway/internal/policy"
	"github.com/aegis-agent/gateway/internal/protocol"
	"github.com/aegis-agent/gateway/internal/registry"
	"github.com/aegis-agent/gateway/internal/security"
	"github.com/aegis-agent/gateway/internal/state"
	"github.com/aegis-agent/gateway/internal/toolserver"
)

const prefix = "tenants/acme/projects/alpha/"

type harness struct {
	key     ed25519.PrivateKey
	store   *state.Memory
	audit   *audit.Memory
	gateway *gateway.Gateway
	handler http.Handler
	grant   security.Grant
	token   string
	servers map[string]*httptest.Server
}

func setup(t *testing.T, drift bool) *harness {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(nil)
	store := state.NewMemory()
	sink := &audit.Memory{}
	servers := map[string]*httptest.Server{}
	backends := map[string]string{}
	for _, kind := range []string{"docs", "tickets", "exports"} {
		s, _ := toolserver.New(kind, pub, store)
		s.Drift = drift && kind == "docs"
		server := httptest.NewServer(s.Handler())
		t.Cleanup(server.Close)
		servers[s.Tool.Name] = server
		backends[s.Tool.Name] = server.URL + "/mcp"
	}
	g := security.Grant{ID: security.ID(), Agent: "support-agent", User: "alice", Tenant: "acme", Task: "review", Expires: time.Now().Add(4 * time.Minute).Unix(), Capabilities: []security.Capability{{Tool: "docs.read", Resource: prefix + "docs/welcome"}, {Tool: "docs.read", Resource: prefix + "docs/injection"}, {Tool: "docs.read", Resource: prefix + "docs/secret"}, {Tool: "docs.read", Resource: prefix + "docs/confidential"}, {Tool: "tickets.create", Resource: prefix + "tickets/incident"}, {Tool: "exports.upload", Resource: prefix + "exports/report", Destination: "vault://acme/alpha"}}}
	store.Create(context.Background(), g)
	gw := gateway.New(key, store, sink, policy.Local{}, strings.Repeat("a", 64), backends)
	return &harness{key, store, sink, gw, gw.Handler(), g, security.AccessToken(key, g), servers}
}
func request(h http.Handler, path, token, key string, payload any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(payload)
	r := httptest.NewRequest("POST", path, bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Idempotency-Key", key)
	r.Header.Set("Accept", "application/json, text/event-stream")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func call(h *harness, token, name, key string, args map[string]any) *httptest.ResponseRecorder {
	return request(h.handler, "/mcp", token, key, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": protocol.Call{Name: name, Arguments: args}})
}
func expect(t *testing.T, w *httptest.ResponseRecorder, status int, reason string) {
	t.Helper()
	if w.Code != status || (reason != "" && !strings.Contains(w.Body.String(), reason)) {
		t.Fatalf("wanted %d %s; got %d %s", status, reason, w.Code, w.Body.String())
	}
}

func TestAuthorizationAndDataMatrix(t *testing.T) {
	h := setup(t, false)
	cases := []struct {
		name, tool string
		args       map[string]any
		status     int
		reason     string
	}{
		{"legitimate", "docs.read", map[string]any{"resource": prefix + "docs/welcome"}, 200, ""},
		{"injection_is_data", "docs.read", map[string]any{"resource": prefix + "docs/injection"}, 200, "Ignore previous instructions"},
		{"cross_tenant", "docs.read", map[string]any{"resource": "tenants/bravo/projects/alpha/docs/welcome"}, 403, "capability_missing"},
		{"cross_project", "docs.read", map[string]any{"resource": "tenants/acme/projects/beta/docs/welcome"}, 403, "capability_missing"},
		{"external_egress", "exports.upload", map[string]any{"resource": prefix + "exports/report", "destination": "https://evil.example", "content": "public"}, 403, "capability_missing"},
		{"secret_input", "tickets.create", map[string]any{"resource": prefix + "tickets/incident", "title": "ticket", "body": "AKIA1234567890ABCDEF"}, 403, "secret_detected"},
		{"secret_output", "docs.read", map[string]any{"resource": prefix + "docs/secret"}, 403, "output_data_policy_denied"},
		{"confidential_read", "docs.read", map[string]any{"resource": prefix + "docs/confidential"}, 200, "CONFIDENTIAL"},
		{"confidential_write", "tickets.create", map[string]any{"resource": prefix + "tickets/incident", "title": "ticket", "body": "[CONFIDENTIAL] roadmap"}, 403, "confidential_write"},
		{"extra_schema_key", "docs.read", map[string]any{"resource": prefix + "docs/welcome", "destination": "evil"}, 400, "schema_rejected"},
		{"type_confusion", "docs.read", map[string]any{"resource": []any{prefix + "docs/welcome"}}, 400, "schema_rejected"},
		{"missing_argument", "docs.read", map[string]any{}, 400, "schema_rejected"},
		{"unknown_tool", "shell.exec", map[string]any{"command": "echo"}, 403, "unknown_tool"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { expect(t, call(h, h.token, c.tool, security.ID(), c.args), c.status, c.reason) })
	}
	if e := audit.Verify(h.audit.Records); e != nil {
		t.Fatal(e)
	}
	for _, r := range h.audit.Records {
		b, _ := json.Marshal(r.Event)
		if strings.Contains(string(b), "AKIA1234567890ABCDEF") {
			t.Fatal("audit leaked secret")
		}
	}
}
func TestIntegrityDriftDenied(t *testing.T) {
	h := setup(t, true)
	expect(t, call(h, h.token, "docs.read", security.ID(), map[string]any{"resource": prefix + "docs/welcome"}), 403, "tool_integrity_failed")
}

func TestSchemaDriftAndUnknownOutcomeRetry(t *testing.T) {
	for _, mode := range []string{"schema-drift", "backend-failure"} {
		t.Run(mode, func(t *testing.T) {
			h := setup(t, false)
			var invocations atomic.Int32
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req protocol.Request
				json.NewDecoder(r.Body).Decode(&req)
				if req.Method == "tools/list" {
					tool, _ := registry.Get("docs.read")
					if mode == "schema-drift" {
						tool.InputSchema["additionalProperties"] = true
					}
					protocol.Success(w, req.ID, map[string]any{"tools": []registry.Tool{tool}})
					return
				}
				invocations.Add(1)
				protocol.Fail(w, req.ID, 500, "uncertain_write")
			}))
			defer backend.Close()
			h.gateway.Backends["docs.read"] = backend.URL + "/mcp"
			key := security.ID()
			args := map[string]any{"resource": prefix + "docs/welcome"}
			if mode == "schema-drift" {
				expect(t, call(h, h.token, "docs.read", key, args), 403, "tool_integrity_failed")
				if invocations.Load() != 0 {
					t.Fatal("schema drift dispatched operation")
				}
			} else {
				expect(t, call(h, h.token, "docs.read", key, args), 502, "upstream_failed_outcome_unknown")
				expect(t, call(h, h.token, "docs.read", key, args), 409, "retry_conflict_or_pending")
				if invocations.Load() != 1 {
					t.Fatal("unknown operation was replayed")
				}
			}
		})
	}
}
func TestIdempotentWriteAndRevokedRetry(t *testing.T) {
	h := setup(t, false)
	key := security.ID()
	args := map[string]any{"resource": prefix + "tickets/incident", "title": "review", "body": "public"}
	first := call(h, h.token, "tickets.create", key, args)
	second := call(h, h.token, "tickets.create", key, args)
	expect(t, first, 200, "")
	expect(t, second, 200, "")
	if first.Body.String() != second.Body.String() {
		t.Fatal("retry returned different ticket")
	}
	args["body"] = "changed"
	expect(t, call(h, h.token, "tickets.create", key, args), 409, "retry_conflict_or_pending")
	args["body"] = "public"
	h.store.Revoke(context.Background(), h.grant.ID)
	expect(t, call(h, h.token, "tickets.create", key, args), 401, "invalid_or_inactive_token")
}
func TestNestedDelegationRevocationAndEscalation(t *testing.T) {
	h := setup(t, false)
	childResponse := request(h.handler, "/v1/delegate", h.token, "", map[string]any{"agent": "reader-child", "ttl_seconds": 120, "capabilities": h.grant.Capabilities[:1]})
	expect(t, childResponse, 201, "")
	var child struct {
		Grant security.Grant `json:"grant"`
		Token string         `json:"access_token"`
	}
	json.Unmarshal(childResponse.Body.Bytes(), &child)
	expect(t, request(h.handler, "/v1/delegate", child.Token, "", map[string]any{"agent": "writer-grandchild", "ttl_seconds": 60, "capabilities": h.grant.Capabilities[4:5]}), 403, "delegation_must_shrink")
	expect(t, request(h.handler, "/v1/delegate", child.Token, "", map[string]any{"agent": "reader-grandchild", "ttl_seconds": 200, "capabilities": h.grant.Capabilities[:1]}), 403, "delegation_must_shrink")
	grandResponse := request(h.handler, "/v1/delegate", child.Token, "", map[string]any{"agent": "reader-grandchild", "ttl_seconds": 60, "capabilities": h.grant.Capabilities[:1]})
	expect(t, grandResponse, 201, "")
	var grand struct {
		Token string `json:"access_token"`
	}
	json.Unmarshal(grandResponse.Body.Bytes(), &grand)
	key := security.ID()
	args := map[string]any{"resource": prefix + "docs/welcome"}
	expect(t, call(h, grand.Token, "docs.read", key, args), 200, "")
	expect(t, request(h.handler, "/v1/revoke", child.Token, "", map[string]string{"grant_id": h.grant.ID}), 403, "revoke_scope_denied")
	expect(t, request(h.handler, "/v1/revoke", h.token, "", map[string]string{"grant_id": child.Grant.ID}), 200, "")
	expect(t, call(h, grand.Token, "docs.read", key, args), 401, "invalid_or_inactive_token")
	expect(t, call(h, h.token, "docs.read", security.ID(), args), 200, "")
}
func TestDownstreamAudienceAndBinding(t *testing.T) {
	h := setup(t, false)
	args := map[string]any{"resource": prefix + "docs/welcome"}
	payload := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": protocol.Call{Name: "docs.read", Arguments: args}}
	pub := h.key.Public().(ed25519.PublicKey)
	server, _ := toolserver.New("docs", pub, h.store)
	expect(t, request(server.Handler(), "/mcp", h.token, security.ID(), payload), 401, "invalid_tool_audience")
	key := security.ID()
	claims := security.Claims{Issuer: security.Issuer, Audience: "urn:aegis:tool:docs.read", Subject: h.grant.Agent, GrantID: h.grant.ID, ID: security.ID(), Issued: time.Now().Unix(), Expires: time.Now().Add(10 * time.Second).Unix(), Tool: "docs.read", Digest: security.Digest(protocol.Call{Name: "docs.read", Arguments: args}), RequestKey: key}
	token := security.Sign(h.key, claims)
	expect(t, request(server.Handler(), "/mcp", token, "different-key", payload), 403, "invocation_binding_failed")
	expect(t, request(server.Handler(), "/mcp", token, key, payload), 200, "")
	expect(t, call(h, token, "docs.read", security.ID(), args), 401, "invalid_or_inactive_token")
	h.store.Revoke(context.Background(), h.grant.ID)
	expect(t, request(server.Handler(), "/mcp", token, key, payload), 401, "grant_inactive")
}

type offlinePolicy struct{}

func (offlinePolicy) Evaluate(context.Context, policy.Input) (policy.Decision, error) {
	return policy.Decision{}, errors.New("offline")
}

type offlineAudit struct{}

func (offlineAudit) Append(context.Context, audit.Event) error { return errors.New("offline") }

type offlineState struct{ state.Store }

func (offlineState) Get(context.Context, string) (security.Grant, error) {
	return security.Grant{}, errors.New("offline")
}
func TestDependenciesFailClosed(t *testing.T) {
	for _, dependency := range []string{"policy", "audit", "state"} {
		t.Run(dependency, func(t *testing.T) {
			h := setup(t, false)
			switch dependency {
			case "policy":
				h.gateway.Policy = offlinePolicy{}
			case "audit":
				h.gateway.Audit = offlineAudit{}
			case "state":
				h.gateway.Store = offlineState{h.store}
			}
			response := call(h, h.token, "docs.read", security.ID(), map[string]any{"resource": prefix + "docs/welcome"})
			if response.Code < 400 {
				t.Fatal("dependency failure allowed action")
			}
		})
	}
}
func TestAdminAndOriginBoundary(t *testing.T) {
	h := setup(t, false)
	expect(t, request(h.handler, "/admin/grants", h.token, "", map[string]any{}), 401, "admin_required")
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader(`{}`))
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	expect(t, w, 403, "browser_origins_disabled")
}
func TestJSONRPCInitializationAndList(t *testing.T) {
	h := setup(t, false)
	for _, method := range []string{"initialize", "tools/list", "ping"} {
		expect(t, request(h.handler, "/mcp", h.token, "", map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": map[string]any{}}), 200, "")
	}
}

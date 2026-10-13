package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aegis-agent/gateway/internal/audit"
	"github.com/aegis-agent/gateway/internal/policy"
	"github.com/aegis-agent/gateway/internal/protocol"
	"github.com/aegis-agent/gateway/internal/registry"
	"github.com/aegis-agent/gateway/internal/security"
	"github.com/aegis-agent/gateway/internal/state"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

type Gateway struct {
	Key      ed25519.PrivateKey
	Store    state.Store
	Audit    audit.Sink
	Policy   policy.Evaluator
	Admin    string
	Backends map[string]string
	Client   *http.Client
	metrics  metrics
}
type metrics struct {
	mu            sync.Mutex
	total, denied int64
	buckets       [8]int64
	sum           float64
}
type timing struct {
	Start    time.Time
	Upstream time.Duration
}
type timingKey struct{}
type timedWriter struct {
	http.ResponseWriter
	timing *timing
}

func (w *timedWriter) WriteHeader(status int) {
	elapsed := time.Since(w.timing.Start)
	overhead := max(time.Duration(0), elapsed-w.timing.Upstream)
	w.Header().Set("Server-Timing", fmt.Sprintf("gateway;dur=%.3f, upstream;dur=%.3f, overhead;dur=%.3f", float64(elapsed)/float64(time.Millisecond), float64(w.timing.Upstream)/float64(time.Millisecond), float64(overhead)/float64(time.Millisecond)))
	w.ResponseWriter.WriteHeader(status)
}

var bounds = []float64{.001, .005, .01, .025, .05, .1, .5, 2}

func New(key ed25519.PrivateKey, store state.Store, sink audit.Sink, p policy.Evaluator, admin string, backends map[string]string) *Gateway {
	return &Gateway{Key: key, Store: store, Audit: sink, Policy: p, Admin: admin, Backends: backends, Client: &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func (g *Gateway) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { protocol.JSON(w, 200, map[string]string{"status": "ok"}) })
	m.HandleFunc("GET /metrics", g.prometheus)
	m.HandleFunc("POST /mcp", g.mcp)
	m.HandleFunc("GET /mcp", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(405) })
	m.HandleFunc("POST /admin/grants", g.root)
	m.HandleFunc("POST /admin/revoke", g.adminRevoke)
	m.HandleFunc("GET /admin/audit", g.auditExport)
	m.HandleFunc("POST /v1/delegate", g.delegate)
	m.HandleFunc("POST /v1/revoke", g.revoke)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" {
			protocol.JSON(w, 403, map[string]string{"error": "browser_origins_disabled"})
			return
		}
		ctx, span := otel.Tracer("aegis/gateway").Start(r.Context(), r.Method+" "+r.URL.Path)
		defer span.End()
		span.SetAttributes(attribute.String("http.request.method", r.Method))
		m.ServeHTTP(w, r.WithContext(ctx))
	})
}
func bearer(r *http.Request) string {
	v := r.Header.Get("Authorization")
	if !strings.HasPrefix(v, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(v, "Bearer ")
}
func (g *Gateway) authenticate(r *http.Request) (security.Grant, error) {
	c, e := security.Verify(g.Key.Public().(ed25519.PublicKey), bearer(r), security.GatewayAudience, time.Now())
	if e != nil {
		return security.Grant{}, e
	}
	grant, e := state.Active(r.Context(), g.Store, c.GrantID, time.Now())
	if e != nil || grant.Agent != c.Subject || c.Expires > grant.Expires {
		return grant, errors.New("inactive identity")
	}
	return grant, nil
}
func event(grant security.Grant, requestID string) audit.Event {
	return audit.Event{RequestID: requestID, GrantID: grant.ID, Agent: grant.Agent, User: grant.User, Tenant: grant.Tenant, Task: grant.Task, Policy: policy.Version}
}
func (g *Gateway) log(ctx context.Context, e audit.Event, decision, reason string) error {
	e.Decision = decision
	e.Reason = reason
	return g.Audit.Append(ctx, e)
}
func (g *Gateway) deny(w http.ResponseWriter, r *http.Request, id json.RawMessage, e audit.Event, status int, reason string) {
	g.metrics.mu.Lock()
	g.metrics.denied++
	g.metrics.mu.Unlock()
	if err := g.log(r.Context(), e, "deny", reason); err != nil {
		protocol.Fail(w, id, 503, "audit_unavailable")
		return
	}
	protocol.Fail(w, id, status, reason)
}
func (g *Gateway) mcp(w http.ResponseWriter, r *http.Request) {
	times := &timing{Start: time.Now()}
	w = &timedWriter{w, times}
	r = r.WithContext(context.WithValue(r.Context(), timingKey{}, times))
	start := time.Now()
	defer func() {
		s := time.Since(start).Seconds()
		g.metrics.mu.Lock()
		defer g.metrics.mu.Unlock()
		g.metrics.total++
		g.metrics.sum += s
		for i, b := range bounds {
			if s <= b {
				g.metrics.buckets[i]++
			}
		}
	}()
	grant, err := g.authenticate(r)
	e := event(grant, security.ID())
	if err != nil {
		g.deny(w, r, nil, e, 401, "invalid_or_inactive_token")
		return
	}
	if v := r.Header.Get("MCP-Protocol-Version"); v != "" && v != protocol.Version {
		g.deny(w, r, nil, e, 400, "unsupported_protocol")
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		g.deny(w, r, nil, e, 415, "json_required")
		return
	}
	var req protocol.Request
	if err = protocol.Read(w, r, &req); err != nil || req.JSONRPC != "2.0" || req.Method == "" {
		g.deny(w, r, nil, e, 400, "invalid_request")
		return
	}
	if req.Method == "notifications/initialized" && len(req.ID) == 0 {
		w.WriteHeader(202)
		return
	}
	if len(req.ID) == 0 || string(req.ID) == "null" {
		g.deny(w, r, req.ID, e, 400, "request_id_required")
		return
	}
	switch req.Method {
	case "initialize":
		protocol.Success(w, req.ID, map[string]any{"protocolVersion": protocol.Version, "capabilities": map[string]any{"tools": map[string]any{"listChanged": false}}, "serverInfo": map[string]string{"name": "aegis-agent-gateway", "version": "1.0.0"}})
	case "ping":
		protocol.Success(w, req.ID, map[string]any{})
	case "tools/list":
		tools := []registry.Tool{}
		for _, t := range registry.Tools() {
			for _, c := range grant.Capabilities {
				if c.Tool == t.Name {
					tools = append(tools, t)
					break
				}
			}
		}
		protocol.Success(w, req.ID, map[string]any{"tools": tools})
	case "tools/call":
		var call protocol.Call
		d := json.NewDecoder(bytes.NewReader(req.Params))
		d.DisallowUnknownFields()
		if d.Decode(&call) != nil {
			g.deny(w, r, req.ID, e, 400, "invalid_call")
			return
		}
		g.call(w, r, req.ID, grant, call, e)
	default:
		g.deny(w, r, req.ID, e, 400, "method_not_supported")
	}
}

var requestKey = regexp.MustCompile(`^[a-zA-Z0-9_-]{8,100}$`)

func (g *Gateway) call(w http.ResponseWriter, r *http.Request, id json.RawMessage, grant security.Grant, call protocol.Call, e audit.Event) {
	e.Tool = call.Name
	e.ArgumentsDigest = security.Digest(call.Arguments)
	t, ok := registry.Get(call.Name)
	if !ok {
		g.deny(w, r, id, e, 403, "unknown_tool")
		return
	}
	if err := registry.Validate(t, call.Arguments); err != nil {
		g.deny(w, r, id, e, 400, "schema_rejected")
		return
	}
	e.Resource, _ = call.Arguments["resource"].(string)
	e.Destination, _ = call.Arguments["destination"].(string)
	capability := security.Capability{Tool: call.Name, Resource: e.Resource, Destination: e.Destination}
	secret, confidential := security.Scan(call.Arguments)
	d, err := g.Policy.Evaluate(r.Context(), policy.Input{Grant: grant, Capability: capability, Secret: secret, Confidential: confidential})
	if err != nil {
		g.deny(w, r, id, e, 503, "policy_unavailable")
		return
	}
	e.Policy = d.Policy
	// Defense in depth: policy cannot widen the issued capability.
	if !grant.Allows(capability) {
		g.deny(w, r, id, e, 403, "capability_missing")
		return
	}
	if !d.Allow {
		g.deny(w, r, id, e, 403, d.Reason)
		return
	}
	if secret || (confidential && call.Name != "docs.read") {
		g.deny(w, r, id, e, 403, "data_policy_denied")
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if !requestKey.MatchString(key) {
		g.deny(w, r, id, e, 400, "idempotency_key_required")
		return
	}
	e.RequestID = key
	url, ok := g.Backends[call.Name]
	if !ok {
		g.deny(w, r, id, e, 503, "backend_unconfigured")
		return
	}
	if err = g.integrity(r.Context(), url, grant, t); err != nil {
		g.deny(w, r, id, e, 403, "tool_integrity_failed")
		return
	}
	// Integrity + policy precede cache lookup, and ancestor revocation is rechecked.
	if _, err = state.Active(r.Context(), g.Store, grant.ID, time.Now()); err != nil {
		g.deny(w, r, id, e, 401, "grant_inactive")
		return
	}
	digest := security.Digest(call)
	receiptKey := "gateway:" + grant.ID + ":" + key
	cached, fresh, err := g.Store.Reserve(r.Context(), receiptKey, digest)
	if err != nil {
		g.deny(w, r, id, e, 409, "retry_conflict_or_pending")
		return
	}
	if err = g.log(r.Context(), e, "allow", "authorized_intent"); err != nil {
		protocol.Fail(w, id, 503, "audit_unavailable")
		return
	}
	var result any
	if fresh {
		result, err = g.upstream(r.Context(), url, grant, call.Name, digest, "tools/call", call, key)
		if err != nil {
			g.deny(w, r, id, e, 502, "upstream_failed_outcome_unknown")
			return
		}
		secret, confidential = security.Scan(result)
		if secret || (confidential && call.Name != "docs.read") {
			g.deny(w, r, id, e, 403, "output_data_policy_denied")
			return
		}
		cached, _ = json.Marshal(result)
		if err = g.log(r.Context(), e, "allow", "completed"); err != nil {
			protocol.Fail(w, id, 503, "audit_unavailable_outcome_unknown")
			return
		}
		if err = g.Store.Complete(r.Context(), receiptKey, digest, cached); err != nil {
			protocol.Fail(w, id, 503, "receipt_unavailable_outcome_unknown")
			return
		}
	} else {
		if json.Unmarshal(cached, &result) != nil {
			g.deny(w, r, id, e, 503, "receipt_invalid")
			return
		}
		secret, confidential = security.Scan(result)
		if secret || (confidential && call.Name != "docs.read") {
			g.deny(w, r, id, e, 403, "output_data_policy_denied")
			return
		}
		if err = g.log(r.Context(), e, "allow", "retry_cached"); err != nil {
			protocol.Fail(w, id, 503, "audit_unavailable")
			return
		}
	}
	// A revocation after dispatch cannot undo a side effect, but blocks result release.
	if _, err = state.Active(r.Context(), g.Store, grant.ID, time.Now()); err != nil {
		g.deny(w, r, id, e, 401, "grant_inactive")
		return
	}
	protocol.Success(w, id, result)
}
func (g *Gateway) upstream(ctx context.Context, url string, grant security.Grant, tool, digest, method string, params any, key string) (any, error) {
	claims := security.Claims{Issuer: security.Issuer, Audience: "urn:aegis:tool:" + tool, Subject: grant.Agent, GrantID: grant.ID, ID: security.ID(), Issued: time.Now().Unix(), Expires: min(time.Now().Add(10*time.Second).Unix(), grant.Expires), Tool: tool, Digest: digest, RequestKey: key}
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", protocol.Version)
	req.Header.Set("Authorization", "Bearer "+security.Sign(g.Key, claims))
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	start := time.Now()
	defer func() {
		if times, ok := ctx.Value(timingKey{}).(*timing); ok {
			times.Upstream += time.Since(start)
		}
	}()
	res, err := g.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("upstream status %d", res.StatusCode)
	}
	b, err = io.ReadAll(io.LimitReader(res.Body, (256<<10)+1))
	if err != nil || len(b) > 256<<10 {
		return nil, errors.New("upstream oversized")
	}
	var out protocol.Response
	if json.Unmarshal(b, &out) != nil || out.JSONRPC != "2.0" || out.Error != nil || out.Result == nil {
		return nil, errors.New("upstream invalid")
	}
	return out.Result, nil
}
func (g *Gateway) integrity(ctx context.Context, url string, grant security.Grant, t registry.Tool) error {
	result, err := g.upstream(ctx, url, grant, t.Name, "", "tools/list", map[string]any{}, "")
	if err != nil {
		return err
	}
	b, _ := json.Marshal(result)
	var list struct {
		Tools []registry.Tool `json:"tools"`
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&list) != nil || len(list.Tools) != 1 || registry.Fingerprint(list.Tools[0]) != registry.Fingerprint(t) {
		return errors.New("tool changed")
	}
	return nil
}
func (g *Gateway) admin(r *http.Request) bool {
	return len(g.Admin) >= 32 && subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(g.Admin)) == 1
}
func (g *Gateway) root(w http.ResponseWriter, r *http.Request) {
	e := event(security.Grant{}, security.ID())
	if !g.admin(r) {
		g.deny(w, r, nil, e, 401, "admin_required")
		return
	}
	var in struct {
		Agent        string                `json:"agent"`
		User         string                `json:"user"`
		Tenant       string                `json:"tenant"`
		Task         string                `json:"task"`
		TTL          int                   `json:"ttl_seconds"`
		Capabilities []security.Capability `json:"capabilities"`
	}
	if protocol.Read(w, r, &in) != nil || in.TTL < 1 || in.TTL > 300 {
		g.deny(w, r, nil, e, 400, "invalid_root_request")
		return
	}
	grant := security.Grant{ID: security.ID(), Agent: in.Agent, User: in.User, Tenant: in.Tenant, Task: in.Task, Expires: time.Now().Add(time.Duration(in.TTL) * time.Second).Unix(), Capabilities: in.Capabilities}
	if security.ValidateGrant(grant, time.Now()) != nil {
		g.deny(w, r, nil, e, 400, "invalid_grant")
		return
	}
	e = event(grant, e.RequestID)
	if g.log(r.Context(), e, "allow", "root_issue_intent") != nil {
		protocol.Fail(w, nil, 503, "audit_unavailable")
		return
	}
	if g.Store.Create(r.Context(), grant) != nil {
		protocol.Fail(w, nil, 503, "state_unavailable")
		return
	}
	protocol.JSON(w, 201, map[string]any{"grant": grant, "access_token": security.AccessToken(g.Key, grant), "token_type": "Bearer"})
}
func (g *Gateway) delegate(w http.ResponseWriter, r *http.Request) {
	parent, err := g.authenticate(r)
	e := event(parent, security.ID())
	if err != nil {
		g.deny(w, r, nil, e, 401, "invalid_or_inactive_token")
		return
	}
	var in struct {
		Agent        string                `json:"agent"`
		TTL          int                   `json:"ttl_seconds"`
		Capabilities []security.Capability `json:"capabilities"`
	}
	if protocol.Read(w, r, &in) != nil || in.TTL < 1 || in.TTL > 300 {
		g.deny(w, r, nil, e, 400, "invalid_delegation")
		return
	}
	child := security.Grant{ID: security.ID(), Parent: parent.ID, Agent: in.Agent, User: parent.User, Tenant: parent.Tenant, Task: parent.Task, Expires: time.Now().Add(time.Duration(in.TTL) * time.Second).Unix(), Depth: parent.Depth + 1, Capabilities: in.Capabilities}
	if security.ValidateGrant(child, time.Now()) != nil || !security.Attenuates(parent, child) {
		g.deny(w, r, nil, e, 403, "delegation_must_shrink")
		return
	}
	if _, err = state.Active(r.Context(), g.Store, parent.ID, time.Now()); err != nil {
		g.deny(w, r, nil, e, 401, "grant_inactive")
		return
	}
	if g.log(r.Context(), event(child, e.RequestID), "allow", "delegation_issue_intent") != nil {
		protocol.Fail(w, nil, 503, "audit_unavailable")
		return
	}
	if g.Store.Create(r.Context(), child) != nil {
		protocol.Fail(w, nil, 503, "state_unavailable")
		return
	}
	protocol.JSON(w, 201, map[string]any{"grant": child, "access_token": security.AccessToken(g.Key, child), "token_type": "Bearer"})
}
func (g *Gateway) adminRevoke(w http.ResponseWriter, r *http.Request) {
	if !g.admin(r) {
		g.deny(w, r, nil, event(security.Grant{}, security.ID()), 401, "admin_required")
		return
	}
	g.performRevoke(w, r, security.Grant{}, true)
}
func (g *Gateway) revoke(w http.ResponseWriter, r *http.Request) {
	grant, e := g.authenticate(r)
	if e != nil {
		g.deny(w, r, nil, event(grant, security.ID()), 401, "invalid_or_inactive_token")
		return
	}
	g.performRevoke(w, r, grant, false)
}
func (g *Gateway) performRevoke(w http.ResponseWriter, r *http.Request, caller security.Grant, admin bool) {
	e := event(caller, security.ID())
	var in struct {
		ID string `json:"grant_id"`
	}
	if protocol.Read(w, r, &in) != nil {
		g.deny(w, r, nil, e, 400, "invalid_revoke")
		return
	}
	target, err := g.Store.Get(r.Context(), in.ID)
	if err != nil {
		g.deny(w, r, nil, e, 404, "grant_not_found")
		return
	}
	allowed := admin
	cursor := target
	for i := 0; i <= security.MaxDepth && !allowed; i++ {
		if cursor.ID == caller.ID {
			allowed = true
			break
		}
		if cursor.Parent == "" {
			break
		}
		cursor, err = g.Store.Get(r.Context(), cursor.Parent)
		if err != nil {
			break
		}
	}
	if !allowed {
		g.deny(w, r, nil, e, 403, "revoke_scope_denied")
		return
	}
	e.GrantID = in.ID
	if g.log(r.Context(), e, "allow", "revoke_intent") != nil {
		protocol.Fail(w, nil, 503, "audit_unavailable")
		return
	}
	if g.Store.Revoke(r.Context(), in.ID) != nil {
		protocol.Fail(w, nil, 503, "state_unavailable")
		return
	}
	protocol.JSON(w, 200, map[string]bool{"revoked": true})
}
func (g *Gateway) auditExport(w http.ResponseWriter, r *http.Request) {
	if !g.admin(r) {
		protocol.Fail(w, nil, 401, "admin_required")
		return
	}
	switch sink := g.Audit.(type) {
	case *audit.Memory:
		protocol.JSON(w, 200, sink.Snapshot())
	case *audit.Postgres:
		records, e := sink.Records(r.Context())
		if e != nil {
			protocol.Fail(w, nil, 503, "audit_unavailable")
			return
		}
		protocol.JSON(w, 200, records)
	default:
		protocol.Fail(w, nil, 503, "audit_export_unavailable")
	}
}
func (g *Gateway) prometheus(w http.ResponseWriter, r *http.Request) {
	g.metrics.mu.Lock()
	defer g.metrics.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# TYPE aegis_requests_total counter\naegis_requests_total %d\n# TYPE aegis_denied_total counter\naegis_denied_total %d\n# TYPE aegis_request_duration_seconds histogram\n", g.metrics.total, g.metrics.denied)
	for i, b := range bounds {
		fmt.Fprintf(w, "aegis_request_duration_seconds_bucket{le=\"%g\"} %d\n", b, g.metrics.buckets[i])
	}
	fmt.Fprintf(w, "aegis_request_duration_seconds_bucket{le=\"+Inf\"} %d\naegis_request_duration_seconds_sum %g\naegis_request_duration_seconds_count %d\n", g.metrics.total, g.metrics.sum, g.metrics.total)
}

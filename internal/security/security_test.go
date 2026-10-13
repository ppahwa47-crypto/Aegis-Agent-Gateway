package security

import (
	"crypto/ed25519"
	"encoding/base64"
	"math/rand"
	"strings"
	"testing"
	"time"
)

func grant() Grant {
	return Grant{ID: "root", Agent: "agent", User: "alice", Tenant: "acme", Task: "review", Expires: time.Now().Add(4 * time.Minute).Unix(), Capabilities: []Capability{{"docs.read", "tenants/acme/projects/alpha/docs/welcome", ""}, {"tickets.create", "tenants/acme/projects/alpha/tickets/incident", ""}}}
}
func TestAudienceExpiryAndTampering(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(nil)
	g := grant()
	token := AccessToken(key, g)
	if _, e := Verify(pub, token, GatewayAudience, time.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e := Verify(pub, token, "urn:aegis:tool:docs.read", time.Now()); e == nil {
		t.Fatal("token passthrough accepted")
	}
	if _, e := Verify(pub, token, GatewayAudience, time.Now().Add(5*time.Minute)); e == nil {
		t.Fatal("expired token accepted")
	}
	p := strings.Split(token, ".")
	p[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"aud":"urn:aegis:gateway","sub":"admin"}`))
	if _, e := Verify(pub, strings.Join(p, "."), GatewayAudience, time.Now()); e == nil {
		t.Fatal("tampered payload accepted")
	}
	bad := Claims{Issuer: Issuer, Audience: GatewayAudience, Subject: "agent", GrantID: "root", ID: "id", Issued: time.Now().Add(time.Second).Unix(), Expires: g.Expires}
	if _, e := Verify(pub, Sign(key, bad), GatewayAudience, time.Now()); e == nil {
		t.Fatal("future token accepted")
	}
}
func TestTupleAndDelegationInvariant(t *testing.T) {
	root := grant()
	child := root
	child.ID = "child"
	child.Parent = root.ID
	child.Depth = 1
	child.Agent = "child-agent"
	child.Capabilities = append([]Capability{}, root.Capabilities[:1]...)
	if !Attenuates(root, child) {
		t.Fatal("valid shrink rejected")
	}
	variants := map[string]func(*Grant){"write": func(g *Grant) { g.Capabilities = root.Capabilities }, "tenant": func(g *Grant) { g.Tenant = "bravo" }, "user": func(g *Grant) { g.User = "bob" }, "task": func(g *Grant) { g.Task = "other" }, "expiry": func(g *Grant) { g.Expires++ }, "depth": func(g *Grant) { g.Depth++ }, "tuple": func(g *Grant) { g.Capabilities = []Capability{{"tickets.create", root.Capabilities[0].Resource, ""}} }}
	grandchild := child
	grandchild.ID = "grandchild"
	grandchild.Parent = child.ID
	grandchild.Depth = 2
	for name, mutate := range variants {
		t.Run(name, func(t *testing.T) {
			g := grandchild
			g.Capabilities = append([]Capability{}, grandchild.Capabilities...)
			mutate(&g)
			if Attenuates(child, g) {
				t.Fatal("permissions expanded")
			}
		})
	}
}
func TestNestedRandomAttenuation(t *testing.T) {
	rng := rand.New(rand.NewSource(2027))
	for trial := 0; trial < 500; trial++ {
		root := grant()
		parent := root
		for depth := 1; depth <= MaxDepth; depth++ {
			child := parent
			child.ID = ID()
			child.Parent = parent.ID
			child.Depth = depth
			child.Expires -= int64(rng.Intn(2))
			if len(child.Capabilities) > 1 && rng.Intn(2) == 0 {
				child.Capabilities = child.Capabilities[:1]
			}
			if !Attenuates(parent, child) {
				t.Fatal("valid nested chain denied")
			}
			for _, c := range child.Capabilities {
				if !root.Allows(c) {
					t.Fatal("transitive widening")
				}
			}
			parent = child
		}
		child := parent
		child.Parent = parent.ID
		child.Depth++
		if Attenuates(parent, child) {
			t.Fatal("depth overflow")
		}
	}
}
func TestCanonicalResourcesAndDLP(t *testing.T) {
	for _, r := range []string{"tenants/acme/projects/alpha/docs/../secret", "tenants/bravo/projects/alpha/docs/welcome", "tenants/acme/projects/alpha/docs/%2e%2e", "tenants/acme/projects/alpha/docs//welcome"} {
		g := grant()
		g.Capabilities = []Capability{{"docs.read", r, ""}}
		if ValidateGrant(g, time.Now()) == nil {
			t.Fatalf("accepted %s", r)
		}
	}
	for _, v := range []any{"AKIA1234567890ABCDEF", map[string]any{"nested": []any{"123-45-6789"}}, map[string]any{"password": "hunter22"}, base64.StdEncoding.EncodeToString([]byte("password=hunter22")), "-----BEGIN PRIVATE KEY-----"} {
		s, _ := Scan(v)
		if !s {
			t.Fatalf("missed %v", v)
		}
	}
	if s, c := Scan("Public deployment summary"); s || c {
		t.Fatal("false positive")
	}
	if s, c := Scan("[CONFIDENTIAL] roadmap"); s || !c {
		t.Fatal("classification missed")
	}
}
func FuzzNoTokenPanic(f *testing.F) {
	pub, _, _ := ed25519.GenerateKey(nil)
	f.Add("bad.token.value")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) { Verify(pub, s, GatewayAudience, time.Now()) })
}

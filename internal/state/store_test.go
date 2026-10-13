package state

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aegis-agent/gateway/internal/security"
)

func TestAncestorRevocationAndExpiry(t *testing.T) {
	s := NewMemory()
	ctx := context.Background()
	root := security.Grant{ID: "root", Agent: "a", User: "u", Tenant: "acme", Task: "t", Expires: time.Now().Add(time.Minute).Unix(), Capabilities: []security.Capability{{Tool: "docs.read", Resource: "tenants/acme/projects/alpha/docs/welcome", Destination: ""}}}
	s.Create(ctx, root)
	child := root
	child.ID = "child"
	child.Parent = "root"
	child.Depth = 1
	s.Create(ctx, child)
	leaf := child
	leaf.ID = "leaf"
	leaf.Parent = "child"
	leaf.Depth = 2
	s.Create(ctx, leaf)
	if _, e := Active(ctx, s, "leaf", time.Now()); e != nil {
		t.Fatal(e)
	}
	s.Revoke(ctx, "root")
	if _, e := Active(ctx, s, "leaf", time.Now()); e == nil {
		t.Fatal("revoked ancestor still active")
	}
	if _, e := Active(ctx, s, "child", time.Now()); e == nil {
		t.Fatal("child still active")
	}
	if _, e := Active(ctx, s, "missing", time.Now()); e == nil {
		t.Fatal("unknown grant accepted")
	}
}
func TestMalformedAncestry(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()
	g := security.Grant{ID: "cycle", Parent: "cycle", Depth: 1, Expires: time.Now().Add(time.Minute).Unix()}
	s.Create(ctx, g)
	if _, e := Active(ctx, s, g.ID, time.Now()); e == nil {
		t.Fatal("cycle accepted")
	}
}
func TestConcurrentRetryReservation(t *testing.T) {
	s := NewMemory()
	ctx := context.Background()
	var won atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, fresh, e := s.Reserve(ctx, "same", "digest")
			if e == nil && fresh {
				won.Add(1)
			}
		}()
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatalf("%d winners", won.Load())
	}
	if e := s.Complete(ctx, "same", "digest", []byte(`{"ticket":"one"}`)); e != nil {
		t.Fatal(e)
	}
	b, fresh, e := s.Reserve(ctx, "same", "digest")
	if e != nil || fresh || string(b) != `{"ticket":"one"}` {
		t.Fatal("cached retry failed")
	}
	if _, _, e = s.Reserve(ctx, "same", "changed"); e == nil {
		t.Fatal("changed replay accepted")
	}
}

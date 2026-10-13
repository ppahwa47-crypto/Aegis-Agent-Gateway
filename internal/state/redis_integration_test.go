package state

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aegis-agent/gateway/internal/security"
	"github.com/redis/go-redis/v9"
)

func password(file string) string {
	if file == "" {
		return ""
	}
	b, e := os.ReadFile(file)
	if e != nil {
		panic(e)
	}
	return strings.TrimSpace(string(b))
}
func TestRedisPersistenceAndRevocation(t *testing.T) {
	addr := os.Getenv("REDIS_TEST_ADDR")
	if addr == "" {
		t.Skip("Redis integration: run docker compose --profile verify run --rm verify")
	}
	ctx := context.Background()
	client := redis.NewClient(&redis.Options{Addr: addr, Username: os.Getenv("REDIS_TEST_USER"), Password: password(os.Getenv("REDIS_TEST_PASSWORD_FILE")), MaxRetries: -1})
	defer client.Close()
	s := &Redis{Client: client}
	root := security.Grant{ID: security.ID(), Agent: "reader", User: "alice", Tenant: "acme", Task: "review", Expires: time.Now().Add(time.Minute).Unix(), Capabilities: []security.Capability{{Tool: "docs.read", Resource: "tenants/acme/projects/alpha/docs/welcome"}}}
	if e := s.Create(ctx, root); e != nil {
		t.Fatal(e)
	}
	child := root
	child.ID = security.ID()
	child.Parent = root.ID
	child.Depth = 1
	if e := s.Create(ctx, child); e != nil {
		t.Fatal(e)
	}
	if _, e := Active(ctx, s, child.ID, time.Now()); e != nil {
		t.Fatal(e)
	}
	key := "gateway:integration:" + security.ID()
	result, fresh, e := s.Reserve(ctx, key, "digest")
	if e != nil || !fresh || len(result) != 0 {
		t.Fatalf("reserve: %v", e)
	}
	if _, _, e = s.Reserve(ctx, key, "digest"); e == nil {
		t.Fatal("pending receipt replayed")
	}
	if e = s.Complete(ctx, key, "digest", []byte(`{"ticket":"persistent"}`)); e != nil {
		t.Fatal(e)
	}
	result, fresh, e = s.Reserve(ctx, key, "digest")
	if e != nil || fresh || string(result) != `{"ticket":"persistent"}` {
		t.Fatalf("cache: %s %v", result, e)
	}
	if _, _, e = s.Reserve(ctx, key, "changed"); e == nil {
		t.Fatal("changed operation accepted")
	}
	if e = s.Revoke(ctx, root.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = Active(ctx, s, child.ID, time.Now()); e == nil {
		t.Fatal("revoked ancestor accepted")
	}
	// Tool account cannot create grants, write other tool receipts, or delete state.
	toolFile := os.Getenv("DOCS_REDIS_PASSWORD_FILE")
	if toolFile != "" {
		docs := redis.NewClient(&redis.Options{Addr: addr, Username: "docs-tool", Password: password(toolFile), MaxRetries: -1})
		defer docs.Close()
		if e = docs.Get(ctx, "grant:"+root.ID).Err(); e != nil {
			t.Fatal("tool could not check revocation: ", e)
		}
		for key, value := range map[string]string{"grant:" + security.ID(): "{}", "receipt:tool:tickets.create:escape": "{}", "receipt:gateway:escape": "{}"} {
			if e = docs.Set(ctx, key, value, 0).Err(); e == nil {
				t.Fatalf("tool modified forbidden key %s", key)
			}
		}
		if e = docs.Del(ctx, "grant:"+root.ID).Err(); e == nil {
			t.Fatal("tool deleted grant")
		}
		toolStore := &Redis{Client: docs}
		k := "tool:docs.read:integration:" + security.ID()
		if _, fresh, e = toolStore.Reserve(ctx, k, "digest"); e != nil || !fresh {
			t.Fatalf("tool receipt reserve: %v", e)
		}
		if e = toolStore.Complete(ctx, k, "digest", []byte(`{"ok":true}`)); e != nil {
			t.Fatal(e)
		}
		if _, _, e = toolStore.Reserve(ctx, k, "digest"); e != nil {
			t.Fatal(e)
		}
	}
}

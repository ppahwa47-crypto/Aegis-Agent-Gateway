package audit

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresAuditChain(t *testing.T) {
	url := os.Getenv("PG_TEST_URL")
	if url == "" {
		t.Skip("PostgreSQL integration: run Compose verify profile")
	}
	ctx := context.Background()
	cfg, e := pgxpool.ParseConfig(url)
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(os.Getenv("PG_TEST_PASSWORD_FILE"))
	if e != nil {
		t.Fatal(e)
	}
	cfg.ConnConfig.Password = strings.TrimSpace(string(b))
	pool, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	sink := &Postgres{Pool: pool}
	if e = sink.Append(ctx, Event{RequestID: "integration", Decision: "deny", Reason: "tenant_boundary", Policy: "aegis/v1"}); e != nil {
		t.Fatal(e)
	}
	records, e := sink.Records(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = Verify(records); e != nil {
		t.Fatal(e)
	}
	if _, e = pool.Exec(ctx, "UPDATE audit_events SET hash='tampered' WHERE sequence=$1", records[len(records)-1].Sequence); e == nil {
		t.Fatal("audit mutation allowed")
	}
}

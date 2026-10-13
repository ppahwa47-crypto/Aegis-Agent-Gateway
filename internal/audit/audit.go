package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Event struct {
	Time            string `json:"time"`
	RequestID       string `json:"request_id"`
	GrantID         string `json:"grant_id,omitempty"`
	Agent           string `json:"agent,omitempty"`
	User            string `json:"user,omitempty"`
	Tenant          string `json:"tenant,omitempty"`
	Task            string `json:"task,omitempty"`
	Tool            string `json:"tool,omitempty"`
	Resource        string `json:"resource,omitempty"`
	Destination     string `json:"destination,omitempty"`
	ArgumentsDigest string `json:"arguments_digest,omitempty"`
	Decision        string `json:"decision"`
	Reason          string `json:"reason"`
	Policy          string `json:"policy"`
}
type Record struct {
	Sequence int64  `json:"sequence"`
	Previous string `json:"previous"`
	Hash     string `json:"hash"`
	Event    Event  `json:"event"`
}
type Sink interface {
	Append(context.Context, Event) error
}

func hash(previous string, b []byte) string {
	s := sha256.Sum256(append([]byte(previous+"\n"), b...))
	return hex.EncodeToString(s[:])
}
func Stamp(e Event) Event { e.Time = time.Now().UTC().Format(time.RFC3339Nano); return e }

type Memory struct {
	mu      sync.Mutex
	Records []Record
}

func (m *Memory) Snapshot() []Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Record{}, m.Records...)
}

func (m *Memory) Append(_ context.Context, e Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e = Stamp(e)
	prev := ""
	if len(m.Records) > 0 {
		prev = m.Records[len(m.Records)-1].Hash
	}
	b, _ := json.Marshal(e)
	m.Records = append(m.Records, Record{int64(len(m.Records) + 1), prev, hash(prev, b), e})
	return nil
}

type Postgres struct{ Pool *pgxpool.Pool }

// A single chain, serialized by a transaction advisory lock. JSON text preserves bytes.
func (p *Postgres) Append(ctx context.Context, e Event) error {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(72931021)"); err != nil {
		return err
	}
	var previous string
	var sequence int64
	err = tx.QueryRow(ctx, "SELECT sequence, hash FROM audit_events ORDER BY sequence DESC LIMIT 1").Scan(&sequence, &previous)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	e = Stamp(e)
	b, _ := json.Marshal(e)
	digest := hash(previous, b)
	_, err = tx.Exec(ctx, "INSERT INTO audit_events(sequence,previous,hash,event) VALUES($1,$2,$3,$4)", sequence+1, previous, digest, string(b))
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func Verify(records []Record) error {
	previous := ""
	for i, r := range records {
		b, _ := json.Marshal(r.Event)
		if r.Sequence != int64(i+1) || r.Previous != previous || r.Hash != hash(previous, b) {
			return errors.New("audit chain invalid")
		}
		previous = r.Hash
	}
	return nil
}

func (p *Postgres) Records(ctx context.Context) ([]Record, error) {
	rows, e := p.Pool.Query(ctx, "SELECT sequence,previous,hash,event FROM audit_events ORDER BY sequence")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var result []Record
	for rows.Next() {
		var r Record
		var b string
		if e = rows.Scan(&r.Sequence, &r.Previous, &r.Hash, &b); e != nil {
			return nil, e
		}
		if e = json.Unmarshal([]byte(b), &r.Event); e != nil {
			return nil, e
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aegis-agent/gateway/internal/audit"
	"github.com/aegis-agent/gateway/internal/gateway"
	"github.com/aegis-agent/gateway/internal/policy"
	"github.com/aegis-agent/gateway/internal/security"
	"github.com/aegis-agent/gateway/internal/state"
	"github.com/aegis-agent/gateway/internal/telemetry"
	"github.com/aegis-agent/gateway/internal/toolserver"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

func env(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
func read(path string) string {
	b, e := os.ReadFile(path)
	if e != nil {
		log.Fatal(e)
	}
	return strings.TrimSpace(string(b))
}
func public() ed25519.PublicKey {
	b, e := base64.StdEncoding.DecodeString(read(env("PUBLIC_KEY_FILE", "secrets/public.key")))
	if e != nil || len(b) != ed25519.PublicKeySize {
		log.Fatal("invalid public key")
	}
	return ed25519.PublicKey(b)
}
func private() ed25519.PrivateKey {
	b, e := base64.StdEncoding.DecodeString(read(env("PRIVATE_KEY_FILE", "secrets/private.key")))
	if e != nil || len(b) != ed25519.PrivateKeySize {
		log.Fatal("invalid private key")
	}
	return ed25519.PrivateKey(b)
}
func keygen() {
	dir := env("SECRETS_DIR", "secrets")
	if e := os.MkdirAll(dir, 0700); e != nil {
		log.Fatal(e)
	}
	if e := os.Chmod(dir, 0700); e != nil {
		log.Fatal(e)
	}
	pub, key, e := ed25519.GenerateKey(nil)
	if e != nil {
		log.Fatal(e)
	}
	files := map[string]string{"private.key": base64.StdEncoding.EncodeToString(key), "public.key": base64.StdEncoding.EncodeToString(pub), "admin.token": security.ID() + security.ID(), "redis.password": security.ID() + security.ID(), "postgres.password": security.ID() + security.ID(), "postgres-admin.password": security.ID() + security.ID(), "docs-redis.password": security.ID() + security.ID(), "tickets-redis.password": security.ID() + security.ID(), "exports-redis.password": security.ID() + security.ID()}
	// Idempotent bootstrap preserves credentials. A partial keypair fails closed.
	mode := os.FileMode(0600)
	if value := os.Getenv("SECRETS_MODE"); value != "" {
		n, e := strconv.ParseUint(value, 8, 12)
		if e != nil || (n != 0600 && n != 0444) {
			log.Fatal("SECRETS_MODE must be 0600 or 0444")
		}
		mode = os.FileMode(n)
	}
	_, privateErr := os.Stat(filepath.Join(dir, "private.key"))
	_, publicErr := os.Stat(filepath.Join(dir, "public.key"))
	if os.IsNotExist(privateErr) != os.IsNotExist(publicErr) {
		log.Fatal("partial keypair: restore both key files before bootstrapping")
	}
	if privateErr == nil && publicErr == nil {
		privateBytes, e := base64.StdEncoding.DecodeString(read(filepath.Join(dir, "private.key")))
		if e != nil || len(privateBytes) != ed25519.PrivateKeySize {
			log.Fatal("invalid existing private key")
		}
		publicBytes, e := base64.StdEncoding.DecodeString(read(filepath.Join(dir, "public.key")))
		if e != nil || len(publicBytes) != ed25519.PublicKeySize || !ed25519.PublicKey(publicBytes).Equal(ed25519.PrivateKey(privateBytes).Public()) {
			log.Fatal("existing keypair mismatch")
		}
	}
	for name, value := range files {
		file, e := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if os.IsExist(e) {
			if os.Getenv("SECRETS_MODE") != "" {
				if e = os.Chmod(filepath.Join(dir, name), mode); e != nil {
					log.Fatal(e)
				}
			}
			continue
		}
		if e != nil {
			log.Fatal(e)
		}
		if _, e = file.WriteString(value + "\n"); e != nil {
			file.Close()
			log.Fatal(e)
		}
		if e = file.Close(); e != nil {
			log.Fatal(e)
		}
	}
	fmt.Println("Development secrets ready in", dir, "(existing credentials preserved)")
}
func serve(ctx context.Context, address string, h http.Handler) *http.Server {
	s := &http.Server{Addr: address, Handler: h, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		log.Println("listening", address)
		if e := s.ListenAndServe(); e != nil && e != http.ErrServerClosed {
			log.Fatal(e)
		}
	}()
	return s
}
func main() {
	mode := "gateway"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	if mode == "keygen" {
		keygen()
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	shutdown, e := telemetry.Start(ctx)
	if e != nil {
		log.Fatal(e)
	}
	defer func() { c, stop := context.WithTimeout(context.Background(), 3*time.Second); defer stop(); shutdown(c) }()
	var servers []*http.Server
	if mode == "local" {
		// Explicit in-memory development mode; no production fallback exists.
		store := state.NewMemory()
		sink := &audit.Memory{}
		key := private()
		backends := map[string]string{}
		for i, kind := range []string{"docs", "tickets", "exports"} {
			tool, e := toolserver.New(kind, key.Public().(ed25519.PublicKey), store)
			if e != nil {
				log.Fatal(e)
			}
			address := fmt.Sprintf("127.0.0.1:%d", 8091+i)
			servers = append(servers, serve(ctx, address, tool.Handler()))
			backends[tool.Tool.Name] = "http://" + address + "/mcp"
		}
		var evaluator policy.Evaluator = policy.Local{}
		if url := os.Getenv("LOCAL_OPA_URL"); url != "" {
			evaluator = policy.NewOPA(url)
		}
		gw := gateway.New(key, store, sink, evaluator, read("secrets/admin.token"), backends)
		servers = append(servers, serve(ctx, "127.0.0.1:8080", gw.Handler()))
	} else {
		client := redis.NewClient(&redis.Options{Addr: env("REDIS_ADDR", "redis:6379"), Username: env("REDIS_USER", "gateway"), Password: read(env("REDIS_PASSWORD_FILE", "/run/secrets/redis_password")), DialTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, MaxRetries: -1})
		if e := client.Ping(ctx).Err(); e != nil {
			log.Fatal("Redis unavailable: ", e)
		}
		defer client.Close()
		store := &state.Redis{Client: client}
		if mode == "tool" {
			tool, e := toolserver.New(env("TOOL_KIND", "docs"), public(), store)
			if e != nil {
				log.Fatal(e)
			}
			tool.Drift = os.Getenv("TOOL_DRIFT") == "1"
			servers = append(servers, serve(ctx, ":8090", tool.Handler()))
		} else if mode == "gateway" {
			cfg, e := pgxpool.ParseConfig(env("DATABASE_URL", "postgres://aegis@postgres:5432/aegis?sslmode=disable"))
			if e != nil {
				log.Fatal(e)
			}
			cfg.ConnConfig.Password = read(env("PG_PASSWORD_FILE", "/run/secrets/postgres_password"))
			pool, e := pgxpool.NewWithConfig(ctx, cfg)
			if e != nil {
				log.Fatal(e)
			}
			defer pool.Close()
			if e = pool.Ping(ctx); e != nil {
				log.Fatal(e)
			}
			gw := gateway.New(private(), store, &audit.Postgres{Pool: pool}, policy.NewOPA(env("OPA_URL", "http://opa:8181")), read(env("ADMIN_TOKEN_FILE", "/run/secrets/admin_token")), map[string]string{"docs.read": env("DOCS_URL", "http://docs:8090/mcp"), "tickets.create": env("TICKETS_URL", "http://tickets:8090/mcp"), "exports.upload": env("EXPORTS_URL", "http://exports:8090/mcp")})
			servers = append(servers, serve(ctx, ":8080", gw.Handler()))
		} else {
			log.Fatal("mode must be keygen, local, gateway, or tool")
		}
	}
	<-ctx.Done()
	c, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	for _, s := range servers {
		s.Shutdown(c)
	}
}

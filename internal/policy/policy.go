package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/aegis-agent/gateway/internal/security"
)

const Version = "aegis/v1"

type Input struct {
	Grant        security.Grant      `json:"grant"`
	Capability   security.Capability `json:"capability"`
	Secret       bool                `json:"secret"`
	Confidential bool                `json:"confidential"`
}
type Decision struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason"`
	Policy string `json:"policy"`
}
type Evaluator interface {
	Evaluate(context.Context, Input) (Decision, error)
}
type OPA struct {
	URL    string
	Client *http.Client
}

func (p OPA) Evaluate(ctx context.Context, in Input) (Decision, error) {
	b, _ := json.Marshal(map[string]any{"input": in})
	req, e := http.NewRequestWithContext(ctx, "POST", p.URL+"/v1/data/aegis/decision", bytes.NewReader(b))
	if e != nil {
		return Decision{}, e
	}
	req.Header.Set("Content-Type", "application/json")
	res, e := p.Client.Do(req)
	if e != nil {
		return Decision{}, e
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return Decision{}, errors.New("policy service unavailable")
	}
	var out struct {
		Result *Decision `json:"result"`
	}
	if e = json.NewDecoder(io.LimitReader(res.Body, 65536)).Decode(&out); e != nil || out.Result == nil || out.Result.Policy != Version || out.Result.Reason == "" {
		return Decision{}, errors.New("invalid policy response")
	}
	return *out.Result, nil
}
func NewOPA(url string) OPA { return OPA{url, &http.Client{Timeout: 2 * time.Second}} }

// Local is a deterministic development evaluator. Deployment ALWAYS uses OPA.
type Local struct{}

func (Local) Evaluate(_ context.Context, in Input) (Decision, error) {
	deny := func(reason string) (Decision, error) { return Decision{false, reason, Version}, nil }
	parts := security.ResourceParts(in.Capability.Resource)
	if len(parts) == 0 || parts[1] != in.Grant.Tenant {
		return deny("tenant_boundary")
	}
	if (parts[1] != "acme" && parts[1] != "bravo") || (parts[2] != "alpha" && parts[2] != "beta") {
		return deny("project_not_registered")
	}
	if !in.Grant.Allows(in.Capability) {
		return deny("capability_missing")
	}
	if in.Secret {
		return deny("secret_detected")
	}
	if in.Confidential && in.Capability.Tool != "docs.read" {
		return deny("confidential_write")
	}
	return Decision{true, "authorized", Version}, nil
}

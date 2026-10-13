package registry

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/aegis-agent/gateway/internal/security"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

func schema(properties map[string]any, required []string) map[string]any {
	return map[string]any{"type": "object", "properties": properties, "required": required, "additionalProperties": false}
}
func str(limit int) map[string]any {
	return map[string]any{"type": "string", "minLength": 1, "maxLength": limit}
}

func Tools() []Tool {
	return []Tool{
		{"docs.read", "Read a document by exact tenant/project resource.", schema(map[string]any{"resource": str(200)}, []string{"resource"})},
		{"tickets.create", "Create an internal support ticket; no external destinations.", schema(map[string]any{"resource": str(200), "title": str(120), "body": str(8000)}, []string{"resource", "title", "body"})},
		{"exports.upload", "Store a public report in an approved local vault destination.", schema(map[string]any{"resource": str(200), "destination": str(200), "content": str(8000)}, []string{"resource", "destination", "content"})},
	}
}

func Get(name string) (Tool, bool) {
	for _, t := range Tools() {
		if t.Name == name {
			return t, true
		}
	}
	return Tool{}, false
}
func ForKind(kind string) (Tool, error) {
	t, ok := Get(kind + map[string]string{"docs": ".read", "tickets": ".create", "exports": ".upload"}[kind])
	if !ok {
		return t, errors.New("invalid tool kind")
	}
	return t, nil
}
func Fingerprint(t Tool) string { return security.Digest(t) }

func Validate(t Tool, args map[string]any) error {
	b, _ := json.Marshal(t.InputSchema)
	c := jsonschema.NewCompiler()
	if err := c.AddResource("schema.json", strings.NewReader(string(b))); err != nil {
		return err
	}
	s, err := c.Compile("schema.json")
	if err != nil {
		return err
	}
	return s.Validate(args)
}

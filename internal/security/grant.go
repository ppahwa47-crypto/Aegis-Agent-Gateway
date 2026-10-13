package security

import (
	"errors"
	"regexp"
	"time"
)

const GatewayAudience = "urn:aegis:gateway"
const Issuer = "urn:aegis:issuer"
const MaxDepth = 8

// Capabilities are indivisible tuples, never Cartesian products or wildcards.
type Capability struct {
	Tool        string `json:"tool"`
	Resource    string `json:"resource"`
	Destination string `json:"destination"`
}

type Grant struct {
	ID           string       `json:"id"`
	Parent       string       `json:"parent,omitempty"`
	Agent        string       `json:"agent"`
	User         string       `json:"user"`
	Tenant       string       `json:"tenant"`
	Task         string       `json:"task"`
	Expires      int64        `json:"expires"`
	Depth        int          `json:"depth"`
	Capabilities []Capability `json:"capabilities"`
	Revoked      bool         `json:"revoked"`
}

var identity = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
var resource = regexp.MustCompile(`^tenants/([a-z0-9-]+)/projects/([a-z0-9-]+)/(docs|tickets|exports)/([a-z0-9][a-z0-9._-]{0,63})$`)

func ResourceParts(value string) []string { return resource.FindStringSubmatch(value) }
func ValidIdentity(value string) bool     { return identity.MatchString(value) }

func (g Grant) Allows(c Capability) bool {
	for _, have := range g.Capabilities {
		if have == c {
			return true
		}
	}
	return false
}

func ValidateGrant(g Grant, now time.Time) error {
	if !ValidIdentity(g.Agent) || !ValidIdentity(g.User) || !ValidIdentity(g.Tenant) || !ValidIdentity(g.Task) || g.ID == "" || g.Depth < 0 || g.Depth > MaxDepth || g.Expires <= now.Unix() || g.Expires > now.Add(5*time.Minute).Unix() || len(g.Capabilities) == 0 || len(g.Capabilities) > 32 {
		return errors.New("invalid grant")
	}
	seen := map[Capability]bool{}
	for _, c := range g.Capabilities {
		p := ResourceParts(c.Resource)
		if len(p) == 0 || p[1] != g.Tenant || seen[c] {
			return errors.New("invalid capability")
		}
		seen[c] = true
		switch c.Tool {
		case "docs.read":
			if p[3] != "docs" || c.Destination != "" {
				return errors.New("invalid read scope")
			}
		case "tickets.create":
			if p[3] != "tickets" || c.Destination != "" {
				return errors.New("invalid ticket scope")
			}
		case "exports.upload":
			if p[3] != "exports" || c.Destination != "vault://"+p[1]+"/"+p[2] {
				return errors.New("invalid destination scope")
			}
		default:
			return errors.New("unknown tool")
		}
	}
	return nil
}

func Attenuates(parent, child Grant) bool {
	if child.Parent != parent.ID || child.User != parent.User || child.Tenant != parent.Tenant || child.Task != parent.Task || child.Expires > parent.Expires || child.Depth != parent.Depth+1 || child.Depth > MaxDepth || len(child.Capabilities) == 0 {
		return false
	}
	for _, c := range child.Capabilities {
		if !parent.Allows(c) {
			return false
		}
	}
	return true
}

package security

import (
	"encoding/base64"
	"regexp"
	"strings"
)

var secrets = regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16}|sk-[a-z0-9_-]{20,}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|password\s*[:=]\s*[^\s]{4,}|\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b)`)

// Synthetic DLP: nested strings and one layer of base64. No semantic promise.
func Scan(v any) (secret, confidential bool) {
	var visit func(any)
	check := func(s string) {
		secret = secret || secrets.MatchString(s)
		confidential = confidential || strings.Contains(strings.ToUpper(s), "[CONFIDENTIAL]")
	}
	visit = func(x any) {
		switch value := x.(type) {
		case string:
			check(value)
			for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
				if b, err := enc.DecodeString(value); err == nil {
					check(string(b))
				}
			}
		case map[string]any:
			for k, item := range value {
				check(k)
				switch strings.ToLower(strings.ReplaceAll(k, "-", "_")) {
				case "password", "api_key", "authorization", "access_token", "private_key", "secret":
					if item != nil && item != "" {
						secret = true
					}
				}
				visit(item)
			}
		case []any:
			for _, item := range value {
				visit(item)
			}
		}
	}
	visit(v)
	return
}

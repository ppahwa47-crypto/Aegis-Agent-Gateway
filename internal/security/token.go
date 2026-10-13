package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type Claims struct {
	Issuer     string `json:"iss"`
	Audience   string `json:"aud"`
	Subject    string `json:"sub"`
	GrantID    string `json:"gid"`
	ID         string `json:"jti"`
	Issued     int64  `json:"iat"`
	Expires    int64  `json:"exp"`
	Tool       string `json:"tool,omitempty"`
	Digest     string `json:"digest,omitempty"`
	RequestKey string `json:"request_key,omitempty"`
}

var encoding = base64.RawURLEncoding

const header = `{"alg":"EdDSA","typ":"JWT"}`

func ID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func Digest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func Sign(key ed25519.PrivateKey, c Claims) string {
	b, _ := json.Marshal(c)
	payload := encoding.EncodeToString([]byte(header)) + "." + encoding.EncodeToString(b)
	return payload + "." + encoding.EncodeToString(ed25519.Sign(key, []byte(payload)))
}

func Verify(key ed25519.PublicKey, token, audience string, now time.Time) (Claims, error) {
	var c Claims
	if len(token) > 4096 {
		return c, errors.New("invalid token")
	}
	p := strings.Split(token, ".")
	if len(p) != 3 || p[0] != encoding.EncodeToString([]byte(header)) {
		return c, errors.New("invalid token header")
	}
	sig, err := encoding.DecodeString(p[2])
	if err != nil || !ed25519.Verify(key, []byte(p[0]+"."+p[1]), sig) {
		return c, errors.New("invalid signature")
	}
	b, err := encoding.DecodeString(p[1])
	if err != nil {
		return c, errors.New("invalid payload")
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil || c.Issuer != Issuer || c.Audience != audience || c.ID == "" || c.GrantID == "" || c.Subject == "" || c.Expires <= now.Unix() || c.Issued > now.Unix() || c.Expires <= c.Issued || c.Expires-c.Issued > 300 {
		return Claims{}, errors.New("invalid claims")
	}
	return c, nil
}

func AccessToken(key ed25519.PrivateKey, g Grant) string {
	return Sign(key, Claims{Issuer: Issuer, Audience: GatewayAudience, Subject: g.Agent, GrantID: g.ID, ID: ID(), Issued: time.Now().Unix(), Expires: g.Expires})
}

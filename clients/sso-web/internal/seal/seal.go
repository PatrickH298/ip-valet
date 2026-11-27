// Package seal signs small values that travel through the browser, such as
// sign-in state and proofs of a detected address, so they come back
// unchanged. A sealed value is readable, not secret: base64 JSON with an
// expiry and an HMAC-SHA256 over its purpose and body. The key is random per
// process, so a restart invalidates every sealed value.
package seal

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Errors from Open.
var (
	ErrInvalid = errors.New("invalid or tampered value")
	ErrExpired = errors.New("expired value")
)

// Sealer seals and opens values with one key.
type Sealer struct {
	key []byte
	Now func() time.Time
}

// New returns a Sealer with a random key.
func New() *Sealer {
	k := make([]byte, 32)
	_, _ = rand.Read(k) // never fails; see crypto/rand.Read
	return &Sealer{key: k, Now: time.Now}
}

type envelope struct {
	V json.RawMessage `json:"v"`
	E int64           `json:"e"` // expiry, Unix seconds
}

// Seal returns v, signed for purpose, valid for ttl.
func (s *Sealer) Seal(purpose string, ttl time.Duration, v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(envelope{V: raw, E: s.Now().Add(ttl).Unix()})
	if err != nil {
		return "", err
	}
	b := base64.RawURLEncoding.EncodeToString(body)
	return b + "." + base64.RawURLEncoding.EncodeToString(s.mac(purpose, b)), nil
}

// Open checks a sealed value's signature, purpose and expiry, and decodes it
// into v.
func (s *Sealer) Open(purpose, token string, v any) error {
	b, sig, ok := strings.Cut(token, ".")
	if !ok || len(token) > 8192 {
		return ErrInvalid
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, s.mac(purpose, b)) {
		return ErrInvalid
	}
	body, err := base64.RawURLEncoding.DecodeString(b)
	if err != nil {
		return ErrInvalid
	}
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return ErrInvalid
	}
	if s.Now().Unix() >= env.E {
		return ErrExpired
	}
	if err := json.Unmarshal(env.V, v); err != nil {
		return ErrInvalid
	}
	return nil
}

// Tag returns a short keyed digest of s, to bind a sealed value to a secret
// (such as a session id) without carrying the secret itself.
func (s *Sealer) Tag(purpose, value string) string {
	return base64.RawURLEncoding.EncodeToString(s.mac("tag:"+purpose, value)[:16])
}

func (s *Sealer) mac(purpose, body string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(purpose))
	m.Write([]byte{0})
	m.Write([]byte(body))
	return m.Sum(nil)
}

// Package auth implements API key generation, parsing and request authentication.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Key kinds.
const (
	KindAdmin  = "admin"
	KindClient = "client"
	KindWorker = "worker"
)

// EnvAdminActor is the audit actor for requests made with the environment admin key.
const EnvAdminActor = "admin:env"

var (
	keyPattern   = regexp.MustCompile(`^ipv_([a-z2-7]{16})_([a-z2-7]{52})$`)
	keyIDPattern = regexp.MustCompile(`^[a-z2-7]{16}$`)
	encoding     = base32.StdEncoding.WithPadding(base32.NoPadding)
)

// Key is a parsed API key.
type Key struct {
	ID     string
	Secret string
}

// String returns the full key, ipv_<id>_<secret>.
func (k Key) String() string { return "ipv_" + k.ID + "_" + k.Secret }

// Hash returns SHA-256 of the secret as ASCII.
func (k Key) Hash() []byte { return HashSecret(k.Secret) }

// HashSecret returns SHA-256 of secret as ASCII.
func HashSecret(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

func encode(b []byte) string { return strings.ToLower(encoding.EncodeToString(b)) }

// NewKey generates a key: a 10-byte id and a 32-byte secret from crypto/rand,
// each base32-encoded in lowercase without padding.
func NewKey() (Key, error) {
	id := make([]byte, 10)
	secret := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return Key{}, err
	}
	if _, err := rand.Read(secret); err != nil {
		return Key{}, err
	}
	return Key{ID: encode(id), Secret: encode(secret)}, nil
}

// ErrMalformedKey is returned when a key does not match the key pattern.
var ErrMalformedKey = errors.New("key does not match ipv_<keyid>_<secret>")

// ParseKey splits a full key into id and secret.
func ParseKey(s string) (Key, error) {
	m := keyPattern.FindStringSubmatch(s)
	if m == nil {
		return Key{}, ErrMalformedKey
	}
	return Key{ID: m[1], Secret: m[2]}, nil
}

// ValidKeyID reports whether s has the form of a key id.
func ValidKeyID(s string) bool { return keyIDPattern.MatchString(s) }

// HashLine returns "<keyid>:<hex sha256 of secret>", the IPVALET_ADMIN_KEY_HASH format.
func HashLine(k Key) string { return k.ID + ":" + hex.EncodeToString(k.Hash()) }

// ParseHashLine parses "<keyid>:<64 hex chars>".
func ParseHashLine(s string) (id string, hash []byte, err error) {
	id, hexHash, ok := strings.Cut(s, ":")
	if !ok || !ValidKeyID(id) || len(hexHash) != 64 {
		return "", nil, fmt.Errorf("must be <keyid>:<64 hex chars>")
	}
	hash, err = hex.DecodeString(hexHash)
	if err != nil {
		return "", nil, fmt.Errorf("must be <keyid>:<64 hex chars>")
	}
	return id, hash, nil
}

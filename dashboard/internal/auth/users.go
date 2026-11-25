// Package auth signs people in to the dashboard. A Provider identifies the
// person behind a request; form and basic sign-in check names and passwords
// from a users file, and form sign-in keeps sessions in memory.
package auth

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

// Users holds each user's bcrypt hash.
type Users struct {
	hashes map[string][]byte
	dummy  []byte // compared against for unknown names, so timing reveals nothing
}

// LoadUsers reads an htpasswd file of bcrypt hashes.
func LoadUsers(path string) (*Users, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	u, err := ParseUsers(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return u, nil
}

// ParseUsers reads htpasswd lines, name:hash, where every hash is bcrypt
// ($2a$, $2b$ or $2y$). Blank lines and lines starting with # are skipped.
func ParseUsers(r io.Reader) (*Users, error) {
	u := &Users{hashes: map[string][]byte{}}
	sc := bufio.NewScanner(r)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, hash, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("line %d: want name:hash", n)
		}
		if err := ValidName(name); err != nil {
			return nil, fmt.Errorf("line %d: user name %v", n, err)
		}
		if !strings.HasPrefix(hash, "$2a$") && !strings.HasPrefix(hash, "$2b$") && !strings.HasPrefix(hash, "$2y$") {
			return nil, fmt.Errorf("line %d (%s): only bcrypt hashes are accepted (htpasswd -B)", n, name)
		}
		if _, err := bcrypt.Cost([]byte(hash)); err != nil {
			return nil, fmt.Errorf("line %d (%s): %v", n, name, err)
		}
		if _, dup := u.hashes[name]; dup {
			return nil, fmt.Errorf("line %d: user %s listed twice", n, name)
		}
		u.hashes[name] = []byte(hash)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(u.hashes) == 0 {
		return nil, fmt.Errorf("no users")
	}
	// A hash of a random password, at the highest cost in the file, for
	// names that do not exist.
	cost := bcrypt.MinCost
	for _, h := range u.hashes {
		if c, _ := bcrypt.Cost(h); c > cost {
			cost = c
		}
	}
	dummy, err := bcrypt.GenerateFromPassword(randomPassword(), cost)
	if err != nil {
		return nil, err
	}
	u.dummy = dummy
	return u, nil
}

// ValidName checks a user name: 1 to 256 characters of UTF-8, with no colon,
// control characters or surrounding spaces. Names travel to the API server as
// IPValet-On-Behalf-Of, which has the same limits.
func ValidName(name string) error {
	switch {
	case !utf8.ValidString(name):
		return fmt.Errorf("must be UTF-8")
	case name == "" || utf8.RuneCountInString(name) > 256:
		return fmt.Errorf("must be 1 to 256 characters")
	case strings.Contains(name, ":"):
		return fmt.Errorf("must not contain a colon")
	case strings.TrimSpace(name) != name:
		return fmt.Errorf("must not start or end with a space")
	}
	for _, c := range name {
		if unicode.IsControl(c) {
			return fmt.Errorf("must not contain control characters")
		}
	}
	return nil
}

// Check reports whether password is name's password. It costs one bcrypt
// comparison whether or not name exists.
func (u *Users) Check(name, password string) bool {
	hash, known := u.hashes[name]
	if !known {
		hash = u.dummy
	}
	ok := bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
	return ok && known
}

// Len is the number of users.
func (u *Users) Len() int { return len(u.hashes) }

// HashLine returns an htpasswd line for name with a bcrypt hash of password.
func HashLine(name, password string) (string, error) {
	if err := ValidName(name); err != nil {
		return "", fmt.Errorf("user name %v", err)
	}
	if password == "" {
		return "", fmt.Errorf("the password is empty")
	}
	if len(password) > 72 {
		return "", fmt.Errorf("bcrypt uses at most 72 bytes of a password")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", err
	}
	return name + ":" + string(bytes.TrimSpace(h)), nil
}

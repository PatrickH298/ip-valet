// Package auth signs people in to the dashboard. Without external sign-in
// there is one local login: a user name, a bcrypt password hash and the
// sign-in method (a form with a session cookie, or HTTP basic auth). It is
// kept in a small file in the dashboard's data directory and changed from
// the dashboard's Account page. Until it is first changed, the login is the
// default: form sign-in as admin with password admin.
package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

// Sign-in methods.
const (
	MethodForm  = "form"
	MethodBasic = "basic"
)

// The login on first boot, and after reset-login.
const (
	DefaultUsername = "admin"
	DefaultPassword = "admin"
)

// MinPasswordLength is the shortest new password accepted, in characters.
const MinPasswordLength = 10

// bcryptCost is the cost of new password hashes (lowered in this package's
// tests).
var bcryptCost = 12

// loginFile is the login's file in the data directory.
const loginFile = "login.json"

// Login is the local login.
type Login struct {
	Version  int    `json:"version"`
	Method   string `json:"method"`
	Username string `json:"username"`
	Hash     string `json:"password_hash"`
}

// Store holds the local login and saves changes to the data directory.
type Store struct {
	path string

	mu        sync.RWMutex
	login     Login
	isDefault bool
}

// OpenStore reads the login from dir, or starts from the default login when
// dir holds none. dir must exist and be writable, so that changing the
// login later cannot fail.
func OpenStore(dir string) (*Store, error) {
	st, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}
	probe, err := os.CreateTemp(dir, ".write-check-*")
	if err != nil {
		return nil, fmt.Errorf("%s is not writable: %w", dir, err)
	}
	probe.Close()
	_ = os.Remove(probe.Name())

	s := &Store{path: filepath.Join(dir, loginFile)}
	b, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		h, err := bcrypt.GenerateFromPassword([]byte(DefaultPassword), bcryptCost)
		if err != nil {
			return nil, err
		}
		s.login = Login{Version: 1, Method: MethodForm, Username: DefaultUsername, Hash: string(h)}
		s.isDefault = true
		return s, nil
	case err != nil:
		return nil, err
	}
	var l Login
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, fmt.Errorf("%s: %w", s.path, err)
	}
	if err := l.valid(); err != nil {
		return nil, fmt.Errorf("%s: %w (run reset-login to start again from the default login)", s.path, err)
	}
	s.login = l
	return s, nil
}

func (l Login) valid() error {
	if l.Method != MethodForm && l.Method != MethodBasic {
		return fmt.Errorf("unknown sign-in method %q", l.Method)
	}
	if err := ValidName(l.Username); err != nil {
		return fmt.Errorf("user name %v", err)
	}
	if _, err := bcrypt.Cost([]byte(l.Hash)); err != nil {
		return fmt.Errorf("password hash: %v", err)
	}
	return nil
}

// Login returns the current login.
func (s *Store) Login() Login {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.login
}

// IsDefault reports whether the login is still the default one.
func (s *Store) IsDefault() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isDefault
}

// Save replaces the login, writing it atomically with mode 0600.
func (s *Store) Save(l Login) error {
	l.Version = 1
	if err := l.valid(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".login-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return err
	}
	s.mu.Lock()
	s.login, s.isDefault = l, false
	s.mu.Unlock()
	return nil
}

// ResetLogin removes the saved login from dir, so the dashboard starts from
// the default login when it next starts.
func ResetLogin(dir string) error {
	err := os.Remove(filepath.Join(dir, loginFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// HashPassword returns a bcrypt hash of a new password.
func HashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcryptCost)
	return string(h), err
}

// ValidName checks a user name: 1 to 256 characters of UTF-8, with no colon
// (basic auth splits on it), no control characters and no surrounding
// spaces. Names travel to the API server as IPValet-On-Behalf-Of, which has
// the same limits.
func ValidName(name string) error {
	switch {
	case !utf8.ValidString(name):
		return errors.New("must be UTF-8")
	case name == "" || utf8.RuneCountInString(name) > 256:
		return errors.New("must be 1 to 256 characters")
	case strings.Contains(name, ":"):
		return errors.New("must not contain a colon")
	case strings.TrimSpace(name) != name:
		return errors.New("must not start or end with a space")
	}
	for _, c := range name {
		if unicode.IsControl(c) {
			return errors.New("must not contain control characters")
		}
	}
	return nil
}

// ValidPassword checks a new password.
func ValidPassword(pw, username string) error {
	switch {
	case utf8.RuneCountInString(pw) < MinPasswordLength:
		return fmt.Errorf("must be at least %d characters", MinPasswordLength)
	case len(pw) > 72:
		return errors.New("must be at most 72 bytes (bcrypt ignores the rest)")
	case pw == username:
		return errors.New("must differ from the user name")
	}
	return nil
}

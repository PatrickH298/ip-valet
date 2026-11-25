package auth

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// Sessions holds signed-in sessions in memory. A restart signs everyone out.
type Sessions struct {
	idle, max time.Duration
	now       func() time.Time

	mu   sync.Mutex
	byID map[string]*session
}

type session struct {
	name     string
	created  time.Time
	lastSeen time.Time
}

// NewSessions returns a store whose sessions end after idle without use, or
// max after they began.
func NewSessions(idle, max time.Duration) *Sessions {
	return &Sessions{idle: idle, max: max, now: time.Now, byID: map[string]*session{}}
}

// Create starts a session for name and returns its id: 256 random bits.
func (s *Sessions) Create(name string) string {
	id := base64.RawURLEncoding.EncodeToString(randomBytes(32))
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[id] = &session{name: name, created: now, lastSeen: now}
	return id
}

// Get returns the user a live session belongs to, and marks it used.
func (s *Sessions) Get(id string) (string, bool) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	ss := s.byID[id]
	if ss == nil {
		return "", false
	}
	if s.expired(ss, now) {
		delete(s.byID, id)
		return "", false
	}
	ss.lastSeen = now
	return ss.name, true
}

// Delete ends a session.
func (s *Sessions) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, id)
}

// Sweep drops ended sessions.
func (s *Sessions) Sweep() {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, ss := range s.byID {
		if s.expired(ss, now) {
			delete(s.byID, id)
		}
	}
}

// Clear ends every session, for example after the login changes.
func (s *Sessions) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.byID)
}

// Len is the number of sessions held, live or not yet swept.
func (s *Sessions) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byID)
}

func (s *Sessions) expired(ss *session, now time.Time) bool {
	return now.Sub(ss.lastSeen) > s.idle || now.Sub(ss.created) > s.max
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b) // never fails; see crypto/rand.Read
	return b
}

package web

import (
	"crypto/rand"
	"encoding/base64"
	"slices"
	"sync"
	"time"
)

// Session is a signed-in person. Sessions live in memory: a restart signs
// everyone out, and the next visit signs them in again through the IdP.
type Session struct {
	ID      string
	User    string
	Groups  []string // the person's groups that some rule names
	Created time.Time
}

type session struct {
	Session
	lastSeen time.Time
	flash    *flash
}

// Sessions holds sessions in memory.
type Sessions struct {
	idle, max time.Duration
	now       func() time.Time

	mu   sync.Mutex
	byID map[string]*session
}

// NewSessions returns a store whose sessions end after idle without use, or
// max after they began.
func NewSessions(idle, max time.Duration) *Sessions {
	return &Sessions{idle: idle, max: max, now: time.Now, byID: map[string]*session{}}
}

// Create starts a session and returns its id: 256 random bits.
func (s *Sessions) Create(user string, groups []string) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	id := base64.RawURLEncoding.EncodeToString(b)
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[id] = &session{Session: Session{ID: id, User: user, Groups: slices.Clone(groups), Created: now}, lastSeen: now}
	return id
}

// Get returns a live session and marks it used.
func (s *Sessions) Get(id string) (Session, bool) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	ss := s.byID[id]
	if ss == nil {
		return Session{}, false
	}
	if s.expired(ss, now) {
		delete(s.byID, id)
		return Session{}, false
	}
	ss.lastSeen = now
	return ss.Session, true
}

// SetFlash keeps a message for the session's next page.
func (s *Sessions) SetFlash(id string, f *flash) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ss := s.byID[id]; ss != nil {
		ss.flash = f
	}
}

// TakeFlash returns and forgets the session's message.
func (s *Sessions) TakeFlash(id string) *flash {
	s.mu.Lock()
	defer s.mu.Unlock()
	ss := s.byID[id]
	if ss == nil {
		return nil
	}
	f := ss.flash
	ss.flash = nil
	return f
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

// Len is the number of sessions held.
func (s *Sessions) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byID)
}

func (s *Sessions) expired(ss *session, now time.Time) bool {
	return now.Sub(ss.lastSeen) > s.idle || now.Sub(ss.Created) > s.max
}

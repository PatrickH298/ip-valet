package httpapi

import (
	"context"
	"io"
	"net/http"
	"time"
)

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) error {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, "ok\n")
	return nil
}

// readyFor is how long a readiness result is reused. /readyz needs no
// authentication, so without this every probe would take a database
// connection; with it, at most one check runs per second however many
// requests arrive.
const readyFor = time.Second

// readiness returns "" when ready, or what is wrong. Concurrent callers wait
// for the one check in flight instead of starting their own.
func (s *Server) readiness() string {
	s.readyMu.Lock()
	defer s.readyMu.Unlock()
	if !s.readyAt.IsZero() && time.Since(s.readyAt) < readyFor {
		return s.readyErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s.readyErr = ""
	var one int
	if err := s.Pool.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil {
		s.readyErr = "database unreachable"
	}
	s.readyAt = time.Now()
	return s.readyErr
}

func (s *Server) readyz(w http.ResponseWriter, _ *http.Request) error {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	problem := s.readiness()
	if problem == "" && s.Listener != nil && !s.Listener.Up() {
		problem = "LISTEN connection down"
	}
	if problem != "" {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, problem+"\n")
		return nil
	}
	_, _ = io.WriteString(w, "ok\n")
	return nil
}

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

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	var one int
	if err := s.Pool.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "database unreachable\n")
		return nil
	}
	if s.Listener != nil && !s.Listener.Up() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "LISTEN connection down\n")
		return nil
	}
	_, _ = io.WriteString(w, "ok\n")
	return nil
}

package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PatrickH298/ip-valet/api/internal/auth"
	"github.com/PatrickH298/ip-valet/api/internal/db"
	"github.com/PatrickH298/ip-valet/api/internal/events"
)

// sseWriter writes Server-Sent Events and flushes after each one.
type sseWriter struct {
	w  http.ResponseWriter
	rc *http.ResponseController
}

// startSSE sends the stream headers and lifts the server's read and write
// deadlines for this request only.
func startSSE(w http.ResponseWriter) (*sseWriter, error) {
	rc := http.NewResponseController(w)
	if err := rc.SetWriteDeadline(time.Time{}); err != nil {
		return nil, err
	}
	// A read deadline would cancel the request context once it passes.
	_ = rc.SetReadDeadline(time.Time{})
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	s := &sseWriter{w: w, rc: rc}
	return s, rc.Flush()
}

func (s *sseWriter) event(id, name string, data any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	if id != "" {
		if _, err := fmt.Fprintf(s.w, "id: %s\n", id); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(s.w, "event: %s\ndata: %s\n\n", name, b); err != nil {
		return err
	}
	return s.rc.Flush()
}

func (s *sseWriter) ping() error {
	if _, err := fmt.Fprint(s.w, ": ping\n\n"); err != nil {
		return err
	}
	return s.rc.Flush()
}

// beginStream registers a stream for shutdown, or refuses it while shutting down.
func (s *Server) beginStream() (context.Context, func(), error) {
	if s.streams.Err() != nil {
		return nil, nil, &apiError{Status: http.StatusServiceUnavailable, Code: "unavailable", Message: "shutting down"}
	}
	s.streamWG.Add(1)
	return s.streams, s.streamWG.Done, nil
}

var errTooManyStreams = &apiError{Status: http.StatusTooManyRequests, Code: "too_many_streams",
	Message: "this key already has the maximum number of open event streams"}

type changedEvent struct {
	Revision int64 `json:"revision"`
}

func (s *Server) workerEvents(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	if err := checkQuery(r); err != nil {
		return err
	}
	stop, done, err := s.beginStream()
	if err != nil {
		return err
	}
	defer done()
	sub, ok := s.Hub.Subscribe(events.KindWorker, p.WorkerID, p.KeyID, s.Config.MaxStreamsPerKey)
	if !ok {
		return errTooManyStreams
	}
	defer s.Hub.Unsubscribe(sub)

	ctx := r.Context()
	sse, err := startSSE(w)
	if err != nil {
		return nil
	}
	send := func() error {
		rev, err := db.CurrentRevision(ctx, s.Pool)
		if err != nil {
			rev = s.Hub.Revision()
		}
		return sse.event(fmt.Sprint(rev), "changed", changedEvent{Revision: rev})
	}
	// Always send one event on connect, whatever Last-Event-ID says.
	if err := send(); err != nil {
		return nil
	}
	hb := time.NewTicker(s.Config.SSEHeartbeat)
	defer hb.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-stop.Done():
			return nil
		case <-sub.C:
			if ok, err := s.Auth.StillValid(ctx, p); err == nil && !ok {
				return nil
			}
			if err := send(); err != nil {
				return nil
			}
		case <-hb.C:
			// A revoked or expired key loses its stream within one heartbeat.
			if ok, err := s.Auth.StillValid(ctx, p); err == nil && !ok {
				return nil
			}
			if err := sse.ping(); err != nil {
				return nil
			}
		}
	}
}

type entryEvent struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

// clientEntryStates computes the overall state of every entry in the
// client's realms that is live or ended within the last 24 hours.
func (s *Server) clientEntryStates(ctx context.Context, clientID string) ([]entryEvent, error) {
	var out []entryEvent
	err := db.InTx(ctx, s.Pool, db.SnapshotRead, func(tx pgx.Tx) error {
		entries, err := db.QueryEntries(ctx, tx, `SELECT `+db.EntryCols+` FROM entries e
			WHERE e.realm IN (SELECT realm FROM client_realms WHERE client_id = $1)
			  AND ((e.deleted_at IS NULL AND (e.expires_at IS NULL OR e.expires_at > now() - interval '24 hours'))
			       OR e.deleted_at > now() - interval '24 hours')
			ORDER BY e.created_at, e.id`, clientID)
		if err != nil {
			return err
		}
		sc, err := loadStateContext(ctx, tx, entries)
		if err != nil {
			return err
		}
		for i := range entries {
			st, _ := sc.entryState(&entries[i])
			out = append(out, entryEvent{ID: entries[i].ID, State: st})
		}
		return nil
	})
	return out, err
}

func (s *Server) clientEvents(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	if err := checkQuery(r); err != nil {
		return err
	}
	ctx := r.Context()
	baseline, err := s.clientEntryStates(ctx, p.ClientID)
	if err != nil {
		return err
	}
	stop, done, err := s.beginStream()
	if err != nil {
		return err
	}
	defer done()
	sub, ok := s.Hub.Subscribe(events.KindClient, "", p.KeyID, s.Config.MaxStreamsPerKey)
	if !ok {
		return errTooManyStreams
	}
	defer s.Hub.Unsubscribe(sub)

	sse, err := startSSE(w)
	if err != nil {
		return nil
	}
	prev := make(map[string]string, len(baseline))
	for _, e := range baseline {
		prev[e.ID] = e.State
	}
	hb := time.NewTicker(s.Config.SSEHeartbeat)
	defer hb.Stop()
	recheck := time.NewTicker(s.Config.ClientEventsRecheck)
	defer recheck.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-stop.Done():
			return nil
		case <-hb.C:
			if ok, err := s.Auth.StillValid(ctx, p); err == nil && !ok {
				return nil
			}
			if err := sse.ping(); err != nil {
				return nil
			}
			continue
		case <-sub.C:
		case <-recheck.C:
		}
		if ok, err := s.Auth.StillValid(ctx, p); err == nil && !ok {
			return nil
		}
		cur, err := s.clientEntryStates(ctx, p.ClientID)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.Log.Warn("client events: recompute failed", "error", err.Error())
			continue
		}
		next := make(map[string]string, len(cur))
		for _, e := range cur {
			next[e.ID] = e.State
			if prev[e.ID] != e.State {
				if err := sse.event("", "entry", e); err != nil {
					return nil
				}
			}
		}
		prev = next
	}
}

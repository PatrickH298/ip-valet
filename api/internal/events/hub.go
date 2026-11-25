// Package events is the in-process hub that turns Postgres notifications into
// wake-ups for SSE streams.
package events

import (
	"sync"
	"sync/atomic"
)

// Stream kinds.
const (
	KindWorker = "worker"
	KindClient = "client"
)

// Sub is one registered stream. C holds at most one pending wake-up.
type Sub struct {
	C        chan struct{}
	kind     string
	workerID string
	keyID    string
}

// Hub fans notifications out to registered streams without blocking:
// a slow stream gets one pending wake-up, never a backlog.
type Hub struct {
	mu   sync.Mutex
	subs map[*Sub]struct{}
	rev  atomic.Int64
}

// NewHub returns an empty hub.
func NewHub() *Hub { return &Hub{subs: map[*Sub]struct{}{}} }

// Subscribe registers a stream opened with keyID. workerID is set for worker
// streams. It refuses (false) once keyID already holds maxPerKey streams on
// this instance, so one key cannot multiply the work every change causes.
func (h *Hub) Subscribe(kind, workerID, keyID string, maxPerKey int) (*Sub, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for s := range h.subs {
		if s.keyID == keyID {
			n++
		}
	}
	if n >= maxPerKey {
		return nil, false
	}
	s := &Sub{C: make(chan struct{}, 1), kind: kind, workerID: workerID, keyID: keyID}
	h.subs[s] = struct{}{}
	return s, true
}

// Unsubscribe removes a stream.
func (h *Hub) Unsubscribe(s *Sub) {
	h.mu.Lock()
	delete(h.subs, s)
	h.mu.Unlock()
}

func (h *Hub) wake(match func(*Sub) bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs {
		if match(s) {
			select {
			case s.C <- struct{}{}:
			default:
			}
		}
	}
}

// Changed handles an ipvalet_changes notification: wakes every stream.
func (h *Hub) Changed(rev int64) {
	for {
		cur := h.rev.Load()
		if rev <= cur || h.rev.CompareAndSwap(cur, rev) {
			break
		}
	}
	h.wake(func(*Sub) bool { return true })
}

// Status handles an ipvalet_status notification: wakes client streams.
func (h *Hub) Status(string) {
	h.wake(func(s *Sub) bool { return s.kind == KindClient })
}

// WakeAll wakes every stream, used after the LISTEN connection reconnects.
func (h *Hub) WakeAll() { h.wake(func(*Sub) bool { return true }) }

// Revision returns the highest revision seen in a notification.
func (h *Hub) Revision() int64 { return h.rev.Load() }

// WorkerStreams counts connected worker streams per worker id.
func (h *Hub) WorkerStreams() map[string]int {
	out := map[string]int{}
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs {
		if s.kind == KindWorker {
			out[s.workerID]++
		}
	}
	return out
}

// ClientStreams counts connected client streams.
func (h *Hub) ClientStreams() int {
	n := 0
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs {
		if s.kind == KindClient {
			n++
		}
	}
	return n
}

package httpapi

import (
	"context"
	"net/netip"
	"time"

	"github.com/PatrickH298/ip-valet/api/internal/db"
	"github.com/PatrickH298/ip-valet/api/internal/state"
)

// clientWorkerView is an entry's state on one worker, as clients see it.
type clientWorkerView struct {
	Label string `json:"label"`
	State string `json:"state"`
	Code  string `json:"code,omitempty"`
}

// adminWorkerView adds admin-only worker fields.
type adminWorkerView struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Label      string  `json:"label"`
	State      string  `json:"state"`
	Code       string  `json:"code,omitempty"`
	LastSeenAt *string `json:"last_seen_at"`
}

type entryView struct {
	ID           string             `json:"id"`
	SubmissionID string             `json:"submission_id"`
	Realm        string             `json:"realm"`
	User         string             `json:"user"`
	Group        string             `json:"group"`
	Prefix       string             `json:"prefix"`
	ExpiresAt    *string            `json:"expires_at"`
	CreatedAt    string             `json:"created_at"`
	UpdatedAt    string             `json:"updated_at"`
	DeletedAt    *string            `json:"deleted_at"`
	State        string             `json:"state"`
	Workers      []clientWorkerView `json:"workers"`
}

type adminEntryView struct {
	ID           string            `json:"id"`
	SubmissionID string            `json:"submission_id"`
	Realm        string            `json:"realm"`
	User         string            `json:"user"`
	Group        string            `json:"group"`
	Prefix       string            `json:"prefix"`
	ExpiresAt    *string           `json:"expires_at"`
	CreatedAt    string            `json:"created_at"`
	UpdatedAt    string            `json:"updated_at"`
	DeletedAt    *string           `json:"deleted_at"`
	State        string            `json:"state"`
	Workers      []adminWorkerView `json:"workers"`
	ClientID     *string           `json:"client_id"`
	KeyID        *string           `json:"key_id"`
	Revision     int64             `json:"revision"`
	DeletedBy    *string           `json:"deleted_by"`
}

// stateContext is what applied state needs: workers, rejections and the
// database time, read in one snapshot.
type stateContext struct {
	workers []state.Worker
	rej     state.Rejections
	rem     state.Removals
	now     time.Time
}

func (c *stateContext) entryState(e *state.Entry) (string, []state.WorkerState) {
	return state.EntryState(e, c.workers, c.rej, c.rem, c.now)
}

// loadStateContext loads workers, the rejections for the given entries'
// prefixes and the database time.
func loadStateContext(ctx context.Context, q db.Querier, entries []state.Entry) (*stateContext, error) {
	workers, err := db.LoadWorkers(ctx, q)
	if err != nil {
		return nil, err
	}
	seen := map[netip.Prefix]bool{}
	prefixes := []netip.Prefix{}
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		ids = append(ids, e.ID)
		if !seen[e.Prefix] {
			seen[e.Prefix] = true
			prefixes = append(prefixes, e.Prefix)
		}
	}
	rej, err := db.LoadRejections(ctx, q, prefixes)
	if err != nil {
		return nil, err
	}
	rem, err := db.LoadRemovals(ctx, q, ids)
	if err != nil {
		return nil, err
	}
	now, err := db.Now(ctx, q)
	if err != nil {
		return nil, err
	}
	return &stateContext{workers: workers, rej: rej, rem: rem, now: now}, nil
}

func clientWorkers(per []state.WorkerState) []clientWorkerView {
	out := make([]clientWorkerView, 0, len(per))
	for _, t := range per {
		out = append(out, clientWorkerView{Label: t.Worker.Label, State: t.State, Code: t.Code})
	}
	return out
}

func adminWorkers(per []state.WorkerState) []adminWorkerView {
	out := make([]adminWorkerView, 0, len(per))
	for _, t := range per {
		out = append(out, adminWorkerView{ID: t.Worker.ID, Name: t.Worker.Name, Label: t.Worker.Label,
			State: t.State, Code: t.Code, LastSeenAt: tsPtr(t.Worker.LastSeenAt)})
	}
	return out
}

func (c *stateContext) clientView(e *state.Entry) entryView {
	st, per := c.entryState(e)
	return entryView{
		ID: e.ID, SubmissionID: e.SubmissionID, Realm: e.Realm, User: e.User, Group: e.Group,
		Prefix: e.Prefix.String(), ExpiresAt: tsPtr(e.ExpiresAt), CreatedAt: ts(e.CreatedAt),
		UpdatedAt: ts(e.UpdatedAt), DeletedAt: tsPtr(e.DeletedAt), State: st, Workers: clientWorkers(per),
	}
}

func (c *stateContext) adminView(e *state.Entry) adminEntryView {
	st, per := c.entryState(e)
	return adminEntryView{
		ID: e.ID, SubmissionID: e.SubmissionID, Realm: e.Realm, User: e.User, Group: e.Group,
		Prefix: e.Prefix.String(), ExpiresAt: tsPtr(e.ExpiresAt), CreatedAt: ts(e.CreatedAt),
		UpdatedAt: ts(e.UpdatedAt), DeletedAt: tsPtr(e.DeletedAt), State: st, Workers: adminWorkers(per),
		ClientID: e.ClientID, KeyID: e.KeyID, Revision: e.Revision, DeletedBy: e.DeletedBy,
	}
}

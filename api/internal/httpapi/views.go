package httpapi

import (
	"context"
	"net/netip"
	"time"

	"github.com/PatrickH298/ip-valet/api/internal/db"
	"github.com/PatrickH298/ip-valet/api/internal/state"
)

// clientTargetView is an entry's state on one target, as clients see it.
type clientTargetView struct {
	Label string `json:"label"`
	State string `json:"state"`
	Code  string `json:"code,omitempty"`
}

// adminTargetView adds admin-only target fields.
type adminTargetView struct {
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
	Targets      []clientTargetView `json:"targets"`
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
	Targets      []adminTargetView `json:"targets"`
	ClientID     *string           `json:"client_id"`
	KeyID        *string           `json:"key_id"`
	Revision     int64             `json:"revision"`
	DeletedBy    *string           `json:"deleted_by"`
}

// stateContext is what applied state needs: targets, rejections and the
// database time, read in one snapshot.
type stateContext struct {
	targets []state.Target
	rej     state.Rejections
	rem     state.Removals
	now     time.Time
}

func (c *stateContext) entryState(e *state.Entry) (string, []state.TargetState) {
	return state.EntryState(e, c.targets, c.rej, c.rem, c.now)
}

// loadStateContext loads targets, the rejections for the given entries'
// prefixes and the database time.
func loadStateContext(ctx context.Context, q db.Querier, entries []state.Entry) (*stateContext, error) {
	targets, err := db.LoadTargets(ctx, q)
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
	return &stateContext{targets: targets, rej: rej, rem: rem, now: now}, nil
}

func clientTargets(per []state.TargetState) []clientTargetView {
	out := make([]clientTargetView, 0, len(per))
	for _, t := range per {
		out = append(out, clientTargetView{Label: t.Target.Label, State: t.State, Code: t.Code})
	}
	return out
}

func adminTargets(per []state.TargetState) []adminTargetView {
	out := make([]adminTargetView, 0, len(per))
	for _, t := range per {
		out = append(out, adminTargetView{ID: t.Target.ID, Name: t.Target.Name, Label: t.Target.Label,
			State: t.State, Code: t.Code, LastSeenAt: tsPtr(t.Target.LastSeenAt)})
	}
	return out
}

func (c *stateContext) clientView(e *state.Entry) entryView {
	st, per := c.entryState(e)
	return entryView{
		ID: e.ID, SubmissionID: e.SubmissionID, Realm: e.Realm, User: e.User, Group: e.Group,
		Prefix: e.Prefix.String(), ExpiresAt: tsPtr(e.ExpiresAt), CreatedAt: ts(e.CreatedAt),
		UpdatedAt: ts(e.UpdatedAt), DeletedAt: tsPtr(e.DeletedAt), State: st, Targets: clientTargets(per),
	}
}

func (c *stateContext) adminView(e *state.Entry) adminEntryView {
	st, per := c.entryState(e)
	return adminEntryView{
		ID: e.ID, SubmissionID: e.SubmissionID, Realm: e.Realm, User: e.User, Group: e.Group,
		Prefix: e.Prefix.String(), ExpiresAt: tsPtr(e.ExpiresAt), CreatedAt: ts(e.CreatedAt),
		UpdatedAt: ts(e.UpdatedAt), DeletedAt: tsPtr(e.DeletedAt), State: st, Targets: adminTargets(per),
		ClientID: e.ClientID, KeyID: e.KeyID, Revision: e.Revision, DeletedBy: e.DeletedBy,
	}
}

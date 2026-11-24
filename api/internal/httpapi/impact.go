package httpapi

import (
	"cmp"
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PatrickH298/ip-valet/api/internal/auth"
	"github.com/PatrickH298/ip-valet/api/internal/db"
	"github.com/PatrickH298/ip-valet/api/internal/rules"
	"github.com/PatrickH298/ip-valet/api/internal/state"
)

// Actions a confirmed change takes on an affected entry.
const (
	actionRemove  = "remove"  // soft-delete: ip_denied, prefix_too_broad, cap_exceeded
	actionShorten = "shorten" // expires_at = now + max_ttl: ttl_exceeded
	actionNone    = "none"    // unrouted: no rule fails, the entry stays
)

// impactItem is a live, unexpired entry that a change affects.
type impactItem struct {
	EntryID string `json:"entry_id"`
	Realm   string `json:"realm"`
	User    string `json:"user"`
	Group   string `json:"group"`
	Prefix  string `json:"prefix"`
	Effect  string `json:"effect"`
	Action  string `json:"action"`

	maxTTL int64 // for shorten: the max to shorten to
}

type enforcedCounts struct {
	Shortened int `json:"shortened"`
	Removed   int `json:"removed"`
}

// impactScope says which entries a change can affect.
type impactScope struct {
	realm    string // rule change: every live, unexpired entry in the realm
	targetID string // routing change: every entry the target matches before the change
}

func newItem(e *state.Entry, effect, action string) impactItem {
	return impactItem{EntryID: e.ID, Realm: e.Realm, User: e.User, Group: e.Group, Prefix: e.Prefix.String(),
		Effect: effect, Action: action}
}

// planRules decides what a rule change does to the realm's live, unexpired
// entries, so that none is left failing a rule:
//
//  1. Entries an IP or prefix rule now rejects are removed.
//  2. For each user and cap rule, if the user's distinct prefixes decided by
//     that rule exceed its limit, the most recently submitted prefixes are
//     kept and the entries holding the others are removed.
//  3. Remaining entries whose lifetime left exceeds their TTL rule's max
//     (or that are unlimited under a finite max) are shortened to now + max.
//
// Items are in the order of entries; each entry appears at most once.
func planRules(rs *rules.Set, entries []state.Entry, now time.Time) []impactItem {
	subject := func(e *state.Entry) rules.Subject {
		return rules.Subject{Realm: e.Realm, User: e.User, Group: e.Group, Prefix: e.Prefix}
	}
	removed := map[string]string{} // entry id → effect
	for i := range entries {
		e := &entries[i]
		if f := rs.CheckIP(subject(e)); f != nil {
			removed[e.ID] = f.Code
		} else if f := rs.CheckPrefix(subject(e)); f != nil {
			removed[e.ID] = f.Code
		}
	}

	type capKey struct {
		user string
		rule int
	}
	groups := map[capKey][]*state.Entry{}
	for i := range entries {
		e := &entries[i]
		if _, gone := removed[e.ID]; gone {
			continue
		}
		if c := rs.CapIndex(subject(e)); c >= 0 {
			k := capKey{e.User, c}
			groups[k] = append(groups[k], e)
		}
	}
	for k, es := range groups {
		latest := map[netip.Prefix]time.Time{}
		for _, e := range es {
			if t, ok := latest[e.Prefix]; !ok || e.UpdatedAt.After(t) {
				latest[e.Prefix] = e.UpdatedAt
			}
		}
		limit := rs.Cap[k.rule].MaxPrefixes
		if len(latest) <= limit {
			continue
		}
		prefixes := make([]netip.Prefix, 0, len(latest))
		for p := range latest {
			prefixes = append(prefixes, p)
		}
		slices.SortFunc(prefixes, func(a, b netip.Prefix) int {
			if c := latest[b].Compare(latest[a]); c != 0 {
				return c // most recently submitted first
			}
			return cmp.Compare(a.String(), b.String())
		})
		drop := map[netip.Prefix]bool{}
		for _, p := range prefixes[limit:] {
			drop[p] = true
		}
		for _, e := range es {
			if drop[e.Prefix] {
				removed[e.ID] = rules.CodeCapExceeded
			}
		}
	}

	var items []impactItem
	for i := range entries {
		e := &entries[i]
		if effect, gone := removed[e.ID]; gone {
			items = append(items, newItem(e, effect, actionRemove))
			continue
		}
		if f := rs.CheckRemainingTTL(subject(e), e.ExpiresAt, now); f != nil {
			it := newItem(e, f.Code, actionShorten)
			it.maxTTL = f.MaxTTLSeconds
			items = append(items, it)
		}
	}
	return items
}

// planRouting reports entries no target matches any more. They fail no rule,
// so they stay, reading unrouted.
func planRouting(targets []state.Target, entries []state.Entry) []impactItem {
	var items []impactItem
	for i := range entries {
		e := &entries[i]
		if !state.Routed(targets, e.Realm, e.User, e.Group, e.Prefix) {
			items = append(items, newItem(e, rules.EffectUnrouted, actionNone))
		}
	}
	return items
}

type impactParams struct {
	dryRun  bool
	confirm bool
}

func parseImpactParams(r *http.Request) (impactParams, error) {
	var p impactParams
	var err error
	if err = checkQuery(r, "dry_run", "confirm"); err != nil {
		return p, err
	}
	if p.dryRun, err = queryBool(r, "dry_run"); err != nil {
		return p, err
	}
	p.confirm, err = queryBool(r, "confirm")
	return p, err
}

// mutation is what an applied change renders for the response.
type mutation struct {
	status   int
	object   any
	warnings []rules.Warning
}

// applyFunc applies a change inside the impact transaction. rev bumps the
// revision at most once for the whole transaction.
type applyFunc func(ctx context.Context, tx pgx.Tx, rev *db.Revision) (*mutation, error)

// withImpact runs a change through the impact check: lock the counter, apply
// the change, work out what it does to existing entries, then roll back (dry
// run, or affected entries without confirm=true) or commit together with the
// removals and shortenings that keep every entry within the rules.
func (s *Server) withImpact(w http.ResponseWriter, r *http.Request, p *auth.Principal, sc impactScope, apply applyFunc) error {
	params, err := parseImpactParams(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	tx, err := s.Pool.BeginTx(ctx, db.ReadCommitted)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck // no-op after commit

	if _, err := db.LockCounter(ctx, tx); err != nil {
		return err
	}
	rev := db.NewRevision(tx)
	now, err := db.Now(ctx, tx)
	if err != nil {
		return err
	}

	// The entries the change can affect, as they are before it.
	var (
		entries []state.Entry // live and unexpired
		held    []string      // routing change: every entry the target held, expired ones too
	)
	if sc.realm != "" {
		entries, err = db.QueryEntries(ctx, tx, `SELECT `+db.EntryCols+` FROM entries e
			WHERE e.realm = $1 AND e.deleted_at IS NULL AND (e.expires_at IS NULL OR e.expires_at > now())
			ORDER BY e.created_at, e.id`, sc.realm)
	} else {
		var all []state.Entry
		all, err = db.EntriesHeldBy(ctx, tx, sc.targetID)
		for _, e := range all {
			held = append(held, e.ID)
			if !e.Ended(now) {
				entries = append(entries, e)
			}
		}
	}
	if err != nil {
		return err
	}

	m, err := apply(ctx, tx, rev)
	if err != nil {
		return err
	}

	var impact []impactItem
	if sc.realm != "" {
		rs, err := db.LoadRules(ctx, tx, sc.realm)
		if err != nil {
			return err
		}
		impact = planRules(&rs, entries, now)
	} else {
		targets, err := db.LoadTargets(ctx, tx)
		if err != nil {
			return err
		}
		impact = planRouting(targets, entries)
		// The target must confirm removing what it no longer matches.
		if _, err := db.RecordStoppedMatching(ctx, tx, sc.targetID, held, func() (int64, error) { return rev.Get(ctx) }); err != nil {
			return err
		}
	}
	if impact == nil {
		impact = []impactItem{}
	}
	extra := map[string]any{"warnings": warningsOrEmpty(m.warnings)}

	if params.dryRun {
		extra["impact"] = impact
		extra["dry_run"] = true
		return writeMutation(w, http.StatusOK, m.object, extra)
	}
	if len(impact) > 0 && !params.confirm {
		return &apiError{Status: http.StatusConflict, Code: "confirmation_required",
			Message: "the change affects existing entries; repeat with confirm=true to apply it and them", Impact: impact}
	}
	enforced, err := s.enforce(ctx, tx, p, rev, entries, impact)
	if err != nil {
		return err
	}
	if params.confirm {
		extra["impact"] = impact
		extra["enforced"] = enforced
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return writeMutation(w, m.status, m.object, extra)
}

// enforce removes and shortens the affected entries, bumping the revision
// once for the whole transaction.
func (s *Server) enforce(ctx context.Context, tx pgx.Tx, p *auth.Principal, rev *db.Revision,
	entries []state.Entry, impact []impactItem) (enforcedCounts, error) {
	var n enforcedCounts
	byID := make(map[string]*state.Entry, len(entries))
	for i := range entries {
		byID[entries[i].ID] = &entries[i]
	}
	for _, it := range impact {
		e := byID[it.EntryID]
		switch it.Action {
		case actionRemove:
			r, err := rev.Get(ctx)
			if err != nil {
				return n, err
			}
			if err := db.SoftDeleteEntries(ctx, tx, []string{e.ID}, p.Actor, r); err != nil {
				return n, err
			}
			if err := auditEntryDelete(ctx, tx, p, e, r, map[string]any{"reason": "rule change", "effect": it.Effect}); err != nil {
				return n, err
			}
			n.Removed++
		case actionShorten:
			r, err := rev.Get(ctx)
			if err != nil {
				return n, err
			}
			// updated_at is left alone: it records when the entry was last submitted.
			var expires time.Time
			if err := tx.QueryRow(ctx, `UPDATE entries SET expires_at = now() + $2::bigint * interval '1 second',
				revision = $3 WHERE id = $1 RETURNING expires_at`, e.ID, it.maxTTL, r).Scan(&expires); err != nil {
				return n, err
			}
			if err := db.InsertAudit(ctx, tx, db.Audit{
				Actor: p.Actor, Action: "entry.shorten", ObjectType: "entry", ObjectID: e.ID,
				Realm: &e.Realm, User: &e.User, Group: &e.Group, Prefix: &e.Prefix,
				Details: map[string]any{"reason": "rule change", "revision": r,
					"max_ttl": rules.FormatSeconds(it.maxTTL), "previous_expires_at": tsPtr(e.ExpiresAt), "expires_at": ts(expires)},
			}); err != nil {
				return n, err
			}
			n.Shortened++
		}
	}
	return n, nil
}

// writeMutation writes an object with extra top-level fields (warnings, impact...).
func writeMutation(w http.ResponseWriter, status int, object any, extra map[string]any) error {
	b, err := json.Marshal(object)
	if err != nil {
		return err
	}
	m := map[string]any{}
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	for k, v := range extra {
		m[k] = v
	}
	writeJSON(w, status, m)
	return nil
}

// respondMutation writes an admin mutation that needs no impact check.
func respondMutation(w http.ResponseWriter, status int, object any, warnings []rules.Warning) error {
	return writeMutation(w, status, object, map[string]any{"warnings": warningsOrEmpty(warnings)})
}

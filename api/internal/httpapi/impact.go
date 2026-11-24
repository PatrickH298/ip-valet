package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PatrickH298/ip-valet/api/internal/auth"
	"github.com/PatrickH298/ip-valet/api/internal/db"
	"github.com/PatrickH298/ip-valet/api/internal/rules"
	"github.com/PatrickH298/ip-valet/api/internal/state"
)

// impactItem is a live, unexpired entry that a change makes fail.
type impactItem struct {
	EntryID string `json:"entry_id"`
	Realm   string `json:"realm"`
	User    string `json:"user"`
	Group   string `json:"group"`
	Prefix  string `json:"prefix"`
	Effect  string `json:"effect"`

	maxTTL int64 // for ttl_exceeded: the max to shorten to
}

type enforcedCounts struct {
	Shortened int `json:"shortened"`
	Removed   int `json:"removed"`
}

// impactScope says which entries a change could affect and what to re-check.
type impactScope struct {
	realm    string // rule change: every live, unexpired entry in the realm; re-check rules
	targetID string // routing change: what the target matched before; re-check routing
}

type effect struct {
	code   string
	maxTTL int64
}

// scopeEntries selects the entries a change could affect, before it is applied.
func scopeEntries(ctx context.Context, tx pgx.Tx, sc impactScope) ([]state.Entry, error) {
	if sc.realm != "" {
		return db.QueryEntries(ctx, tx, `SELECT `+db.EntryCols+` FROM entries e
			WHERE e.realm = $1 AND e.deleted_at IS NULL AND (e.expires_at IS NULL OR e.expires_at > now())
			ORDER BY e.created_at, e.id`, sc.realm)
	}
	return db.QueryEntries(ctx, tx, `SELECT `+db.EntryCols+` FROM entries e JOIN targets t ON t.id = $1
		WHERE e.deleted_at IS NULL AND (e.expires_at IS NULL OR e.expires_at > now())
		  AND ((family(e.prefix) = 4 AND t.ipv4) OR (family(e.prefix) = 6 AND t.ipv6))
		  AND EXISTS (SELECT 1 FROM subscriptions s WHERE s.target_id = t.id
		      AND (s.realm IS NULL OR s.realm = e.realm)
		      AND (s.username IS NULL OR s.username = e.username)
		      AND (s.grp IS NULL OR s.grp = e.grp))
		ORDER BY e.created_at, e.id`, sc.targetID)
}

// evalEffects returns, per entry id, every check the entry now fails, in check order.
func evalEffects(ctx context.Context, tx pgx.Tx, sc impactScope, entries []state.Entry) (map[string][]effect, error) {
	out := make(map[string][]effect, len(entries))
	if len(entries) == 0 {
		return out, nil
	}
	if sc.targetID != "" {
		targets, err := db.LoadTargets(ctx, tx)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if !state.Routed(targets, e.Realm, e.User, e.Group, e.Prefix) {
				out[e.ID] = []effect{{code: rules.EffectUnrouted}}
			}
		}
		return out, nil
	}
	rs, err := db.LoadRules(ctx, tx, sc.realm)
	if err != nil {
		return nil, err
	}
	now, err := db.Now(ctx, tx)
	if err != nil {
		return nil, err
	}
	held := map[string][]rules.Held{}
	for _, e := range entries {
		held[e.User] = append(held[e.User], rules.Held{Group: e.Group, Prefix: e.Prefix})
	}
	for _, e := range entries {
		sub := rules.Subject{Realm: e.Realm, User: e.User, Group: e.Group, Prefix: e.Prefix}
		var effs []effect
		if f := rs.CheckIP(sub); f != nil {
			effs = append(effs, effect{code: f.Code})
		}
		if f := rs.CheckPrefix(sub); f != nil {
			effs = append(effs, effect{code: f.Code})
		}
		if f := rs.CheckRemainingTTL(sub, e.ExpiresAt, now); f != nil {
			effs = append(effs, effect{code: f.Code, maxTTL: f.MaxTTLSeconds})
		}
		if f := rs.CheckCap(sub, held[e.User]); f != nil {
			effs = append(effs, effect{code: f.Code})
		}
		if effs != nil {
			out[e.ID] = effs
		}
	}
	return out, nil
}

// diffImpact reports each entry whose failing checks gained a new one; the
// item's effect is the first new failure in check order.
func diffImpact(entries []state.Entry, before, after map[string][]effect) []impactItem {
	items := []impactItem{}
	for _, e := range entries {
		had := map[string]bool{}
		for _, f := range before[e.ID] {
			had[f.code] = true
		}
		for _, f := range after[e.ID] {
			if !had[f.code] {
				items = append(items, impactItem{EntryID: e.ID, Realm: e.Realm, User: e.User, Group: e.Group,
					Prefix: e.Prefix.String(), Effect: f.code, maxTTL: f.maxTTL})
				break
			}
		}
	}
	return items
}

type impactParams struct {
	dryRun  bool
	confirm bool
	enforce bool
}

func parseImpactParams(r *http.Request) (impactParams, error) {
	var p impactParams
	var err error
	if err = checkQuery(r, "dry_run", "confirm", "on_existing"); err != nil {
		return p, err
	}
	if p.dryRun, err = queryBool(r, "dry_run"); err != nil {
		return p, err
	}
	if p.confirm, err = queryBool(r, "confirm"); err != nil {
		return p, err
	}
	switch r.URL.Query().Get("on_existing") {
	case "", "keep":
	case "enforce":
		p.enforce = true
	default:
		return p, invalid("on_existing", "must be keep or enforce")
	}
	return p, nil
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
// the change, re-evaluate affected entries, then roll back (dry run, or
// unconfirmed impact) or commit, enforcing on existing entries if asked.
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
	entries, err := scopeEntries(ctx, tx, sc)
	if err != nil {
		return err
	}
	before, err := evalEffects(ctx, tx, sc, entries)
	if err != nil {
		return err
	}
	m, err := apply(ctx, tx, rev)
	if err != nil {
		return err
	}
	after, err := evalEffects(ctx, tx, sc, entries)
	if err != nil {
		return err
	}
	impact := diffImpact(entries, before, after)
	extra := map[string]any{"warnings": warningsOrEmpty(m.warnings)}

	if params.dryRun {
		extra["impact"] = impact
		extra["dry_run"] = true
		return writeMutation(w, http.StatusOK, m.object, extra)
	}
	if len(impact) > 0 && !params.confirm {
		return &apiError{Status: http.StatusConflict, Code: "confirmation_required",
			Message: "the change affects existing entries; repeat with confirm=true", Impact: impact}
	}
	if params.confirm {
		var enforced enforcedCounts
		if params.enforce {
			if enforced, err = s.enforce(ctx, tx, p, rev, entries, impact); err != nil {
				return err
			}
		}
		extra["impact"] = impact
		extra["enforced"] = enforced
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return writeMutation(w, m.status, m.object, extra)
}

func (s *Server) enforce(ctx context.Context, tx pgx.Tx, p *auth.Principal, rev *db.Revision,
	entries []state.Entry, impact []impactItem) (enforcedCounts, error) {
	var n enforcedCounts
	byID := make(map[string]*state.Entry, len(entries))
	for i := range entries {
		byID[entries[i].ID] = &entries[i]
	}
	for _, it := range impact {
		e := byID[it.EntryID]
		switch it.Effect {
		case rules.CodeIPDenied, rules.CodePrefixTooBroad, rules.EffectUnrouted:
			r, err := rev.Get(ctx)
			if err != nil {
				return n, err
			}
			if err := db.SoftDeleteEntries(ctx, tx, []string{e.ID}, p.Actor, r); err != nil {
				return n, err
			}
			if err := auditEntryDelete(ctx, tx, p, e, r, map[string]any{"reason": "on_existing=enforce", "effect": it.Effect}); err != nil {
				return n, err
			}
			n.Removed++
		case rules.CodeTTLExceeded:
			r, err := rev.Get(ctx)
			if err != nil {
				return n, err
			}
			var expires time.Time
			if err := tx.QueryRow(ctx, `UPDATE entries SET expires_at = now() + $2::bigint * interval '1 second',
				revision = $3, updated_at = now() WHERE id = $1 RETURNING expires_at`, e.ID, it.maxTTL, r).Scan(&expires); err != nil {
				return n, err
			}
			if err := db.InsertAudit(ctx, tx, db.Audit{
				Actor: p.Actor, Action: "entry.shorten", ObjectType: "entry", ObjectID: e.ID,
				Realm: &e.Realm, User: &e.User, Group: &e.Group, Prefix: &e.Prefix,
				Details: map[string]any{"reason": "on_existing=enforce", "revision": r,
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

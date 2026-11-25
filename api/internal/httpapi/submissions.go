package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"

	"github.com/jackc/pgx/v5"

	"github.com/PatrickH298/ip-valet/api/internal/auth"
	"github.com/PatrickH298/ip-valet/api/internal/db"
	"github.com/PatrickH298/ip-valet/api/internal/rules"
	"github.com/PatrickH298/ip-valet/api/internal/state"
)

const maxGroups = 32

type submissionRequest struct {
	Realm  *string  `json:"realm"`
	User   *string  `json:"user"`
	Groups []string `json:"groups"`
	Prefix *string  `json:"prefix"`
	TTL    *string  `json:"ttl"`
}

type groupResult struct {
	Group string       `json:"group"`
	OK    bool         `json:"ok"`
	Code  string       `json:"code,omitempty"`
	Limit *rules.Limit `json:"limit,omitempty"`
}

type submissionEntryView struct {
	ID        string             `json:"id"`
	Realm     string             `json:"realm"`
	User      string             `json:"user"`
	Group     string             `json:"group"`
	Prefix    string             `json:"prefix"`
	ExpiresAt *string            `json:"expires_at"`
	Replaced  bool               `json:"replaced"`
	State     string             `json:"state"`
	Workers   []clientWorkerView `json:"workers"`
}

type submissionResponse struct {
	SubmissionID string                `json:"submission_id"`
	Prefix       string                `json:"prefix"`
	Entries      []submissionEntryView `json:"entries"`
}

// validSubmission is a submission that passed shape validation.
type validSubmission struct {
	realm     string
	user      string
	groups    []string
	prefix    netip.Prefix
	prefixErr error
	ttl       rules.TTL
}

func parseSubmission(p *auth.Principal, req *submissionRequest) (*validSubmission, error) {
	fe := fieldErrors{}
	v := &validSubmission{}
	switch {
	case req.Realm != nil:
		if !rules.ValidRealm(*req.Realm) {
			fe.add("realm", "must match ^[a-z0-9][a-z0-9._-]{0,62}$")
		}
		v.realm = *req.Realm
	case len(p.Realms) == 1:
		v.realm = p.Realms[0]
	default:
		fe.add("realm", "required when the client is bound to more than one realm")
	}
	switch {
	case req.User == nil:
		fe.add("user", "required")
	case !rules.ValidIdent(*req.User):
		fe.add("user", "must be 1 to 256 characters without control characters, and not \"*\"")
	default:
		v.user = *req.User
	}
	switch {
	case len(req.Groups) == 0:
		fe.add("groups", "must not be empty")
	case len(req.Groups) > maxGroups:
		fe.add("groups", fmt.Sprintf("at most %d groups", maxGroups))
	}
	seen := map[string]bool{}
	for _, g := range req.Groups {
		if !rules.ValidIdent(g) {
			fe.add("groups", "each group must be 1 to 256 characters without control characters, and not \"*\"")
			continue
		}
		if !seen[g] {
			seen[g] = true
			v.groups = append(v.groups, g)
		}
	}
	if req.Prefix == nil {
		fe.add("prefix", "required")
	} else {
		v.prefix, v.prefixErr = rules.NormalizePrefix(*req.Prefix)
	}
	if req.TTL == nil {
		fe.add("ttl", "required")
	} else if t, err := rules.ParseTTL(*req.TTL); err != nil {
		fe.add("ttl", err.Error())
	} else {
		v.ttl = t
	}
	if err := fe.err(); err != nil {
		return nil, err
	}
	return v, nil
}

func (s *Server) postSubmission(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var req submissionRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	sub, err := parseSubmission(p, &req)
	if err != nil {
		return err
	}
	ctx := r.Context()

	type written struct {
		entry    state.Entry
		replaced bool
	}
	var (
		out          []written
		submissionID = newUUID()
		results      = make([]groupResult, len(sub.groups))
	)
	err = db.InTx(ctx, s.Pool, db.ReadCommitted, func(tx pgx.Tx) error {
		if _, err := db.LockCounter(ctx, tx); err != nil {
			return err
		}
		var (
			rs      rules.Set
			workers []state.Worker
			held    []rules.Held
		)
		realmOK := p.HasRealm(sub.realm)
		if realmOK && sub.prefixErr == nil {
			var err error
			if rs, err = db.LoadRules(ctx, tx, sub.realm); err != nil {
				return err
			}
			if workers, err = db.LoadWorkers(ctx, tx); err != nil {
				return err
			}
			if held, err = loadHeld(ctx, tx, sub.realm, sub.user); err != nil {
				return err
			}
		}

		failed := 0
		for i, g := range sub.groups {
			results[i] = groupResult{Group: g, OK: true}
			var f *rules.Failure
			cand := rules.Subject{Realm: sub.realm, User: sub.user, Group: g, Prefix: sub.prefix}
			switch {
			case !realmOK:
				f = &rules.Failure{Code: rules.CodeRealmNotAllowed}
			case sub.prefixErr != nil:
				f = &rules.Failure{Code: rules.CodeInvalidPrefix}
			case !state.Routed(workers, sub.realm, sub.user, g, sub.prefix):
				f = &rules.Failure{Code: rules.CodeNoSubscriber}
			default:
				f = rs.CheckRules(cand, sub.ttl, held)
			}
			if f != nil {
				failed++
				results[i] = groupResult{Group: g, OK: false, Code: f.Code, Limit: f.Limit}
			}
		}
		if failed > 0 {
			return &apiError{Status: http.StatusUnprocessableEntity, Code: "submission_rejected",
				Message: fmt.Sprintf("%d of %d groups failed", failed, len(sub.groups)), Results: results}
		}

		rev, err := db.Bump(ctx, tx)
		if err != nil {
			return err
		}
		var ttlSecs *int64
		if !sub.ttl.Unlimited {
			ttlSecs = &sub.ttl.Seconds
		}
		for _, g := range sub.groups {
			row := tx.QueryRow(ctx, `
				INSERT INTO entries AS e (submission_id, realm, username, grp, prefix, expires_at, revision, client_id, key_id)
				VALUES ($1, $2, $3, $4, $5,
				        CASE WHEN $6::bigint IS NULL THEN NULL ELSE now() + $6::bigint * interval '1 second' END,
				        $7, $8, $9)
				ON CONFLICT (realm, username, grp, prefix) WHERE deleted_at IS NULL
				DO UPDATE SET submission_id = EXCLUDED.submission_id, expires_at = EXCLUDED.expires_at,
				              revision = EXCLUDED.revision, client_id = EXCLUDED.client_id,
				              key_id = EXCLUDED.key_id, updated_at = now()
				RETURNING `+db.EntryCols+`, (e.xmax <> 0)`,
				submissionID, sub.realm, sub.user, g, sub.prefix, ttlSecs, rev, p.ClientID, p.KeyID)
			var wr written
			e := &wr.entry
			if err := row.Scan(&e.ID, &e.SubmissionID, &e.Realm, &e.User, &e.Group, &e.Prefix, &e.ExpiresAt,
				&e.Revision, &e.ClientID, &e.KeyID, &e.CreatedAt, &e.UpdatedAt, &e.DeletedAt, &e.DeletedBy,
				&e.DeletedRevision, &wr.replaced); err != nil {
				return err
			}
			action := "entry.create"
			if wr.replaced {
				action = "entry.replace"
			}
			if err := db.InsertAudit(ctx, tx, db.Audit{
				Actor: p.Actor, ClientID: &p.ClientID, Action: action, ObjectType: "entry", ObjectID: e.ID,
				Realm: &e.Realm, User: &e.User, Group: &e.Group, Prefix: &e.Prefix,
				Details: map[string]any{"submission_id": submissionID, "revision": rev,
					"ttl": sub.ttl.String(), "expires_at": tsPtr(e.ExpiresAt), "key_id": p.KeyID},
			}); err != nil {
				return err
			}
			out = append(out, wr)
		}
		return nil
	})
	if s.Metrics != nil {
		result := "accepted"
		if err != nil {
			result = ""
			for _, gr := range results {
				if !gr.OK && gr.Code != "" {
					result = gr.Code
					break
				}
			}
		}
		if result != "" {
			s.Metrics.Submissions.WithLabelValues(result).Inc()
		}
	}
	if err != nil {
		return err
	}

	entries := make([]state.Entry, len(out))
	for i := range out {
		entries[i] = out[i].entry
	}
	resp := submissionResponse{SubmissionID: submissionID, Prefix: sub.prefix.String()}
	err = db.InTx(ctx, s.Pool, db.SnapshotRead, func(tx pgx.Tx) error {
		sc, err := loadStateContext(ctx, tx, entries)
		if err != nil {
			return err
		}
		for _, wr := range out {
			st, per := sc.entryState(&wr.entry)
			resp.Entries = append(resp.Entries, submissionEntryView{
				ID: wr.entry.ID, Realm: wr.entry.Realm, User: wr.entry.User, Group: wr.entry.Group,
				Prefix: wr.entry.Prefix.String(), ExpiresAt: tsPtr(wr.entry.ExpiresAt), Replaced: wr.replaced,
				State: st, Workers: clientWorkers(per),
			})
		}
		return nil
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, resp)
	return nil
}

// loadHeld returns the user's live, unexpired entries in the realm.
func loadHeld(ctx context.Context, q db.Querier, realm, user string) ([]rules.Held, error) {
	rows, err := q.Query(ctx, `
		SELECT grp::text, prefix FROM entries
		WHERE realm = $1 AND username = $2 AND deleted_at IS NULL
		  AND (expires_at IS NULL OR expires_at > now())`, realm, user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []rules.Held
	for rows.Next() {
		var h rules.Held
		if err := rows.Scan(&h.Group, &h.Prefix); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

type deletedResponse struct {
	Deleted []string `json:"deleted"`
}

func (s *Server) deleteSubmission(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	id := r.PathValue("id")
	if !validUUID(id) {
		return errNotFound
	}
	ctx := r.Context()
	ids := []string{}
	err := db.InTx(ctx, s.Pool, db.ReadCommitted, func(tx pgx.Tx) error {
		if _, err := db.LockCounter(ctx, tx); err != nil {
			return err
		}
		entries, err := db.QueryEntries(ctx, tx, `SELECT `+db.EntryCols+` FROM entries e
			WHERE e.submission_id = $1 AND e.deleted_at IS NULL ORDER BY e.created_at, e.id FOR UPDATE`, id)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			return errNotFound
		}
		for _, e := range entries {
			if !p.HasRealm(e.Realm) {
				return errNotFound
			}
		}
		rev, err := db.Bump(ctx, tx)
		if err != nil {
			return err
		}
		for _, e := range entries {
			ids = append(ids, e.ID)
		}
		if err := db.SoftDeleteEntries(ctx, tx, ids, p.Actor, rev); err != nil {
			return err
		}
		for _, e := range entries {
			if err := auditEntryDelete(ctx, tx, p, &e, rev, nil); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, deletedResponse{Deleted: ids})
	return nil
}

func clientIDPtr(p *auth.Principal) *string {
	if p.ClientID == "" {
		return nil
	}
	return &p.ClientID
}

func auditEntryDelete(ctx context.Context, q db.Querier, p *auth.Principal, e *state.Entry, rev int64, extra map[string]any) error {
	details := map[string]any{"revision": rev, "submission_id": e.SubmissionID}
	for k, v := range extra {
		details[k] = v
	}
	return db.InsertAudit(ctx, q, db.Audit{
		Actor: p.Actor, ClientID: clientIDPtr(p), Action: "entry.delete", ObjectType: "entry", ObjectID: e.ID,
		Realm: &e.Realm, User: &e.User, Group: &e.Group, Prefix: &e.Prefix, Details: details,
	})
}

// deleteEntry soft-deletes one entry. inRealms restricts it to a client's realms.
func (s *Server) deleteEntry(ctx context.Context, p *auth.Principal, id string, inRealms bool) (*state.Entry, error) {
	if !validUUID(id) {
		return nil, errNotFound
	}
	var out *state.Entry
	err := db.InTx(ctx, s.Pool, db.ReadCommitted, func(tx pgx.Tx) error {
		if _, err := db.LockCounter(ctx, tx); err != nil {
			return err
		}
		e, err := db.GetEntry(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if e == nil || e.DeletedAt != nil || (inRealms && !p.HasRealm(e.Realm)) {
			return errNotFound
		}
		rev, err := db.Bump(ctx, tx)
		if err != nil {
			return err
		}
		if err := db.SoftDeleteEntries(ctx, tx, []string{id}, p.Actor, rev); err != nil {
			return err
		}
		if err := auditEntryDelete(ctx, tx, p, e, rev, nil); err != nil {
			return err
		}
		out, err = db.GetEntry(ctx, tx, id, false)
		return err
	})
	return out, err
}

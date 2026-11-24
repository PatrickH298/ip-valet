package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PatrickH298/ip-valet/api/internal/auth"
	"github.com/PatrickH298/ip-valet/api/internal/db"
	"github.com/PatrickH298/ip-valet/api/internal/rules"
)

type workerView struct {
	ID                    string  `json:"id"`
	Name                  string  `json:"name"`
	Label                 string  `json:"label"`
	IPv4                  bool    `json:"ipv4"`
	IPv6                  bool    `json:"ipv6"`
	AppliedRevision       int64   `json:"applied_revision"`
	AppliedGeneratedAt    *string `json:"applied_generated_at"`
	SubscriptionsRevision int64   `json:"subscriptions_revision"`
	LastSeenAt            *string `json:"last_seen_at"`
	CreatedAt             string  `json:"created_at"`
	UpdatedAt             string  `json:"updated_at"`
}

const workerSelect = `SELECT id::text, name, label, ipv4, ipv6, applied_revision, applied_generated_at,
	subscriptions_revision, last_seen_at, created_at, updated_at FROM workers`

func scanWorker(row pgx.Row) (workerView, error) {
	var (
		v      workerView
		ag, ls *time.Time
		c, u   time.Time
	)
	err := row.Scan(&v.ID, &v.Name, &v.Label, &v.IPv4, &v.IPv6, &v.AppliedRevision, &ag,
		&v.SubscriptionsRevision, &ls, &c, &u)
	v.AppliedGeneratedAt, v.LastSeenAt, v.CreatedAt, v.UpdatedAt = tsPtr(ag), tsPtr(ls), ts(c), ts(u)
	return v, err
}

func getWorkerView(ctx context.Context, q db.Querier, id string) (*workerView, error) {
	if !validUUID(id) {
		return nil, errNotFound
	}
	v, err := scanWorker(q.QueryRow(ctx, workerSelect+` WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (s *Server) listWorkers(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	if err := checkQuery(r, "limit", "cursor"); err != nil {
		return err
	}
	page, err := parsePage(r)
	if err != nil {
		return err
	}
	var c nameCursor
	after, err := page.cursorInto(&c)
	if err != nil {
		return err
	}
	rows, err := s.Pool.Query(r.Context(), workerSelect+` WHERE NOT $1 OR name > $2 ORDER BY name LIMIT $3`,
		after, c.Name, page.limit+1)
	if err != nil {
		return err
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (workerView, error) { return scanWorker(row) })
	if err != nil {
		return err
	}
	resp := listResponse[workerView]{Items: items}
	if len(items) > page.limit {
		resp.Items = items[:page.limit]
		resp.NextCursor = encodeCursor(nameCursor{Name: resp.Items[page.limit-1].Name})
	}
	if resp.Items == nil {
		resp.Items = []workerView{}
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

func (s *Server) getWorker(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	if err := checkQuery(r); err != nil {
		return err
	}
	v, err := getWorkerView(r.Context(), s.Pool, r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, v)
	return nil
}

type workerFields struct {
	name, label       string
	ipv4, ipv6        bool
	setName, setLabel bool
	setIPv4, setIPv6  bool
}

func parseWorkerFields(r *http.Request, create bool) (*workerFields, error) {
	m, err := decodeObject(r, "name", "label", "ipv4", "ipv6")
	if err != nil {
		return nil, err
	}
	fe := fieldErrors{}
	f := &workerFields{}
	if v, ok := rawString(fe, m, "name"); ok {
		if !validLabel(v, 128) {
			fe.add("name", "must be 1 to 128 characters without control characters")
		}
		f.name, f.setName = v, true
	} else if _, present := m["name"]; !present && create {
		fe.add("name", "required")
	}
	if v, ok := rawString(fe, m, "label"); ok {
		if !validLabel(v, 256) {
			fe.add("label", "must be 1 to 256 characters without control characters")
		}
		f.label, f.setLabel = v, true
	} else if _, present := m["label"]; !present && create {
		fe.add("label", "required")
	}
	for _, fam := range []struct {
		key string
		v   *bool
		set *bool
	}{{"ipv4", &f.ipv4, &f.setIPv4}, {"ipv6", &f.ipv6, &f.setIPv6}} {
		raw, ok := m[fam.key]
		if !ok {
			if create {
				fe.add(fam.key, "required")
			}
			continue
		}
		if err := json.Unmarshal(raw, fam.v); err != nil || isNull(raw) {
			fe.add(fam.key, "must be true or false")
			continue
		}
		*fam.set = true
	}
	if err := fe.err(); err != nil {
		return nil, err
	}
	return f, nil
}

func (s *Server) createWorker(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	if err := checkQuery(r); err != nil {
		return err
	}
	f, err := parseWorkerFields(r, true)
	if err != nil {
		return err
	}
	if !f.ipv4 && !f.ipv6 {
		return invalid("ipv4", "at least one of ipv4 and ipv6 must be true")
	}
	ctx := r.Context()
	var v *workerView
	err = db.InTx(ctx, s.Pool, db.ReadCommitted, func(tx pgx.Tx) error {
		var id string
		err := tx.QueryRow(ctx, `INSERT INTO workers (name, label, ipv4, ipv6) VALUES ($1, $2, $3, $4) RETURNING id::text`,
			f.name, f.label, f.ipv4, f.ipv6).Scan(&id)
		if db.IsUniqueViolation(err) {
			return errConflict
		}
		if err != nil {
			return err
		}
		if v, err = getWorkerView(ctx, tx, id); err != nil {
			return err
		}
		return db.InsertAudit(ctx, tx, db.Audit{Actor: p.Actor, Action: "worker.create", ObjectType: "worker",
			ObjectID: id, Details: map[string]any{"name": f.name, "label": f.label, "ipv4": f.ipv4, "ipv6": f.ipv6}})
	})
	if err != nil {
		return err
	}
	return respondMutation(w, http.StatusCreated, v, nil)
}

func (s *Server) patchWorker(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	if _, err := parseImpactParams(r); err != nil {
		return err
	}
	id := r.PathValue("id")
	f, err := parseWorkerFields(r, false)
	if err != nil {
		return err
	}
	ctx := r.Context()
	old, err := getWorkerView(ctx, s.Pool, id)
	if err != nil {
		return err
	}
	familyChange := (f.setIPv4 && f.ipv4 != old.IPv4) || (f.setIPv6 && f.ipv6 != old.IPv6)

	apply := func(ctx context.Context, tx pgx.Tx, rev *db.Revision) (*workerView, error) {
		cur, err := getWorkerView(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		ipv4, ipv6 := cur.IPv4, cur.IPv6
		if f.setIPv4 {
			ipv4 = f.ipv4
		}
		if f.setIPv6 {
			ipv6 = f.ipv6
		}
		if !ipv4 && !ipv6 {
			return nil, invalid("ipv4", "at least one of ipv4 and ipv6 must be true")
		}
		_, err = tx.Exec(ctx, `UPDATE workers SET
			name = CASE WHEN $2 THEN $3 ELSE name END,
			label = CASE WHEN $4 THEN $5 ELSE label END,
			ipv4 = $6, ipv6 = $7, updated_at = now() WHERE id = $1`,
			id, f.setName, f.name, f.setLabel, f.label, ipv4, ipv6)
		if db.IsUniqueViolation(err) {
			return nil, errConflict
		}
		if err != nil {
			return nil, err
		}
		details := map[string]any{"before": cur}
		if ipv4 != cur.IPv4 || ipv6 != cur.IPv6 {
			if rev == nil {
				return nil, &apiError{Status: http.StatusConflict, Code: "conflict",
					Message: "the worker changed concurrently; retry the request"}
			}
			r, err := rev.Get(ctx)
			if err != nil {
				return nil, err
			}
			if _, err := tx.Exec(ctx, `UPDATE workers SET subscriptions_revision = $2 WHERE id = $1`, id, r); err != nil {
				return nil, err
			}
			details["revision"] = r
		}
		v, err := getWorkerView(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		details["after"] = v
		return v, db.InsertAudit(ctx, tx, db.Audit{Actor: p.Actor, Action: "worker.update", ObjectType: "worker",
			ObjectID: id, Details: details})
	}

	if familyChange {
		return s.withImpact(w, r, p, impactScope{workerID: id}, func(ctx context.Context, tx pgx.Tx, rev *db.Revision) (*mutation, error) {
			v, err := apply(ctx, tx, rev)
			if err != nil {
				return nil, err
			}
			return &mutation{status: http.StatusOK, object: v}, nil
		})
	}
	var v *workerView
	err = db.InTx(ctx, s.Pool, db.ReadCommitted, func(tx pgx.Tx) error {
		var err error
		v, err = apply(ctx, tx, nil)
		return err
	})
	if err != nil {
		return err
	}
	return respondMutation(w, http.StatusOK, v, nil)
}

func (s *Server) deleteWorker(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	id := r.PathValue("id")
	if !validUUID(id) {
		return errNotFound
	}
	return s.withImpact(w, r, p, impactScope{workerID: id}, func(ctx context.Context, tx pgx.Tx, _ *db.Revision) (*mutation, error) {
		v, err := getWorkerView(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM workers WHERE id = $1`, id); err != nil {
			return nil, err
		}
		if err := db.InsertAudit(ctx, tx, db.Audit{Actor: p.Actor, Action: "worker.delete", ObjectType: "worker",
			ObjectID: id, Details: map[string]any{"worker": v}}); err != nil {
			return nil, err
		}
		return &mutation{status: http.StatusOK, object: v}, nil
	})
}

// ---------- subscriptions ----------

type subscriptionView struct {
	ID        string `json:"id"`
	WorkerID  string `json:"worker_id"`
	Realm     string `json:"realm"`
	User      string `json:"user"`
	Group     string `json:"group"`
	CreatedAt string `json:"created_at"`
}

const subscriptionSelect = `SELECT id::text, worker_id::text, realm::text, username::text, grp::text, created_at
	FROM subscriptions`

func scanSubscription(row pgx.Row) (subscriptionView, error) {
	var (
		v       subscriptionView
		r, u, g *string
		c       time.Time
	)
	err := row.Scan(&v.ID, &v.WorkerID, &r, &u, &g, &c)
	v.Realm, v.User, v.Group, v.CreatedAt = rules.SelectorString(r), rules.SelectorString(u), rules.SelectorString(g), ts(c)
	return v, err
}

func (s *Server) listSubscriptions(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	if err := checkQuery(r, "limit", "cursor"); err != nil {
		return err
	}
	ctx := r.Context()
	id := r.PathValue("id")
	if _, err := getWorkerView(ctx, s.Pool, id); err != nil {
		return err
	}
	page, err := parsePage(r)
	if err != nil {
		return err
	}
	var c timeIDCursor
	after, err := page.cursorInto(&c)
	if err != nil {
		return err
	}
	if !after {
		c.ID = "00000000-0000-0000-0000-000000000000"
	}
	rows, err := s.Pool.Query(ctx, subscriptionSelect+` WHERE worker_id = $1 AND (NOT $2 OR (created_at, id) > ($3, $4::uuid))
		ORDER BY created_at, id LIMIT $5`, id, after, c.T, c.ID, page.limit+1)
	if err != nil {
		return err
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (subscriptionView, error) { return scanSubscription(row) })
	if err != nil {
		return err
	}
	resp := listResponse[subscriptionView]{Items: items}
	if len(items) > page.limit {
		resp.Items = items[:page.limit]
		last := resp.Items[page.limit-1]
		t, _ := time.Parse(time.RFC3339Nano, last.CreatedAt)
		resp.NextCursor = encodeCursor(timeIDCursor{T: t, ID: last.ID})
	}
	if resp.Items == nil {
		resp.Items = []subscriptionView{}
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

func (s *Server) createSubscription(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	if err := checkQuery(r); err != nil {
		return err
	}
	workerID := r.PathValue("id")
	if !validUUID(workerID) {
		return errNotFound
	}
	m, err := decodeObject(r, "realm", "user", "group")
	if err != nil {
		return err
	}
	fe := fieldErrors{}
	var realm *string
	if v, ok := rawString(fe, m, "realm"); ok {
		if realm, err = rules.ParseRealmSelector(v); err != nil {
			fe.add("realm", err.Error())
		}
	} else if _, present := m["realm"]; !present {
		fe.add("realm", `required ("*" or a realm)`)
	}
	user, _ := rawSelector(fe, m, "user", true)
	group, _ := rawSelector(fe, m, "group", true)
	if err := fe.err(); err != nil {
		return err
	}
	ctx := r.Context()
	var (
		v    subscriptionView
		warn []rules.Warning
	)
	err = db.InTx(ctx, s.Pool, db.ReadCommitted, func(tx pgx.Tx) error {
		if _, err := db.LockCounter(ctx, tx); err != nil {
			return err
		}
		if _, err := getWorkerView(ctx, tx, workerID); err != nil {
			return err
		}
		if realm != nil {
			if _, err := getRealmView(ctx, tx, *realm); errors.Is(err, errNotFound) {
				return invalid("realm", "unknown realm")
			} else if err != nil {
				return err
			}
		}
		var err error
		v, err = scanSubscription(tx.QueryRow(ctx, `INSERT INTO subscriptions (worker_id, realm, username, grp)
			VALUES ($1, $2, $3, $4) RETURNING id::text, worker_id::text, realm::text, username::text, grp::text, created_at`,
			workerID, realm, user, group))
		if db.IsUniqueViolation(err) {
			return &apiError{Status: http.StatusConflict, Code: "conflict", Message: "the worker already has this subscription"}
		}
		if err != nil {
			return err
		}
		rev, err := db.Bump(ctx, tx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE workers SET subscriptions_revision = $2 WHERE id = $1`, workerID, rev); err != nil {
			return err
		}
		if w := rules.CrossRealmWarning(v.ID, realm, user, group); w != nil {
			warn = append(warn, *w)
		}
		return db.InsertAudit(ctx, tx, db.Audit{Actor: p.Actor, Action: "subscription.create", ObjectType: "subscription",
			ObjectID: v.ID, Realm: realm, User: user, Group: group,
			Details: map[string]any{"worker_id": workerID, "revision": rev}})
	})
	if err != nil {
		return err
	}
	return respondMutation(w, http.StatusCreated, v, warn)
}

func (s *Server) deleteSubscription(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	id := r.PathValue("id")
	if !validUUID(id) {
		return errNotFound
	}
	sub, err := scanSubscription(s.Pool.QueryRow(r.Context(), subscriptionSelect+` WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return errNotFound
	}
	if err != nil {
		return err
	}
	return s.withImpact(w, r, p, impactScope{workerID: sub.WorkerID}, func(ctx context.Context, tx pgx.Tx, rev *db.Revision) (*mutation, error) {
		v, err := scanSubscription(tx.QueryRow(ctx, `DELETE FROM subscriptions WHERE id = $1
			RETURNING id::text, worker_id::text, realm::text, username::text, grp::text, created_at`, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errNotFound
		}
		if err != nil {
			return nil, err
		}
		rv, err := rev.Get(ctx)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `UPDATE workers SET subscriptions_revision = $2 WHERE id = $1`, v.WorkerID, rv); err != nil {
			return nil, err
		}
		if err := db.InsertAudit(ctx, tx, db.Audit{Actor: p.Actor, Action: "subscription.delete", ObjectType: "subscription",
			ObjectID: id, Details: map[string]any{"worker_id": v.WorkerID, "realm": v.Realm, "user": v.User,
				"group": v.Group, "revision": rv}}); err != nil {
			return nil, err
		}
		return &mutation{status: http.StatusOK, object: v}, nil
	})
}

// ---------- health ----------

type rejectionView struct {
	Prefix   string  `json:"prefix"`
	Code     string  `json:"code"`
	Detail   *string `json:"detail"`
	Revision int64   `json:"revision"`
}

type workerHealthView struct {
	WorkerID           string          `json:"worker_id"`
	Name               string          `json:"name"`
	Label              string          `json:"label"`
	AppliedRevision    int64           `json:"applied_revision"`
	Revision           int64           `json:"revision"`
	Lag                int64           `json:"lag"`
	AppliedGeneratedAt *string         `json:"applied_generated_at"`
	LastSeenAt         *string         `json:"last_seen_at"`
	LastError          *string         `json:"last_error"`
	LastErrorAt        *string         `json:"last_error_at"`
	LastInstance       *string         `json:"last_instance"`
	LastVersion        *string         `json:"last_version"`
	WorkerStreams      int             `json:"worker_streams"`
	Rejections         []rejectionView `json:"rejections"`
}

type healthResponse struct {
	Revision int64              `json:"revision"`
	Workers  []workerHealthView `json:"workers"`
}

func (s *Server) loadHealth(ctx context.Context, workerID string) (*healthResponse, error) {
	out := &healthResponse{Workers: []workerHealthView{}}
	streams := s.Hub.WorkerStreams()
	err := db.InTx(ctx, s.Pool, db.SnapshotRead, func(tx pgx.Tx) error {
		var err error
		if out.Revision, err = db.CurrentRevision(ctx, tx); err != nil {
			return err
		}
		sql := `SELECT id::text, name, label, applied_revision, applied_generated_at, last_seen_at, last_error,
			last_error_at, last_instance, last_version FROM workers`
		var args []any
		if workerID != "" {
			sql += ` WHERE id = $1`
			args = append(args, workerID)
		}
		sql += ` ORDER BY name`
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		idx := map[string]int{}
		for rows.Next() {
			var (
				h          workerHealthView
				ag, ls, le *time.Time
			)
			if err := rows.Scan(&h.WorkerID, &h.Name, &h.Label, &h.AppliedRevision, &ag, &ls, &h.LastError, &le,
				&h.LastInstance, &h.LastVersion); err != nil {
				rows.Close()
				return err
			}
			h.AppliedGeneratedAt, h.LastSeenAt, h.LastErrorAt = tsPtr(ag), tsPtr(ls), tsPtr(le)
			h.Revision = out.Revision
			h.Lag = out.Revision - h.AppliedRevision
			h.WorkerStreams = streams[h.WorkerID]
			h.Rejections = []rejectionView{}
			idx[h.WorkerID] = len(out.Workers)
			out.Workers = append(out.Workers, h)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		sql = `SELECT worker_id::text, prefix, code, detail, revision FROM worker_rejections`
		if workerID != "" {
			sql += ` WHERE worker_id = $1`
		}
		sql += ` ORDER BY worker_id, prefix`
		rows, err = tx.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				tid string
				rv  rejectionView
				pfx netip.Prefix
			)
			if err := rows.Scan(&tid, &pfx, &rv.Code, &rv.Detail, &rv.Revision); err != nil {
				return err
			}
			rv.Prefix = pfx.String()
			if i, ok := idx[tid]; ok {
				out.Workers[i].Rejections = append(out.Workers[i].Rejections, rv)
			}
		}
		return rows.Err()
	})
	return out, err
}

func (s *Server) workerHealth(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	if err := checkQuery(r); err != nil {
		return err
	}
	id := r.PathValue("id")
	if !validUUID(id) {
		return errNotFound
	}
	h, err := s.loadHealth(r.Context(), id)
	if err != nil {
		return err
	}
	if len(h.Workers) == 0 {
		return errNotFound
	}
	writeJSON(w, http.StatusOK, h.Workers[0])
	return nil
}

func (s *Server) allHealth(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	if err := checkQuery(r); err != nil {
		return err
	}
	h, err := s.loadHealth(r.Context(), "")
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, h)
	return nil
}

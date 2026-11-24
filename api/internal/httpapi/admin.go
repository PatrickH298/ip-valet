package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/PatrickH298/ip-valet/api/internal/auth"
	"github.com/PatrickH298/ip-valet/api/internal/db"
	"github.com/PatrickH298/ip-valet/api/internal/rules"
)

// validLabel checks names and labels: 1 to max characters, no control characters.
func validLabel(s string, max int) bool {
	n := utf8.RuneCountInString(s)
	if !utf8.ValidString(s) || n < 1 || n > max {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// ---------- realms ----------

type realmView struct {
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
}

type nameCursor struct {
	Name string `json:"n"`
}

func (s *Server) listRealms(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
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
	rows, err := s.Pool.Query(r.Context(), `SELECT name::text, created_at FROM realms
		WHERE NOT $1 OR name > $2 ORDER BY name LIMIT $3`, after, c.Name, page.limit+1)
	if err != nil {
		return err
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (realmView, error) {
		var v realmView
		var t time.Time
		err := row.Scan(&v.Name, &t)
		v.CreatedAt = ts(t)
		return v, err
	})
	if err != nil {
		return err
	}
	resp := listResponse[realmView]{Items: items}
	if len(items) > page.limit {
		resp.Items = items[:page.limit]
		resp.NextCursor = encodeCursor(nameCursor{Name: resp.Items[page.limit-1].Name})
	}
	if resp.Items == nil {
		resp.Items = []realmView{}
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

func getRealmView(ctx context.Context, q db.Querier, name string) (*realmView, error) {
	if !rules.ValidRealm(name) {
		return nil, errNotFound
	}
	var t time.Time
	err := q.QueryRow(ctx, `SELECT created_at FROM realms WHERE name = $1`, name).Scan(&t)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	return &realmView{Name: name, CreatedAt: ts(t)}, nil
}

func (s *Server) getRealm(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	if err := checkQuery(r); err != nil {
		return err
	}
	v, err := getRealmView(r.Context(), s.Pool, r.PathValue("name"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, v)
	return nil
}

func (s *Server) createRealm(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var req struct {
		Name *string `json:"name"`
	}
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	if req.Name == nil {
		return invalid("name", "required")
	}
	if !rules.ValidRealm(*req.Name) {
		return invalid("name", "must match ^[a-z0-9][a-z0-9._-]{0,62}$")
	}
	name := *req.Name
	ctx := r.Context()
	var v *realmView
	err := db.InTx(ctx, s.Pool, db.ReadCommitted, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO realms (name) VALUES ($1)`, name); err != nil {
			if db.IsUniqueViolation(err) {
				return errConflict
			}
			return err
		}
		seed := rules.Seed(name, rules.SeedDefaults{
			TTLSeconds: int64(s.Config.DefaultTTL / time.Second),
			PrefixV4:   s.Config.DefaultPrefixV4,
			PrefixV6:   s.Config.DefaultPrefixV6,
		})
		if err := db.InsertSeed(ctx, tx, seed); err != nil {
			return err
		}
		if err := db.InsertAudit(ctx, tx, db.Audit{Actor: p.Actor, Action: "realm.create", ObjectType: "realm",
			ObjectID: name, Realm: &name}); err != nil {
			return err
		}
		var err error
		v, err = getRealmView(ctx, tx, name)
		return err
	})
	if err != nil {
		return err
	}
	return respondMutation(w, http.StatusCreated, v, nil)
}

type realmDeleteView struct {
	Name                 string `json:"name"`
	EntriesRemoved       int    `json:"entries_removed"`
	RulesDeleted         int    `json:"rules_deleted"`
	SubscriptionsDeleted int    `json:"subscriptions_deleted"`
	ClientsUnbound       int    `json:"clients_unbound"`
	Revision             *int64 `json:"revision"`
}

func (s *Server) deleteRealm(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	if err := checkQuery(r); err != nil {
		return err
	}
	name := r.PathValue("name")
	if !rules.ValidRealm(name) {
		return errNotFound
	}
	ctx := r.Context()
	out := realmDeleteView{Name: name}
	err := db.InTx(ctx, s.Pool, db.ReadCommitted, func(tx pgx.Tx) error {
		if _, err := db.LockCounter(ctx, tx); err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM realms WHERE name = $1 FOR UPDATE)`, name).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return errNotFound
		}
		entries, err := db.QueryEntries(ctx, tx, `SELECT `+db.EntryCols+` FROM entries e
			WHERE e.realm = $1 AND e.deleted_at IS NULL ORDER BY e.created_at, e.id FOR UPDATE`, name)
		if err != nil {
			return err
		}
		var targetIDs []string
		rows, err := tx.Query(ctx, `SELECT DISTINCT target_id::text FROM subscriptions WHERE realm = $1`, name)
		if err != nil {
			return err
		}
		if targetIDs, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM ip_rules WHERE realm = $1) + (SELECT count(*) FROM prefix_rules WHERE realm = $1) +
			(SELECT count(*) FROM ttl_rules WHERE realm = $1) + (SELECT count(*) FROM cap_rules WHERE realm = $1),
			(SELECT count(*) FROM subscriptions WHERE realm = $1),
			(SELECT count(*) FROM client_realms WHERE realm = $1)`, name).
			Scan(&out.RulesDeleted, &out.SubscriptionsDeleted, &out.ClientsUnbound); err != nil {
			return err
		}
		if len(entries) > 0 || out.SubscriptionsDeleted > 0 {
			rev, err := db.Bump(ctx, tx)
			if err != nil {
				return err
			}
			out.Revision = &rev
			ids := make([]string, len(entries))
			for i, e := range entries {
				ids[i] = e.ID
			}
			if err := db.SoftDeleteEntries(ctx, tx, ids, p.Actor, rev); err != nil {
				return err
			}
			for i := range entries {
				if err := auditEntryDelete(ctx, tx, p, &entries[i], rev, map[string]any{"reason": "realm.delete"}); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(ctx, `UPDATE targets SET subscriptions_revision = $2 WHERE id = ANY($1::uuid[])`,
				targetIDs, rev); err != nil {
				return err
			}
		}
		out.EntriesRemoved = len(entries)
		if _, err := tx.Exec(ctx, `DELETE FROM realms WHERE name = $1`, name); err != nil {
			return err
		}
		return db.InsertAudit(ctx, tx, db.Audit{Actor: p.Actor, Action: "realm.delete", ObjectType: "realm",
			ObjectID: name, Realm: &name, Details: map[string]any{
				"entries_removed": out.EntriesRemoved, "rules_deleted": out.RulesDeleted,
				"subscriptions_deleted": out.SubscriptionsDeleted, "clients_unbound": out.ClientsUnbound,
				"revision": out.Revision}})
	})
	if err != nil {
		return err
	}
	return respondMutation(w, http.StatusOK, out, nil)
}

// ---------- clients ----------

type clientView struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Realms             []string `json:"realms"`
	RateLimitPerMinute *int     `json:"rate_limit_per_minute"`
	CreatedAt          string   `json:"created_at"`
	UpdatedAt          string   `json:"updated_at"`
}

const clientSelect = `SELECT c.id::text, c.name, ARRAY(SELECT cr.realm::text FROM client_realms cr
		WHERE cr.client_id = c.id ORDER BY cr.realm), c.rate_limit_per_minute, c.created_at, c.updated_at FROM clients c`

func scanClient(row pgx.Row) (clientView, error) {
	var (
		v    clientView
		c, u time.Time
		rl   *int32
	)
	err := row.Scan(&v.ID, &v.Name, &v.Realms, &rl, &c, &u)
	if rl != nil {
		n := int(*rl)
		v.RateLimitPerMinute = &n
	}
	v.CreatedAt, v.UpdatedAt = ts(c), ts(u)
	if v.Realms == nil {
		v.Realms = []string{}
	}
	return v, err
}

func getClientView(ctx context.Context, q db.Querier, id string) (*clientView, error) {
	if !validUUID(id) {
		return nil, errNotFound
	}
	v, err := scanClient(q.QueryRow(ctx, clientSelect+` WHERE c.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (s *Server) listClients(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
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
	rows, err := s.Pool.Query(r.Context(), clientSelect+` WHERE NOT $1 OR c.name > $2 ORDER BY c.name LIMIT $3`,
		after, c.Name, page.limit+1)
	if err != nil {
		return err
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (clientView, error) { return scanClient(row) })
	if err != nil {
		return err
	}
	resp := listResponse[clientView]{Items: items}
	if len(items) > page.limit {
		resp.Items = items[:page.limit]
		resp.NextCursor = encodeCursor(nameCursor{Name: resp.Items[page.limit-1].Name})
	}
	if resp.Items == nil {
		resp.Items = []clientView{}
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

func (s *Server) getClient(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	if err := checkQuery(r); err != nil {
		return err
	}
	v, err := getClientView(r.Context(), s.Pool, r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, v)
	return nil
}

// clientFields holds parsed client fields; set* say which were present.
type clientFields struct {
	name               string
	realms             []string
	rateLimit          *int
	setName, setRealms bool
	setRate            bool
}

func parseClientFields(r *http.Request, create bool) (*clientFields, error) {
	m, err := decodeObject(r, "name", "realms", "rate_limit_per_minute")
	if err != nil {
		return nil, err
	}
	fe := fieldErrors{}
	f := &clientFields{}
	if v, ok := rawString(fe, m, "name"); ok {
		if !validLabel(v, 128) {
			fe.add("name", "must be 1 to 128 characters without control characters")
		}
		f.name, f.setName = v, true
	} else if _, present := m["name"]; !present && create {
		fe.add("name", "required")
	}
	if raw, ok := m["realms"]; ok {
		var list []string
		if err := json.Unmarshal(raw, &list); err != nil || len(list) == 0 {
			fe.add("realms", "must be an array of at least one realm")
		} else {
			seen := map[string]bool{}
			for _, v := range list {
				if !rules.ValidRealm(v) {
					fe.add("realms", "invalid realm name "+fmt.Sprintf("%q", v))
				} else if !seen[v] {
					seen[v] = true
					f.realms = append(f.realms, v)
				}
			}
			f.setRealms = true
		}
	} else if create {
		fe.add("realms", "required")
	}
	if raw, ok := m["rate_limit_per_minute"]; ok {
		if !isNull(raw) {
			var n int
			if err := json.Unmarshal(raw, &n); err != nil || n < 0 || n > 1<<30 {
				fe.add("rate_limit_per_minute", "must be null or a non-negative integer")
			}
			f.rateLimit = &n
		}
		f.setRate = true
	}
	if err := fe.err(); err != nil {
		return nil, err
	}
	return f, nil
}

func setClientRealms(ctx context.Context, tx pgx.Tx, clientID string, realms []string) error {
	var missing []string
	rows, err := tx.Query(ctx, `SELECT r FROM unnest($1::text[]) AS r WHERE r NOT IN (SELECT name FROM realms)`, realms)
	if err != nil {
		return err
	}
	if missing, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
		return err
	}
	if len(missing) > 0 {
		return invalid("realms", "unknown realm "+strings.Join(missing, ", "))
	}
	if _, err := tx.Exec(ctx, `DELETE FROM client_realms WHERE client_id = $1`, clientID); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO client_realms (client_id, realm) SELECT $1, unnest($2::text[])`, clientID, realms)
	return err
}

func (s *Server) createClient(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	f, err := parseClientFields(r, true)
	if err != nil {
		return err
	}
	ctx := r.Context()
	var v *clientView
	err = db.InTx(ctx, s.Pool, db.ReadCommitted, func(tx pgx.Tx) error {
		var id string
		err := tx.QueryRow(ctx, `INSERT INTO clients (name, rate_limit_per_minute)
			VALUES ($1, $2) RETURNING id::text`, f.name, f.rateLimit).Scan(&id)
		if db.IsUniqueViolation(err) {
			return errConflict
		}
		if err != nil {
			return err
		}
		if err := setClientRealms(ctx, tx, id, f.realms); err != nil {
			return err
		}
		if v, err = getClientView(ctx, tx, id); err != nil {
			return err
		}
		return db.InsertAudit(ctx, tx, db.Audit{Actor: p.Actor, ClientID: &id, Action: "client.create",
			ObjectType: "client", ObjectID: id, Details: map[string]any{"client": v}})
	})
	if err != nil {
		return err
	}
	return respondMutation(w, http.StatusCreated, v, nil)
}

func (s *Server) patchClient(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	if err := checkQuery(r); err != nil {
		return err
	}
	id := r.PathValue("id")
	if !validUUID(id) {
		return errNotFound
	}
	f, err := parseClientFields(r, false)
	if err != nil {
		return err
	}
	ctx := r.Context()
	var v *clientView
	err = db.InTx(ctx, s.Pool, db.ReadCommitted, func(tx pgx.Tx) error {
		old, err := getClientView(ctx, tx, id)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE clients SET
			name = CASE WHEN $2 THEN $3 ELSE name END,
			rate_limit_per_minute = CASE WHEN $4 THEN $5 ELSE rate_limit_per_minute END,
			updated_at = now()
			WHERE id = $1`, id, f.setName, f.name, f.setRate, f.rateLimit)
		if db.IsUniqueViolation(err) {
			return errConflict
		}
		if err != nil {
			return err
		}
		if f.setRealms {
			if err := setClientRealms(ctx, tx, id, f.realms); err != nil {
				return err
			}
		}
		if v, err = getClientView(ctx, tx, id); err != nil {
			return err
		}
		return db.InsertAudit(ctx, tx, db.Audit{Actor: p.Actor, ClientID: &id, Action: "client.update",
			ObjectType: "client", ObjectID: id, Details: map[string]any{"before": old, "after": v}})
	})
	if err != nil {
		return err
	}
	return respondMutation(w, http.StatusOK, v, nil)
}

func (s *Server) deleteClient(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	if err := checkQuery(r); err != nil {
		return err
	}
	id := r.PathValue("id")
	ctx := r.Context()
	var v *clientView
	err := db.InTx(ctx, s.Pool, db.ReadCommitted, func(tx pgx.Tx) error {
		var err error
		if v, err = getClientView(ctx, tx, id); err != nil {
			return err
		}
		var nKeys int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM api_keys WHERE client_id = $1`, id).Scan(&nKeys); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM clients WHERE id = $1`, id); err != nil {
			return err
		}
		return db.InsertAudit(ctx, tx, db.Audit{Actor: p.Actor, ClientID: &id, Action: "client.delete",
			ObjectType: "client", ObjectID: id, Details: map[string]any{"client": v, "keys_deleted": nKeys}})
	})
	if err != nil {
		return err
	}
	return respondMutation(w, http.StatusOK, v, nil)
}

// ---------- keys ----------

type keyView struct {
	ID         string  `json:"id"`
	Kind       string  `json:"kind"`
	ClientID   *string `json:"client_id"`
	TargetID   *string `json:"target_id"`
	Name       string  `json:"name"`
	CreatedAt  string  `json:"created_at"`
	ExpiresAt  *string `json:"expires_at"`
	RevokedAt  *string `json:"revoked_at"`
	LastUsedAt *string `json:"last_used_at"`
}

const keySelect = `SELECT id, kind, client_id::text, target_id::text, name, created_at, expires_at, revoked_at,
	last_used_at FROM api_keys`

func scanKey(row pgx.Row) (keyView, error) {
	var (
		v         keyView
		c         time.Time
		e, rv, lu *time.Time
	)
	err := row.Scan(&v.ID, &v.Kind, &v.ClientID, &v.TargetID, &v.Name, &c, &e, &rv, &lu)
	v.CreatedAt, v.ExpiresAt, v.RevokedAt, v.LastUsedAt = ts(c), tsPtr(e), tsPtr(rv), tsPtr(lu)
	return v, err
}

func getKeyView(ctx context.Context, q db.Querier, id string) (*keyView, error) {
	if !auth.ValidKeyID(id) {
		return nil, errNotFound
	}
	v, err := scanKey(q.QueryRow(ctx, keySelect+` WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	return &v, nil
}

type timeIDCursor struct {
	T  time.Time `json:"t"`
	ID string    `json:"i"`
}

func (s *Server) listKeys(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	if err := checkQuery(r, "kind", "client_id", "target_id", "limit", "cursor"); err != nil {
		return err
	}
	page, err := parsePage(r)
	if err != nil {
		return err
	}
	q := r.URL.Query()
	var (
		where []string
		args  []any
	)
	arg := func(v any) string { args = append(args, v); return fmt.Sprintf("$%d", len(args)) }
	if v := q.Get("kind"); v != "" {
		if v != auth.KindAdmin && v != auth.KindClient && v != auth.KindWorker {
			return invalid("kind", "must be admin, client or worker")
		}
		where = append(where, "kind = "+arg(v))
	}
	for _, f := range []string{"client_id", "target_id"} {
		if v := q.Get(f); v != "" {
			if !validUUID(v) {
				return invalid(f, "must be a UUID")
			}
			where = append(where, f+" = "+arg(v)+"::uuid")
		}
	}
	var c timeIDCursor
	if ok, err := page.cursorInto(&c); err != nil {
		return err
	} else if ok {
		where = append(where, "(created_at, id) > ("+arg(c.T)+", "+arg(c.ID)+")")
	}
	sql := keySelect
	if len(where) > 0 {
		sql += " WHERE " + strings.Join(where, " AND ")
	}
	sql += " ORDER BY created_at, id LIMIT " + arg(page.limit+1)
	rows, err := s.Pool.Query(r.Context(), sql, args...)
	if err != nil {
		return err
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (keyView, error) { return scanKey(row) })
	if err != nil {
		return err
	}
	resp := listResponse[keyView]{Items: items}
	if len(items) > page.limit {
		resp.Items = items[:page.limit]
		last := resp.Items[page.limit-1]
		t, _ := time.Parse(time.RFC3339Nano, last.CreatedAt)
		resp.NextCursor = encodeCursor(timeIDCursor{T: t, ID: last.ID})
	}
	if resp.Items == nil {
		resp.Items = []keyView{}
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

func (s *Server) getKey(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	if err := checkQuery(r); err != nil {
		return err
	}
	v, err := getKeyView(r.Context(), s.Pool, r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, v)
	return nil
}

type createdKeyView struct {
	keyView
	Key string `json:"key"`
}

// InsertKey creates a key of the given kind and returns it. Used by the API
// and by the create-admin-key command.
func InsertKey(ctx context.Context, q db.Querier, kind string, clientID, targetID *string, name string, expiresAt *time.Time) (auth.Key, error) {
	key, err := auth.NewKey()
	if err != nil {
		return auth.Key{}, err
	}
	_, err = q.Exec(ctx, `INSERT INTO api_keys (id, kind, client_id, target_id, name, secret_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, key.ID, kind, clientID, targetID, name, key.Hash(), expiresAt)
	return key, err
}

func (s *Server) createKey(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var req struct {
		Kind      *string `json:"kind"`
		ClientID  *string `json:"client_id"`
		TargetID  *string `json:"target_id"`
		Name      *string `json:"name"`
		ExpiresAt *string `json:"expires_at"`
	}
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	fe := fieldErrors{}
	kind := ""
	if req.Kind == nil {
		fe.add("kind", "required")
	} else {
		kind = *req.Kind
	}
	switch kind {
	case auth.KindAdmin:
		if req.ClientID != nil {
			fe.add("client_id", "not allowed for admin keys")
		}
		if req.TargetID != nil {
			fe.add("target_id", "not allowed for admin keys")
		}
	case auth.KindClient:
		if req.ClientID == nil || !validUUID(*req.ClientID) {
			fe.add("client_id", "required for client keys (a client id)")
		}
		if req.TargetID != nil {
			fe.add("target_id", "not allowed for client keys")
		}
	case auth.KindWorker:
		if req.TargetID == nil || !validUUID(*req.TargetID) {
			fe.add("target_id", "required for worker keys (a target id)")
		}
		if req.ClientID != nil {
			fe.add("client_id", "not allowed for worker keys")
		}
	case "":
	default:
		fe.add("kind", "must be admin, client or worker")
	}
	if req.Name == nil || !validLabel(*req.Name, 128) {
		fe.add("name", "required: 1 to 128 characters without control characters")
	}
	var expires *time.Time
	if req.ExpiresAt != nil {
		t, err := time.Parse(time.RFC3339Nano, *req.ExpiresAt)
		if err != nil {
			fe.add("expires_at", "must be an RFC 3339 timestamp")
		} else if !t.After(time.Now()) {
			fe.add("expires_at", "must be in the future")
		}
		expires = &t
	}
	if err := fe.err(); err != nil {
		return err
	}
	ctx := r.Context()
	var out createdKeyView
	err := db.InTx(ctx, s.Pool, db.ReadCommitted, func(tx pgx.Tx) error {
		key, err := InsertKey(ctx, tx, kind, req.ClientID, req.TargetID, *req.Name, expires)
		if db.IsForeignKeyViolation(err) {
			if kind == auth.KindClient {
				return invalid("client_id", "unknown client")
			}
			return invalid("target_id", "unknown target")
		}
		if err != nil {
			return err
		}
		v, err := getKeyView(ctx, tx, key.ID)
		if err != nil {
			return err
		}
		out = createdKeyView{keyView: *v, Key: key.String()}
		return db.InsertAudit(ctx, tx, db.Audit{Actor: p.Actor, ClientID: req.ClientID, Action: "key.create",
			ObjectType: "api_key", ObjectID: key.ID, Details: map[string]any{"kind": kind, "name": *req.Name,
				"client_id": req.ClientID, "target_id": req.TargetID, "expires_at": tsPtr(expires)}})
	})
	if err != nil {
		return err
	}
	return respondMutation(w, http.StatusCreated, out, nil)
}

func (s *Server) revokeKey(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	if err := checkQuery(r); err != nil {
		return err
	}
	if r.ContentLength > 0 {
		var empty struct{}
		if err := decodeJSON(r, &empty); err != nil {
			return err
		}
	}
	id := r.PathValue("id")
	ctx := r.Context()
	var v *keyView
	err := db.InTx(ctx, s.Pool, db.ReadCommitted, func(tx pgx.Tx) error {
		var err error
		if v, err = getKeyView(ctx, tx, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE api_keys SET revoked_at = coalesce(revoked_at, now()) WHERE id = $1`, id); err != nil {
			return err
		}
		if v, err = getKeyView(ctx, tx, id); err != nil {
			return err
		}
		return db.InsertAudit(ctx, tx, db.Audit{Actor: p.Actor, ClientID: v.ClientID, Action: "key.revoke",
			ObjectType: "api_key", ObjectID: id, Details: map[string]any{"kind": v.Kind, "name": v.Name}})
	})
	if err != nil {
		return err
	}
	return respondMutation(w, http.StatusOK, v, nil)
}

// ---------- audit ----------

type auditView struct {
	ID         int64           `json:"id"`
	At         string          `json:"at"`
	Actor      string          `json:"actor"`
	ClientID   *string         `json:"client_id"`
	Action     string          `json:"action"`
	ObjectType string          `json:"object_type"`
	ObjectID   *string         `json:"object_id"`
	Realm      *string         `json:"realm"`
	User       *string         `json:"user"`
	Group      *string         `json:"group"`
	Prefix     *string         `json:"prefix"`
	Details    json.RawMessage `json:"details"`
}

type idCursor struct {
	ID int64 `json:"i"`
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	if err := checkQuery(r, "since", "until", "actor", "realm", "action", "limit", "cursor"); err != nil {
		return err
	}
	page, err := parsePage(r)
	if err != nil {
		return err
	}
	var (
		where []string
		args  []any
	)
	arg := func(v any) string { args = append(args, v); return fmt.Sprintf("$%d", len(args)) }
	since, err := queryTime(r, "since")
	if err != nil {
		return err
	}
	if since != nil {
		where = append(where, "at >= "+arg(*since))
	}
	until, err := queryTime(r, "until")
	if err != nil {
		return err
	}
	if until != nil {
		where = append(where, "at < "+arg(*until))
	}
	q := r.URL.Query()
	for _, f := range []string{"actor", "realm", "action"} {
		if v := q.Get(f); v != "" {
			where = append(where, f+" = "+arg(v))
		}
	}
	var c idCursor
	if ok, err := page.cursorInto(&c); err != nil {
		return err
	} else if ok {
		where = append(where, "id < "+arg(c.ID))
	}
	sql := `SELECT id, at, actor, client_id::text, action, object_type, object_id, realm, username, grp,
		host(prefix) || '/' || masklen(prefix), details FROM audit_log`
	if len(where) > 0 {
		sql += " WHERE " + strings.Join(where, " AND ")
	}
	sql += " ORDER BY id DESC LIMIT " + arg(page.limit+1)
	rows, err := s.Pool.Query(r.Context(), sql, args...)
	if err != nil {
		return err
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (auditView, error) {
		var (
			v  auditView
			at time.Time
		)
		err := row.Scan(&v.ID, &at, &v.Actor, &v.ClientID, &v.Action, &v.ObjectType, &v.ObjectID, &v.Realm,
			&v.User, &v.Group, &v.Prefix, &v.Details)
		v.At = ts(at)
		return v, err
	})
	if err != nil {
		return err
	}
	resp := listResponse[auditView]{Items: items}
	if len(items) > page.limit {
		resp.Items = items[:page.limit]
		resp.NextCursor = encodeCursor(idCursor{ID: resp.Items[page.limit-1].ID})
	}
	if resp.Items == nil {
		resp.Items = []auditView{}
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

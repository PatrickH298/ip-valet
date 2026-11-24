package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PatrickH298/ip-valet/api/internal/auth"
	"github.com/PatrickH298/ip-valet/api/internal/db"
	"github.com/PatrickH298/ip-valet/api/internal/rules"
	"github.com/PatrickH298/ip-valet/api/internal/state"
)

type entryFilter struct {
	realms       []string // nil = every realm
	realm        *string
	user         *string
	group        *string
	prefix       *netip.Prefix
	state        string
	includeEnded bool
	clientID     *string
	targetID     *string
}

type entryCursor struct {
	CreatedAt time.Time `json:"c"`
	ID        string    `json:"i"`
}

func parseEntryFilter(r *http.Request, admin bool) (*entryFilter, error) {
	allowed := []string{"realm", "user", "group", "prefix", "state", "include_ended", "limit", "cursor"}
	if admin {
		allowed = append(allowed, "client_id", "target_id")
	}
	if err := checkQuery(r, allowed...); err != nil {
		return nil, err
	}
	q := r.URL.Query()
	f := &entryFilter{}
	fe := fieldErrors{}
	if v := q.Get("realm"); v != "" {
		if !rules.ValidRealm(v) {
			fe.add("realm", "invalid realm name")
		}
		f.realm = &v
	}
	if v := q.Get("user"); v != "" {
		if !rules.ValidIdent(v) {
			fe.add("user", "invalid user name")
		}
		f.user = &v
	}
	if v := q.Get("group"); v != "" {
		if !rules.ValidIdent(v) {
			fe.add("group", "invalid group name")
		}
		f.group = &v
	}
	if v := q.Get("prefix"); v != "" {
		p, err := rules.NormalizePrefix(v)
		if err != nil {
			fe.add("prefix", "invalid prefix")
		}
		f.prefix = &p
	}
	if v := q.Get("state"); v != "" {
		if !slices.Contains(state.AllStates, v) {
			fe.add("state", "must be one of "+strings.Join(state.AllStates, ", "))
		}
		f.state = v
	}
	if v := q.Get("client_id"); v != "" {
		if !validUUID(v) {
			fe.add("client_id", "must be a UUID")
		}
		f.clientID = &v
	}
	if v := q.Get("target_id"); v != "" {
		if !validUUID(v) {
			fe.add("target_id", "must be a UUID")
		}
		f.targetID = &v
	}
	if err := fe.err(); err != nil {
		return nil, err
	}
	var err error
	if f.includeEnded, err = queryBool(r, "include_ended"); err != nil {
		return nil, err
	}
	return f, nil
}

// queryEntries runs the filtered, paginated entry query.
func queryEntries(ctx context.Context, q db.Querier, f *entryFilter, page pageParams) ([]state.Entry, *string, error) {
	var (
		where []string
		args  []any
	)
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	if f.realms != nil {
		where = append(where, "e.realm = ANY("+arg(f.realms)+"::text[])")
	}
	if f.realm != nil {
		where = append(where, "e.realm = "+arg(*f.realm))
	}
	if f.user != nil {
		where = append(where, "e.username = "+arg(*f.user))
	}
	if f.group != nil {
		where = append(where, "e.grp = "+arg(*f.group))
	}
	if f.prefix != nil {
		where = append(where, "e.prefix = "+arg(*f.prefix)+"::cidr")
	}
	if !f.includeEnded {
		where = append(where, "e.deleted_at IS NULL AND (e.expires_at IS NULL OR e.expires_at > now())")
	}
	if f.clientID != nil {
		where = append(where, "e.client_id = "+arg(*f.clientID)+"::uuid")
	}
	if f.targetID != nil {
		where = append(where, `EXISTS (SELECT 1 FROM targets t JOIN subscriptions s ON s.target_id = t.id
			WHERE t.id = `+arg(*f.targetID)+`::uuid
			  AND ((family(e.prefix) = 4 AND t.ipv4) OR (family(e.prefix) = 6 AND t.ipv6))
			  AND (s.realm IS NULL OR s.realm = e.realm)
			  AND (s.username IS NULL OR s.username = e.username)
			  AND (s.grp IS NULL OR s.grp = e.grp))`)
	}
	var c entryCursor
	if ok, err := page.cursorInto(&c); err != nil {
		return nil, nil, err
	} else if ok {
		where = append(where, "(e.created_at, e.id) > ("+arg(c.CreatedAt)+", "+arg(c.ID)+"::uuid)")
	}
	sql := `SELECT ` + db.EntryCols + ` FROM entries e`
	if len(where) > 0 {
		sql += " WHERE " + strings.Join(where, " AND ")
	}
	sql += " ORDER BY e.created_at, e.id LIMIT " + arg(page.limit+1)
	entries, err := db.QueryEntries(ctx, q, sql, args...)
	if err != nil {
		return nil, nil, err
	}
	var next *string
	if len(entries) > page.limit {
		entries = entries[:page.limit]
		last := entries[len(entries)-1]
		next = encodeCursor(entryCursor{CreatedAt: last.CreatedAt, ID: last.ID})
	}
	return entries, next, nil
}

func (s *Server) listClientEntries(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	f, err := parseEntryFilter(r, false)
	if err != nil {
		return err
	}
	if f.realm != nil && !p.HasRealm(*f.realm) {
		return &apiError{Status: http.StatusForbidden, Code: "realm_not_allowed", Message: "realm is not bound to this client"}
	}
	f.realms = p.Realms
	page, err := parsePage(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	resp := listResponse[entryView]{Items: []entryView{}}
	err = db.InTx(ctx, s.Pool, db.SnapshotRead, func(tx pgx.Tx) error {
		entries, next, err := queryEntries(ctx, tx, f, page)
		if err != nil {
			return err
		}
		sc, err := loadStateContext(ctx, tx, entries)
		if err != nil {
			return err
		}
		for i := range entries {
			v := sc.clientView(&entries[i])
			if f.state == "" || v.State == f.state {
				resp.Items = append(resp.Items, v)
			}
		}
		resp.NextCursor = next
		return nil
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

func (s *Server) listAdminEntries(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	f, err := parseEntryFilter(r, true)
	if err != nil {
		return err
	}
	page, err := parsePage(r)
	if err != nil {
		return err
	}
	ctx := r.Context()
	resp := listResponse[adminEntryView]{Items: []adminEntryView{}}
	err = db.InTx(ctx, s.Pool, db.SnapshotRead, func(tx pgx.Tx) error {
		entries, next, err := queryEntries(ctx, tx, f, page)
		if err != nil {
			return err
		}
		sc, err := loadStateContext(ctx, tx, entries)
		if err != nil {
			return err
		}
		for i := range entries {
			v := sc.adminView(&entries[i])
			if f.state == "" || v.State == f.state {
				resp.Items = append(resp.Items, v)
			}
		}
		resp.NextCursor = next
		return nil
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

// loadEntryView loads one entry and renders it; inRealms limits it to a client's realms.
func (s *Server) loadEntryView(ctx context.Context, id string, p *auth.Principal, admin bool) (any, error) {
	if !validUUID(id) {
		return nil, errNotFound
	}
	var out any
	err := db.InTx(ctx, s.Pool, db.SnapshotRead, func(tx pgx.Tx) error {
		e, err := db.GetEntry(ctx, tx, id, false)
		if err != nil {
			return err
		}
		if e == nil || (!admin && !p.HasRealm(e.Realm)) {
			return errNotFound
		}
		sc, err := loadStateContext(ctx, tx, []state.Entry{*e})
		if err != nil {
			return err
		}
		if admin {
			out = sc.adminView(e)
		} else {
			out = sc.clientView(e)
		}
		return nil
	})
	return out, err
}

func (s *Server) getClientEntry(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	if err := checkQuery(r); err != nil {
		return err
	}
	v, err := s.loadEntryView(r.Context(), r.PathValue("id"), p, false)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, v)
	return nil
}

func (s *Server) getAdminEntry(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	if err := checkQuery(r); err != nil {
		return err
	}
	v, err := s.loadEntryView(r.Context(), r.PathValue("id"), p, true)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, v)
	return nil
}

func (s *Server) deleteClientEntry(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	e, err := s.deleteEntry(r.Context(), p, r.PathValue("id"), true)
	if err != nil {
		return err
	}
	v, err := s.loadEntryView(r.Context(), e.ID, p, false)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, v)
	return nil
}

func (s *Server) deleteAdminEntry(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	e, err := s.deleteEntry(r.Context(), p, r.PathValue("id"), false)
	if err != nil {
		return err
	}
	v, err := s.loadEntryView(r.Context(), e.ID, p, true)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, v)
	return nil
}

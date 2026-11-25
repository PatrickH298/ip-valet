package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/PatrickH298/ip-valet/dashboard/internal/api"
	"github.com/PatrickH298/ip-valet/dashboard/internal/auth"
)

// keyRow is a key with its owner and status, for tables.
type keyRow struct {
	Key         api.Key
	Owner       string
	OwnerURL    string
	Status      string
	StatusClass string
	Self        bool // the dashboard's own key
}

// keyRow describes k; names maps client and worker ids to names, when known.
func (s *Server) keyRow(k api.Key, clients, workers map[string]string) keyRow {
	row := keyRow{Key: k, Self: k.ID == s.SelfKeyID}
	switch {
	case k.ClientID != nil:
		row.Owner, row.OwnerURL = "client", "/clients/"+url.PathEscape(*k.ClientID)
		if n, ok := clients[*k.ClientID]; ok {
			row.Owner = "client " + n
		}
	case k.WorkerID != nil:
		row.Owner, row.OwnerURL = "worker", "/workers/"+url.PathEscape(*k.WorkerID)
		if n, ok := workers[*k.WorkerID]; ok {
			row.Owner = "worker " + n
		}
	default:
		row.Owner = "admin"
	}
	now := time.Now()
	switch {
	case k.RevokedAt != nil:
		row.Status, row.StatusClass = "revoked", "off"
	case k.ExpiresAt != nil && !k.ExpiresAt.After(now):
		row.Status, row.StatusClass = "expired", "off"
	case k.ExpiresAt != nil && k.ExpiresAt.Before(now.Add(14*24*time.Hour)):
		row.Status, row.StatusClass = "expires "+relTime(k.ExpiresAt), "warn"
	default:
		row.Status, row.StatusClass = "active", "ok"
	}
	return row
}

// keyBody turns a key form into an API body: name and an optional expiry
// given in days.
func keyBody(f *Form, kind string) map[string]any {
	b := map[string]any{"kind": kind, "name": strings.TrimSpace(f.Get("name"))}
	if d := strings.TrimSpace(f.Get("expires_in_days")); d != "" {
		n, err := strconv.Atoi(d)
		if err != nil || n < 1 || n > 3650 {
			f.Errors["expires_in_days"] = "must be a whole number of days from 1 to 3650"
			return b
		}
		b["expires_at"] = time.Now().Add(time.Duration(n) * 24 * time.Hour).UTC().Format(time.RFC3339)
	}
	return b
}

type keyCreatedView struct {
	Key      api.CreatedKey
	Owner    string
	Back     string
	Warnings []api.Warning
}

// keyCreated shows a new key's secret, this once. It is never redirected,
// stored or logged.
func (s *Server) keyCreated(w http.ResponseWriter, r *http.Request, section string, k api.CreatedKey, owner, back string) {
	s.render(w, r, http.StatusCreated, "key_created", "Key created", section,
		keyCreatedView{Key: k, Owner: owner, Back: back, Warnings: k.Warnings})
}

type keysView struct {
	Kind  string
	Keys  []keyRow
	Next  string
	Paged bool
	Form  *Form
}

func (s *Server) keys(w http.ResponseWriter, r *http.Request) error {
	return s.keysPage(w, r, http.StatusOK, newForm(url.Values{"expires_in_days": {"365"}}))
}

func (s *Server) keysPage(w http.ResponseWriter, r *http.Request, status int, f *Form) error {
	q := r.URL.Query()
	kind := q.Get("kind")
	if kind != "admin" && kind != "client" && kind != "worker" {
		kind = ""
	}
	page, err := s.API.Keys(r.Context(), api.KeyFilter{Kind: kind}, api.PageQuery{Limit: 100, Cursor: q.Get("cursor")})
	if err != nil {
		return err
	}
	clients, workers, err := s.names(r)
	if err != nil {
		return err
	}
	v := keysView{Kind: kind, Form: f, Paged: q.Get("cursor") != ""}
	for _, k := range page.Items {
		v.Keys = append(v.Keys, s.keyRow(k, clients, workers))
	}
	if page.NextCursor != nil {
		v.Next = queryURL("/keys", "kind", kind, "cursor", *page.NextCursor)
	}
	s.render(w, r, status, "keys", "Keys", "keys", v)
	return nil
}

// names maps client and worker ids to their names.
func (s *Server) names(r *http.Request) (clients, workers map[string]string, err error) {
	cs, err := s.API.Clients(r.Context())
	if err != nil {
		return nil, nil, err
	}
	ws, err := s.API.Workers(r.Context())
	if err != nil {
		return nil, nil, err
	}
	clients, workers = map[string]string{}, map[string]string{}
	for _, c := range cs {
		clients[c.ID] = c.Name
	}
	for _, wk := range ws {
		workers[wk.ID] = wk.Name
	}
	return clients, workers, nil
}

func (s *Server) createAdminKey(w http.ResponseWriter, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return err
	}
	f := newForm(r.PostForm)
	body := keyBody(f, "admin")
	if f.HasErrors() {
		return s.keysPage(w, r, http.StatusBadRequest, f)
	}
	k, err := s.API.CreateKey(r.Context(), body)
	if err != nil {
		if f.refused(err) {
			return s.keysPage(w, r, http.StatusBadRequest, f)
		}
		return err
	}
	s.keyCreated(w, r, "keys", k, "admin", "/keys")
	return nil
}

func (s *Server) revokeKey(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	k, err := s.API.Key(r.Context(), id)
	if err != nil {
		return err
	}
	if err := r.ParseForm(); err != nil {
		return err
	}
	back := auth.SafeNext(r.PostForm.Get("back"))
	if back == "/" {
		back = "/keys"
	}
	v := confirmView{
		Heading: "Revoke key " + k.Name + "?",
		Message: "The key stops working at its next request. Revoking cannot be undone.",
		Button:  "Revoke key", Danger: true, Cancel: back,
	}
	if k.ID == s.SelfKeyID {
		v.Notes = append(v.Notes, "This is the dashboard's own key. The dashboard stops working until it is "+
			"given a new key in IPVALET_DASHBOARD_API_KEY_FILE and restarted.")
	}
	if !s.ask(w, r, "keys", v) {
		return nil
	}
	if _, err := s.API.RevokeKey(r.Context(), id); err != nil {
		return err
	}
	s.redirect(w, r, back, &flash{Kind: "ok", Lines: []string{"Key " + k.Name + " revoked."}})
	return nil
}

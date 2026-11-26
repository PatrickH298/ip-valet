package web

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PatrickH298/ip-valet/dashboard/internal/api"
)

// entryStates are the states an entry can be in, for the filter.
var entryStates = []string{"active", "pending", "partial", "rejected", "unrouted", "removing", "removed", "expired"}

type entriesView struct {
	Filter  url.Values
	Entries []api.Entry
	Next    string
	Paged   bool
	Error   string
	Realms  []api.Realm
	Workers []api.Worker
	Clients []api.Client
	States  []string
}

func (s *Server) entries(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	f := api.EntryFilter{
		Realm: q.Get("realm"), User: strings.TrimSpace(q.Get("user")), Group: strings.TrimSpace(q.Get("group")),
		Prefix: strings.TrimSpace(q.Get("prefix")), State: q.Get("state"), ClientID: q.Get("client_id"),
		WorkerID: q.Get("worker_id"), IncludeEnded: q.Get("include_ended") == "on",
	}
	v := entriesView{Filter: q, Paged: q.Get("cursor") != "", States: entryStates}
	page, err := s.API.Entries(r.Context(), f, api.PageQuery{Limit: 100, Cursor: q.Get("cursor")})
	var ae *api.Error
	switch {
	case errors.As(err, &ae) && ae.Status == http.StatusBadRequest:
		v.Error = describe(ae)
		for k, m := range ae.Fields {
			v.Error = "The " + k + " filter " + m + "."
		}
	case err != nil:
		return err
	default:
		v.Entries = page.Items
		if page.NextCursor != nil {
			next := url.Values{}
			for k, vals := range q {
				if k != "cursor" && len(vals) > 0 && vals[0] != "" {
					next.Set(k, vals[0])
				}
			}
			next.Set("cursor", *page.NextCursor)
			v.Next = "/entries?" + next.Encode()
		}
	}
	if v.Realms, err = s.API.Realms(r.Context()); err != nil {
		return err
	}
	if v.Workers, err = s.API.Workers(r.Context()); err != nil {
		return err
	}
	if v.Clients, err = s.API.Clients(r.Context()); err != nil {
		return err
	}
	s.render(w, r, http.StatusOK, "entries", "Entries", "entries", v)
	return nil
}

type entryView struct {
	Entry      api.Entry
	ClientName string
	KeyName    string
	ByAdmin    bool // added with an admin key
	Ended      bool
}

func (s *Server) entry(w http.ResponseWriter, r *http.Request) error {
	e, err := s.API.Entry(r.Context(), r.PathValue("id"))
	if err != nil {
		return err
	}
	v := entryView{Entry: e, Ended: e.DeletedAt != nil || (e.ExpiresAt != nil && !e.ExpiresAt.After(time.Now()))}
	if e.ClientID != nil {
		if c, err := s.API.Client(r.Context(), *e.ClientID); err == nil {
			v.ClientName = c.Name
		} else if !api.IsNotFound(err) {
			return err
		}
	}
	if e.KeyID != nil {
		if k, err := s.API.Key(r.Context(), *e.KeyID); err == nil {
			v.KeyName, v.ByAdmin = k.Name, k.Kind == "admin"
		} else if !api.IsNotFound(err) {
			return err
		}
	}
	s.render(w, r, http.StatusOK, "entry", e.Prefix+" for "+e.User, "entries", v)
	return nil
}

func (s *Server) deleteEntry(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	e, err := s.API.Entry(r.Context(), id)
	if err != nil {
		return err
	}
	if err := r.ParseForm(); err != nil {
		return err
	}
	back := "/entries/" + url.PathEscape(id)
	if !s.ask(w, r, "entries", confirmView{
		Heading: "Delete " + e.Prefix + " for " + e.User + "?",
		Message: "Every worker that holds the entry removes it; it reads removing until they confirm. " +
			"The user can register the address again, within the realm's rules.",
		Button: "Delete entry", Danger: true, Cancel: back,
	}) {
		return nil
	}
	if _, err := s.API.DeleteEntry(r.Context(), id); err != nil {
		return err
	}
	s.redirect(w, r, back, &flash{Kind: "ok", Lines: []string{"Entry deleted."}})
	return nil
}

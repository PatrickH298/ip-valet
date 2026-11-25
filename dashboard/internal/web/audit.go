package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PatrickH298/ip-valet/dashboard/internal/api"
)

type auditView struct {
	Filter url.Values
	Rows   []auditRow
	Next   string
	Paged  bool
	Error  string
}

type auditRow struct {
	Entry     api.AuditEntry
	ActorName string // the key's name, when the actor is a key that still exists
	Details   string // indented JSON
	ObjectURL string // the object's page, when it has one
}

// objectURL links an audited object to its page.
func objectURL(e api.AuditEntry) string {
	if e.ObjectID == nil {
		return ""
	}
	id := url.PathEscape(*e.ObjectID)
	switch e.ObjectType {
	case "entry":
		return "/entries/" + id
	case "worker":
		return "/workers/" + id
	case "client":
		return "/clients/" + id
	case "realm":
		return "/realms/" + id
	case "rule":
		if e.Realm != nil {
			return "/realms/" + url.PathEscape(*e.Realm)
		}
	}
	return ""
}

func indentJSON(v map[string]any) string {
	if len(v) == 0 {
		return ""
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}

// day parses a YYYY-MM-DD date in loc; the second result is the next day.
func day(s string, loc *time.Location) (time.Time, time.Time, error) {
	t, err := time.ParseInLocation("2006-01-02", s, loc)
	return t, t.AddDate(0, 0, 1), err
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	v := auditView{Filter: q, Paged: q.Get("cursor") != ""}
	f := api.AuditFilter{Actor: strings.TrimSpace(q.Get("actor")), OnBehalfOf: strings.TrimSpace(q.Get("on_behalf_of")),
		Realm: strings.TrimSpace(q.Get("realm")), Action: strings.TrimSpace(q.Get("action"))}
	if d := q.Get("since"); d != "" {
		from, _, err := day(d, s.Location)
		if err != nil {
			v.Error = "The From date must be a date."
		}
		f.Since = from.UTC().Format(time.RFC3339)
	}
	if d := q.Get("until"); d != "" {
		_, next, err := day(d, s.Location)
		if err != nil {
			v.Error = "The To date must be a date."
		}
		f.Until = next.UTC().Format(time.RFC3339)
	}
	if v.Error == "" {
		page, err := s.API.Audit(r.Context(), f, api.PageQuery{Limit: 100, Cursor: q.Get("cursor")})
		var ae *api.Error
		switch {
		case errors.As(err, &ae) && ae.Status == http.StatusBadRequest:
			v.Error = describe(ae)
		case err != nil:
			return err
		default:
			names := map[string]string{}
			for _, e := range page.Items {
				names[e.Actor] = ""
			}
			for id := range names {
				if len(id) != 16 || strings.Contains(id, ":") {
					continue
				}
				if k, err := s.API.Key(r.Context(), id); err == nil {
					names[id] = k.Name
				} else if !api.IsNotFound(err) {
					return err
				}
			}
			for _, e := range page.Items {
				v.Rows = append(v.Rows, auditRow{Entry: e, ActorName: names[e.Actor], Details: indentJSON(e.Details),
					ObjectURL: objectURL(e)})
			}
			if page.NextCursor != nil {
				next := url.Values{}
				for k, vals := range q {
					if k != "cursor" && len(vals) > 0 && vals[0] != "" {
						next.Set(k, vals[0])
					}
				}
				next.Set("cursor", *page.NextCursor)
				v.Next = "/audit?" + next.Encode()
			}
		}
	}
	s.render(w, r, http.StatusOK, "audit", "Audit log", "audit", v)
	return nil
}

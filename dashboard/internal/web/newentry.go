package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/PatrickH298/ip-valet/dashboard/internal/api"
)

type newEntryView struct {
	Realms  []api.Realm
	Form    *Form
	Results []groupOutcome // when the API refused some groups
}

type groupOutcome struct {
	Group  string
	OK     bool
	Reason string
}

// failureText says in words why a group was refused.
func failureText(r api.GroupResult) string {
	lim := r.Limit
	switch r.Code {
	case "invalid_prefix":
		return "not an IP address or prefix"
	case "no_subscriber":
		return "no worker takes this realm, user, group and address family"
	case "ip_denied":
		return "an IP rule denies this address, or none accepts it"
	case "prefix_too_broad":
		if lim != nil && lim.MinPrefixLen != nil {
			return fmt.Sprintf("broader than the /%d the prefix rules allow", *lim.MinPrefixLen)
		}
		return "broader than the prefix rules allow"
	case "ttl_exceeded":
		if lim != nil && lim.MaxTTL != "" {
			return "longer than the " + lim.MaxTTL + " the TTL rules allow"
		}
		return "longer than the TTL rules allow"
	case "cap_exceeded":
		if lim != nil && lim.MaxPrefixes != nil {
			return fmt.Sprintf("the user already holds the %d prefixes a cap rule allows", *lim.MaxPrefixes)
		}
		return "the user is at a cap rule's limit"
	case "realm_not_allowed":
		return "the realm is not allowed"
	}
	return r.Code
}

func (s *Server) newEntry(w http.ResponseWriter, r *http.Request) error {
	f := newForm(url.Values{"realm": {r.URL.Query().Get("realm")}, "ttl": {"1d"}})
	return s.newEntryPage(w, r, http.StatusOK, f, nil)
}

func (s *Server) newEntryPage(w http.ResponseWriter, r *http.Request, status int, f *Form, results []groupOutcome) error {
	realms, err := s.API.Realms(r.Context())
	if err != nil {
		return err
	}
	s.render(w, r, status, "entry_new", "Add entry", "entries", newEntryView{Realms: realms, Form: f, Results: results})
	return nil
}

// groupsOf reads the groups field: one group per line.
func groupsOf(v string) []string {
	var out []string
	for _, g := range strings.Split(v, "\n") {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, g)
		}
	}
	return out
}

func (s *Server) createEntry(w http.ResponseWriter, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return err
	}
	f := newForm(r.PostForm)
	realm, user := f.Get("realm"), strings.TrimSpace(f.Get("user"))
	groups := groupsOf(f.Get("groups"))
	sub, err := s.API.Submit(r.Context(), realm, user, groups, strings.TrimSpace(f.Get("prefix")),
		strings.TrimSpace(f.Get("ttl")))
	var ae *api.Error
	switch {
	case errors.As(err, &ae) && ae.Code == "submission_rejected":
		f.Error = "Nothing was added: every group must pass the realm's rules."
		var out []groupOutcome
		for _, gr := range ae.Results {
			o := groupOutcome{Group: gr.Group, OK: gr.OK, Reason: "passes"}
			if !gr.OK {
				o.Reason = failureText(gr)
			}
			out = append(out, o)
		}
		return s.newEntryPage(w, r, http.StatusUnprocessableEntity, f, out)
	case err != nil:
		if f.refused(err) {
			return s.newEntryPage(w, r, http.StatusBadRequest, f, nil)
		}
		return err
	}
	verb := "Added"
	for _, e := range sub.Entries {
		if e.Replaced {
			verb = "Added or renewed"
		}
	}
	s.redirect(w, r, queryURL("/entries", "realm", realm, "user", user), &flash{Kind: "ok", Lines: []string{
		fmt.Sprintf("%s %s for %s in %s.", verb, sub.Prefix, user, plural(len(sub.Entries), "group", "groups"))}})
	return nil
}

package web

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/PatrickH298/ip-valet/dashboard/internal/api"
)

type realmsView struct {
	Realms []api.Realm
	Form   *Form
}

func (s *Server) realms(w http.ResponseWriter, r *http.Request) error {
	return s.realmsPage(w, r, http.StatusOK, nil)
}

func (s *Server) realmsPage(w http.ResponseWriter, r *http.Request, status int, f *Form) error {
	realms, err := s.API.Realms(r.Context())
	if err != nil {
		return err
	}
	s.render(w, r, status, "realms", "Realms", "realms", realmsView{Realms: realms, Form: f})
	return nil
}

func (s *Server) createRealm(w http.ResponseWriter, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return err
	}
	f := newForm(r.PostForm)
	name := strings.TrimSpace(f.Get("name"))
	realm, x, err := s.API.CreateRealm(r.Context(), name)
	if err != nil {
		if f.refused(err) {
			return s.realmsPage(w, r, http.StatusBadRequest, f)
		}
		return err
	}
	s.redirect(w, r, "/realms/"+url.PathEscape(realm.Name),
		done("Realm "+realm.Name+" created with the default rules.", x))
	return nil
}

// ruleList is one of a realm's four rule lists.
type ruleList struct {
	Name  string
	Title string
	Help  string
	Rules []api.Rule
}

var listInfo = map[string][3]string{
	api.ListIP: {"IP rules", "The first rule whose selector matches and whose prefix overlaps the submitted prefix " +
		"decides: deny rejects; accept accepts only a prefix entirely inside the rule's. No matching rule rejects.",
		"IP rule"},
	api.ListPrefix: {"Prefix rules", "The first matching rule sets the shortest prefix length allowed per family.", "prefix rule"},
	api.ListTTL:    {"TTL rules", "The first matching rule sets the longest TTL a submission may ask for.", "TTL rule"},
	api.ListCap: {"Cap rules", "The first matching rule limits how many distinct prefixes a user may hold " +
		"in the realm.", "cap rule"},
}

type realmView struct {
	Realm api.Realm
	Lists []ruleList
}

func (s *Server) realm(w http.ResponseWriter, r *http.Request) error {
	name := r.PathValue("realm")
	realm, err := s.API.Realm(r.Context(), name)
	if err != nil {
		return err
	}
	v := realmView{Realm: realm}
	for _, l := range api.RuleLists {
		rules, err := s.API.Rules(r.Context(), name, l)
		if err != nil {
			return err
		}
		v.Lists = append(v.Lists, ruleList{Name: l, Title: listInfo[l][0], Help: listInfo[l][1], Rules: rules})
	}
	s.render(w, r, http.StatusOK, "realm", "Realm "+realm.Name, "realms", v)
	return nil
}

func (s *Server) deleteRealm(w http.ResponseWriter, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return err
	}
	name := r.PathValue("realm")
	if r.PostForm.Get("confirm") != "yes" {
		// The API deletes a realm without an impact check, so count what goes with it here.
		if _, err := s.API.Realm(r.Context(), name); err != nil {
			return err
		}
		page, err := s.API.Entries(r.Context(), api.EntryFilter{Realm: name}, api.PageQuery{Limit: 1000})
		if err != nil {
			return err
		}
		count := strconv.Itoa(len(page.Items))
		if page.NextCursor != nil {
			count = "More than 1000"
		}
		s.ask(w, r, "realms", confirmView{
			Heading: "Delete realm " + name + "?",
			Message: "This deletes the realm's rules, its subscriptions on every worker, and its bindings to clients. " +
				"Clients left with no realm can no longer do anything.",
			Notes:  []string{count + " live entries in the realm will be removed from every worker that holds them."},
			Button: "Delete realm", Danger: true, Cancel: "/realms/" + url.PathEscape(name),
		})
		return nil
	}
	res, err := s.API.DeleteRealm(r.Context(), name)
	if err != nil {
		return err
	}
	s.redirect(w, r, "/realms", done(fmt.Sprintf("Realm %s deleted: %d entries removed, %d rules and %d subscriptions "+
		"deleted, %d clients unbound.", res.Name, res.EntriesRemoved, res.RulesDeleted, res.SubscriptionsDeleted,
		res.ClientsUnbound), res.Extras))
	return nil
}

// --- rules

type ruleFormView struct {
	Realm     string
	List      string
	ListTitle string
	Help      string
	Rule      *api.Rule // nil for a new rule
	Form      *Form
	Action    string
}

func validList(l string) bool {
	_, ok := listInfo[l]
	return ok
}

func (s *Server) newRule(w http.ResponseWriter, r *http.Request) error {
	realm, list := r.PathValue("realm"), r.PathValue("list")
	if !validList(list) {
		return &api.Error{Status: http.StatusNotFound, Code: "not_found"}
	}
	if _, err := s.API.Realm(r.Context(), realm); err != nil {
		return err
	}
	f := newForm(url.Values{"user": {"*"}, "group": {"*"}})
	if list == api.ListIP {
		f.Values.Set("action", "accept")
	}
	s.ruleForm(w, r, http.StatusOK, realm, list, nil, f)
	return nil
}

func (s *Server) ruleForm(w http.ResponseWriter, r *http.Request, status int, realm, list string, rule *api.Rule, f *Form) {
	v := ruleFormView{Realm: realm, List: list, ListTitle: listInfo[list][0], Help: listInfo[list][1], Rule: rule,
		Form: f, Action: "/realms/" + url.PathEscape(realm) + "/rules/" + list}
	title := "New " + listInfo[list][2]
	if rule != nil {
		v.Action += "/" + url.PathEscape(rule.ID)
		title = fmt.Sprintf("%s %d", titleCase(listInfo[list][2]), rule.Position)
	}
	s.render(w, r, status, "rule", title+" in "+realm, "realms", v)
}

// findRule fetches one rule; the API lists rules but has no single-rule read.
func (s *Server) findRule(r *http.Request, realm, list, id string) (*api.Rule, error) {
	if !validList(list) {
		return nil, &api.Error{Status: http.StatusNotFound, Code: "not_found"}
	}
	rules, err := s.API.Rules(r.Context(), realm, list)
	if err != nil {
		return nil, err
	}
	for i := range rules {
		if rules[i].ID == id {
			return &rules[i], nil
		}
	}
	return nil, &api.Error{Status: http.StatusNotFound, Code: "not_found"}
}

func (s *Server) editRule(w http.ResponseWriter, r *http.Request) error {
	realm, list, id := r.PathValue("realm"), r.PathValue("list"), r.PathValue("id")
	rule, err := s.findRule(r, realm, list, id)
	if err != nil {
		return err
	}
	f := newForm(url.Values{"user": {rule.User}, "group": {rule.Group}, "description": {deref(rule.Description)}})
	switch list {
	case api.ListIP:
		f.Values.Set("prefix", rule.Prefix)
		f.Values.Set("action", rule.Action)
	case api.ListPrefix:
		f.Values.Set("min_len_v4", numOr(rule.MinLenV4, ""))
		f.Values.Set("min_len_v6", numOr(rule.MinLenV6, ""))
	case api.ListTTL:
		f.Values.Set("max_ttl", rule.MaxTTL)
	case api.ListCap:
		f.Values.Set("max_prefixes", numOr(rule.MaxPrefixes, ""))
	}
	s.ruleForm(w, r, http.StatusOK, realm, list, rule, f)
	return nil
}

// ruleBody turns the rule form into an API body, noting fields that are not
// numbers where numbers are needed.
func ruleBody(list string, f *Form, create bool) map[string]any {
	b := map[string]any{
		"user":  strings.TrimSpace(f.Get("user")),
		"group": strings.TrimSpace(f.Get("group")),
	}
	if d := strings.TrimSpace(f.Get("description")); d != "" {
		b["description"] = d
	} else if !create {
		b["description"] = nil
	}
	intField := func(name string, optional bool) {
		v := strings.TrimSpace(f.Get(name))
		if v == "" {
			if optional {
				b[name] = nil
			} else {
				f.Errors[name] = "required"
			}
			return
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			f.Errors[name] = "must be a whole number"
			return
		}
		b[name] = n
	}
	if create {
		if p := strings.TrimSpace(f.Get("position")); p != "" {
			intField("position", false)
		}
	}
	switch list {
	case api.ListIP:
		b["prefix"] = strings.TrimSpace(f.Get("prefix"))
		b["action"] = f.Get("action")
	case api.ListPrefix:
		intField("min_len_v4", true)
		intField("min_len_v6", true)
	case api.ListTTL:
		b["max_ttl"] = strings.TrimSpace(f.Get("max_ttl"))
	case api.ListCap:
		intField("max_prefixes", false)
	}
	return b
}

func (s *Server) createRule(w http.ResponseWriter, r *http.Request) error {
	realm, list := r.PathValue("realm"), r.PathValue("list")
	if !validList(list) {
		return &api.Error{Status: http.StatusNotFound, Code: "not_found"}
	}
	if err := r.ParseForm(); err != nil {
		return err
	}
	f := newForm(r.PostForm)
	body := ruleBody(list, f, true)
	if f.HasErrors() {
		s.ruleForm(w, r, http.StatusBadRequest, realm, list, nil, f)
		return nil
	}
	back := "/realms/" + url.PathEscape(realm)
	return s.run(w, r, change{
		Section: "realms", Heading: "Add this rule?", Button: "Add rule and enforce it", Cancel: back,
		Message: "Existing entries in " + realm + " break the new rule. Confirming adds it and enforces it on them.",
		Run: func(mode api.Impact) (api.Extras, error) {
			m, err := s.API.CreateRule(r.Context(), realm, list, body, mode)
			return m.Extras, err
		},
		Done: func(x api.Extras) {
			s.redirect(w, r, back+"#"+list, done("Rule added.", x))
		},
		Refused: func(err error) bool {
			if !f.refused(err) {
				return false
			}
			s.ruleForm(w, r, http.StatusBadRequest, realm, list, nil, f)
			return true
		},
	})
}

func (s *Server) updateRule(w http.ResponseWriter, r *http.Request) error {
	realm, list, id := r.PathValue("realm"), r.PathValue("list"), r.PathValue("id")
	rule, err := s.findRule(r, realm, list, id)
	if err != nil {
		return err
	}
	if err := r.ParseForm(); err != nil {
		return err
	}
	f := newForm(r.PostForm)
	body := ruleBody(list, f, false)
	if f.HasErrors() {
		s.ruleForm(w, r, http.StatusBadRequest, realm, list, rule, f)
		return nil
	}
	back := "/realms/" + url.PathEscape(realm)
	return s.run(w, r, change{
		Section: "realms", Heading: "Save this rule?", Button: "Save rule and enforce it", Cancel: back,
		Message: "Existing entries in " + realm + " break the changed rule. Confirming saves it and enforces it on them.",
		Run: func(mode api.Impact) (api.Extras, error) {
			m, err := s.API.UpdateRule(r.Context(), realm, list, id, body, mode)
			return m.Extras, err
		},
		Done: func(x api.Extras) {
			s.redirect(w, r, back+"#"+list, done("Rule saved.", x))
		},
		Refused: func(err error) bool {
			if !f.refused(err) {
				return false
			}
			s.ruleForm(w, r, http.StatusBadRequest, realm, list, rule, f)
			return true
		},
	})
}

func (s *Server) moveRule(w http.ResponseWriter, r *http.Request) error {
	realm, list, id := r.PathValue("realm"), r.PathValue("list"), r.PathValue("id")
	if !validList(list) {
		return &api.Error{Status: http.StatusNotFound, Code: "not_found"}
	}
	if err := r.ParseForm(); err != nil {
		return err
	}
	pos, err := strconv.Atoi(r.PostForm.Get("position"))
	if err != nil || pos < 1 {
		return &api.Error{Status: http.StatusBadRequest, Code: "invalid_request", Message: "position must be at least 1"}
	}
	back := "/realms/" + url.PathEscape(realm)
	return s.run(w, r, change{
		Section: "realms", Heading: "Move this rule?", Button: "Move rule and enforce the new order", Cancel: back,
		Message: fmt.Sprintf("Moving the rule to position %d changes which rule decides for existing entries in %s.",
			pos, realm),
		Run: func(mode api.Impact) (api.Extras, error) {
			m, err := s.API.UpdateRule(r.Context(), realm, list, id, map[string]any{"position": pos}, mode)
			return m.Extras, err
		},
		Done: func(x api.Extras) {
			s.redirect(w, r, back+"#"+list, done(fmt.Sprintf("Rule moved to position %d.", pos), x))
		},
	})
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request) error {
	realm, list, id := r.PathValue("realm"), r.PathValue("list"), r.PathValue("id")
	rule, err := s.findRule(r, realm, list, id)
	if err != nil {
		return err
	}
	if err := r.ParseForm(); err != nil {
		return err
	}
	back := "/realms/" + url.PathEscape(realm)
	return s.run(w, r, change{
		Section: "realms", Preview: true, Danger: true, Cancel: back,
		Heading: fmt.Sprintf("Delete %s %d?", listInfo[list][2], rule.Position),
		Message: "Later rules move up one position.",
		Button:  "Delete rule",
		Run: func(mode api.Impact) (api.Extras, error) {
			m, err := s.API.DeleteRule(r.Context(), realm, list, id, mode)
			return m.Extras, err
		},
		Done: func(x api.Extras) {
			s.redirect(w, r, back+"#"+list, done("Rule deleted.", x))
		},
	})
}

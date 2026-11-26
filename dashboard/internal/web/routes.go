package web

import (
	"net/http"

	"github.com/PatrickH298/ip-valet/dashboard/internal/api"
)

func (s *Server) routes(m *http.ServeMux) {
	s.handle(m, "GET /{$}", s.overview)

	s.handle(m, "GET /realms", s.realms)
	s.handle(m, "POST /realms", s.createRealm)
	s.handle(m, "GET /realms/{realm}", s.realm)
	s.handle(m, "POST /realms/{realm}/delete", s.deleteRealm)
	s.handle(m, "GET /realms/{realm}/rules/{list}/new", s.newRule)
	s.handle(m, "POST /realms/{realm}/rules/{list}", s.createRule)
	s.handle(m, "GET /realms/{realm}/rules/{list}/{id}", s.editRule)
	s.handle(m, "POST /realms/{realm}/rules/{list}/{id}", s.updateRule)
	s.handle(m, "POST /realms/{realm}/rules/{list}/{id}/move", s.moveRule)
	s.handle(m, "POST /realms/{realm}/rules/{list}/{id}/delete", s.deleteRule)

	s.handle(m, "GET /workers", s.workers)
	s.handle(m, "POST /workers", s.createWorker)
	s.handle(m, "GET /workers/{id}", s.worker)
	s.handle(m, "POST /workers/{id}", s.updateWorker)
	s.handle(m, "POST /workers/{id}/delete", s.deleteWorker)
	s.handle(m, "POST /workers/{id}/subscriptions", s.createSubscription)
	s.handle(m, "POST /workers/{id}/subscriptions/{sid}/delete", s.deleteSubscription)
	s.handle(m, "POST /workers/{id}/keys", s.createWorkerKey)

	s.handle(m, "GET /clients", s.clients)
	s.handle(m, "POST /clients", s.createClient)
	s.handle(m, "GET /clients/{id}", s.client)
	s.handle(m, "POST /clients/{id}", s.updateClient)
	s.handle(m, "POST /clients/{id}/delete", s.deleteClient)
	s.handle(m, "POST /clients/{id}/keys", s.createClientKey)

	s.handle(m, "GET /keys", s.keys)
	s.handle(m, "POST /keys", s.createAdminKey)
	s.handle(m, "POST /keys/{id}/revoke", s.revokeKey)

	s.handle(m, "GET /entries", s.entries)
	s.handle(m, "GET /entries/new", s.newEntry)
	s.handle(m, "POST /entries", s.createEntry)
	s.handle(m, "GET /entries/{id}", s.entry)
	s.handle(m, "POST /entries/{id}/delete", s.deleteEntry)

	s.handle(m, "GET /audit", s.audit)

	if s.Local != nil {
		s.handle(m, "GET /account", s.account)
		s.handle(m, "POST /account", s.changeLogin)
	}

	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.errorPage(w, r, http.StatusNotFound, "Not found", "There is no such page.")
	})
}

// confirmView is a page that asks before a change, listing what it does.
type confirmView struct {
	Heading  string
	Message  string
	Notes    []string
	Action   string      // where the confirmed form posts
	Fields   [][2]string // the original form, re-posted
	Impact   []api.ImpactItem
	Warnings []api.Warning
	Preview  bool // the impact comes from a dry run
	Button   string
	Danger   bool
	Cancel   string
}

// change is an impact-checked change, run in up to two steps: a preview or
// an attempt that the API answers with its impact, then the confirmed change.
type change struct {
	Section string
	Heading string
	Message string
	Button  string
	Danger  bool
	Cancel  string
	Preview bool                                 // always preview with a dry run first (deletions)
	Run     func(api.Impact) (api.Extras, error) // performs the change in a mode
	Done    func(api.Extras)                     // after success: usually a redirect
	Refused func(error) bool                     // shows a refusal on the form; false passes it on
}

// run carries out c for a form already parsed into r.PostForm.
func (s *Server) run(w http.ResponseWriter, r *http.Request, c change) error {
	mode := api.Plain
	switch {
	case r.PostForm.Get("confirm") == "yes":
		mode = api.Confirm
	case c.Preview:
		mode = api.DryRun
	}
	x, err := c.Run(mode)
	if api.IsCode(err, "confirmation_required") {
		s.confirm(w, r, c, err.(*api.Error).Impact, nil, false)
		return nil
	}
	if err != nil {
		if c.Refused != nil && c.Refused(err) {
			return nil
		}
		return err
	}
	if mode == api.DryRun {
		s.confirm(w, r, c, x.Impact, x.Warnings, true)
		return nil
	}
	c.Done(x)
	return nil
}

func (s *Server) confirm(w http.ResponseWriter, r *http.Request, c change, impact []api.ImpactItem,
	warnings []api.Warning, preview bool) {
	v := confirmView{Heading: c.Heading, Message: c.Message, Action: r.URL.Path,
		Fields: hidden(r.PostForm, "confirm"), Impact: impact, Warnings: warnings, Preview: preview,
		Button: c.Button, Danger: c.Danger, Cancel: c.Cancel}
	s.render(w, r, http.StatusOK, "confirm", c.Heading, c.Section, v)
}

// ask shows a confirmation page for a change without an impact check.
// It reports true when the form already carries the confirmation.
func (s *Server) ask(w http.ResponseWriter, r *http.Request, section string, v confirmView) bool {
	if r.PostForm.Get("confirm") == "yes" {
		return true
	}
	v.Action = r.URL.Path
	v.Fields = hidden(r.PostForm, "confirm")
	s.render(w, r, http.StatusOK, "confirm", v.Heading, section, v)
	return false
}

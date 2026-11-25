package web

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/PatrickH298/ip-valet/dashboard/internal/api"
)

type workersView struct {
	Workers []workerListRow
	Form    *Form
}

type workerListRow struct {
	Worker      api.Worker
	Lag         int64
	Status      string
	StatusClass string
}

func (s *Server) workers(w http.ResponseWriter, r *http.Request) error {
	return s.workersPage(w, r, http.StatusOK, newForm(url.Values{"ipv4": {"on"}, "ipv6": {"on"}}))
}

func (s *Server) workersPage(w http.ResponseWriter, r *http.Request, status int, f *Form) error {
	workers, err := s.API.Workers(r.Context())
	if err != nil {
		return err
	}
	health, err := s.API.Health(r.Context())
	if err != nil {
		return err
	}
	byID := map[string]api.WorkerHealth{}
	for _, h := range health.Workers {
		byID[h.WorkerID] = h
	}
	v := workersView{Form: f}
	for _, wk := range workers {
		row := workerListRow{Worker: wk}
		if h, ok := byID[wk.ID]; ok {
			row.Lag = h.Lag
			row.Status, row.StatusClass = workerStatus(h)
		}
		v.Workers = append(v.Workers, row)
	}
	s.render(w, r, status, "workers", "Workers", "workers", v)
	return nil
}

func (s *Server) createWorker(w http.ResponseWriter, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return err
	}
	f := newForm(r.PostForm)
	m, err := s.API.CreateWorker(r.Context(), strings.TrimSpace(f.Get("name")), strings.TrimSpace(f.Get("label")),
		f.Checked("ipv4"), f.Checked("ipv6"))
	if err != nil {
		if f.refused(err) {
			return s.workersPage(w, r, http.StatusBadRequest, f)
		}
		return err
	}
	s.redirect(w, r, "/workers/"+url.PathEscape(m.ID),
		done("Worker "+m.Name+" created. Subscribe it to entries and create a key for it below.", m.Extras))
	return nil
}

type workerView struct {
	Worker      api.Worker
	Health      api.WorkerHealth
	Status      string
	StatusClass string
	Subs        []api.Subscription
	Keys        []keyRow
	Realms      []api.Realm
	Edit        *Form
	SubForm     *Form
	KeyForm     *Form
}

func (s *Server) worker(w http.ResponseWriter, r *http.Request) error {
	return s.workerPage(w, r, http.StatusOK, nil, nil, nil)
}

func (s *Server) workerPage(w http.ResponseWriter, r *http.Request, status int, edit, sub, key *Form) error {
	id := r.PathValue("id")
	wk, err := s.API.Worker(r.Context(), id)
	if err != nil {
		return err
	}
	h, err := s.API.WorkerHealth(r.Context(), id)
	if err != nil {
		return err
	}
	subs, err := s.API.Subscriptions(r.Context(), id)
	if err != nil {
		return err
	}
	keys, err := s.API.AllKeys(r.Context(), api.KeyFilter{WorkerID: id})
	if err != nil {
		return err
	}
	realms, err := s.API.Realms(r.Context())
	if err != nil {
		return err
	}
	if edit == nil {
		edit = newForm(url.Values{"name": {wk.Name}, "label": {wk.Label}})
		if wk.IPv4 {
			edit.Values.Set("ipv4", "on")
		}
		if wk.IPv6 {
			edit.Values.Set("ipv6", "on")
		}
	}
	if sub == nil {
		sub = newForm(url.Values{"realm": {"*"}, "user": {"*"}, "group": {"*"}})
	}
	if key == nil {
		key = newForm(url.Values{"name": {wk.Name}, "expires_in_days": {""}})
	}
	v := workerView{Worker: wk, Health: h, Subs: subs, Realms: realms, Edit: edit, SubForm: sub, KeyForm: key}
	v.Status, v.StatusClass = workerStatus(h)
	for _, k := range keys {
		v.Keys = append(v.Keys, s.keyRow(k, nil, nil))
	}
	s.render(w, r, status, "worker", "Worker "+wk.Name, "workers", v)
	return nil
}

func (s *Server) updateWorker(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	if err := r.ParseForm(); err != nil {
		return err
	}
	f := newForm(r.PostForm)
	body := map[string]any{
		"name":  strings.TrimSpace(f.Get("name")),
		"label": strings.TrimSpace(f.Get("label")),
		"ipv4":  f.Checked("ipv4"),
		"ipv6":  f.Checked("ipv6"),
	}
	back := "/workers/" + url.PathEscape(id)
	return s.run(w, r, change{
		Section: "workers", Heading: "Change this worker's address families?", Cancel: back,
		Message: "Entries of a family the worker no longer applies stop being routed to it, and it must confirm " +
			"removing them.",
		Button: "Save worker",
		Run: func(mode api.Impact) (api.Extras, error) {
			m, err := s.API.UpdateWorker(r.Context(), id, body, mode)
			return m.Extras, err
		},
		Done: func(x api.Extras) { s.redirect(w, r, back, done("Worker saved.", x)) },
		Refused: func(err error) bool {
			if !f.refused(err) {
				return false
			}
			_ = s.workerPage(w, r, http.StatusBadRequest, f, nil, nil)
			return true
		},
	})
}

func (s *Server) deleteWorker(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	wk, err := s.API.Worker(r.Context(), id)
	if err != nil {
		return err
	}
	if err := r.ParseForm(); err != nil {
		return err
	}
	return s.run(w, r, change{
		Section: "workers", Preview: true, Danger: true, Cancel: "/workers/" + url.PathEscape(id),
		Heading: "Delete worker " + wk.Name + "?",
		Message: "This deletes its subscriptions, its rejections and its keys. The worker program stops working " +
			"at its next request; anything it applied stays where it applied it until removed there.",
		Button: "Delete worker",
		Run: func(mode api.Impact) (api.Extras, error) {
			m, err := s.API.DeleteWorker(r.Context(), id, mode)
			return m.Extras, err
		},
		Done: func(x api.Extras) { s.redirect(w, r, "/workers", done("Worker "+wk.Name+" deleted.", x)) },
	})
}

func (s *Server) createSubscription(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	if err := r.ParseForm(); err != nil {
		return err
	}
	f := newForm(r.PostForm)
	m, err := s.API.CreateSubscription(r.Context(), id, strings.TrimSpace(f.Get("realm")),
		strings.TrimSpace(f.Get("user")), strings.TrimSpace(f.Get("group")))
	if err != nil {
		if f.refused(err) {
			return s.workerPage(w, r, http.StatusBadRequest, nil, f, nil)
		}
		return err
	}
	s.redirect(w, r, "/workers/"+url.PathEscape(id)+"#subscriptions", done(fmt.Sprintf(
		"Subscribed to realm %s, user %s, group %s. Matching entries read pending until the worker catches up.",
		selector(m.Realm), selector(m.User), selector(m.Group)), m.Extras))
	return nil
}

func (s *Server) deleteSubscription(w http.ResponseWriter, r *http.Request) error {
	id, sid := r.PathValue("id"), r.PathValue("sid")
	if err := r.ParseForm(); err != nil {
		return err
	}
	back := "/workers/" + url.PathEscape(id) + "#subscriptions"
	return s.run(w, r, change{
		Section: "workers", Preview: true, Danger: true, Cancel: back,
		Heading: "Delete this subscription?",
		Message: "Entries no other subscription routes to this worker stop being routed to it, and it must confirm " +
			"removing them. Entries no worker matches any more stay, reading unrouted.",
		Button: "Delete subscription",
		Run: func(mode api.Impact) (api.Extras, error) {
			m, err := s.API.DeleteSubscription(r.Context(), sid, mode)
			return m.Extras, err
		},
		Done: func(x api.Extras) { s.redirect(w, r, back, done("Subscription deleted.", x)) },
	})
}

func (s *Server) createWorkerKey(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	wk, err := s.API.Worker(r.Context(), id)
	if err != nil {
		return err
	}
	if err := r.ParseForm(); err != nil {
		return err
	}
	f := newForm(r.PostForm)
	body := keyBody(f, "worker")
	if f.HasErrors() {
		return s.workerPage(w, r, http.StatusBadRequest, nil, nil, f)
	}
	body["worker_id"] = id
	k, err := s.API.CreateKey(r.Context(), body)
	if err != nil {
		if f.refused(err) {
			return s.workerPage(w, r, http.StatusBadRequest, nil, nil, f)
		}
		return err
	}
	s.keyCreated(w, r, "workers", k, "worker "+wk.Name, "/workers/"+url.PathEscape(id)+"#keys")
	return nil
}

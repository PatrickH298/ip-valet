package web

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/PatrickH298/ip-valet/dashboard/internal/api"
)

type clientsView struct {
	Clients []api.Client
	Realms  []api.Realm
	Form    *Form
}

func (s *Server) clients(w http.ResponseWriter, r *http.Request) error {
	return s.clientsPage(w, r, http.StatusOK, nil)
}

func (s *Server) clientsPage(w http.ResponseWriter, r *http.Request, status int, f *Form) error {
	clients, err := s.API.Clients(r.Context())
	if err != nil {
		return err
	}
	realms, err := s.API.Realms(r.Context())
	if err != nil {
		return err
	}
	s.render(w, r, status, "clients", "Clients", "clients", clientsView{Clients: clients, Realms: realms, Form: f})
	return nil
}

// realmsOf returns the realms ticked on a form.
func realmsOf(f *Form) []string {
	out := []string{}
	for _, v := range f.Values["realms"] {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func (s *Server) createClient(w http.ResponseWriter, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return err
	}
	f := newForm(r.PostForm)
	c, x, err := s.API.CreateClient(r.Context(), strings.TrimSpace(f.Get("name")), realmsOf(f))
	if err != nil {
		if f.refused(err) {
			return s.clientsPage(w, r, http.StatusBadRequest, f)
		}
		return err
	}
	s.redirect(w, r, "/clients/"+url.PathEscape(c.ID), done("Client "+c.Name+" created. Create a key for it below.", x))
	return nil
}

type clientView struct {
	Client  api.Client
	Realms  []api.Realm
	Keys    []keyRow
	Edit    *Form
	KeyForm *Form
}

func (s *Server) client(w http.ResponseWriter, r *http.Request) error {
	return s.clientPage(w, r, http.StatusOK, nil, nil)
}

func (s *Server) clientPage(w http.ResponseWriter, r *http.Request, status int, edit, key *Form) error {
	id := r.PathValue("id")
	c, err := s.API.Client(r.Context(), id)
	if err != nil {
		return err
	}
	realms, err := s.API.Realms(r.Context())
	if err != nil {
		return err
	}
	keys, err := s.API.AllKeys(r.Context(), api.KeyFilter{ClientID: id})
	if err != nil {
		return err
	}
	if edit == nil {
		edit = newForm(url.Values{"name": {c.Name}, "realms": c.Realms})
	}
	if key == nil {
		key = newForm(url.Values{"name": {c.Name}})
	}
	v := clientView{Client: c, Realms: realms, Edit: edit, KeyForm: key}
	for _, k := range keys {
		v.Keys = append(v.Keys, s.keyRow(k, nil, nil))
	}
	s.render(w, r, status, "client", "Client "+c.Name, "clients", v)
	return nil
}

func (s *Server) updateClient(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	if err := r.ParseForm(); err != nil {
		return err
	}
	f := newForm(r.PostForm)
	_, x, err := s.API.UpdateClient(r.Context(), id, map[string]any{
		"name": strings.TrimSpace(f.Get("name")), "realms": realmsOf(f)})
	if err != nil {
		if f.refused(err) {
			return s.clientPage(w, r, http.StatusBadRequest, f, nil)
		}
		return err
	}
	s.redirect(w, r, "/clients/"+url.PathEscape(id), done("Client saved.", x))
	return nil
}

func (s *Server) deleteClient(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	c, err := s.API.Client(r.Context(), id)
	if err != nil {
		return err
	}
	if err := r.ParseForm(); err != nil {
		return err
	}
	if !s.ask(w, r, "clients", confirmView{
		Heading: "Delete client " + c.Name + "?",
		Message: "This deletes the client's keys, so the client program stops working at its next request. " +
			"The entries it registered stay until they expire or are deleted.",
		Button: "Delete client", Danger: true, Cancel: "/clients/" + url.PathEscape(id),
	}) {
		return nil
	}
	if _, err := s.API.DeleteClient(r.Context(), id); err != nil {
		return err
	}
	s.redirect(w, r, "/clients", &flash{Kind: "ok", Lines: []string{"Client " + c.Name + " deleted."}})
	return nil
}

func (s *Server) createClientKey(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	c, err := s.API.Client(r.Context(), id)
	if err != nil {
		return err
	}
	if err := r.ParseForm(); err != nil {
		return err
	}
	f := newForm(r.PostForm)
	body := keyBody(f, "client")
	if f.HasErrors() {
		return s.clientPage(w, r, http.StatusBadRequest, nil, f)
	}
	body["client_id"] = id
	k, err := s.API.CreateKey(r.Context(), body)
	if err != nil {
		if f.refused(err) {
			return s.clientPage(w, r, http.StatusBadRequest, nil, f)
		}
		return err
	}
	s.keyCreated(w, r, "clients", k, "client "+c.Name, "/clients/"+url.PathEscape(id)+"#keys")
	return nil
}

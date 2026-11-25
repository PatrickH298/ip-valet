package web

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/PatrickH298/ip-valet/dashboard/internal/auth"
)

type accountView struct {
	Default   bool
	Method    string
	MinLength int
	Form      *Form
}

func (s *Server) account(w http.ResponseWriter, r *http.Request) error {
	lg := s.Local.Store.Login()
	s.accountPage(w, r, http.StatusOK, newForm(url.Values{"username": {lg.Username}, "method": {lg.Method}}))
	return nil
}

func (s *Server) accountPage(w http.ResponseWriter, r *http.Request, status int, f *Form) {
	v := accountView{Default: s.Local.Store.IsDefault(), Method: s.Local.Store.Login().Method,
		MinLength: auth.MinPasswordLength, Form: f}
	s.render(w, r, status, "account", "Account", "account", v)
}

func (s *Server) changeLogin(w http.ResponseWriter, r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return err
	}
	f := newForm(r.PostForm)
	err := s.Local.ChangeLogin(w, r, auth.Change{
		Current:     f.Get("current"),
		Method:      f.Get("method"),
		Username:    f.Get("username"),
		NewPassword: f.Get("new_password"),
		Confirm:     f.Get("confirm"),
	})
	var ce auth.ChangeErrors
	switch {
	case errors.As(err, &ce):
		for k, v := range ce {
			f.Errors[k] = v
		}
		s.accountPage(w, r, http.StatusBadRequest, f)
		return nil
	case err != nil:
		return err
	}
	msg := "Login saved. Every other session has been signed out."
	if f.Get("method") == auth.MethodBasic {
		msg = "Login saved. Your browser now asks for the user name and password."
	}
	s.redirect(w, r, "/", &flash{Kind: "ok", Lines: []string{msg}})
	return nil
}

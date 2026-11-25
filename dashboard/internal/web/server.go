// Package web serves the dashboard's pages. Everything it shows or changes
// goes through the admin API; it keeps no state of its own beyond what the
// sign-in provider holds.
package web

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strings"
	"time"

	"github.com/PatrickH298/ip-valet/dashboard/internal/api"
	"github.com/PatrickH298/ip-valet/dashboard/internal/auth"
)

// Options configure a Server.
type Options struct {
	API            *api.Admin
	Auth           auth.Provider
	Local          *auth.Local // the local login, changed on the Account page; nil with external sign-in
	Log            *slog.Logger
	Location       *time.Location
	TrustedProxies []netip.Prefix
	SecureCookies  bool   // mark the flash cookie Secure
	SelfKeyID      string // the id of the dashboard's own admin key
	Version        string
}

// Server serves the dashboard.
type Server struct {
	Options
	pages    map[string]*template.Template
	flashKey []byte
	static   http.Handler
}

// maxForm bounds a posted form.
const maxForm = 64 << 10

// New parses the templates and returns a server.
func New(o Options) (*Server, error) {
	s := &Server{Options: o, flashKey: make([]byte, 32)}
	_, _ = rand.Read(s.flashKey)
	if s.Location == nil {
		s.Location = time.UTC
	}
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	s.static = staticHandler()
	return s, nil
}

// Handler returns the dashboard's HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", s.static)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	s.Auth.Routes(mux)

	app := http.NewServeMux()
	s.routes(app)
	mux.Handle("/", s.requireSignIn(app))

	cop := http.NewCrossOriginProtection()
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.Log.Warn("cross-origin request refused", "method", r.Method, "path", r.URL.Path,
			"client_ip", auth.ClientIPFrom(r.Context()).String(), "origin", r.Header.Get("Origin"),
			"sec_fetch_site", r.Header.Get("Sec-Fetch-Site"))
		s.errorPage(w, r, http.StatusForbidden, "Request refused",
			"The request came from another site, so it was refused. Use the dashboard's own pages and forms.")
	}))
	return s.wrap(cop.Handler(mux))
}

// handlerFunc is a page handler that may fail.
type handlerFunc func(w http.ResponseWriter, r *http.Request) error

func (s *Server) handle(mux *http.ServeMux, pattern string, h handlerFunc) {
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if err := h(w, r); err != nil {
			s.fail(w, r, err)
		}
	})
}

// requireSignIn lets signed-in requests through, carrying the person both
// for pages and as IPValet-On-Behalf-Of on API calls.
func (s *Server) requireSignIn(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := s.Auth.Identify(r)
		if id == nil {
			s.Auth.Challenge(w, r)
			return
		}
		if info := infoFrom(r.Context()); info != nil {
			info.user = id.Name
		}
		// The default login must be replaced before anything else.
		if s.Local != nil && s.Local.Store.IsDefault() && r.URL.Path != "/account" {
			http.Redirect(w, r, "/account", http.StatusSeeOther)
			return
		}
		ctx := api.OnBehalfOf(auth.WithIdentity(r.Context(), id), id.Name)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type reqInfo struct{ user string }

type infoKey struct{}

func infoFrom(ctx context.Context) *reqInfo {
	i, _ := ctx.Value(infoKey{}).(*reqInfo)
	return i
}

// wrap adds the caller's address, security headers, a form size limit, panic
// recovery and access logs.
func (s *Server) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ip := auth.ClientIP(r, s.TrustedProxies)
		info := &reqInfo{}
		r = r.WithContext(context.WithValue(auth.WithClientIP(r.Context(), ip), infoKey{}, info))
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; "+
			"form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			h.Set("Cache-Control", "no-store")
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxForm)
		}
		sw := &statusWriter{ResponseWriter: w}
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.Log.Error("panic serving request", "panic", fmt.Sprint(v), "stack", string(debug.Stack()))
				if sw.status == 0 {
					s.errorPage(sw, r, http.StatusInternalServerError, "Something went wrong",
						"The dashboard hit an unexpected error. Its log has the details.")
				}
			}
			status := sw.status
			if status == 0 {
				status = http.StatusOK
			}
			level := slog.LevelInfo
			if strings.HasPrefix(r.URL.Path, "/static/") || r.URL.Path == "/healthz" {
				level = slog.LevelDebug
			}
			s.Log.Log(r.Context(), level, "request", "method", r.Method, "path", r.URL.Path, "status", status,
				"duration_ms", float64(time.Since(start).Microseconds())/1000, "user", info.user,
				"client_ip", ip.String())
		}()
		next.ServeHTTP(sw, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// fail renders the error page for err.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ae *api.Error
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &mbe):
		s.errorPage(w, r, http.StatusRequestEntityTooLarge, "Too much data", "The form sent was too large.")
	case errors.As(err, &ae) && ae.Status == 0:
		s.Log.Error("API server unreachable", "error", err.Error())
		s.errorPage(w, r, http.StatusBadGateway, "API server unreachable",
			"The dashboard could not reach the API server. Check that it is running and that "+
				"IPVALET_DASHBOARD_API_URL points at its admin listener.")
	case errors.As(err, &ae) && (ae.Status == http.StatusUnauthorized || ae.Status == http.StatusForbidden):
		s.Log.Error("API server refused the dashboard's key", "status", ae.Status, "code", ae.Code,
			"request_id", ae.RequestID)
		s.errorPage(w, r, http.StatusBadGateway, "Dashboard key refused",
			"The API server refused the dashboard's admin key ("+ae.Code+"). It may have been revoked or "+
				"have expired; give the dashboard a new key in IPVALET_DASHBOARD_API_KEY_FILE.")
	case errors.As(err, &ae) && ae.Status == http.StatusNotFound:
		s.errorPage(w, r, http.StatusNotFound, "Not found", "There is nothing here. It may have been deleted.")
	case errors.As(err, &ae) && ae.Status == http.StatusServiceUnavailable:
		s.errorPage(w, r, http.StatusServiceUnavailable, "API server unavailable",
			"The API server cannot reach its database right now. Try again shortly.")
	case errors.As(err, &ae) && ae.Status < 500:
		s.errorPage(w, r, http.StatusBadRequest, "Request refused", describe(ae))
	case errors.As(err, &ae):
		s.Log.Error("API server error", "status", ae.Status, "code", ae.Code, "request_id", ae.RequestID)
		s.errorPage(w, r, http.StatusBadGateway, "API server error",
			"The API server failed (request "+ae.RequestID+"). Its log has the details.")
	default:
		s.Log.Error("internal error", "method", r.Method, "path", r.URL.Path, "error", err.Error())
		s.errorPage(w, r, http.StatusInternalServerError, "Something went wrong",
			"The dashboard hit an unexpected error. Its log has the details.")
	}
}

// describe turns an API refusal into one sentence.
func describe(e *api.Error) string {
	msg := e.Message
	if msg == "" {
		msg = e.Code
	}
	if msg != "" {
		msg = strings.ToUpper(msg[:1]) + msg[1:]
	}
	if !strings.HasSuffix(msg, ".") {
		msg += "."
	}
	return msg
}

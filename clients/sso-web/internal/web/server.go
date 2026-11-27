// Package web serves the sso-web site: sign-in through the IdP, the page
// where people register their addresses, address detection, and the list
// of their registrations with revocation. Every change goes through the
// ip-valet API with the site's client key.
package web

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/httpx"
	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/idp"
	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/ipvalet"
	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/rules"
	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/seal"
)

// Options configure a Server.
type Options struct {
	API      *ipvalet.Client
	Provider idp.Provider // set before Handler is called
	Sessions *Sessions
	Sealer   *seal.Sealer
	Rules    []rules.Rule
	Log      *slog.Logger
	Location *time.Location

	PublicURL          *url.URL
	Title              string
	DetectV4, DetectV6 *url.URL

	DefaultSubnetV4, DefaultSubnetV6 int
	MaxSubnetV4, MaxSubnetV6         int

	Cookies        httpx.CookieMode
	TrustedProxies []netip.Prefix
	TrustAll       bool
	LogoutURL      *url.URL
	Version        string
}

// Server serves the site.
type Server struct {
	Options
	pages        *templates
	csp          string
	warnedHeader atomic.Bool
}

// maxForm bounds a posted form.
const maxForm = 64 << 10

// New parses the templates and returns a server.
func New(o Options) (*Server, error) {
	s := &Server{Options: o}
	if s.Location == nil {
		s.Location = time.UTC
	}
	var err error
	if s.pages, err = parseTemplates(); err != nil {
		return nil, err
	}
	// The page's scripts fetch /status here, and addresses from the
	// detection hosts.
	origins := []string{"'self'"}
	for _, u := range []*url.URL{o.DetectV4, o.DetectV6} {
		if u != nil {
			origins = append(origins, u.Scheme+"://"+u.Host)
		}
	}
	connect := strings.Join(origins, " ")
	forms := "'self'"
	if o.LogoutURL != nil {
		// form-action also covers where a form's response redirects.
		forms += " " + o.LogoutURL.Scheme + "://" + o.LogoutURL.Host
	}
	s.csp = "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; connect-src " + connect +
		"; form-action " + forms + "; frame-ancestors 'none'; base-uri 'none'"
	return s, nil
}

// Handler returns the site's handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", staticHandler())
	mux.HandleFunc("GET /healthz", healthz)
	mux.HandleFunc("GET /detect", s.detect)
	mux.HandleFunc("GET /login", s.login)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /signed-out", s.signedOut)
	s.Provider.Routes(mux)
	mux.Handle("GET /{$}", s.withSession(s.home))
	mux.Handle("GET /status", s.withSession(s.status))
	mux.Handle("POST /register", s.withSession(s.registerDetected))
	mux.Handle("POST /register/manual", s.withSession(s.registerManual))
	mux.Handle("POST /revoke", s.withSession(s.revoke))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.Fail(w, r, http.StatusNotFound, "Not found", "There is no such page.")
	})

	cop := http.NewCrossOriginProtection()
	for _, p := range s.Provider.CrossSitePosts() {
		cop.AddInsecureBypassPattern(p)
	}
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.Log.Warn("cross-origin request refused", "method", r.Method, "path", r.URL.Path,
			"client_ip", httpx.ClientIPFrom(r.Context()).String(), "origin", r.Header.Get("Origin"))
		s.Fail(w, r, http.StatusForbidden, "Request refused",
			"The request came from another site, so it was refused. Use this site's own page.")
	}))
	return s.wrap(cop.Handler(mux), true)
}

// DetectHandler serves only address detection, for its own port.
func (s *Server) DetectHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthz)
	mux.HandleFunc("GET /detect", s.detect)
	mux.HandleFunc("GET /{$}", s.detect)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	return s.wrap(mux, false)
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

// handlerFunc is a page handler for a signed-in person.
type handlerFunc func(w http.ResponseWriter, r *http.Request, sess Session, grants []rules.Grant)

// withSession lets requests with a live session through; others sign in.
func (s *Server) withSession(h handlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.session(r)
		if !ok {
			next := "/"
			if r.Method == http.MethodGet {
				next = r.URL.RequestURI()
			}
			http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusSeeOther)
			return
		}
		if info := infoFrom(r.Context()); info != nil {
			info.user = sess.User
		}
		grants := rules.Grants(s.Rules, rules.Identity{User: sess.User, Groups: sess.Groups})
		if len(grants) == 0 {
			s.Sessions.Delete(sess.ID)
			s.noAccess(w, r, sess.User)
			return
		}
		h(w, r, sess, grants)
	})
}

type reqInfo struct{ user string }

type infoKey struct{}

func infoFrom(ctx context.Context) *reqInfo {
	i, _ := ctx.Value(infoKey{}).(*reqInfo)
	return i
}

// wrap adds the caller's address, security headers, a form size limit,
// panic recovery and access logs.
func (s *Server) wrap(next http.Handler, pages bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ip := httpx.ClientIP(r, s.TrustedProxies)
		s.checkForwardedHeader(r)
		info := &reqInfo{}
		ctx := httpx.WithRequest(r.Context(), ip, httpx.RequestIsHTTPS(r, s.TrustedProxies))
		r = r.WithContext(context.WithValue(ctx, infoKey{}, info))
		h := w.Header()
		if pages {
			h.Set("Content-Security-Policy", s.csp)
			h.Set("X-Frame-Options", "DENY")
		}
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
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
					s.Fail(sw, r, http.StatusInternalServerError, "Something went wrong",
						"The site hit an unexpected error. Its log has the details.")
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

// checkForwardedHeader warns once when a peer that is not trusted sends
// X-Forwarded-For: behind a reverse proxy that is not listed in
// IPVALET_SSO_TRUSTED_PROXIES, every person would seem to come from the
// proxy, and register its address.
func (s *Server) checkForwardedHeader(r *http.Request) {
	if s.TrustAll || r.Header.Get("X-Forwarded-For") == "" || s.warnedHeader.Load() {
		return
	}
	peer := httpx.Peer(r)
	if httpx.IsTrusted(peer, s.TrustedProxies) || !s.warnedHeader.CompareAndSwap(false, true) {
		return
	}
	s.Log.Warn("a peer that is not a trusted proxy sent X-Forwarded-For; if it is your reverse proxy, add it to "+
		"IPVALET_SSO_TRUSTED_PROXIES, or everyone will seem to come from it (logged once)", "peer", peer.String())
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

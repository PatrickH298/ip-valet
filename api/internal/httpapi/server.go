// Package httpapi serves the client, worker, admin and health HTTP APIs.
package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PatrickH298/ip-valet/api/internal/auth"
	"github.com/PatrickH298/ip-valet/api/internal/config"
	"github.com/PatrickH298/ip-valet/api/internal/db"
	"github.com/PatrickH298/ip-valet/api/internal/events"
	"github.com/PatrickH298/ip-valet/api/internal/metrics"
	"github.com/PatrickH298/ip-valet/api/internal/rules"
)

// ListenerStatus reports whether the LISTEN connection is up.
type ListenerStatus interface{ Up() bool }

// Deps are the server's collaborators.
type Deps struct {
	Config   config.Config
	Pool     *pgxpool.Pool
	Hub      *events.Hub
	Auth     *auth.Authenticator
	Listener ListenerStatus
	Metrics  *metrics.Metrics
	Log      *slog.Logger
}

// Server holds the routes and their dependencies.
type Server struct {
	Deps
	all      *http.ServeMux // every route, for a single listener
	pubMux   *http.ServeMux // client and worker routes, health
	adminMux *http.ServeMux // admin routes, health
	patterns []string

	readyMu  sync.Mutex
	readyAt  time.Time
	readyErr string

	warnUntrustedXFF sync.Once

	// streams is cancelled on shutdown to end every SSE stream.
	streams      context.Context
	cancelStream context.CancelFunc
	streamWG     sync.WaitGroup
}

// New builds the server and registers every route.
func New(d Deps) *Server {
	s := &Server{Deps: d, all: http.NewServeMux(), pubMux: http.NewServeMux(), adminMux: http.NewServeMux()}
	s.streams, s.cancelStream = context.WithCancel(context.Background())
	s.routes()
	return s
}

// CloseStreams ends every SSE stream and waits for them to return.
func (s *Server) CloseStreams() {
	s.cancelStream()
	s.streamWG.Wait()
}

// Routes lists every registered "METHOD /path" pattern, for the OpenAPI check.
func (s *Server) Routes() []string { return append([]string(nil), s.patterns...) }

func (s *Server) routes() {
	s.public("GET /healthz", s.healthz)
	s.public("GET /readyz", s.readyz)

	// Client.
	s.handle("POST /v1/submissions", auth.KindClient, s.postSubmission)
	s.handle("DELETE /v1/submissions/{id}", auth.KindClient, s.deleteSubmission)
	s.handle("GET /v1/entries", auth.KindClient, s.listClientEntries)
	s.handle("GET /v1/entries/{id}", auth.KindClient, s.getClientEntry)
	s.handle("DELETE /v1/entries/{id}", auth.KindClient, s.deleteClientEntry)
	s.handle("GET /v1/events", auth.KindClient, s.clientEvents)

	// Worker.
	s.handle("GET /v1/worker/desired-state", auth.KindWorker, s.desiredState)
	s.handle("GET /v1/worker/events", auth.KindWorker, s.workerEvents)
	s.handle("POST /v1/worker/status", auth.KindWorker, s.workerStatus)

	// Admin.
	const a = "/v1/admin"
	s.handle("GET "+a+"/realms", auth.KindAdmin, s.listRealms)
	s.handle("POST "+a+"/realms", auth.KindAdmin, s.createRealm)
	s.handle("GET "+a+"/realms/{name}", auth.KindAdmin, s.getRealm)
	s.handle("DELETE "+a+"/realms/{name}", auth.KindAdmin, s.deleteRealm)

	s.handle("GET "+a+"/clients", auth.KindAdmin, s.listClients)
	s.handle("POST "+a+"/clients", auth.KindAdmin, s.createClient)
	s.handle("GET "+a+"/clients/{id}", auth.KindAdmin, s.getClient)
	s.handle("PATCH "+a+"/clients/{id}", auth.KindAdmin, s.patchClient)
	s.handle("DELETE "+a+"/clients/{id}", auth.KindAdmin, s.deleteClient)

	s.handle("GET "+a+"/workers", auth.KindAdmin, s.listWorkers)
	s.handle("POST "+a+"/workers", auth.KindAdmin, s.createWorker)
	s.handle("GET "+a+"/workers/{id}", auth.KindAdmin, s.getWorker)
	s.handle("PATCH "+a+"/workers/{id}", auth.KindAdmin, s.patchWorker)
	s.handle("DELETE "+a+"/workers/{id}", auth.KindAdmin, s.deleteWorker)
	s.handle("GET "+a+"/workers/{id}/subscriptions", auth.KindAdmin, s.listSubscriptions)
	s.handle("POST "+a+"/workers/{id}/subscriptions", auth.KindAdmin, s.createSubscription)
	s.handle("DELETE "+a+"/subscriptions/{id}", auth.KindAdmin, s.deleteSubscription)
	s.handle("GET "+a+"/workers/{id}/health", auth.KindAdmin, s.workerHealth)
	s.handle("GET "+a+"/health", auth.KindAdmin, s.allHealth)

	s.handle("GET "+a+"/keys", auth.KindAdmin, s.listKeys)
	s.handle("POST "+a+"/keys", auth.KindAdmin, s.createKey)
	s.handle("GET "+a+"/keys/{id}", auth.KindAdmin, s.getKey)
	s.handle("POST "+a+"/keys/{id}/revoke", auth.KindAdmin, s.revokeKey)

	s.handle("GET "+a+"/realms/{realm}/rules/{list}", auth.KindAdmin, s.listRules)
	s.handle("POST "+a+"/realms/{realm}/rules/{list}", auth.KindAdmin, s.createRule)
	s.handle("PATCH "+a+"/realms/{realm}/rules/{list}/{id}", auth.KindAdmin, s.patchRule)
	s.handle("DELETE "+a+"/realms/{realm}/rules/{list}/{id}", auth.KindAdmin, s.deleteRule)
	s.handle("PUT "+a+"/realms/{realm}/rules/{list}/order", auth.KindAdmin, s.reorderRules)

	s.handle("GET "+a+"/entries", auth.KindAdmin, s.listAdminEntries)
	s.handle("GET "+a+"/entries/{id}", auth.KindAdmin, s.getAdminEntry)
	s.handle("DELETE "+a+"/entries/{id}", auth.KindAdmin, s.deleteAdminEntry)

	s.handle("GET "+a+"/audit", auth.KindAdmin, s.listAudit)
}

// handlerFunc is an authenticated handler; returned errors become error responses.
type handlerFunc func(w http.ResponseWriter, r *http.Request, p *auth.Principal) error

// register adds a route to the combined mux and to the public or admin one:
// /v1/admin routes are admin-only, health routes are on both.
func (s *Server) register(pattern string, h http.Handler) {
	s.patterns = append(s.patterns, pattern)
	s.all.Handle(pattern, h)
	_, path, _ := strings.Cut(pattern, " ")
	switch {
	case strings.HasPrefix(path, "/v1/admin/"):
		s.adminMux.Handle(pattern, h)
	case strings.HasPrefix(path, "/v1/"):
		s.pubMux.Handle(pattern, h)
	default:
		s.pubMux.Handle(pattern, h)
		s.adminMux.Handle(pattern, h)
	}
}

func (s *Server) public(pattern string, h func(http.ResponseWriter, *http.Request) error) {
	s.register(pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := h(w, r); err != nil {
			s.writeErr(w, r, err)
		}
	}))
}

func (s *Server) handle(pattern, kind string, h handlerFunc) {
	s.register(pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ip netip.Addr
		if info := reqInfoFrom(r.Context()); info != nil {
			ip = info.ip
		}
		p, err := s.Auth.Authenticate(r.Context(), r.Header.Get("Authorization"), kind, ip)
		if err != nil {
			s.writeErr(w, r, err)
			return
		}
		if info := reqInfoFrom(r.Context()); info != nil {
			info.actor = p.Actor
		}
		if r.ContentLength > s.Config.MaxBodyBytes {
			s.writeErr(w, r, &http.MaxBytesError{Limit: s.Config.MaxBodyBytes})
			return
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, s.Config.MaxBodyBytes)
		}
		if err := h(w, r, p); err != nil {
			s.writeErr(w, r, err)
		}
	}))
}

type ctxKey int

const reqInfoKey ctxKey = 0

type reqInfo struct {
	id    string
	actor string
	ip    netip.Addr
}

func reqInfoFrom(ctx context.Context) *reqInfo {
	i, _ := ctx.Value(reqInfoKey).(*reqInfo)
	return i
}

func newRequestID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// statusWriter records the status code; Unwrap lets http.ResponseController
// reach Flush and the deadline setters.
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

var allMethods = []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

// Handler serves every route, for running with no separate admin listener.
func (s *Server) Handler() http.Handler { return s.wrap(s.all) }

// PublicHandler serves the client and worker APIs and health, without any
// admin route: the listener the reverse proxy exposes.
func (s *Server) PublicHandler() http.Handler { return s.wrap(s.pubMux) }

// AdminHandler serves the admin API and health: the listener kept off the
// public proxy.
func (s *Server) AdminHandler() http.Handler { return s.wrap(s.adminMux) }

// wrap adds request ids, access logs, metrics, panic recovery and JSON
// 404/405 responses around a mux.
func (s *Server) wrap(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		info := &reqInfo{id: newRequestID()}
		var untrustedXFF bool
		info.ip, untrustedXFF = clientIP(r, s.Config.TrustedProxies)
		if untrustedXFF {
			s.warnUntrustedXFF.Do(func() {
				s.Log.Warn("a request carried X-Forwarded-For from a peer not in IPVALET_TRUSTED_PROXIES; "+
					"the header is ignored, so every client behind that proxy shares one failed-authentication budget",
					"peer", info.ip.String())
			})
		}
		h := w.Header()
		h.Set("X-Request-Id", info.id)
		h.Set("X-Content-Type-Options", "nosniff")
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			// Responses can carry new keys and address lists; no cache may keep them.
			h.Set("Cache-Control", "no-store")
		}
		r = r.WithContext(db.WithClientIP(context.WithValue(r.Context(), reqInfoKey, info), info.ip))
		sw := &statusWriter{ResponseWriter: w}

		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.Log.Error("panic serving request", "request_id", info.id, "panic", fmt.Sprint(v), "stack", string(debug.Stack()))
				if sw.status == 0 {
					s.writeErr(sw, r, errors.New("panic"))
				}
			}
			route := "unmatched"
			if r.Pattern != "" {
				_, route, _ = strings.Cut(r.Pattern, " ")
			}
			status := sw.status
			if status == 0 {
				status = http.StatusOK
			}
			d := time.Since(start)
			if s.Metrics != nil {
				s.Metrics.Requests.WithLabelValues(route, r.Method, strconv.Itoa(status)).Inc()
				s.Metrics.Duration.WithLabelValues(route, r.Method).Observe(d.Seconds())
			}
			level := slog.LevelInfo
			if route == "/healthz" || route == "/readyz" {
				level = slog.LevelDebug
			}
			s.Log.Log(r.Context(), level, "request", "method", r.Method, "route", route, "status", status,
				"duration_ms", float64(d.Microseconds())/1000, "actor", info.actor, "client_ip", info.ip.String(),
				"request_id", info.id)
		}()

		if _, pattern := mux.Handler(r); pattern == "" {
			var allow []string
			for _, m := range allMethods {
				r2 := r.Clone(r.Context())
				r2.Method = m
				if _, p := mux.Handler(r2); p != "" {
					allow = append(allow, m)
				}
			}
			if len(allow) > 0 {
				sw.Header().Set("Allow", strings.Join(allow, ", "))
				s.writeErr(sw, r, &apiError{Status: http.StatusMethodNotAllowed, Code: "method_not_allowed",
					Message: "method not allowed"})
				return
			}
			s.writeErr(sw, r, errNotFound)
			return
		}
		mux.ServeHTTP(sw, r)
	})
}

// warningsOrEmpty never returns nil, so JSON always has an array.
func warningsOrEmpty(w []rules.Warning) []rules.Warning {
	if w == nil {
		return []rules.Warning{}
	}
	return w
}

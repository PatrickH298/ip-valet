// Package testutil runs API instances against a disposable Postgres database
// for the acceptance tests.
//
// Set IPVALET_TEST_DATABASE_URL to a postgres:// URL of a role that may create
// databases; each test gets its own database, dropped afterwards. Without it
// the tests that need Postgres are skipped.
package testutil

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PatrickH298/ip-valet/api/internal/app"
	"github.com/PatrickH298/ip-valet/api/internal/auth"
	"github.com/PatrickH298/ip-valet/api/internal/config"
)

// EnvDatabaseURL names the variable holding the test server's URL.
const EnvDatabaseURL = "IPVALET_TEST_DATABASE_URL"

// NewDatabase creates an empty database and returns its URL. It is dropped
// when the test ends.
func NewDatabase(t testing.TB) string {
	t.Helper()
	base := os.Getenv(EnvDatabaseURL)
	if base == "" {
		t.Skip(EnvDatabaseURL + " is not set; skipping a test that needs Postgres")
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		t.Fatalf("%s must be a postgres:// URL", EnvDatabaseURL)
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "ipvalet_test_" + hex.EncodeToString(b)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connecting to %s: %v", EnvDatabaseURL, err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("creating test database: %v", err)
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(ctx, base)
		if err != nil {
			return
		}
		defer c.Close(ctx)
		_, _ = c.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})
	u.Path = "/" + name
	return u.String()
}

// Env returns a getenv over a map, for config.Load.
func Env(m map[string]string) config.Getenv {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

// Config builds a Config for dbURL with test-friendly defaults and overrides.
func Config(t testing.TB, dbURL string, env map[string]string) config.Config {
	t.Helper()
	m := map[string]string{
		"IPVALET_DATABASE_URL": dbURL,
		"IPVALET_METRICS_ADDR": "",
		"IPVALET_DB_MAX_CONNS": "20",
	}
	for k, v := range env {
		m[k] = v
	}
	cfg, err := config.Load(Env(m), os.ReadFile)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

// Logger returns a discarding logger, or a stderr one with IPVALET_TEST_LOG=1.
func Logger() *slog.Logger {
	if os.Getenv("IPVALET_TEST_LOG") != "" {
		return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// Instance is one running API instance behind an httptest server.
type Instance struct {
	App    *app.App
	Server *httptest.Server
	URL    string
}

// StartInstance starts an API instance for dbURL. configure may adjust the
// httptest server (timeouts) before it starts.
func StartInstance(t testing.TB, cfg config.Config, configure ...func(*http.Server)) *Instance {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	a, err := app.Start(ctx, cfg, Logger())
	if err != nil {
		t.Fatalf("starting instance: %v", err)
	}
	srv := httptest.NewUnstartedServer(a.API.Handler())
	ref := app.NewHTTPServer("", nil, Logger())
	srv.Config.ReadHeaderTimeout = ref.ReadHeaderTimeout
	srv.Config.ReadTimeout = ref.ReadTimeout
	srv.Config.WriteTimeout = ref.WriteTimeout
	srv.Config.IdleTimeout = ref.IdleTimeout
	for _, f := range configure {
		f(srv.Config)
	}
	srv.Start()
	inst := &Instance{App: a, Server: srv, URL: srv.URL}
	t.Cleanup(func() {
		a.API.CloseStreams()
		srv.CloseClientConnections()
		srv.Close()
		a.Close()
	})
	return inst
}

// Harness is a database, one API instance, an admin key and a direct pool.
type Harness struct {
	T        testing.TB
	DBURL    string
	Pool     *pgxpool.Pool
	Inst     *Instance
	AdminKey string
	Client   *http.Client
}

// New starts a harness. env overrides configuration variables.
func New(t testing.TB, env map[string]string) *Harness {
	t.Helper()
	dbURL := NewDatabase(t)
	h := &Harness{T: t, DBURL: dbURL, Client: &http.Client{Timeout: 30 * time.Second}}
	h.Inst = StartInstance(t, Config(t, dbURL, env))
	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	h.Pool = pool
	key, err := auth.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO api_keys (id, kind, name, secret_hash)
		VALUES ($1, 'admin', 'test admin', $2)`, key.ID, key.Hash()); err != nil {
		t.Fatal(err)
	}
	h.AdminKey = key.String()
	return h
}

// Resp is a captured HTTP response.
type Resp struct {
	Status int
	Header http.Header
	Body   []byte
}

// JSON decodes the body as an object.
func (r Resp) JSON(t testing.TB) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.Body, &m); err != nil {
		t.Fatalf("response is not a JSON object (status %d): %s", r.Status, r.Body)
	}
	return m
}

// Code returns error.code from an error body.
func (r Resp) Code(t testing.TB) string {
	t.Helper()
	e, _ := r.JSON(t)["error"].(map[string]any)
	c, _ := e["code"].(string)
	return c
}

// Validator checks requests and responses against the OpenAPI document; set
// by the acceptance tests.
var Validator func(t testing.TB, req *http.Request, reqBody []byte, resp *http.Response, respBody []byte)

// DoURL sends a request to base+path with an optional bearer key and JSON body.
func DoURL(t testing.TB, c *http.Client, base, method, path, key string, body any, header ...string) Resp {
	t.Helper()
	var raw []byte
	switch b := body.(type) {
	case nil:
	case []byte:
		raw = b
	case string:
		raw = []byte(b)
	default:
		var err error
		if raw, err = json.Marshal(b); err != nil {
			t.Fatal(err)
		}
	}
	var rdr io.Reader
	if raw != nil {
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, base+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if raw != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if Validator != nil {
		Validator(t, req, raw, resp, b)
	}
	return Resp{Status: resp.StatusCode, Header: resp.Header, Body: b}
}

// Do sends a request to the harness instance.
func (h *Harness) Do(method, path, key string, body any, header ...string) Resp {
	h.T.Helper()
	return DoURL(h.T, h.Client, h.Inst.URL, method, path, key, body, header...)
}

// Must sends a request and fails unless the status matches.
func (h *Harness) Must(status int, method, path, key string, body any) map[string]any {
	h.T.Helper()
	r := h.Do(method, path, key, body)
	if r.Status != status {
		h.T.Fatalf("%s %s: status %d, want %d: %s", method, path, r.Status, status, r.Body)
	}
	if len(r.Body) == 0 {
		return nil
	}
	return r.JSON(h.T)
}

// Admin is Must with the admin key.
func (h *Harness) Admin(status int, method, path string, body any) map[string]any {
	h.T.Helper()
	return h.Must(status, method, path, h.AdminKey, body)
}

// CreateRealm creates a realm with its seeded rules.
func (h *Harness) CreateRealm(name string) {
	h.T.Helper()
	h.Admin(201, "POST", "/v1/admin/realms", map[string]any{"name": name})
}

// CreateTarget creates a target and returns its id.
func (h *Harness) CreateTarget(name string, ipv4, ipv6 bool) string {
	h.T.Helper()
	return h.Admin(201, "POST", "/v1/admin/targets", map[string]any{
		"name": name, "label": strings.ToUpper(name[:1]) + name[1:], "ipv4": ipv4, "ipv6": ipv6})["id"].(string)
}

// Subscribe adds a subscription and returns its id.
func (h *Harness) Subscribe(targetID, realm, user, group string) string {
	h.T.Helper()
	return h.Admin(201, "POST", "/v1/admin/targets/"+targetID+"/subscriptions", map[string]any{
		"realm": realm, "user": user, "group": group})["id"].(string)
}

// CreateClient creates a client bound to realms and returns its id.
func (h *Harness) CreateClient(name string, realms ...string) string {
	h.T.Helper()
	return h.Admin(201, "POST", "/v1/admin/clients", map[string]any{"name": name, "realms": realms})["id"].(string)
}

// ClientKey creates a client key.
func (h *Harness) ClientKey(clientID string) string {
	h.T.Helper()
	return h.Admin(201, "POST", "/v1/admin/keys", map[string]any{"kind": "client", "client_id": clientID, "name": "k"})["key"].(string)
}

// WorkerKey creates a worker key.
func (h *Harness) WorkerKey(targetID string) string {
	h.T.Helper()
	return h.Admin(201, "POST", "/v1/admin/keys", map[string]any{"kind": "worker", "target_id": targetID, "name": "w"})["key"].(string)
}

// Setup is the common fixture: realm, dual-stack target subscribed to
// everything in the realm, a client bound to the realm, and keys.
type Setup struct {
	Realm     string
	TargetID  string
	ClientID  string
	ClientKey string
	WorkerKey string
}

// Basic creates the common fixture for realm.
func (h *Harness) Basic(realm string) Setup {
	h.T.Helper()
	h.CreateRealm(realm)
	tid := h.CreateTarget("home-"+realm, true, true)
	h.Subscribe(tid, realm, "*", "*")
	cid := h.CreateClient("client-"+realm, realm)
	return Setup{Realm: realm, TargetID: tid, ClientID: cid, ClientKey: h.ClientKey(cid), WorkerKey: h.WorkerKey(tid)}
}

// Submit posts a submission with the client key.
func (h *Harness) Submit(key string, body map[string]any) Resp {
	h.T.Helper()
	return h.Do("POST", "/v1/submissions", key, body)
}

// Revision reads the counter directly.
func (h *Harness) Revision() int64 {
	h.T.Helper()
	var v int64
	if err := h.Pool.QueryRow(context.Background(), `SELECT value FROM revision_counter`).Scan(&v); err != nil {
		h.T.Fatal(err)
	}
	return v
}

// Exec runs SQL directly.
func (h *Harness) Exec(sql string, args ...any) {
	h.T.Helper()
	if _, err := h.Pool.Exec(context.Background(), sql, args...); err != nil {
		h.T.Fatalf("%s: %v", sql, err)
	}
}

// DesiredState fetches the worker's desired state.
func (h *Harness) DesiredState(workerKey string, header ...string) Resp {
	h.T.Helper()
	return h.Do("GET", "/v1/worker/desired-state", workerKey, nil, header...)
}

// Apply fetches desired state and reports success with no rejections; it
// returns the reported revision.
func (h *Harness) Apply(workerKey string, rejected ...map[string]any) int64 {
	h.T.Helper()
	ds := h.DesiredState(workerKey)
	if ds.Status != 200 {
		h.T.Fatalf("desired state: %d %s", ds.Status, ds.Body)
	}
	m := ds.JSON(h.T)
	rev := int64(m["revision"].(float64))
	if rejected == nil {
		rejected = []map[string]any{}
	}
	h.Must(200, "POST", "/v1/worker/status", workerKey, map[string]any{
		"worker_id": "test-worker", "version": "0.0.1", "revision": rev,
		"generated_at": m["generated_at"], "rejected": rejected})
	return rev
}

// RulesOf lists a realm's rules of one list.
func (h *Harness) RulesOf(realm, list string) []map[string]any {
	h.T.Helper()
	m := h.Admin(200, "GET", "/v1/admin/realms/"+realm+"/rules/"+list+"?limit=1000", nil)
	var out []map[string]any
	for _, it := range m["items"].([]any) {
		out = append(out, it.(map[string]any))
	}
	return out
}

// ClearRules deletes every rule in a list, confirming any impact.
func (h *Harness) ClearRules(realm, list string) {
	h.T.Helper()
	for _, r := range h.RulesOf(realm, list) {
		h.Admin(200, "DELETE", "/v1/admin/realms/"+realm+"/rules/"+list+"/"+r["id"].(string)+"?confirm=true", nil)
	}
}

// AddRule appends a rule (position optional in body) and returns the response.
func (h *Harness) AddRule(realm, list string, body map[string]any) map[string]any {
	h.T.Helper()
	return h.Admin(201, "POST", "/v1/admin/realms/"+realm+"/rules/"+list+"?confirm=true", body)
}

// Package e2e drives the dashboard against a real API server, built from
// ../api and backed by the Postgres named by IPVALET_TEST_DATABASE_URL.
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/PatrickH298/ip-valet/dashboard/internal/app"
	"github.com/PatrickH298/ip-valet/dashboard/internal/config"
)

// env is the API server shared by every test in the package.
var env struct {
	skip      string
	apiPublic string // client and worker APIs
	apiAdmin  string // admin API
	envKey    string // the API server's environment admin key
}

func TestMain(m *testing.M) { os.Exit(run(m)) }

func run(m *testing.M) int {
	base := os.Getenv("IPVALET_TEST_DATABASE_URL")
	if base == "" {
		if os.Getenv("CI") != "" {
			fmt.Fprintln(os.Stderr, "IPVALET_TEST_DATABASE_URL must be set in CI")
			return 1
		}
		env.skip = "IPVALET_TEST_DATABASE_URL is not set"
		return m.Run()
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, base)
	if err != nil {
		fmt.Fprintln(os.Stderr, "connecting to the test database:", err)
		return 1
	}
	defer conn.Close(ctx)
	name := "ipvalet_dash_" + randHex(6)
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		fmt.Fprintln(os.Stderr, "creating the test database:", err)
		return 1
	}
	defer func() { _, _ = conn.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") }()
	u, _ := url.Parse(base)
	u.Path = "/" + name

	dir, err := os.MkdirTemp("", "ipvalet-dash-e2e")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(dir)
	bin := filepath.Join(dir, "ipvalet-api")
	build := exec.Command("go", "build", "-o", bin, "./cmd/ipvalet-api")
	build.Dir = filepath.Join("..", "..", "..", "api")
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "building the API server:", err)
		return 1
	}

	env.envKey = newKey()
	pub, adm := freeAddr(), freeAddr()
	env.apiPublic, env.apiAdmin = "http://"+pub, "http://"+adm
	api := exec.Command(bin, "serve")
	api.Env = append(os.Environ(), "IPVALET_DATABASE_URL="+u.String(), "IPVALET_ADMIN_KEY="+env.envKey,
		"IPVALET_LISTEN_ADDR="+pub, "IPVALET_ADMIN_LISTEN_ADDR="+adm, "IPVALET_METRICS_ADDR=",
		"IPVALET_LOG_LEVEL=warn")
	if os.Getenv("IPVALET_TEST_LOG") != "" {
		api.Stdout, api.Stderr = os.Stderr, os.Stderr
	}
	if err := api.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "starting the API server:", err)
		return 1
	}
	defer func() { _ = api.Process.Kill(); _ = api.Wait() }()
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := http.Get(env.apiAdmin + "/readyz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			fmt.Fprintln(os.Stderr, "the API server did not become ready")
			return 1
		}
		time.Sleep(50 * time.Millisecond)
	}
	return m.Run()
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newKey() string {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	id, secret := make([]byte, 10), make([]byte, 32)
	_, _ = rand.Read(id)
	_, _ = rand.Read(secret)
	return "ipv_" + strings.ToLower(enc.EncodeToString(id)) + "_" + strings.ToLower(enc.EncodeToString(secret))
}

func freeAddr() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// uniq returns a fresh realm-safe name.
func uniq(prefix string) string { return prefix + randHex(4) }

// call sends a JSON request to the API server and decodes the response.
func call(t *testing.T, base, key, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, base+path, rdr)
	req.Header.Set("Authorization", "Bearer "+key)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// admin calls the admin API with the environment key and expects want.
func admin(t *testing.T, want int, method, path string, body any) map[string]any {
	t.Helper()
	status, out := call(t, env.apiAdmin, env.envKey, method, path, body)
	if status != want {
		t.Fatalf("%s %s: %d, want %d: %v", method, path, status, want, out)
	}
	return out
}

func items(m map[string]any) []map[string]any {
	var out []map[string]any
	for _, it := range m["items"].([]any) {
		out = append(out, it.(map[string]any))
	}
	return out
}

// setup is a realm with a client and a worker subscribed to all of it.
type setup struct {
	Realm     string
	ClientID  string
	ClientKey string
	WorkerID  string
}

func newSetup(t *testing.T) setup {
	t.Helper()
	s := setup{Realm: uniq("r")}
	admin(t, 201, "POST", "/v1/admin/realms", map[string]any{"name": s.Realm})
	s.ClientID = admin(t, 201, "POST", "/v1/admin/clients", map[string]any{"name": uniq("c"), "realms": []string{s.Realm}})["id"].(string)
	s.ClientKey = admin(t, 201, "POST", "/v1/admin/keys", map[string]any{"kind": "client", "client_id": s.ClientID,
		"name": "c"})["key"].(string)
	s.WorkerID = admin(t, 201, "POST", "/v1/admin/workers", map[string]any{"name": uniq("w"), "label": "fw",
		"ipv4": true, "ipv6": true})["id"].(string)
	admin(t, 201, "POST", "/v1/admin/workers/"+s.WorkerID+"/subscriptions",
		map[string]any{"realm": s.Realm, "user": "*", "group": "*"})
	return s
}

// submit registers prefix for user in the setup's realm.
func (s setup) submit(t *testing.T, user, prefix string) string {
	t.Helper()
	status, out := call(t, env.apiPublic, s.ClientKey, "POST", "/v1/submissions",
		map[string]any{"realm": s.Realm, "user": user, "groups": []string{"g"}, "prefix": prefix, "ttl": "1d"})
	if status != 201 {
		t.Fatalf("submit %s: %d %v", prefix, status, out)
	}
	return out["entries"].([]any)[0].(map[string]any)["id"].(string)
}

// dash is a running dashboard and a browser-like client signed in or not.
type dash struct {
	t     *testing.T
	URL   string
	c     *http.Client
	Key   string // the dashboard's own admin key
	KeyID string
}

const (
	alicePW = "alice-password"
	bobPW   = "bob-password"
)

// newDash starts a dashboard with its own admin key and two users.
func newDash(t *testing.T, mod func(*config.Config)) *dash {
	t.Helper()
	if env.skip != "" {
		t.Skip(env.skip)
	}
	key := admin(t, 201, "POST", "/v1/admin/keys", map[string]any{"kind": "admin", "name": "dashboard " + t.Name()})
	cfg := testConfig(t, key["key"].(string))
	if mod != nil {
		mod(&cfg)
	}
	d, err := app.Start(context.Background(), cfg, logger())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(d.Handler)
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return &dash{t: t, URL: srv.URL, c: &http.Client{Jar: jar, Timeout: 30 * time.Second}, Key: key["key"].(string),
		KeyID: key["id"].(string)}
}

func testConfig(t *testing.T, key string) config.Config {
	t.Helper()
	users := filepath.Join(t.TempDir(), "users")
	var lines []string
	for _, u := range [][2]string{{"alice", alicePW}, {"bob", bobPW}} {
		h, _ := bcrypt.GenerateFromPassword([]byte(u[1]), bcrypt.MinCost)
		lines = append(lines, u[0]+":"+string(h))
	}
	if err := os.WriteFile(users, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	api, _ := url.Parse(env.apiAdmin)
	return config.Config{APIURL: api, APIKey: key, APITimeout: 10 * time.Second, Auth: config.AuthForm,
		UsersFile: users, SessionIdle: 30 * time.Minute, SessionMax: 12 * time.Hour, LoginFailuresPerMinute: 10,
		Location: time.UTC, ShutdownTimeout: 5 * time.Second, LogLevel: slog.LevelWarn}
}

func logger() *slog.Logger {
	if os.Getenv("IPVALET_TEST_LOG") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// page is a response, after following redirects.
type page struct {
	Status int
	Body   string
	URL    *url.URL
	Header http.Header
}

func (d *dash) do(method, path string, form url.Values, header ...string) page {
	d.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, d.URL+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := d.c.Do(req)
	if err != nil {
		d.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return page{Status: resp.StatusCode, Body: string(b), URL: resp.Request.URL, Header: resp.Header}
}

func (d *dash) get(path string) page { d.t.Helper(); return d.do("GET", path, nil) }

func (d *dash) post(path string, form url.Values, header ...string) page {
	d.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	return d.do("POST", path, form, header...)
}

// must fails unless the page has the status and holds every snippet.
func (p page) must(t *testing.T, status int, snippets ...string) page {
	t.Helper()
	if p.Status != status {
		t.Fatalf("%s: status %d, want %d\n%s", p.URL, p.Status, status, text(p.Body))
	}
	for _, s := range snippets {
		if !strings.Contains(html.UnescapeString(p.Body), s) {
			t.Fatalf("%s: no %q in\n%s", p.URL, s, text(p.Body))
		}
	}
	return p
}

var tags = regexp.MustCompile(`(?s)<[^>]*>|\s+`)

// text squeezes a page to its words, for failure messages.
func text(body string) string {
	if i := strings.Index(body, "<main>"); i >= 0 {
		body = body[i:]
	}
	s := strings.TrimSpace(tags.ReplaceAllString(body, " "))
	if len(s) > 2000 {
		s = s[:2000] + "…"
	}
	return html.UnescapeString(s)
}

func (d *dash) signIn(name, pw string) {
	d.t.Helper()
	d.post("/login", url.Values{"name": {name}, "password": {pw}}).must(d.t, 200, "Overview")
}

var hiddenInput = regexp.MustCompile(`<input type="hidden" name="([^"]*)" value="([^"]*)">`)
var confirmAction = regexp.MustCompile(`<form method="post" action="([^"]*)" class="buttons">`)

// confirm submits the confirmation form on a confirmation page, as a
// browser would.
func (d *dash) confirm(p page) page {
	d.t.Helper()
	m := confirmAction.FindStringSubmatch(p.Body)
	if m == nil {
		d.t.Fatalf("%s: not a confirmation page\n%s", p.URL, text(p.Body))
	}
	form := url.Values{}
	start := strings.Index(p.Body, m[0])
	for _, h := range hiddenInput.FindAllStringSubmatch(p.Body[start:], -1) {
		form.Add(html.UnescapeString(h[1]), html.UnescapeString(h[2]))
	}
	return d.post(html.UnescapeString(m[1]), form)
}

var keyPattern = regexp.MustCompile(`ipv_[a-z2-7]{16}_[a-z2-7]{52}`)

// Package e2e runs sso-web against a real API server, built from ../api and
// backed by the Postgres named by IPVALET_TEST_DATABASE_URL, with a fake
// OpenID Connect provider and crewjam/saml's identity provider. A cookie-jar
// HTTP client plays the browser.
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/app"
	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/config"
)

var env struct {
	skip      string
	apiPublic string
	apiAdmin  string
	adminKey  string
	clientKey string
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
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "ipvalet_sso_" + hex.EncodeToString(b)
	u, _ := url.Parse(base)
	u.Path = "/" + name
	defer func() {
		if conn, err := pgx.Connect(ctx, base); err == nil {
			_, _ = conn.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
			conn.Close(ctx)
		}
	}()
	dir, err := os.MkdirTemp("", "ipvalet-sso-e2e")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(dir)
	bin := filepath.Join(dir, "ipvalet-api")
	build := exec.Command("go", "build", "-o", bin, "./cmd/ipvalet-api")
	build.Dir = filepath.Join("..", "..", "..", "..", "api")
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "building the API server:", err)
		return 1
	}
	env.adminKey = newKey()
	pub, adm := freeAddr(), freeAddr()
	env.apiPublic, env.apiAdmin = "http://"+pub, "http://"+adm
	api := exec.Command(bin, "serve")
	api.Env = append(os.Environ(), "IPVALET_DATABASE_URL="+u.String(), "IPVALET_ADMIN_KEY="+env.adminKey,
		"IPVALET_LISTEN_ADDR="+pub, "IPVALET_ADMIN_LISTEN_ADDR="+adm, "IPVALET_METRICS_ADDR=", "IPVALET_LOG_LEVEL=warn")
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
			if resp.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			fmt.Fprintln(os.Stderr, "the API server did not become ready")
			return 1
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := setup(); err != nil {
		fmt.Fprintln(os.Stderr, "setting up the API:", err)
		return 1
	}
	return m.Run()
}

// setup creates two realms, a worker that applies both, a client bound to
// both with a key, and limits: in office, at most 1 day for group staff; in
// vpn, at most 2 addresses per user.
func setup() error {
	steps := []struct {
		method, path string
		body         any
	}{
		{"POST", "/v1/admin/realms", map[string]any{"name": "office"}},
		{"POST", "/v1/admin/realms", map[string]any{"name": "vpn"}},
		{"POST", "/v1/admin/realms/office/rules/ttl", map[string]any{"user": "*", "group": "staff", "max_ttl": "1d"}},
		{"POST", "/v1/admin/realms/vpn/rules/cap", map[string]any{"user": "*", "group": "*", "max_prefixes": 2}},
	}
	for _, s := range steps {
		if st, out := call(env.apiAdmin, env.adminKey, s.method, s.path, s.body); st/100 != 2 {
			return fmt.Errorf("%s %s: %d %v", s.method, s.path, st, out)
		}
	}
	st, w := call(env.apiAdmin, env.adminKey, "POST", "/v1/admin/workers", map[string]any{"name": "fw", "label": "Firewall",
		"ipv4": true, "ipv6": true})
	if st != 201 {
		return fmt.Errorf("worker: %d %v", st, w)
	}
	for _, realm := range []string{"office", "vpn"} {
		if st, out := call(env.apiAdmin, env.adminKey, "POST", "/v1/admin/workers/"+w["id"].(string)+"/subscriptions",
			map[string]any{"realm": realm, "user": "*", "group": "*"}); st != 201 {
			return fmt.Errorf("subscription: %d %v", st, out)
		}
	}
	st, c := call(env.apiAdmin, env.adminKey, "POST", "/v1/admin/clients", map[string]any{"name": "sso-web",
		"realms": []string{"office", "vpn"}})
	if st != 201 {
		return fmt.Errorf("client: %d %v", st, c)
	}
	st, k := call(env.apiAdmin, env.adminKey, "POST", "/v1/admin/keys", map[string]any{"kind": "client",
		"client_id": c["id"], "name": "sso-web"})
	if st != 201 {
		return fmt.Errorf("key: %d %v", st, k)
	}
	env.clientKey = k["key"].(string)
	return nil
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

func call(base, key, method, path string, body any) (int, map[string]any) {
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
		return 0, map[string]any{"error": err.Error()}
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// entries lists a user's live entries through the admin API.
func entries(t *testing.T, user string) []map[string]any {
	t.Helper()
	st, out := call(env.apiAdmin, env.adminKey, "GET", "/v1/admin/entries?user="+url.QueryEscape(user), nil)
	if st != 200 {
		t.Fatalf("entries: %d %v", st, out)
	}
	var list []map[string]any
	for _, it := range out["items"].([]any) {
		list = append(list, it.(map[string]any))
	}
	return list
}

// site is a running sso-web.
type site struct {
	base   string // its public URL
	detect string // its detection endpoint, on the detection listener
}

// startSite runs sso-web with the base settings plus extra, until the test ends.
func startSite(t *testing.T, extra map[string]string) site {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := site{base: "http://" + ln.Addr().String(), detect: "http://" + dl.Addr().String() + "/detect"}
	vars := map[string]string{
		"IPVALET_SSO_PUBLIC_URL":    s.base,
		"IPVALET_SSO_API_URL":       env.apiPublic,
		"IPVALET_SSO_API_KEY":       env.clientKey,
		"IPVALET_SSO_DETECT_V6_URL": s.detect,
		"IPVALET_SSO_LOG_LEVEL":     "error",
	}
	if os.Getenv("IPVALET_TEST_LOG") != "" {
		vars["IPVALET_SSO_LOG_LEVEL"] = "debug"
	}
	for k, v := range extra {
		vars[k] = v
	}
	get := func(k string) (string, bool) { v, ok := vars[k]; return v, ok }
	environ := func() []string {
		var out []string
		for k, v := range vars {
			out = append(out, k+"="+v)
		}
		return out
	}
	cfg, err := config.Load(get, os.ReadFile, environ)
	if err != nil {
		t.Fatal(err)
	}
	var logOut io.Writer = io.Discard
	if os.Getenv("IPVALET_TEST_LOG") != "" {
		logOut = os.Stderr
	}
	log := slog.New(slog.NewJSONHandler(logOut, &slog.HandlerOptions{Level: cfg.LogLevel}))
	ctx, cancel := context.WithCancel(context.Background())
	st, err := app.Start(ctx, cfg, log)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := st.Serve(ctx, ln, dl, time.Second); err != nil {
			t.Errorf("serve: %v", err)
		}
	}()
	t.Cleanup(func() { cancel(); <-done })
	return s
}

// browser is a cookie-jar client; it can claim an address with
// X-Forwarded-For, which sso-web believes from every peer by default.
type browser struct {
	t      *testing.T
	client *http.Client
	from   string // X-Forwarded-For for every request, when not empty
}

func newBrowser(t *testing.T, from string) *browser {
	jar, _ := cookiejar.New(nil)
	b := &browser{t: t, from: from}
	b.client = &http.Client{Jar: jar, Timeout: 30 * time.Second, Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
		if b.from != "" {
			r.Header.Set("X-Forwarded-For", b.from)
		}
		return http.DefaultTransport.RoundTrip(r)
	})}
	return b
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type page struct {
	status int
	body   string
	url    string // after redirects
	header http.Header
}

func (b *browser) do(req *http.Request) page {
	b.t.Helper()
	resp, err := b.client.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return page{status: resp.StatusCode, body: string(body), url: resp.Request.URL.String(), header: resp.Header}
}

func (b *browser) get(u string) page {
	req, _ := http.NewRequest("GET", u, nil)
	return b.do(req)
}

// post sends a form as a browser does from origin.
func (b *browser) post(u, origin string, form url.Values) page {
	req, _ := http.NewRequest("POST", u, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	return b.do(req)
}

var (
	tokenRE = regexp.MustCompile(`data-detect-token="([^"]+)"`)
	tagRE   = regexp.MustCompile(`<[^>]+>`)
	spaceRE = regexp.MustCompile(`\s+`)
)

// text is a page's visible text, tags removed and spaces collapsed.
func text(html string) string {
	return strings.TrimSpace(spaceRE.ReplaceAllString(tagRE.ReplaceAllString(html, " "), " "))
}

func mustContain(t *testing.T, p page, want ...string) {
	t.Helper()
	txt := text(p.body)
	for _, w := range want {
		if !strings.Contains(txt, w) && !strings.Contains(p.body, w) {
			t.Fatalf("page %s (%d) lacks %q:\n%s", p.url, p.status, w, txt)
		}
	}
}

func mustNotContain(t *testing.T, p page, unwanted ...string) {
	t.Helper()
	txt := text(p.body)
	for _, w := range unwanted {
		if strings.Contains(txt, w) {
			t.Fatalf("page %s (%d) has %q:\n%s", p.url, p.status, w, txt)
		}
	}
}

func detectToken(t *testing.T, p page) string {
	t.Helper()
	m := tokenRE.FindStringSubmatch(p.body)
	if m == nil {
		t.Fatalf("no detection token on %s:\n%s", p.url, text(p.body))
	}
	return m[1]
}

func stringsReader(s string) io.Reader { return strings.NewReader(s) }

package acceptance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/PatrickH298/ip-valet/api/internal/app"
	"github.com/PatrickH298/ip-valet/api/internal/auth"
	"github.com/PatrickH298/ip-valet/api/internal/config"
	"github.com/PatrickH298/ip-valet/api/internal/testutil"
)

func TestAuthFailuresAndKinds(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("authentik")

	other, _ := auth.NewKey()
	known, _ := auth.ParseKey(s.ClientKey)
	wrongSecret := auth.Key{ID: known.ID, Secret: other.Secret}

	revoked := h.ClientKey(s.ClientID)
	rk, _ := auth.ParseKey(revoked)
	h.Admin(200, "POST", "/v1/admin/keys/"+rk.ID+"/revoke", nil)

	expired := h.ClientKey(s.ClientID)
	ek, _ := auth.ParseKey(expired)
	h.Exec(`UPDATE api_keys SET expires_at = now() - interval '1 minute' WHERE id = $1`, ek.ID)

	cases := map[string]string{
		"missing":      "",
		"wrong scheme": "Basic " + s.ClientKey,
		"malformed":    "Bearer ipv_short_secret",
		"uppercase":    "Bearer " + strings.ToUpper(s.ClientKey),
		"unknown":      "Bearer " + other.String(),
		"wrong secret": "Bearer " + wrongSecret.String(),
		"revoked":      "Bearer " + revoked,
		"expired":      "Bearer " + expired,
	}
	for name, header := range cases {
		r := h.Do("GET", "/v1/entries", "", nil, "Authorization", header)
		if r.Status != 401 || r.Code(t) != "unauthenticated" {
			t.Errorf("%s: got %d %s, want 401 unauthenticated", name, r.Status, r.Body)
		}
		if r.Header.Get("WWW-Authenticate") != "Bearer" {
			t.Errorf("%s: missing WWW-Authenticate: Bearer", name)
		}
	}

	wrongKind := []struct{ method, path, key string }{
		{"GET", "/v1/admin/realms", s.ClientKey},
		{"GET", "/v1/worker/desired-state", s.ClientKey},
		{"GET", "/v1/entries", s.WorkerKey},
		{"GET", "/v1/admin/realms", s.WorkerKey},
		{"GET", "/v1/entries", h.AdminKey},
		{"GET", "/v1/worker/desired-state", h.AdminKey},
		{"POST", "/v1/submissions", h.AdminKey},
	}
	for _, c := range wrongKind {
		r := h.Do(c.method, c.path, c.key, nil)
		if r.Status != 403 || r.Code(t) != "forbidden" {
			t.Errorf("%s %s with wrong kind: got %d %s, want 403 forbidden", c.method, c.path, r.Status, r.Body)
		}
	}
	// Every response carries a request id.
	if r := h.Do("GET", "/v1/entries", s.ClientKey, nil); r.Header.Get("X-Request-Id") == "" {
		t.Error("missing X-Request-Id")
	}
}

func TestCreateAdminKeyCommand(t *testing.T) {
	t.Parallel()
	dbURL := testutil.NewDatabase(t)
	var out, errOut bytes.Buffer
	env := testutil.Env(map[string]string{"IPVALET_DATABASE_URL": dbURL})
	code := app.Main(context.Background(), []string{"create-admin-key", "--name", "bootstrap", "--expires", "30d"},
		app.IO{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errOut, Getenv: env, ReadFile: os.ReadFile})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	full := strings.TrimSpace(out.String())
	key, err := auth.ParseKey(full)
	if err != nil {
		t.Fatalf("stdout is not a key: %q", out.String())
	}

	h := &testutil.Harness{T: t, DBURL: dbURL}
	h.Inst = testutil.StartInstance(t, testutil.Config(t, dbURL, nil))
	h.Client = httpClient()
	h.AdminKey = full
	h.Admin(200, "GET", "/v1/admin/realms", nil)

	// The database holds only the hash.
	var dump string
	pool := pgxPool(t, dbURL)
	if err := pool.QueryRow(context.Background(),
		`SELECT string_agg(row_to_json(k)::text, '') FROM api_keys k`).Scan(&dump); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(dump, key.Secret) {
		t.Fatal("api_keys holds the secret")
	}
	var hash []byte
	if err := pool.QueryRow(context.Background(), `SELECT secret_hash FROM api_keys WHERE id = $1`, key.ID).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(key.Secret))
	if !bytes.Equal(hash, want[:]) {
		t.Fatal("stored hash is not SHA-256 of the secret")
	}
	var audit string
	if err := pool.QueryRow(context.Background(), `SELECT coalesce(string_agg(row_to_json(a)::text, ''), '') FROM audit_log a`).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(audit, key.Secret) {
		t.Fatal("audit log holds the secret")
	}
}

func TestEnvironmentAdminKey(t *testing.T) {
	t.Parallel()
	dbURL := testutil.NewDatabase(t)
	key, _ := auth.NewKey()

	var hashOut bytes.Buffer
	if code := app.Main(context.Background(), []string{"hash-key"}, app.IO{
		Stdin: strings.NewReader(key.String() + "\n"), Stdout: &hashOut, Stderr: &bytes.Buffer{},
		Getenv: testutil.Env(nil), ReadFile: os.ReadFile}); code != 0 {
		t.Fatal("hash-key failed")
	}
	hashLine := strings.TrimSpace(hashOut.String())

	file := filepath.Join(t.TempDir(), "admin-key")
	if err := os.WriteFile(file, []byte(key.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	variants := map[string]map[string]string{
		"IPVALET_ADMIN_KEY":      {"IPVALET_ADMIN_KEY": key.String()},
		"IPVALET_ADMIN_KEY_FILE": {"IPVALET_ADMIN_KEY_FILE": file},
		"IPVALET_ADMIN_KEY_HASH": {"IPVALET_ADMIN_KEY_HASH": hashLine},
	}
	i := 0
	for name, env := range variants {
		inst := testutil.StartInstance(t, testutil.Config(t, dbURL, env))
		c := httpClient()
		realm := "env" + strconv.Itoa(i)
		i++
		r := testutil.DoURL(t, c, inst.URL, "POST", "/v1/admin/realms", key.String(), map[string]any{"name": realm})
		if r.Status != 201 {
			t.Fatalf("%s: create realm: %d %s", name, r.Status, r.Body)
		}
		var actor string
		if err := pgxPool(t, dbURL).QueryRow(context.Background(),
			`SELECT actor FROM audit_log WHERE action = 'realm.create' AND object_id = $1`, realm).Scan(&actor); err != nil {
			t.Fatal(err)
		}
		if actor != auth.EnvAdminActor {
			t.Errorf("%s: audit actor %q, want admin:env", name, actor)
		}
		// Not listable or revocable.
		r = testutil.DoURL(t, c, inst.URL, "POST", "/v1/admin/keys/"+key.ID+"/revoke", key.String(), nil)
		if r.Status != 404 {
			t.Errorf("%s: revoking the env key: %d", name, r.Status)
		}
		// Wrong secret with the env key id fails.
		bad, _ := auth.NewKey()
		r = testutil.DoURL(t, c, inst.URL, "GET", "/v1/admin/realms", (auth.Key{ID: key.ID, Secret: bad.Secret}).String(), nil)
		if r.Status != 401 {
			t.Errorf("%s: wrong secret: %d", name, r.Status)
		}
	}

	conflicts := []map[string]string{
		{"IPVALET_ADMIN_KEY": key.String(), "IPVALET_ADMIN_KEY_HASH": hashLine},
		{"IPVALET_ADMIN_KEY": key.String(), "IPVALET_ADMIN_KEY_FILE": file},
		{"IPVALET_ADMIN_KEY_FILE": file, "IPVALET_ADMIN_KEY_HASH": hashLine},
	}
	for _, env := range conflicts {
		env["IPVALET_DATABASE_URL"] = dbURL
		var errOut bytes.Buffer
		code := app.Main(context.Background(), []string{"serve"}, app.IO{Stdin: strings.NewReader(""),
			Stdout: &bytes.Buffer{}, Stderr: &errOut, Getenv: testutil.Env(env), ReadFile: os.ReadFile})
		if code == 0 || !strings.Contains(errOut.String(), "IPVALET_ADMIN_KEY") {
			t.Errorf("startup with %v: exit %d, stderr %q", keys(env), code, errOut.String())
		}
		if _, err := config.Load(testutil.Env(env), os.ReadFile); err == nil {
			t.Errorf("config.Load accepted %v", keys(env))
		}
	}
}

func keys(m map[string]string) []string {
	var out []string
	for k := range m {
		if strings.HasPrefix(k, "IPVALET_ADMIN") {
			out = append(out, k)
		}
	}
	return out
}

func TestRevocationIsImmediate(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("authentik")
	h.Must(200, "GET", "/v1/entries", s.ClientKey, nil)
	k, _ := auth.ParseKey(s.ClientKey)
	h.Admin(200, "POST", "/v1/admin/keys/"+k.ID+"/revoke", nil)
	if r := h.Do("GET", "/v1/entries", s.ClientKey, nil); r.Status != 401 {
		t.Fatalf("after revoke: %d", r.Status)
	}
	// Admin keys too.
	adminKey := h.Admin(201, "POST", "/v1/admin/keys", map[string]any{"kind": "admin", "name": "second"})["key"].(string)
	h.Must(200, "GET", "/v1/admin/realms", adminKey, nil)
	ak, _ := auth.ParseKey(adminKey)
	h.Admin(200, "POST", "/v1/admin/keys/"+ak.ID+"/revoke", nil)
	if r := h.Do("GET", "/v1/admin/realms", adminKey, nil); r.Status != 401 {
		t.Fatalf("admin key after revoke: %d", r.Status)
	}
}

func TestFailedAuthenticationThrottle(t *testing.T) {
	t.Parallel()
	// The test server's peer is 127.0.0.1; trusting it lets X-Forwarded-For
	// name the client, as behind the reverse proxy.
	h := testutil.New(t, map[string]string{"IPVALET_AUTH_FAILURES_PER_MINUTE": "3", "IPVALET_TRUSTED_PROXIES": "127.0.0.1"})
	s := h.Basic("r")
	bad, _ := auth.NewKey()
	from := func(key, ip string) testutil.Resp {
		return h.Do("GET", "/v1/entries", key, nil, "X-Forwarded-For", ip)
	}
	for i := 0; i < 3; i++ {
		if r := from(bad.String(), "198.51.100.7"); r.Status != 401 {
			t.Fatalf("failure %d: %d", i, r.Status)
		}
	}
	// The budget is spent: even a valid key from that network is refused unchecked.
	r := from(s.ClientKey, "198.51.100.7")
	if r.Status != 429 || r.Code(t) != "too_many_attempts" {
		t.Fatalf("after the budget: %d %s", r.Status, r.Body)
	}
	if ra, err := strconv.Atoi(r.Header.Get("Retry-After")); err != nil || ra < 1 || ra > 20 {
		t.Fatalf("Retry-After = %q", r.Header.Get("Retry-After"))
	}
	// Prepending an address does not escape: the rightmost untrusted hop counts.
	if r := h.Do("GET", "/v1/entries", s.ClientKey, nil, "X-Forwarded-For", "203.0.113.50, 198.51.100.7"); r.Status != 429 {
		t.Fatalf("spoofed chain: %d", r.Status)
	}
	// Other networks are unaffected, and successes never spend the budget.
	for i := 0; i < 10; i++ {
		if r := from(s.ClientKey, "198.51.100.8"); r.Status != 200 {
			t.Fatalf("other network: %d", r.Status)
		}
	}
	// A valid key on the wrong route is 403 and is not a failed authentication.
	for i := 0; i < 5; i++ {
		if r := h.Do("GET", "/v1/admin/realms", s.ClientKey, nil, "X-Forwarded-For", "198.51.100.9"); r.Status != 403 {
			t.Fatalf("wrong kind: %d", r.Status)
		}
	}
	if r := from(s.ClientKey, "198.51.100.9"); r.Status != 200 {
		t.Fatalf("after 403s: %d", r.Status)
	}
	// IPv6 is counted per /64, so one host cannot rotate addresses to escape.
	for _, ip := range []string{"2001:db8:1::1", "2001:db8:1::2", "2001:db8:1::3"} {
		from(bad.String(), ip)
	}
	if r := from(s.ClientKey, "2001:db8:1::99"); r.Status != 429 {
		t.Fatalf("same /64: %d", r.Status)
	}
	if r := from(s.ClientKey, "2001:db8:2::1"); r.Status != 200 {
		t.Fatalf("another /64: %d", r.Status)
	}

	// Failures are counted in metrics by reason.
	rec := httptest.NewRecorder()
	h.Inst.App.MetricsHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	for _, want := range []string{`ipvalet_auth_failures_total{reason="unknown_key"} 6`, `ipvalet_auth_failures_total{reason="throttled"} 3`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("metrics lack %s", want)
		}
	}

	// Without a trusted proxy, X-Forwarded-For is ignored: every request here
	// comes from 127.0.0.1, whatever the header says.
	h2 := testutil.New(t, map[string]string{"IPVALET_AUTH_FAILURES_PER_MINUTE": "3"})
	s2 := h2.Basic("r")
	for i, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		if r := h2.Do("GET", "/v1/entries", bad.String(), nil, "X-Forwarded-For", ip); r.Status != 401 {
			t.Fatalf("untrusted failure %d: %d", i, r.Status)
		}
	}
	if r := h2.Do("GET", "/v1/entries", s2.ClientKey, nil, "X-Forwarded-For", "192.0.2.4"); r.Status != 429 {
		t.Fatalf("an untrusted X-Forwarded-For escaped the throttle: %d", r.Status)
	}
}

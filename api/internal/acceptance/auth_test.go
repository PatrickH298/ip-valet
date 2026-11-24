package acceptance

import (
	"bytes"
	"context"
	"crypto/sha256"
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

func TestRateLimiting(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("authentik")

	// Off by default.
	for i := 0; i < 60; i++ {
		if r := h.Do("GET", "/v1/entries", s.ClientKey, nil); r.Status != 200 {
			t.Fatalf("request %d with no limit: %d", i, r.Status)
		}
	}

	h.Admin(200, "PATCH", "/v1/admin/clients/"+s.ClientID, map[string]any{"rate_limit_per_minute": 3})
	limited := h.ClientKey(s.ClientID)
	for i := 0; i < 3; i++ {
		if r := h.Do("GET", "/v1/entries", limited, nil); r.Status != 200 {
			t.Fatalf("request %d under the limit: %d", i, r.Status)
		}
	}
	r := h.Do("GET", "/v1/entries", limited, nil)
	if r.Status != 429 || r.Code(t) != "rate_limited" {
		t.Fatalf("over the limit: %d %s", r.Status, r.Body)
	}
	ra, err := strconv.Atoi(r.Header.Get("Retry-After"))
	if err != nil || ra < 1 || ra > 60 {
		t.Fatalf("Retry-After = %q", r.Header.Get("Retry-After"))
	}
	// Workers and admins are never limited.
	for i := 0; i < 10; i++ {
		h.Must(200, "GET", "/v1/worker/desired-state", s.WorkerKey, nil)
		h.Admin(200, "GET", "/v1/admin/realms", nil)
	}

	// IPVALET_DEFAULT_RATE_LIMIT applies to clients without their own limit.
	h2 := testutil.New(t, map[string]string{"IPVALET_DEFAULT_RATE_LIMIT": "2"})
	s2 := h2.Basic("authentik")
	h2.Must(200, "GET", "/v1/entries", s2.ClientKey, nil)
	h2.Must(200, "GET", "/v1/entries", s2.ClientKey, nil)
	if r := h2.Do("GET", "/v1/entries", s2.ClientKey, nil); r.Status != 429 {
		t.Fatalf("default limit: %d", r.Status)
	}
	// A client limit of 0 turns it off.
	h2.Admin(200, "PATCH", "/v1/admin/clients/"+s2.ClientID, map[string]any{"rate_limit_per_minute": 0})
	for i := 0; i < 5; i++ {
		h2.Must(200, "GET", "/v1/entries", s2.ClientKey, nil)
	}
}

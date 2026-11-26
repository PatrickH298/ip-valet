// Package e2e runs the UniFi worker against a real API server, built from
// ../api and backed by the Postgres named by IPVALET_TEST_DATABASE_URL, and a
// fake UniFi controller.
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
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PatrickH298/ip-valet/workers/unifi/internal/app"
	"github.com/PatrickH298/ip-valet/workers/unifi/internal/config"
	"github.com/PatrickH298/ip-valet/workers/unifi/internal/rules"
	"github.com/PatrickH298/ip-valet/workers/unifi/internal/unifi/unifitest"
)

var env struct {
	skip      string
	apiPublic string
	apiAdmin  string
	adminKey  string
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
	name := "ipvalet_unifi_" + hex.EncodeToString(b)
	u, _ := url.Parse(base)
	u.Path = "/" + name
	defer func() {
		if conn, err := pgx.Connect(ctx, base); err == nil {
			_, _ = conn.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
			conn.Close(ctx)
		}
	}()
	dir, err := os.MkdirTemp("", "ipvalet-unifi-e2e")
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
	// The API creates its database on start.
	api := exec.Command(bin, "serve")
	api.Env = append(os.Environ(), "IPVALET_DATABASE_URL="+u.String(), "IPVALET_ADMIN_KEY="+env.adminKey,
		"IPVALET_LISTEN_ADDR="+pub, "IPVALET_ADMIN_LISTEN_ADDR="+adm, "IPVALET_METRICS_ADDR=", "IPVALET_LOG_LEVEL=warn",
		"IPVALET_SSE_HEARTBEAT=1s")
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
	return m.Run()
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
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func admin(t *testing.T, want int, method, path string, body any) map[string]any {
	t.Helper()
	status, out := call(t, env.apiAdmin, env.adminKey, method, path, body)
	if status != want {
		t.Fatalf("%s %s: %d %v", method, path, status, out)
	}
	return out
}

func submit(t *testing.T, key, realm, user, group, prefix string) string {
	t.Helper()
	status, out := call(t, env.apiPublic, key, "POST", "/v1/submissions",
		map[string]any{"realm": realm, "user": user, "groups": []string{group}, "prefix": prefix, "ttl": "1d"})
	if status != 201 {
		t.Fatalf("submit %s: %d %v", prefix, status, out)
	}
	return out["entries"].([]any)[0].(map[string]any)["id"].(string)
}

// entryOnWorker returns an entry's overall state and its state and code on the worker.
func entryOnWorker(t *testing.T, id string) (string, string, string) {
	t.Helper()
	e := admin(t, 200, "GET", "/v1/admin/entries/"+id, nil)
	for _, w := range e["workers"].([]any) {
		m := w.(map[string]any)
		code, _ := m["code"].(string)
		return e["state"].(string), m["state"].(string), code
	}
	return e["state"].(string), "", ""
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestWorkerAgainstTheAPI(t *testing.T) {
	if env.skip != "" {
		t.Skip(env.skip)
	}
	realm := "home" + hex.EncodeToString([]byte{byte(time.Now().UnixNano())})
	admin(t, 201, "POST", "/v1/admin/realms", map[string]any{"name": realm})
	cid := admin(t, 201, "POST", "/v1/admin/clients", map[string]any{"name": "web " + realm, "realms": []string{realm}})["id"].(string)
	ckey := admin(t, 201, "POST", "/v1/admin/keys", map[string]any{"kind": "client", "client_id": cid, "name": "c"})["key"].(string)
	wid := admin(t, 201, "POST", "/v1/admin/workers", map[string]any{"name": "unifi " + realm, "label": "UniFi",
		"ipv4": true, "ipv6": true})["id"].(string)
	admin(t, 201, "POST", "/v1/admin/workers/"+wid+"/subscriptions", map[string]any{"realm": realm, "user": "*", "group": "*"})
	wkey := admin(t, 201, "POST", "/v1/admin/keys", map[string]any{"kind": "worker", "worker_id": wid, "name": "w"})["key"].(string)

	staff4 := submit(t, ckey, realm, "ann", "staff", "8.8.8.8")
	staff6 := submit(t, ckey, realm, "ann", "staff", "2a00:1450:4001:80b::/64")
	guest := submit(t, ckey, realm, "bob", "guests", "1.1.1.1")

	ctl := unifitest.New("unifi-key")
	defer ctl.Close()
	apiURL, _ := url.Parse(env.apiPublic)
	ctlURL, _ := url.Parse(ctl.URL)
	rule, err := rules.Parse("STAFF", "realm="+realm+" group=staff ipv4_list=staff-v4 ipv6_list=staff-v6")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{APIURL: apiURL, APIKey: wkey, ControllerURL: ctlURL, ControllerKey: "unifi-key", Site: "Default",
		VerifyTLS: true, Rules: []rules.Rule{rule}, CreateLists: true, Floor: rules.Floor{MinV4: 24, MinV6: 48},
		SyncInterval: time.Hour, Timeout: 5 * time.Second, DataDir: t.TempDir(), Instance: "e2e"}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if os.Getenv("IPVALET_TEST_LOG") != "" {
		log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	w, err := app.New(cfg, log)
	if err != nil {
		t.Fatal(err)
	}

	// One pass: the staff entries go into the lists, the guest's is rejected.
	if res := w.Sync(context.Background()); res.Err != nil || !res.Reported {
		t.Fatalf("sync: %+v", res)
	}
	if got := strings.Join(ctl.Items("staff-v4"), " "); got != "8.8.8.8/32" {
		t.Fatalf("staff-v4 = %q", got)
	}
	if got := strings.Join(ctl.Items("staff-v6"), " "); got != "2a00:1450:4001:80b::/64" {
		t.Fatalf("staff-v6 = %q", got)
	}
	for _, id := range []string{staff4, staff6} {
		if st, on, _ := entryOnWorker(t, id); st != "active" || on != "active" {
			t.Fatalf("staff entry %s: %s / %s", id, st, on)
		}
	}
	if st, on, code := entryOnWorker(t, guest); st != "rejected" || on != "rejected" || code != "no_matching_rule" {
		t.Fatalf("guest entry: %s / %s / %s", st, on, code)
	}
	health := admin(t, 200, "GET", "/v1/admin/workers/"+wid+"/health", nil)
	if health["lag"].(float64) != 0 || health["last_instance"] != "e2e" {
		t.Fatalf("health %v", health)
	}

	// Running: a change signal brings a new entry in, and a deletion out,
	// long before the hour-long sync interval.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = w.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	newer := submit(t, ckey, realm, "cat", "staff", "8.8.4.4")
	waitFor(t, "8.8.4.4 in staff-v4", func() bool {
		return strings.Join(ctl.Items("staff-v4"), " ") == "8.8.4.4/32 8.8.8.8/32"
	})
	waitFor(t, "the new entry to read active", func() bool { st, _, _ := entryOnWorker(t, newer); return st == "active" })
	if status, _ := call(t, env.apiPublic, ckey, "DELETE", "/v1/entries/"+staff4, nil); status != 200 {
		t.Fatalf("delete: %d", status)
	}
	waitFor(t, "8.8.8.8 out of staff-v4", func() bool { return strings.Join(ctl.Items("staff-v4"), " ") == "8.8.4.4/32" })
	waitFor(t, "the deleted entry to read removed", func() bool { st, _, _ := entryOnWorker(t, staff4); return st == "removed" })
}

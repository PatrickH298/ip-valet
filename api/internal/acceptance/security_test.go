package acceptance

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/PatrickH298/ip-valet/api/internal/testutil"
)

// rawGet sends a request outside the OpenAPI check, for listeners that
// deliberately answer documented paths with 404.
func rawGet(t *testing.T, url, key string) int {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := httpClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func TestAdminListenerSeparation(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("r")
	public := httptest.NewServer(h.Inst.App.API.PublicHandler())
	t.Cleanup(public.Close)
	admin := httptest.NewServer(h.Inst.App.API.AdminHandler())
	t.Cleanup(admin.Close)

	cases := []struct {
		name, url, key string
		want           int
	}{
		{"admin route on the public listener", public.URL + "/v1/admin/realms", h.AdminKey, 404},
		{"admin route on the admin listener", admin.URL + "/v1/admin/realms", h.AdminKey, 200},
		{"client route on the admin listener", admin.URL + "/v1/entries", s.ClientKey, 404},
		{"client route on the public listener", public.URL + "/v1/entries", s.ClientKey, 200},
		{"worker route on the public listener", public.URL + "/v1/worker/desired-state", s.WorkerKey, 200},
		{"healthz on the public listener", public.URL + "/healthz", "", 200},
		{"readyz on the admin listener", admin.URL + "/readyz", "", 200},
	}
	for _, c := range cases {
		if got := rawGet(t, c.url, c.key); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
}

func TestKeyCreatedOnAnotherInstance(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("r")
	other := testutil.StartInstance(t, testutil.Config(t, h.DBURL, nil))
	// Created through the first instance after the second one started: the
	// second learns of it through NOTIFY ipvalet_keys.
	key := h.ClientKey(s.ClientID)
	deadline := time.Now().Add(2 * time.Second)
	for rawGet(t, other.URL+"/v1/entries", key) != 200 {
		if time.Now().After(deadline) {
			t.Fatal("the other instance never accepted the new key")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestAuditRecordsClientAddress(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, map[string]string{"IPVALET_TRUSTED_PROXIES": "127.0.0.1"})
	r := h.Do("POST", "/v1/admin/realms", h.AdminKey, map[string]any{"name": "r"}, "X-Forwarded-For", "198.51.100.20")
	if r.Status != 201 {
		t.Fatalf("create realm: %d %s", r.Status, r.Body)
	}
	items := h.Admin(200, "GET", "/v1/admin/audit?action=realm.create", nil)["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["client_ip"] != "198.51.100.20" {
		t.Fatalf("audit = %v", items)
	}
}

func TestKeyHygiene(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("r")

	warned := func(m map[string]any) bool {
		for _, w := range m["warnings"].([]any) {
			if w.(map[string]any)["code"] == "admin_key_without_expiry" {
				return true
			}
		}
		return false
	}
	if !warned(h.Admin(201, "POST", "/v1/admin/keys", map[string]any{"kind": "admin", "name": "forever"})) {
		t.Error("no warning for an admin key without expiry")
	}
	soon := time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339)
	expiring := h.Admin(201, "POST", "/v1/admin/keys", map[string]any{"kind": "admin", "name": "soon", "expires_at": soon})
	if warned(expiring) {
		t.Error("warning for an admin key with an expiry")
	}
	if warned(h.Admin(201, "POST", "/v1/admin/keys", map[string]any{"kind": "client", "client_id": s.ClientID, "name": "c"})) {
		t.Error("warning for a client key")
	}
	stale := h.Admin(201, "POST", "/v1/admin/keys", map[string]any{"kind": "client", "client_id": s.ClientID, "name": "stale"})
	h.Exec(`UPDATE api_keys SET created_at = now() - interval '31 days' WHERE id = $1`, stale["id"])

	keys := h.Admin(200, "GET", "/v1/admin/health", nil)["keys"].(map[string]any)
	ids := func(list any) map[string]bool {
		out := map[string]bool{}
		for _, k := range list.([]any) {
			out[k.(map[string]any)["id"].(string)] = true
		}
		return out
	}
	if exp := ids(keys["expiring_soon"]); len(exp) != 1 || !exp[expiring["id"].(string)] {
		t.Errorf("expiring_soon = %v", keys["expiring_soon"])
	}
	if unused := ids(keys["unused"]); len(unused) != 1 || !unused[stale["id"].(string)] {
		t.Errorf("unused = %v", keys["unused"])
	}
}

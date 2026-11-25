package e2e

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/PatrickH298/ip-valet/dashboard/internal/app"
	"github.com/PatrickH298/ip-valet/dashboard/internal/config"
)

func TestSignInAndOut(t *testing.T) {
	t.Parallel()
	d := newDash(t, nil)
	// Signed out, a page sends you to sign in and back.
	p := d.get("/realms?x=1").must(t, 200, "Sign in")
	if p.URL.Path != "/login" || p.URL.Query().Get("next") != "/realms?x=1" {
		t.Fatalf("redirected to %s", p.URL)
	}
	d.post("/login", url.Values{"name": {"alice"}, "password": {"nope"}, "next": {"/realms?x=1"}}).
		must(t, 401, "Wrong user name or password.")
	d.post("/login", url.Values{"name": {"nobody"}, "password": {alicePW}}).must(t, 401, "Wrong user name or password.")
	p = d.post("/login", url.Values{"name": {"alice"}, "password": {alicePW}, "next": {"/realms?x=1"}}).
		must(t, 200, "Realms", "alice", "Sign out")
	if p.URL.RequestURI() != "/realms?x=1" {
		t.Fatalf("after sign-in: %s", p.URL)
	}
	// Signed in, the sign-in page moves on.
	if p := d.get("/login"); p.URL.Path != "/" {
		t.Fatalf("/login when signed in: %s", p.URL)
	}
	d.post("/logout", nil).must(t, 200, "Sign in")
	if p := d.get("/workers"); p.URL.Path != "/login" {
		t.Fatalf("after sign-out: %s", p.URL)
	}
}

func TestLoginThrottle(t *testing.T) {
	t.Parallel()
	d := newDash(t, func(c *config.Config) { c.LoginFailuresPerMinute = 2 })
	for range 2 {
		d.post("/login", url.Values{"name": {"alice"}, "password": {"wrong"}}).must(t, 401)
	}
	p := d.post("/login", url.Values{"name": {"alice"}, "password": {alicePW}}).must(t, 429, "Too many failed sign-ins")
	if p.Header.Get("Retry-After") == "" {
		t.Fatal("no Retry-After")
	}
}

func TestBasicAuth(t *testing.T) {
	t.Parallel()
	d := newDash(t, func(c *config.Config) { c.Auth = config.AuthBasic })
	p := d.get("/")
	if p.Status != 401 || !strings.HasPrefix(p.Header.Get("WWW-Authenticate"), "Basic ") {
		t.Fatalf("no credentials: %d %v", p.Status, p.Header)
	}
	req, _ := http.NewRequest("GET", d.URL+"/", nil)
	req.SetBasicAuth("bob", "wrong")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("wrong password: %d", resp.StatusCode)
	}
	req, _ = http.NewRequest("GET", d.URL+"/", nil)
	req.SetBasicAuth("bob", bobPW)
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("right password: %d", resp.StatusCode)
	}
}

func TestSecureCookie(t *testing.T) {
	t.Parallel()
	if env.skip != "" {
		t.Skip(env.skip)
	}
	key := admin(t, 201, "POST", "/v1/admin/keys", map[string]any{"kind": "admin", "name": "tls"})["key"].(string)
	cfg := testConfig(t, key)
	cfg.SecureCookies = true
	dd, err := app.Start(context.Background(), cfg, logger())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(dd.Handler)
	defer srv.Close()
	c := srv.Client()
	c.Jar, _ = cookiejar.New(nil)
	resp, err := c.PostForm(srv.URL+"/login", url.Values{"name": {"alice"}, "password": {alicePW}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Request.URL.Path != "/" {
		t.Fatalf("sign-in over TLS: %d %s", resp.StatusCode, resp.Request.URL)
	}
	u, _ := url.Parse(srv.URL)
	var names []string
	for _, ck := range c.Jar.Cookies(u) {
		names = append(names, ck.Name)
	}
	if strings.Join(names, ",") != "__Host-ipvalet-session" {
		t.Fatalf("cookies %v", names)
	}
}

func TestCrossOriginRefused(t *testing.T) {
	t.Parallel()
	d := newDash(t, nil)
	d.signIn("alice", alicePW)
	name := uniq("x")
	d.post("/realms", url.Values{"name": {name}}, "Sec-Fetch-Site", "cross-site").must(t, 403, "Request refused")
	d.post("/realms", url.Values{"name": {name}}, "Origin", "https://evil.example").must(t, 403)
	admin(t, 404, "GET", "/v1/admin/realms/"+name, nil)
	// Signing in from another site is refused too.
	d.post("/login", url.Values{"name": {"alice"}, "password": {alicePW}}, "Sec-Fetch-Site", "cross-site").must(t, 403)
	// The same site is fine.
	d.post("/realms", url.Values{"name": {name}}, "Sec-Fetch-Site", "same-origin").must(t, 200, "Realm "+name)
}

func TestSecurityHeaders(t *testing.T) {
	t.Parallel()
	d := newDash(t, nil)
	p := d.get("/login")
	for k, want := range map[string]string{
		"Content-Security-Policy": "default-src 'none'; style-src 'self'",
		"X-Frame-Options":         "DENY",
		"X-Content-Type-Options":  "nosniff",
		"Cache-Control":           "no-store",
		"Referrer-Policy":         "same-origin",
	} {
		if !strings.Contains(p.Header.Get(k), want) {
			t.Errorf("%s: %q, want %q", k, p.Header.Get(k), want)
		}
	}
	style := strings.SplitN(strings.SplitN(p.Body, `<link rel="stylesheet" href="`, 2)[1], `"`, 2)[0]
	s := d.get(strings.ReplaceAll(style, "&amp;", "&"))
	if s.Status != 200 || !strings.Contains(s.Header.Get("Cache-Control"), "immutable") ||
		!strings.HasPrefix(s.Header.Get("Content-Type"), "text/css") {
		t.Fatalf("stylesheet %s: %d %v", style, s.Status, s.Header)
	}
}

// TestRuleWithImpact adds a cap rule that existing entries break: the
// dashboard shows them, enforces it on confirmation, and the audit log
// names the person.
func TestRuleWithImpact(t *testing.T) {
	t.Parallel()
	s := newSetup(t)
	oldest := s.submit(t, "u1", "8.8.8.1")
	s.submit(t, "u1", "8.8.8.2")
	s.submit(t, "u1", "8.8.8.3")
	d := newDash(t, nil)
	d.signIn("alice", alicePW)

	p := d.post("/realms/"+s.Realm+"/rules/cap", url.Values{"user": {"*"}, "group": {"*"}, "max_prefixes": {"2"},
		"description": {"two each"}}).must(t, 200, "Add this rule?", "1 entry is affected", "8.8.8.1/32", "removed",
		"its user is over a cap")
	// Nothing is saved until confirmed.
	if n := len(items(admin(t, 200, "GET", "/v1/admin/realms/"+s.Realm+"/rules/cap", nil))); n != 0 {
		t.Fatalf("%d cap rules before confirming", n)
	}
	d.confirm(p).must(t, 200, "Rule added.", "Entries removed: 1. Entries shortened: 0.", "two each")
	if st := admin(t, 200, "GET", "/v1/admin/entries/"+oldest, nil)["deleted_at"]; st == nil {
		t.Fatal("the oldest entry was not removed")
	}
	audit := items(admin(t, 200, "GET", "/v1/admin/audit?action=rule.create&realm="+s.Realm, nil))
	if len(audit) != 1 || audit[0]["on_behalf_of"] != "alice" || audit[0]["actor"] != d.KeyID {
		t.Fatalf("audit %v", audit)
	}
	// The dashboard's audit page shows who.
	d.get("/audit?realm="+s.Realm+"&on_behalf_of=alice").must(t, 200, "rule.create", "entry.delete", "alice")
}

func TestRuleEditing(t *testing.T) {
	t.Parallel()
	s := newSetup(t)
	d := newDash(t, nil)
	d.signIn("bob", bobPW)
	ttl := items(admin(t, 200, "GET", "/v1/admin/realms/"+s.Realm+"/rules/ttl", nil))[0]["id"].(string)
	base := "/realms/" + s.Realm + "/rules/"

	d.get(base+"ttl/"+ttl).must(t, 200, "TTL rule 1", "30d")
	d.post(base+"ttl/"+ttl, url.Values{"user": {"*"}, "group": {"*"}, "max_ttl": {"forever"}}).
		must(t, 400, "Check the fields marked below", "forever")
	d.post(base+"ttl/"+ttl, url.Values{"user": {"*"}, "group": {"*"}, "max_ttl": {"7d"}, "description": {"a week"}}).
		must(t, 200, "Rule saved.", "a week")
	if r := items(admin(t, 200, "GET", "/v1/admin/realms/"+s.Realm+"/rules/ttl", nil))[0]; r["max_ttl"] != "7d" {
		t.Fatalf("ttl rule %v", r)
	}

	// A number field that is not a number never reaches the API.
	d.post(base+"cap", url.Values{"user": {"*"}, "group": {"*"}, "max_prefixes": {"lots"}}).
		must(t, 400, "must be a whole number")

	// Add an IP rule at the top, move it down, then delete it with a preview.
	d.post(base+"ip", url.Values{"user": {"*"}, "group": {"*"}, "prefix": {"9.9.9.0/24"}, "action": {"deny"},
		"position": {"1"}}).must(t, 200, "Rule added.")
	rules := items(admin(t, 200, "GET", "/v1/admin/realms/"+s.Realm+"/rules/ip", nil))
	if rules[0]["prefix"] != "9.9.9.0/24" {
		t.Fatalf("first ip rule %v", rules[0])
	}
	id := rules[0]["id"].(string)
	d.post(base+"ip/"+id+"/move", url.Values{"position": {"2"}}).must(t, 200, "Rule moved to position 2.")
	if r := items(admin(t, 200, "GET", "/v1/admin/realms/"+s.Realm+"/rules/ip", nil))[1]; r["id"] != id {
		t.Fatalf("second ip rule %v", r)
	}
	p := d.post(base+"ip/"+id+"/delete", nil).must(t, 200, "Delete IP rule 2?", "No existing entries are affected.")
	d.confirm(p).must(t, 200, "Rule deleted.")
	if n := len(items(admin(t, 200, "GET", "/v1/admin/realms/"+s.Realm+"/rules/ip", nil))); n != 27 {
		t.Fatalf("%d ip rules after deleting", n)
	}
}

func TestRealmLifecycle(t *testing.T) {
	t.Parallel()
	d := newDash(t, nil)
	d.signIn("alice", alicePW)
	d.post("/realms", url.Values{"name": {"Not Valid"}}).must(t, 400, "Check the fields marked below")
	s := newSetup(t)
	d.post("/realms", url.Values{"name": {s.Realm}}).must(t, 400, "already exists")
	s.submit(t, "u", "8.8.4.1")
	s.submit(t, "u", "8.8.4.2")
	p := d.post("/realms/"+s.Realm+"/delete", nil).must(t, 200, "Delete realm "+s.Realm+"?", "2 live entries")
	d.confirm(p).must(t, 200, "Realm "+s.Realm+" deleted: 2 entries removed")
	admin(t, 404, "GET", "/v1/admin/realms/"+s.Realm, nil)
}

func TestWorkerLifecycle(t *testing.T) {
	t.Parallel()
	s := newSetup(t)
	d := newDash(t, nil)
	d.signIn("alice", alicePW)
	name := uniq("w")
	p := d.post("/workers", url.Values{"name": {name}, "label": {"Office firewall"}, "ipv4": {"on"}}).
		must(t, 200, "Worker "+name, "never reported", "Office firewall")
	wid := strings.TrimPrefix(p.URL.Path, "/workers/")
	base := "/workers/" + wid

	d.post(base+"/subscriptions", url.Values{"realm": {s.Realm}, "user": {"*"}, "group": {"g"}}).
		must(t, 200, "Subscribed to realm "+s.Realm+", user any, group g.")
	d.post(base+"/keys", url.Values{"name": {"k"}, "expires_in_days": {"soon"}}).must(t, 400, "whole number of days")
	p = d.post(base+"/keys", url.Values{"name": {"k"}, "expires_in_days": {"30"}}).
		must(t, 201, "Key created", "Copy the key now")
	key := keyPattern.FindString(p.Body)
	if key == "" {
		t.Fatal("no key on the page")
	}
	if p.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("key page Cache-Control %q", p.Header.Get("Cache-Control"))
	}
	if status, _ := call(t, env.apiPublic, key, "GET", "/v1/worker/desired-state", nil); status != 200 {
		t.Fatalf("new worker key: %d", status)
	}
	kid := strings.Split(key, "_")[1]

	// An entry for the subscription reads pending on the new worker.
	s.submit(t, "u", "8.8.2.1")
	d.get("/entries?worker_id="+wid).must(t, 200, "8.8.2.1/32", name+": pending")

	// Revoke the key through its confirmation page.
	p = d.post("/keys/"+kid+"/revoke", url.Values{"back": {base + "#keys"}}).must(t, 200, "Revoke key k?")
	d.confirm(p).must(t, 200, "Key k revoked.", "revoked")
	if status, _ := call(t, env.apiPublic, key, "GET", "/v1/worker/desired-state", nil); status != 401 {
		t.Fatalf("revoked worker key: %d", status)
	}

	// Once this worker is the only one routing the entry, turning off its
	// family leaves the entry unrouted, which the dashboard asks about first.
	for _, sub := range items(admin(t, 200, "GET", "/v1/admin/workers/"+s.WorkerID+"/subscriptions", nil)) {
		admin(t, 200, "DELETE", "/v1/admin/subscriptions/"+sub["id"].(string)+"?confirm=true", nil)
	}
	p = d.post(base, url.Values{"name": {name}, "label": {"Office firewall"}, "ipv6": {"on"}}).
		must(t, 200, "Change this worker's address families?", "8.8.2.1/32", "no worker matches it any more")
	d.confirm(p).must(t, 200, "Worker saved.")
	if w := admin(t, 200, "GET", "/v1/admin/workers/"+wid, nil); w["ipv4"] != false {
		t.Fatalf("worker %v", w)
	}

	p = d.post(base+"/delete", nil).must(t, 200, "Delete worker "+name+"?")
	d.confirm(p).must(t, 200, "Worker "+name+" deleted.")
	admin(t, 404, "GET", "/v1/admin/workers/"+wid, nil)
}

func TestClientLifecycle(t *testing.T) {
	t.Parallel()
	r1, r2 := uniq("r"), uniq("r")
	admin(t, 201, "POST", "/v1/admin/realms", map[string]any{"name": r1})
	admin(t, 201, "POST", "/v1/admin/realms", map[string]any{"name": r2})
	d := newDash(t, nil)
	d.signIn("alice", alicePW)
	name := uniq("c")
	d.post("/clients", url.Values{"name": {name}}).must(t, 400, "Check the fields marked below")
	p := d.post("/clients", url.Values{"name": {name}, "realms": {r1}}).must(t, 200, "Client "+name, "Realms: "+r1)
	cid := strings.TrimPrefix(p.URL.Path, "/clients/")
	d.post("/clients/"+cid, url.Values{"name": {name}, "realms": {r1, r2}}).must(t, 200, "Client saved.")
	if c := admin(t, 200, "GET", "/v1/admin/clients/"+cid, nil); len(c["realms"].([]any)) != 2 {
		t.Fatalf("client %v", c)
	}
	p = d.post("/clients/"+cid+"/keys", url.Values{"name": {"web"}}).must(t, 201, "Key created")
	key := keyPattern.FindString(p.Body)
	if status, _ := call(t, env.apiPublic, key, "GET", "/v1/entries", nil); status != 200 {
		t.Fatalf("new client key: %d", status)
	}
	p = d.post("/clients/"+cid+"/delete", nil).must(t, 200, "Delete client "+name+"?")
	d.confirm(p).must(t, 200, "Client "+name+" deleted.")
	if status, _ := call(t, env.apiPublic, key, "GET", "/v1/entries", nil); status != 401 {
		t.Fatalf("deleted client's key: %d", status)
	}
}

func TestEntries(t *testing.T) {
	t.Parallel()
	s := newSetup(t)
	id := s.submit(t, "carol", "8.8.1.1")
	s.submit(t, "dave", "8.8.1.2")
	d := newDash(t, nil)
	d.signIn("bob", bobPW)
	d.get("/entries?realm="+s.Realm).must(t, 200, "8.8.1.1/32", "8.8.1.2/32", "pending")
	d.get("/entries?realm="+s.Realm+"&user=carol").must(t, 200, "8.8.1.1/32")
	if p := d.get("/entries?realm=" + s.Realm + "&user=carol"); strings.Contains(p.Body, "8.8.1.2/32") {
		t.Fatal("the user filter let dave's entry through")
	}
	d.get("/entries?prefix=not-a-prefix").must(t, 200, "The prefix filter")
	d.get("/entries/"+id).must(t, 200, "8.8.1.1/32 for carol", "Delete this entry")
	p := d.post("/entries/"+id+"/delete", nil).must(t, 200, "Delete 8.8.1.1/32 for carol?")
	d.confirm(p).must(t, 200, "Entry deleted.", "removing")
	audit := items(admin(t, 200, "GET", "/v1/admin/audit?action=entry.delete&realm="+s.Realm, nil))
	if len(audit) != 1 || audit[0]["on_behalf_of"] != "bob" {
		t.Fatalf("audit %v", audit)
	}
}

func TestOverviewAndKeys(t *testing.T) {
	t.Parallel()
	s := newSetup(t)
	d := newDash(t, nil)
	d.signIn("alice", alicePW)
	d.get("/").must(t, 200, "ready", "Revision", "never reported")
	d.get("/workers").must(t, 200, "never reported")
	d.get("/workers/"+s.WorkerID).must(t, 200, "Subscriptions", s.Realm)
	d.get("/clients/"+s.ClientID).must(t, 200, s.Realm)
	// The dashboard's own key is marked, and revoking it warns.
	d.get("/keys?kind=admin").must(t, 200, "this dashboard", d.KeyID)
	d.post("/keys/"+d.KeyID+"/revoke", url.Values{"back": {"/keys"}}).must(t, 200, "the dashboard's own key")
	// A new admin key, shown once.
	p := d.post("/keys", url.Values{"name": {"ops"}, "expires_in_days": {""}}).
		must(t, 201, "A new admin key", "with no expiry", "Warning:")
	if keyPattern.FindString(p.Body) == "" {
		t.Fatal("no key on the page")
	}
}

func TestNotFound(t *testing.T) {
	t.Parallel()
	d := newDash(t, nil)
	d.signIn("alice", alicePW)
	d.get("/workers/00000000-0000-4000-8000-000000000000").must(t, 404, "Not found")
	d.get("/realms/nope-"+randHex(3)).must(t, 404, "Not found")
	d.get("/realms/x/rules/bogus/new").must(t, 404)
	d.get("/no-such-page").must(t, 404, "There is no such page.")
}

func TestStartChecksTheAPI(t *testing.T) {
	t.Parallel()
	if env.skip != "" {
		t.Skip(env.skip)
	}
	// A key the API server does not know.
	if _, err := app.Start(context.Background(), testConfig(t, newKey()), logger()); err == nil ||
		!strings.Contains(err.Error(), "refused IPVALET_DASHBOARD_API_KEY") {
		t.Fatalf("unknown key: %v", err)
	}
	// The public listener instead of the admin one.
	key := admin(t, 201, "POST", "/v1/admin/keys", map[string]any{"kind": "admin", "name": "wrong port"})["key"].(string)
	cfg := testConfig(t, key)
	cfg.APIURL, _ = url.Parse(env.apiPublic)
	if _, err := app.Start(context.Background(), cfg, logger()); err == nil || !strings.Contains(err.Error(), "admin listener") {
		t.Fatalf("public listener: %v", err)
	}
	// An API server that is not up yet is only a warning, and pages say so.
	cfg.APIURL, _ = url.Parse("http://" + freeAddr())
	dd, err := app.Start(context.Background(), cfg, logger())
	if err != nil {
		t.Fatalf("API server down: %v", err)
	}
	srv := httptest.NewServer(dd.Handler)
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	resp, err := c.PostForm(srv.URL+"/login?", url.Values{"name": {"alice"}, "password": {alicePW}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("overview with the API down: %d", resp.StatusCode)
	}
	resp, _ = c.Get(srv.URL + "/realms")
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("realms with the API down: %d", resp.StatusCode)
	}
}

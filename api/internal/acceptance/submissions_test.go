package acceptance

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PatrickH298/ip-valet/api/internal/testutil"
)

func TestNoSubscriberFailsWholeSubmission(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	h.CreateRealm("authentik")
	tid := h.CreateWorker("v4only", true, false)
	h.Subscribe(tid, "authentik", "*", "fwusers")
	key := h.ClientKey(h.CreateClient("web", "authentik"))
	before := h.Revision()

	res := results(t, h.Submit(key, sub("patrick", "8.8.8.8", "1d", "fwusers", "guests")))
	if res["fwusers"]["ok"] != true || res["guests"]["code"] != "no_subscriber" {
		t.Fatalf("results = %v", res)
	}
	// Family mismatch: the only matching worker is IPv4-only.
	res = results(t, h.Submit(key, sub("patrick", "2a00:1450::/64", "1d", "fwusers")))
	if res["fwusers"]["code"] != "no_subscriber" {
		t.Fatalf("family mismatch: %v", res)
	}
	if n := countRows(h, `SELECT count(*) FROM entries`); n != 0 {
		t.Fatalf("%d entries written", n)
	}
	if n := countRows(h, `SELECT count(*) FROM audit_log WHERE action LIKE 'entry.%'`); n != 0 {
		t.Fatalf("%d entry audit rows written", n)
	}
	if h.Revision() != before {
		t.Fatal("revision bumped by a rejected submission")
	}
	submitOK(h, key, sub("patrick", "8.8.8.8", "1d", "fwusers"))
}

func TestEveryFailingGroupListed(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("authentik")
	h.AddRule(s.Realm, "ip", map[string]any{"user": "*", "group": "x", "prefix": "8.8.8.0/24", "action": "deny", "position": 1})
	h.AddRule(s.Realm, "ttl", map[string]any{"user": "*", "group": "b", "max_ttl": "1h", "position": 1})
	h.AddRule(s.Realm, "cap", map[string]any{"user": "*", "group": "b", "max_prefixes": 0})

	r := h.Submit(s.ClientKey, sub("p", "8.8.8.8", "2h", "a", "x", "b", "a"))
	res := results(t, r)
	if len(res) != 3 {
		t.Fatalf("duplicates not removed: %v", res)
	}
	if res["a"]["ok"] != true {
		t.Errorf("a: %v", res["a"])
	}
	if res["x"]["code"] != "ip_denied" {
		t.Errorf("x: %v", res["x"])
	}
	// b fails both TTL and cap; only the first failing check is reported.
	if res["b"]["code"] != "ttl_exceeded" || res["b"]["limit"].(map[string]any)["max_ttl"] != "1h" {
		t.Errorf("b: %v", res["b"])
	}
	if msg := r.JSON(t)["error"].(map[string]any)["message"]; msg != "2 of 3 groups failed" {
		t.Errorf("message = %v", msg)
	}

	// Client scope: a realm the client is not bound to fails first.
	h.CreateRealm("other")
	body := sub("alice", "8.8.8.8", "1h", "a")
	body["realm"] = "other"
	if res := results(t, h.Submit(s.ClientKey, body)); res["a"]["code"] != "realm_not_allowed" {
		t.Errorf("realm: %v", res)
	}
}

func TestResubmitReplaces(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("authentik")
	first := submitOK(h, s.ClientKey, sub("p", "8.8.8.8", "7d", "g"))
	id := firstEntryID(first)
	e1 := adminEntry(h, id)
	rev1 := e1["revision"].(float64)
	exp1, _ := time.Parse(time.RFC3339Nano, e1["expires_at"].(string))

	second := submitOK(h, s.ClientKey, sub("p", "8.8.8.8", "1h", "g", "h"))
	entries := second["entries"].([]any)
	got := entries[0].(map[string]any)
	if got["id"] != id || got["replaced"] != true {
		t.Fatalf("replace: %v", got)
	}
	if entries[1].(map[string]any)["replaced"] != false {
		t.Fatalf("new group entry marked replaced: %v", entries[1])
	}
	e2 := adminEntry(h, id)
	exp2, _ := time.Parse(time.RFC3339Nano, e2["expires_at"].(string))
	if !exp2.Before(exp1) || time.Until(exp2) > time.Hour || time.Until(exp2) < 59*time.Minute {
		t.Fatalf("expiry %v not shortened to about now+1h (was %v)", exp2, exp1)
	}
	if e2["revision"].(float64) <= rev1 {
		t.Fatalf("revision %v not bumped from %v", e2["revision"], rev1)
	}
	if e2["submission_id"] != second["submission_id"] || e2["created_at"] != e1["created_at"] {
		t.Fatalf("submission id or created_at wrong: %v", e2)
	}
	if n := countRows(h, `SELECT count(*) FROM entries WHERE prefix = '8.8.8.8/32' AND grp = 'g'`); n != 1 {
		t.Fatalf("%d rows for the same entry", n)
	}
	if n := countRows(h, `SELECT count(*) FROM audit_log WHERE action = 'entry.replace' AND object_id = $1`, id); n != 1 {
		t.Fatalf("%d entry.replace audit rows", n)
	}
}

func TestResubmitRevivesExpired(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("authentik")
	id := firstEntryID(submitOK(h, s.ClientKey, sub("p", "8.8.8.8", "1d", "g")))
	h.Exec(`UPDATE entries SET expires_at = now() - interval '1 minute' WHERE id = $1`, id)
	if st, _ := entryState(h, id); st != "removing" && st != "expired" {
		t.Fatalf("expired entry state %s", st)
	}
	resp := submitOK(h, s.ClientKey, sub("p", "8.8.8.8", "1d", "g"))
	e := resp["entries"].([]any)[0].(map[string]any)
	if e["id"] != id || e["replaced"] != true || e["state"] != "pending" {
		t.Fatalf("revive: %v", e)
	}
}

func TestConcurrentSubmissionsRespectCap(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("authentik")
	h.AddRule(s.Realm, "cap", map[string]any{"user": "*", "group": "*", "max_prefixes": 3})

	const n = 12
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		statuses = map[int]int{}
	)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			r := testutil.DoURL(t, httpClient(), h.Inst.URL, "POST", "/v1/submissions", s.ClientKey,
				sub("racer", "8.8.7."+string(rune('0'+i%10))+string(rune('0'+i/10)), "1d", "g"))
			mu.Lock()
			statuses[r.Status]++
			mu.Unlock()
		}(i)
	}
	close(start)
	wg.Wait()
	if statuses[http.StatusCreated] != 3 || statuses[http.StatusUnprocessableEntity] != n-3 {
		t.Fatalf("statuses = %v, want 3 created and %d rejected", statuses, n-3)
	}
	if c := countRows(h, `SELECT count(*) FROM entries WHERE username = 'racer' AND deleted_at IS NULL`); c != 3 {
		t.Fatalf("%d live entries", c)
	}
}

func TestClientRealmIsolation(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	a := h.Basic("alpha")
	b := h.Basic("beta")
	resp := submitOK(h, b.ClientKey, sub("p", "8.8.8.8", "1d", "g"))
	id := firstEntryID(resp)
	subID := resp["submission_id"].(string)

	for _, c := range []struct{ method, path string }{
		{"GET", "/v1/entries/" + id},
		{"DELETE", "/v1/entries/" + id},
		{"DELETE", "/v1/submissions/" + subID},
	} {
		if r := h.Do(c.method, c.path, a.ClientKey, nil); r.Status != 404 || r.Code(t) != "not_found" {
			t.Errorf("%s %s from another realm: %d %s", c.method, c.path, r.Status, r.Body)
		}
	}
	list := h.Must(200, "GET", "/v1/entries?include_ended=true", a.ClientKey, nil)
	if items := list["items"].([]any); len(items) != 0 {
		t.Errorf("alpha client sees %d entries", len(items))
	}
	if r := h.Do("GET", "/v1/entries?realm=beta", a.ClientKey, nil); r.Status != 403 || r.Code(t) != "realm_not_allowed" {
		t.Errorf("list other realm: %d %s", r.Status, r.Body)
	}
	// The owning realm's client still can.
	h.Must(200, "GET", "/v1/entries/"+id, b.ClientKey, nil)
	del := h.Must(200, "DELETE", "/v1/entries/"+id, b.ClientKey, nil)
	if del["state"] != "removing" || del["deleted_at"] == nil {
		t.Errorf("deleted entry = %v", del)
	}
	if r := h.Do("DELETE", "/v1/entries/"+id, b.ClientKey, nil); r.Status != 404 {
		t.Errorf("deleting twice: %d", r.Status)
	}

	// Submission deletion removes every entry of the submission.
	resp = submitOK(h, b.ClientKey, sub("q", "8.8.4.4", "1d", "g1", "g2"))
	d := h.Must(200, "DELETE", "/v1/submissions/"+resp["submission_id"].(string), b.ClientKey, nil)
	if len(d["deleted"].([]any)) != 2 {
		t.Errorf("deleted = %v", d)
	}
	if r := h.Do("DELETE", "/v1/submissions/"+resp["submission_id"].(string), b.ClientKey, nil); r.Status != 404 {
		t.Errorf("deleting a submission twice: %d", r.Status)
	}
}

func TestSubmissionValidation(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("authentik")
	bad := []any{
		`{"user":"p","groups":["g"],"prefix":"8.8.8.8","ttl":"1d","extra":1}`,
		`{"user":"p","groups":[],"prefix":"8.8.8.8","ttl":"1d"}`,
		`{"user":"*","groups":["g"],"prefix":"8.8.8.8","ttl":"1d"}`,
		`{"user":"p","groups":["*"],"prefix":"8.8.8.8","ttl":"1d"}`,
		`{"user":"p","groups":["g"],"prefix":"8.8.8.8"}`,
		`{"user":"p\u0001","groups":["g"],"prefix":"8.8.8.8","ttl":"1d"}`,
		`{"realm":"Bad Realm","user":"p","groups":["g"],"prefix":"8.8.8.8","ttl":"1d"}`,
		`not json`,
		`{"user":"p","groups":["g"],"prefix":"8.8.8.8","ttl":"1d"} {}`,
	}
	for _, b := range bad {
		if r := h.Submit(s.ClientKey, nil); r.Status != 400 {
			t.Errorf("empty body: %d", r.Status)
		}
		r := h.Do("POST", "/v1/submissions", s.ClientKey, b)
		if r.Status != 400 || r.Code(t) != "invalid_request" {
			t.Errorf("%s: %d %s", b, r.Status, r.Body)
		}
	}
	many := make([]string, 33)
	for i := range many {
		many[i] = "g" + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}
	if r := h.Submit(s.ClientKey, sub("p", "8.8.8.8", "1d", many...)); r.Status != 400 {
		t.Errorf("33 groups: %d", r.Status)
	}
	// Realm is required when the client has more than one realm.
	h.CreateRealm("second")
	h.Admin(200, "PATCH", "/v1/admin/clients/"+s.ClientID, map[string]any{"realms": []string{"authentik", "second"}})
	if r := h.Submit(s.ClientKey, sub("p", "8.8.8.8", "1d", "g")); r.Status != 400 {
		t.Errorf("missing realm with two realms: %d", r.Status)
	}
	// Body limit.
	huge := `{"user":"` + strings.Repeat("a", 70000) + `"}`
	if r := h.Do("POST", "/v1/submissions", s.ClientKey, huge); r.Status != 413 || r.Code(t) != "body_too_large" {
		t.Errorf("huge body: %d %s", r.Status, r.Body)
	}
}

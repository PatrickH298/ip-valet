package acceptance

import (
	"strings"
	"testing"
	"time"

	"github.com/PatrickH298/ip-valet/api/internal/auth"
	"github.com/PatrickH298/ip-valet/api/internal/testutil"
)

// impactItems returns impact items keyed by entry id.
func impactItems(t *testing.T, list any) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, it := range list.([]any) {
		m := it.(map[string]any)
		out[m["entry_id"].(string)] = m
	}
	return out
}

func TestImpactCheck(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("r")
	e1 := firstEntryID(submitOK(h, s.ClientKey, sub("p", "8.8.8.8", "7d", "g")))
	e2 := firstEntryID(submitOK(h, s.ClientKey, sub("q", "8.8.4.4", "7d", "g")))
	e3 := firstEntryID(submitOK(h, s.ClientKey, sub("q", "1.1.1.1", "1h", "g")))
	ttlRule := h.RulesOf("r", "ttl")[0]
	path := "/v1/admin/realms/r/rules/ttl/" + ttlRule["id"].(string)
	tighten := map[string]any{"max_ttl": "1d"}

	// Unconfirmed: 409 with the impact; nothing changes.
	r := h.Do("PATCH", path, h.AdminKey, tighten)
	if r.Status != 409 || r.Code(t) != "confirmation_required" {
		t.Fatalf("unconfirmed: %d %s", r.Status, r.Body)
	}
	items := impactItems(t, r.JSON(t)["error"].(map[string]any)["impact"])
	if len(items) != 2 {
		t.Fatalf("impact = %v", items)
	}
	for _, id := range []string{e1, e2} {
		if it := items[id]; it["effect"] != "ttl_exceeded" || it["action"] != "shorten" {
			t.Fatalf("impact item %v", it)
		}
	}
	if h.RulesOf("r", "ttl")[0]["max_ttl"] != "30d" {
		t.Fatal("rule changed by an unconfirmed request")
	}
	// There is no way to keep entries that fail a rule.
	if r := h.Do("PATCH", path+"?confirm=true&on_existing=keep", h.AdminKey, tighten); r.Status != 400 {
		t.Fatalf("on_existing accepted: %d", r.Status)
	}

	// Dry run: 200 with impact; nothing changes.
	rev := h.Revision()
	dry := h.Admin(200, "PATCH", path+"?dry_run=true", tighten)
	if len(dry["impact"].([]any)) != 2 || dry["max_ttl"] != "1d" || dry["dry_run"] != true {
		t.Fatalf("dry run = %v", dry)
	}
	if h.RulesOf("r", "ttl")[0]["max_ttl"] != "30d" || h.Revision() != rev {
		t.Fatal("dry run changed something")
	}

	// Confirmed: both shortened, the revision bumped once.
	out := h.Admin(200, "PATCH", path+"?confirm=true", tighten)
	enf := out["enforced"].(map[string]any)
	if enf["shortened"].(float64) != 2 || enf["removed"].(float64) != 0 || len(out["impact"].([]any)) != 2 {
		t.Fatalf("enforced = %v", out)
	}
	if h.Revision() != rev+1 {
		t.Fatalf("revision %d, want %d", h.Revision(), rev+1)
	}
	for _, id := range []string{e1, e2} {
		e := adminEntry(h, id)
		exp, _ := time.Parse(time.RFC3339Nano, e["expires_at"].(string))
		if d := time.Until(exp); d > 24*time.Hour || d < 23*time.Hour {
			t.Fatalf("%s expires in %v", id, d)
		}
		if int64(e["revision"].(float64)) != rev+1 || e["state"] != "pending" {
			t.Fatalf("shortened entry %v", e)
		}
	}
	if e := adminEntry(h, e3); int64(e["revision"].(float64)) == rev+1 {
		t.Fatal("unaffected entry was touched")
	}

	// An IP rule that now denies entries removes them.
	rev = h.Revision()
	out = h.Admin(201, "POST", "/v1/admin/realms/r/rules/ip?confirm=true", map[string]any{
		"user": "*", "group": "*", "prefix": "8.8.0.0/16", "action": "deny", "position": 1})
	if enf := out["enforced"].(map[string]any); enf["removed"].(float64) != 2 || enf["shortened"].(float64) != 0 {
		t.Fatalf("enforced = %v", out)
	}
	for id, it := range impactItems(t, out["impact"]) {
		if (id != e1 && id != e2) || it["effect"] != "ip_denied" || it["action"] != "remove" {
			t.Fatalf("impact item %v", it)
		}
	}
	if h.Revision() != rev+1 {
		t.Fatalf("revision %d, want %d", h.Revision(), rev+1)
	}
	for _, id := range []string{e1, e2} {
		if e := adminEntry(h, id); e["deleted_at"] == nil || e["deleted_by"] == nil || e["state"] != "removing" {
			t.Fatalf("not removed: %v", e)
		}
	}

	// A cap removes the least recently submitted prefixes over the limit.
	z1 := firstEntryID(submitOK(h, s.ClientKey, sub("z", "9.9.9.1", "1h", "g")))
	z2 := firstEntryID(submitOK(h, s.ClientKey, sub("z", "9.9.9.2", "1h", "g")))
	z3 := submitOK(h, s.ClientKey, sub("z", "9.9.9.3", "1h", "g", "h"))
	submitOK(h, s.ClientKey, sub("z", "9.9.9.1", "1h", "g")) // the most recent now
	out = h.Admin(201, "POST", "/v1/admin/realms/r/rules/cap?confirm=true", map[string]any{
		"user": "*", "group": "*", "max_prefixes": 2})
	items = impactItems(t, out["impact"])
	if len(items) != 1 || items[z2]["effect"] != "cap_exceeded" || items[z2]["action"] != "remove" {
		t.Fatalf("cap impact = %v", items)
	}
	if e := adminEntry(h, z2); e["deleted_at"] == nil {
		t.Fatal("oldest prefix kept")
	}
	for _, id := range []string{z1, firstEntryID(z3), z3["entries"].([]any)[1].(map[string]any)["id"].(string)} {
		if e := adminEntry(h, id); e["deleted_at"] != nil {
			t.Fatalf("recent prefix removed: %v", e)
		}
	}

	// No entry is left failing a rule: a no-op change finds nothing to do.
	var ids []string
	for _, rr := range h.RulesOf("r", "ip") {
		ids = append(ids, rr["id"].(string))
	}
	if dry := h.Admin(200, "PUT", "/v1/admin/realms/r/rules/ip/order?dry_run=true", map[string]any{"ids": ids}); len(dry["impact"].([]any)) != 0 {
		t.Fatalf("entries still fail a rule: %v", dry["impact"])
	}

	// Deleting the only subscription leaves the realm's entries unrouted. They
	// fail no rule, so they stay.
	subs := h.Admin(200, "GET", "/v1/admin/workers/"+s.WorkerID+"/subscriptions", nil)["items"].([]any)
	subPath := "/v1/admin/subscriptions/" + subs[0].(map[string]any)["id"].(string)
	r = h.Do("DELETE", subPath, h.AdminKey, nil)
	if r.Status != 409 {
		t.Fatalf("subscription delete: %d %s", r.Status, r.Body)
	}
	for _, it := range impactItems(t, r.JSON(t)["error"].(map[string]any)["impact"]) {
		if it["effect"] != "unrouted" || it["action"] != "none" {
			t.Fatalf("impact %v", it)
		}
	}
	rev = h.Revision()
	out = h.Admin(200, "DELETE", subPath+"?confirm=true", nil)
	if out["enforced"].(map[string]any)["removed"].(float64) != 0 || h.Revision() != rev+1 {
		t.Fatalf("subscription delete = %v (revision %d -> %d)", out, rev, h.Revision())
	}
	if st, per := entryState(h, z1); st != "unrouted" || per["home-r"] != "removing" {
		t.Fatalf("unrouted entry: %s %v", st, per)
	}
	h.Apply(s.WorkerKey)
	if st, per := entryState(h, z1); st != "unrouted" || len(per) != 0 {
		t.Fatalf("unrouted entry after the worker confirmed: %s %v", st, per)
	}
}

func TestWorkerFamilyChangeImpact(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("r")
	v6 := firstEntryID(submitOK(h, s.ClientKey, sub("p", "2a00:1450::/64", "1d", "g")))
	submitOK(h, s.ClientKey, sub("p", "8.8.8.8", "1d", "g"))
	path := "/v1/admin/workers/" + s.WorkerID
	if r := h.Do("PATCH", path, h.AdminKey, map[string]any{"ipv6": false}); r.Status != 409 {
		t.Fatalf("family change: %d %s", r.Status, r.Body)
	}
	// A label change needs no confirmation and bumps nothing.
	rev := h.Revision()
	h.Admin(200, "PATCH", path, map[string]any{"label": "Renamed"})
	if h.Revision() != rev {
		t.Fatal("label change bumped the revision")
	}
	out := h.Admin(200, "PATCH", path+"?confirm=true", map[string]any{"ipv6": false})
	if len(out["impact"].([]any)) != 1 || out["impact"].([]any)[0].(map[string]any)["entry_id"] != v6 {
		t.Fatalf("impact = %v", out["impact"])
	}
	if h.Revision() != rev+1 || int64(out["subscriptions_revision"].(float64)) != rev+1 {
		t.Fatalf("family change revision: %v", out)
	}
	// The worker dropped the entry; it reads removing there until the worker confirms.
	if st, per := entryState(h, v6); st != "unrouted" || per["home-r"] != "removing" {
		t.Fatalf("v6 entry: %s %v", st, per)
	}
	h.Apply(s.WorkerKey)
	if st, per := entryState(h, v6); st != "unrouted" || len(per) != 0 {
		t.Fatalf("v6 entry after the worker confirmed: %s %v", st, per)
	}
	if r := h.Do("DELETE", path, h.AdminKey, nil); r.Status != 409 {
		t.Fatalf("worker delete: %d", r.Status)
	}
	h.Admin(200, "DELETE", path+"?confirm=true", nil)
}

func TestRealmDeletion(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	// home-doomed subscribes to the realm by name, so its subscription goes
	// with the realm; wild subscribes to every realm and keeps matching.
	s := h.Basic("doomed")
	h.CreateRealm("kept")
	wild := h.CreateWorker("wild", true, true)
	h.Subscribe(wild, "*", "*", "*")
	wk := h.WorkerKey(wild)
	h.Admin(200, "PATCH", "/v1/admin/clients/"+s.ClientID, map[string]any{"realms": []string{"doomed", "kept"}})
	body := sub("p", "8.8.8.8", "1d", "g")
	body["realm"] = "doomed"
	id := firstEntryID(submitOK(h, s.ClientKey, body))
	h.Apply(s.WorkerKey)
	h.Apply(wk)
	if st, _ := entryState(h, id); st != "active" {
		t.Fatalf("before: %s", st)
	}

	rev := h.Revision()
	out := h.Admin(200, "DELETE", "/v1/admin/realms/doomed", nil)
	if out["entries_removed"].(float64) != 1 || out["rules_deleted"].(float64) != 29 ||
		out["subscriptions_deleted"].(float64) != 1 || out["clients_unbound"].(float64) != 1 {
		t.Fatalf("counts = %v", out)
	}
	if h.Revision() != rev+1 {
		t.Fatalf("revision %d, want %d", h.Revision(), rev+1)
	}
	for _, tbl := range []string{"ip_rules", "prefix_rules", "ttl_rules", "cap_rules", "subscriptions", "client_realms"} {
		if n := countRows(h, `SELECT count(*) FROM `+tbl+` WHERE realm = 'doomed'`); n != 0 {
			t.Errorf("%s still has %d rows", tbl, n)
		}
	}
	if r := h.Do("GET", "/v1/admin/realms/doomed", h.AdminKey, nil); r.Status != 404 {
		t.Errorf("realm still readable: %d", r.Status)
	}
	// Both workers held the entry; it is removing until each worker confirms,
	// even on the worker whose subscription went with the realm.
	if st, per := entryState(h, id); st != "removing" || per["home-doomed"] != "removing" || per["wild"] != "removing" {
		t.Fatalf("after realm deletion: %s %v", st, per)
	}
	h.Apply(s.WorkerKey)
	if st, per := entryState(h, id); st != "removing" || per["home-doomed"] != "removed" || per["wild"] != "removing" {
		t.Fatalf("after one worker confirmed: %s %v", st, per)
	}
	h.Apply(wk)
	if st, _ := entryState(h, id); st != "removed" {
		t.Fatalf("after both workers confirmed: %s", st)
	}
	// The client keeps working in its other realm.
	h.Must(200, "GET", "/v1/entries", s.ClientKey, nil)
	// A client left with no realm gets 403 realm_not_allowed everywhere.
	lone := h.CreateClient("lone", "kept")
	lk := h.ClientKey(lone)
	h.Admin(200, "DELETE", "/v1/admin/realms/kept", nil)
	if r := h.Do("GET", "/v1/entries", lk, nil); r.Status != 403 || r.Code(t) != "realm_not_allowed" {
		t.Fatalf("client without realms: %d %s", r.Status, r.Body)
	}
}

func TestRemovalAfterSubscriptionChanges(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	h.CreateRealm("r")
	a := h.CreateWorker("alpha", true, true)
	b := h.CreateWorker("beta", true, true)
	h.Subscribe(a, "r", "*", "*")
	subB := h.Subscribe(b, "r", "*", "*")
	key := h.ClientKey(h.CreateClient("web", "r"))
	wa, wb := h.WorkerKey(a), h.WorkerKey(b)
	deleted := firstEntryID(submitOK(h, key, sub("p", "8.8.8.8", "1d", "g")))
	live := firstEntryID(submitOK(h, key, sub("p", "8.8.4.4", "1d", "g")))
	h.Apply(wa)
	h.Apply(wb)

	// Delete one entry, then beta's subscription, before either worker catches up.
	h.Must(200, "DELETE", "/v1/entries/"+deleted, key, nil)
	h.Admin(200, "DELETE", "/v1/admin/subscriptions/"+subB, nil) // alpha still routes everything
	if st, per := entryState(h, deleted); st != "removing" || per["alpha"] != "removing" || per["beta"] != "removing" {
		t.Fatalf("deleted entry: %s %v", st, per)
	}
	// The live entry stays active on alpha and reads removing on beta.
	if st, per := entryState(h, live); st != "active" || per["alpha"] != "active" || per["beta"] != "removing" {
		t.Fatalf("live entry: %s %v", st, per)
	}
	h.Apply(wb)
	if st, per := entryState(h, deleted); st != "removing" || per["beta"] != "removed" || per["alpha"] != "removing" {
		t.Fatalf("after beta confirmed: %s %v", st, per)
	}
	if _, per := entryState(h, live); len(per) != 1 || per["alpha"] == "" {
		t.Fatalf("live entry after beta confirmed: %v", per)
	}
	h.Apply(wa)
	if st, _ := entryState(h, deleted); st != "removed" {
		t.Fatalf("after both confirmed: %s", st)
	}
	if st, _ := entryState(h, live); st != "active" {
		t.Fatalf("live entry: %s", st)
	}
}

func TestKeySecretShownOnce(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("r")
	cr := h.Do("POST", "/v1/admin/keys", h.AdminKey, map[string]any{"kind": "client", "client_id": s.ClientID, "name": "once"})
	if cr.Status != 201 {
		t.Fatalf("create key: %d %s", cr.Status, cr.Body)
	}
	// No cache may keep the response that carries the secret.
	if cr.Header.Get("Cache-Control") != "no-store" || cr.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers: %v", cr.Header)
	}
	created := cr.JSON(t)
	full := created["key"].(string)
	k, err := auth.ParseKey(full)
	if err != nil || created["id"] != k.ID {
		t.Fatalf("created = %v", created)
	}
	for _, path := range []string{"/v1/admin/keys/" + k.ID, "/v1/admin/keys", "/v1/admin/keys?client_id=" + s.ClientID,
		"/v1/admin/audit"} {
		r := h.Do("GET", path, h.AdminKey, nil)
		if r.Status != 200 {
			t.Fatalf("%s: %d", path, r.Status)
		}
		if strings.Contains(string(r.Body), k.Secret) || strings.Contains(string(r.Body), `"key":`) ||
			strings.Contains(string(r.Body), "secret_hash") {
			t.Fatalf("%s exposes the secret: %s", path, r.Body)
		}
	}
	got := h.Admin(200, "GET", "/v1/admin/keys/"+k.ID, nil)
	if got["kind"] != "client" || got["client_id"] != s.ClientID || got["name"] != "once" {
		t.Fatalf("key record = %v", got)
	}
}

func TestAdminCRUD(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("r")

	// Conflicts.
	if r := h.Do("POST", "/v1/admin/realms", h.AdminKey, map[string]any{"name": "r"}); r.Status != 409 || r.Code(t) != "conflict" {
		t.Errorf("duplicate realm: %d", r.Status)
	}
	if r := h.Do("POST", "/v1/admin/clients", h.AdminKey, map[string]any{"name": "client-r", "realms": []string{"r"}}); r.Status != 409 {
		t.Errorf("duplicate client: %d", r.Status)
	}
	if r := h.Do("POST", "/v1/admin/workers", h.AdminKey, map[string]any{"name": "home-r", "label": "x", "ipv4": true, "ipv6": false}); r.Status != 409 {
		t.Errorf("duplicate worker: %d", r.Status)
	}
	if r := h.Do("POST", "/v1/admin/workers/"+s.WorkerID+"/subscriptions", h.AdminKey, map[string]any{"realm": "r", "user": "*", "group": "*"}); r.Status != 409 {
		t.Errorf("duplicate subscription: %d", r.Status)
	}
	// Validation.
	for _, c := range []struct {
		path string
		body any
	}{
		{"/v1/admin/realms", map[string]any{"name": "Bad"}},
		{"/v1/admin/clients", map[string]any{"name": "c", "realms": []string{}}},
		{"/v1/admin/clients", map[string]any{"name": "c", "realms": []string{"missing"}}},
		{"/v1/admin/clients", map[string]any{"name": "c", "realms": []string{"r"}, "user_allowlist": []string{"p"}}},
		{"/v1/admin/workers", map[string]any{"name": "t", "label": "T", "ipv4": false, "ipv6": false}},
		{"/v1/admin/keys", map[string]any{"kind": "worker", "name": "w"}},
		{"/v1/admin/keys", map[string]any{"kind": "admin", "name": "a", "client_id": s.ClientID}},
		{"/v1/admin/realms/r/rules/ip", map[string]any{"user": "*", "group": "*", "prefix": "1.2.3.0/24", "action": "maybe"}},
		{"/v1/admin/realms/r/rules/ttl", map[string]any{"user": "*", "group": "*", "max_ttl": "forever"}},
		{"/v1/admin/realms/r/rules/cap", map[string]any{"user": "*", "group": "*"}},
		{"/v1/admin/realms/r/rules/ip", map[string]any{"user": "*", "group": "*", "prefix": "1.2.3.0/24", "action": "deny", "position": 99}},
	} {
		if r := h.Do("POST", c.path, h.AdminKey, c.body); r.Status != 400 || r.Code(t) != "invalid_request" {
			t.Errorf("POST %s %v: %d %s", c.path, c.body, r.Status, r.Body)
		}
	}
	// Reorder must list every rule once.
	ids := []string{}
	for _, r := range h.RulesOf("r", "ip")[1:] {
		ids = append(ids, r["id"].(string))
	}
	if r := h.Do("PUT", "/v1/admin/realms/r/rules/ip/order", h.AdminKey, map[string]any{"ids": ids}); r.Status != 400 {
		t.Errorf("partial order: %d", r.Status)
	}
	// Unknown ids and lists are 404; unknown routes and methods are JSON errors.
	for _, p := range []string{"/v1/admin/clients/00000000-0000-0000-0000-000000000000", "/v1/admin/realms/r/rules/nope",
		"/v1/admin/keys/aaaaaaaaaaaaaaaa", "/v1/admin/entries/not-a-uuid", "/v1/nothing"} {
		if r := h.Do("GET", p, h.AdminKey, nil); r.Status != 404 || r.Code(t) != "not_found" {
			t.Errorf("GET %s: %d %s", p, r.Status, r.Body)
		}
	}
	if r := h.Do("PUT", "/v1/submissions", s.ClientKey, nil); r.Status != 405 || r.Header.Get("Allow") == "" {
		t.Errorf("PUT /v1/submissions: %d", r.Status)
	}

	// Client update and delete: keys go, entries stay with no client.
	id := firstEntryID(submitOK(h, s.ClientKey, sub("p", "8.8.8.8", "1d", "g")))
	upd := h.Admin(200, "PATCH", "/v1/admin/clients/"+s.ClientID, map[string]any{"name": "renamed"})
	if upd["name"] != "renamed" {
		t.Fatalf("patched = %v", upd)
	}
	h.Admin(200, "DELETE", "/v1/admin/clients/"+s.ClientID, nil)
	if n := countRows(h, `SELECT count(*) FROM api_keys WHERE client_id = $1`, s.ClientID); n != 0 {
		t.Fatalf("%d keys left", n)
	}
	if e := adminEntry(h, id); e["client_id"] != nil {
		t.Fatalf("entry client_id = %v", e["client_id"])
	}
	if r := h.Do("GET", "/v1/entries", s.ClientKey, nil); r.Status != 401 {
		t.Fatalf("deleted client's key: %d", r.Status)
	}

	// Admin entry listing with filters and pagination.
	cid := h.CreateClient("again", "r")
	key := h.ClientKey(cid)
	for i := 0; i < 5; i++ {
		submitOK(h, key, sub("pg", "8.8.8."+string(rune('1'+i)), "1d", "g"))
	}
	seen := map[string]bool{}
	cursor := ""
	for pages := 0; pages < 10; pages++ {
		path := "/v1/admin/entries?user=pg&limit=2&worker_id=" + s.WorkerID
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		page := h.Admin(200, "GET", path, nil)
		for _, it := range page["items"].([]any) {
			seen[it.(map[string]any)["id"].(string)] = true
		}
		if page["next_cursor"] == nil {
			break
		}
		cursor = page["next_cursor"].(string)
	}
	if len(seen) != 5 {
		t.Fatalf("paged through %d entries, want 5", len(seen))
	}
	audit := h.Admin(200, "GET", "/v1/admin/audit?action=client.delete", nil)["items"].([]any)
	if len(audit) != 1 {
		t.Fatalf("audit = %v", audit)
	}
	h.Admin(200, "GET", "/v1/admin/health", nil)
}

func TestRemovalOfExpiredEntryAfterSubscriptionDeleted(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("r")
	id := firstEntryID(submitOK(h, s.ClientKey, sub("p", "8.8.8.8", "1d", "g")))
	h.Apply(s.WorkerKey)

	// The entry expires, then the worker's only subscription is deleted before
	// the worker has applied a desired state generated after the expiry.
	h.Exec(`UPDATE entries SET expires_at = now() + interval '300 milliseconds' WHERE id = $1`, id)
	time.Sleep(400 * time.Millisecond)
	subs := h.Admin(200, "GET", "/v1/admin/workers/"+s.WorkerID+"/subscriptions", nil)["items"].([]any)
	h.Admin(200, "DELETE", "/v1/admin/subscriptions/"+subs[0].(map[string]any)["id"].(string), nil)
	if st, per := entryState(h, id); st != "removing" || per["home-r"] != "removing" {
		t.Fatalf("expired, worker no longer matches: %s %v", st, per)
	}
	h.Apply(s.WorkerKey)
	if st, per := entryState(h, id); st != "expired" || per["home-r"] != "expired" {
		t.Fatalf("after the worker confirmed: %s %v", st, per)
	}
}

// TestAdminSubmissions: an admin adds entries in any realm, through the same
// routing and rules as a client; the entries belong to no client, and the
// audit log names the admin key and the person.
func TestAdminSubmissions(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("r")
	h.CreateRealm("other") // no client is bound to it, and no worker subscribes

	post := func(body map[string]any, header ...string) testutil.Resp {
		return h.Do("POST", "/v1/admin/submissions", h.AdminKey, body, header...)
	}
	body := sub("ann", "8.8.8.8", "1d", "g1", "g2")
	body["realm"] = "r"
	r := post(body, "IPValet-On-Behalf-Of", "alice")
	if r.Status != 201 {
		t.Fatalf("admin submission: %d %s", r.Status, r.Body)
	}
	m := r.JSON(t)
	entries := m["entries"].([]any)
	if len(entries) != 2 || m["prefix"] != "8.8.8.8/32" {
		t.Fatalf("response %v", m)
	}
	id := entries[0].(map[string]any)["id"].(string)
	e := adminEntry(h, id)
	if e["client_id"] != nil || e["state"] != "pending" {
		t.Fatalf("entry %v", e)
	}
	audit := h.Admin(200, "GET", "/v1/admin/audit?action=entry.create&realm=r", nil)["items"].([]any)
	if len(audit) != 2 {
		t.Fatalf("audit %v", audit)
	}
	for _, a := range audit {
		a := a.(map[string]any)
		if a["on_behalf_of"] != "alice" || a["client_id"] != nil || a["actor"] == "" {
			t.Fatalf("audit row %v", a)
		}
	}
	// The realm's clients see the entries.
	if list := h.Must(200, "GET", "/v1/entries?user=ann", s.ClientKey, nil)["items"].([]any); len(list) != 2 {
		t.Fatalf("client view %v", list)
	}
	// Submitting again replaces in place.
	r = post(body)
	if r.Status != 201 || !r.JSON(t)["entries"].([]any)[0].(map[string]any)["replaced"].(bool) {
		t.Fatalf("re-submission: %d %s", r.Status, r.Body)
	}

	// The realm's rules apply.
	denied := sub("ann", "10.0.0.1", "1d", "g1")
	denied["realm"] = "r"
	if r := post(denied); r.Status != 422 || r.Code(t) != "submission_rejected" ||
		!strings.Contains(string(r.Body), "ip_denied") {
		t.Fatalf("reserved address: %d %s", r.Status, r.Body)
	}
	long := sub("ann", "8.8.4.4", "31d", "g1")
	long["realm"] = "r"
	if r := post(long); r.Status != 422 || !strings.Contains(string(r.Body), "ttl_exceeded") {
		t.Fatalf("long TTL: %d %s", r.Status, r.Body)
	}
	// So does routing: no worker takes realm other.
	unrouted := sub("ann", "8.8.4.4", "1d", "g1")
	unrouted["realm"] = "other"
	if r := post(unrouted); r.Status != 422 || !strings.Contains(string(r.Body), "no_subscriber") {
		t.Fatalf("unrouted: %d %s", r.Status, r.Body)
	}
	// The realm is required and must exist.
	if r := post(sub("ann", "8.8.4.4", "1d", "g1")); r.Status != 400 || r.Code(t) != "invalid_request" {
		t.Fatalf("no realm: %d %s", r.Status, r.Body)
	}
	missing := sub("ann", "8.8.4.4", "1d", "g1")
	missing["realm"] = "nope"
	if r := post(missing); r.Status != 400 || !strings.Contains(string(r.Body), "no such realm") {
		t.Fatalf("unknown realm: %d %s", r.Status, r.Body)
	}
	// Client keys cannot use it.
	body["realm"] = "r"
	if r := h.Do("POST", "/v1/admin/submissions", s.ClientKey, body); r.Status != 403 {
		t.Fatalf("client key: %d", r.Status)
	}
}

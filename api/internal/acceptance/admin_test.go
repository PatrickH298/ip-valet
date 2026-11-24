package acceptance

import (
	"strings"
	"testing"
	"time"

	"github.com/PatrickH298/ip-valet/api/internal/auth"
	"github.com/PatrickH298/ip-valet/api/internal/testutil"
)

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
	impact := r.JSON(t)["error"].(map[string]any)["impact"].([]any)
	if len(impact) != 2 {
		t.Fatalf("impact = %v", impact)
	}
	for _, it := range impact {
		m := it.(map[string]any)
		if m["effect"] != "ttl_exceeded" || (m["entry_id"] != e1 && m["entry_id"] != e2) {
			t.Fatalf("impact item %v", m)
		}
	}
	if h.RulesOf("r", "ttl")[0]["max_ttl"] != "30d" {
		t.Fatal("rule changed by an unconfirmed request")
	}

	// Dry run: 200 with impact; nothing changes.
	rev := h.Revision()
	dry := h.Admin(200, "PATCH", path+"?dry_run=true", tighten)
	if len(dry["impact"].([]any)) != 2 || dry["max_ttl"] != "1d" {
		t.Fatalf("dry run = %v", dry)
	}
	if h.RulesOf("r", "ttl")[0]["max_ttl"] != "30d" || h.Revision() != rev {
		t.Fatal("dry run changed something")
	}

	// Confirmed and enforced: both shortened, the revision bumped once.
	out := h.Admin(200, "PATCH", path+"?confirm=true&on_existing=enforce", tighten)
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

	// Removal: a deny rule above everything, confirmed with enforce.
	rev = h.Revision()
	out = h.Admin(201, "POST", "/v1/admin/realms/r/rules/ip?confirm=true&on_existing=enforce", map[string]any{
		"user": "*", "group": "*", "prefix": "8.8.0.0/16", "action": "deny", "position": 1})
	if enf := out["enforced"].(map[string]any); enf["removed"].(float64) != 2 {
		t.Fatalf("enforced = %v", out)
	}
	if h.Revision() != rev+1 {
		t.Fatalf("revision %d, want %d", h.Revision(), rev+1)
	}
	for _, id := range []string{e1, e2} {
		if e := adminEntry(h, id); e["deleted_at"] == nil || e["deleted_by"] == nil {
			t.Fatalf("not removed: %v", e)
		}
	}

	// keep (the default) leaves entries alone and does not bump.
	rev = h.Revision()
	out = h.Admin(201, "POST", "/v1/admin/realms/r/rules/ip?confirm=true", map[string]any{
		"user": "*", "group": "*", "prefix": "1.1.1.0/24", "action": "deny", "position": 1})
	if enf := out["enforced"].(map[string]any); enf["removed"].(float64) != 0 || len(out["impact"].([]any)) != 1 {
		t.Fatalf("keep = %v", out)
	}
	if e := adminEntry(h, e3); e["deleted_at"] != nil || h.Revision() != rev {
		t.Fatal("keep changed the entry or the revision")
	}
	// The entry already fails ip_denied, so a further change adds no impact for it.
	h.Admin(201, "POST", "/v1/admin/realms/r/rules/ip", map[string]any{
		"user": "*", "group": "*", "prefix": "1.1.0.0/16", "action": "deny", "position": 1})

	// Caps are reported, never enforced.
	submitOK(h, s.ClientKey, sub("z", "9.9.9.1", "1h", "g"))
	submitOK(h, s.ClientKey, sub("z", "9.9.9.2", "1h", "g"))
	out = h.Admin(201, "POST", "/v1/admin/realms/r/rules/cap?confirm=true&on_existing=enforce", map[string]any{
		"user": "*", "group": "*", "max_prefixes": 1})
	if enf := out["enforced"].(map[string]any); enf["removed"].(float64) != 0 || len(out["impact"].([]any)) != 2 {
		t.Fatalf("cap = %v", out)
	}

	// Subscription deletion goes through the impact check (unrouted).
	subs := h.Admin(200, "GET", "/v1/admin/targets/"+s.TargetID+"/subscriptions", nil)["items"].([]any)
	subPath := "/v1/admin/subscriptions/" + subs[0].(map[string]any)["id"].(string)
	if r := h.Do("DELETE", subPath, h.AdminKey, nil); r.Status != 409 {
		t.Fatalf("subscription delete: %d %s", r.Status, r.Body)
	}
	rev = h.Revision()
	out = h.Admin(200, "DELETE", subPath+"?confirm=true&on_existing=enforce", nil)
	if out["enforced"].(map[string]any)["removed"].(float64) < 1 || h.Revision() != rev+1 {
		t.Fatalf("subscription delete enforced = %v (revision %d -> %d)", out, rev, h.Revision())
	}
	for _, it := range out["impact"].([]any) {
		if it.(map[string]any)["effect"] != "unrouted" {
			t.Fatalf("impact %v", it)
		}
	}
}

func TestTargetFamilyChangeImpact(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("r")
	v6 := firstEntryID(submitOK(h, s.ClientKey, sub("p", "2a00:1450::/64", "1d", "g")))
	submitOK(h, s.ClientKey, sub("p", "8.8.8.8", "1d", "g"))
	path := "/v1/admin/targets/" + s.TargetID
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
	if st, _ := entryState(h, v6); st != "unrouted" {
		t.Fatalf("v6 entry: %s", st)
	}
	if r := h.Do("DELETE", path, h.AdminKey, nil); r.Status != 409 {
		t.Fatalf("target delete: %d", r.Status)
	}
	h.Admin(200, "DELETE", path+"?confirm=true", nil)
}

func TestRealmDeletion(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("doomed")
	h.CreateRealm("kept")
	// A wildcard-realm subscription still matches the realm's entries after the
	// realm-specific one is deleted with the realm.
	wild := h.CreateTarget("wild", true, true)
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
	if st, per := entryState(h, id); st != "removing" || per["wild"] != "removing" {
		t.Fatalf("after realm deletion: %s %v", st, per)
	}
	h.Apply(wk)
	if st, _ := entryState(h, id); st != "removed" {
		t.Fatalf("after the worker confirmed: %s", st)
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

func TestKeySecretShownOnce(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("r")
	created := h.Admin(201, "POST", "/v1/admin/keys", map[string]any{"kind": "client", "client_id": s.ClientID, "name": "once"})
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
	if r := h.Do("POST", "/v1/admin/targets", h.AdminKey, map[string]any{"name": "home-r", "label": "x", "ipv4": true, "ipv6": false}); r.Status != 409 {
		t.Errorf("duplicate target: %d", r.Status)
	}
	if r := h.Do("POST", "/v1/admin/targets/"+s.TargetID+"/subscriptions", h.AdminKey, map[string]any{"realm": "r", "user": "*", "group": "*"}); r.Status != 409 {
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
		{"/v1/admin/targets", map[string]any{"name": "t", "label": "T", "ipv4": false, "ipv6": false}},
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
	upd := h.Admin(200, "PATCH", "/v1/admin/clients/"+s.ClientID, map[string]any{"user_allowlist": []string{"p"}, "name": "renamed"})
	if upd["name"] != "renamed" || len(upd["user_allowlist"].([]any)) != 1 {
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
		path := "/v1/admin/entries?user=pg&limit=2&target_id=" + s.TargetID
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

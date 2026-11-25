package acceptance

import (
	"context"
	"net/netip"
	"testing"

	"github.com/PatrickH298/ip-valet/api/internal/rules"
	"github.com/PatrickH298/ip-valet/api/internal/testutil"
)

// openRealm leaves a realm with only accept-all IP rules and no prefix rule.
func openRealm(h *testutil.Harness, realm string) {
	h.T.Helper()
	h.ClearRules(realm, "ip")
	h.AddRule(realm, "ip", map[string]any{"user": "*", "group": "*", "prefix": "0.0.0.0/0", "action": "accept"})
	h.AddRule(realm, "ip", map[string]any{"user": "*", "group": "*", "prefix": "::/0", "action": "accept"})
	h.ClearRules(realm, "prefix")
}

func TestPrefixNormalisation(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("authentik")
	openRealm(h, s.Realm)

	cases := []struct{ in, want string }{
		{"203.0.113.7/24", "203.0.113.0/24"},
		{"::ffff:203.0.113.7", "203.0.113.7/32"},
		{"::ffff:203.0.113.7/120", "203.0.113.0/24"},
		{"198.51.100.1", "198.51.100.1/32"},
		{"2001:db8::1", "2001:db8::1/128"},
		{"2001:DB8:0:0:1::/80", "2001:db8:0:0:1::/80"},
	}
	for i, c := range cases {
		resp := submitOK(h, s.ClientKey, sub("u"+string(rune('a'+i)), c.in, "1d", "g"))
		want := netip.MustParsePrefix(c.want).String()
		if resp["prefix"] != want {
			t.Errorf("%s: response prefix %v, want %s", c.in, resp["prefix"], want)
		}
		id := firstEntryID(resp)
		var stored string
		if err := h.Pool.QueryRow(context.Background(), `SELECT prefix::text FROM entries WHERE id = $1`, id).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if stored != want {
			t.Errorf("%s: stored %s, want %s", c.in, stored, want)
		}
	}
	for _, bad := range []string{"fe80::1%eth0", "::ffff:0:0/80", "300.1.1.1", "1.2.3.4/33", "", "nonsense"} {
		r := h.Submit(s.ClientKey, sub("x", bad, "1d", "g"))
		if res := results(t, r); res["g"]["code"] != "invalid_prefix" {
			t.Errorf("%q: %v", bad, res["g"])
		}
	}
}

func TestIPRuleOverlapSemantics(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("authentik")
	h.ClearRules(s.Realm, "ip")
	h.ClearRules(s.Realm, "prefix")
	h.AddRule(s.Realm, "ip", map[string]any{"user": "*", "group": "*", "prefix": "10.0.0.0/8", "action": "deny"})
	h.AddRule(s.Realm, "ip", map[string]any{"user": "*", "group": "*", "prefix": "0.0.0.0/0", "action": "accept"})
	ip := h.RulesOf(s.Realm, "ip")
	if len(ip) != 2 || ip[0]["action"] != "deny" || ip[1]["action"] != "accept" {
		t.Fatalf("unexpected rules: %v", ip)
	}
	if res := results(t, h.Submit(s.ClientKey, sub("p", "8.0.0.0/6", "1d", "g"))); res["g"]["code"] != "ip_denied" {
		t.Fatalf("8.0.0.0/6: %v", res["g"])
	}
	submitOK(h, s.ClientKey, sub("p", "1.2.3.4/32", "1d", "g"))
}

func TestIPRulePartialAcceptAndEmptyList(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("authentik")
	h.ClearRules(s.Realm, "ip")
	h.ClearRules(s.Realm, "prefix")

	// Empty list: default deny.
	for _, p := range []string{"1.2.3.4", "2a00:1450::1"} {
		if res := results(t, h.Submit(s.ClientKey, sub("p", p, "1d", "g"))); res["g"]["code"] != "ip_denied" {
			t.Fatalf("empty list %s: %v", p, res["g"])
		}
	}
	h.AddRule(s.Realm, "ip", map[string]any{"user": "*", "group": "*", "prefix": "1.2.3.0/24", "action": "accept"})
	if res := results(t, h.Submit(s.ClientKey, sub("p", "1.2.0.0/16", "1d", "g"))); res["g"]["code"] != "ip_denied" {
		t.Fatalf("partly covered: %v", res["g"])
	}
	submitOK(h, s.ClientKey, sub("p", "1.2.3.128/25", "1d", "g"))
}

func TestFirstMatchWinsAndReorder(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("authentik")
	h.ClearRules(s.Realm, "ip")
	h.ClearRules(s.Realm, "prefix")
	h.ClearRules(s.Realm, "ttl")

	// IP list.
	deny := h.AddRule(s.Realm, "ip", map[string]any{"user": "*", "group": "*", "prefix": "1.2.3.0/24", "action": "deny"})
	acc := h.AddRule(s.Realm, "ip", map[string]any{"user": "*", "group": "*", "prefix": "0.0.0.0/0", "action": "accept"})
	if res := results(t, h.Submit(s.ClientKey, sub("p", "1.2.3.4", "1d", "g"))); res["g"]["code"] != "ip_denied" {
		t.Fatalf("deny first: %v", res["g"])
	}
	h.Admin(200, "PUT", "/v1/admin/realms/"+s.Realm+"/rules/ip/order", map[string]any{"ids": []string{acc["id"].(string), deny["id"].(string)}})
	submitOK(h, s.ClientKey, sub("p", "1.2.3.4", "1d", "g"))

	// TTL list: a user-specific rule above the catch-all.
	short := h.AddRule(s.Realm, "ttl", map[string]any{"user": "patrick", "group": "*", "max_ttl": "1h"})
	long := h.AddRule(s.Realm, "ttl", map[string]any{"user": "*", "group": "*", "max_ttl": "30d"})
	if res := results(t, h.Submit(s.ClientKey, sub("patrick", "5.6.7.8", "2h", "g"))); res["g"]["code"] != "ttl_exceeded" {
		t.Fatalf("ttl first match: %v", res["g"])
	}
	h.Admin(200, "PUT", "/v1/admin/realms/"+s.Realm+"/rules/ttl/order", map[string]any{"ids": []string{long["id"].(string), short["id"].(string)}})
	submitOK(h, s.ClientKey, sub("patrick", "5.6.7.8", "2h", "g"))

	// Prefix list, reordered by PATCHing a position.
	h.AddRule(s.Realm, "prefix", map[string]any{"user": "*", "group": "*", "min_len_v4": 32, "min_len_v6": 64})
	wide := h.AddRule(s.Realm, "prefix", map[string]any{"user": "*", "group": "wide", "min_len_v4": 24, "min_len_v6": 48})
	// The new rule was inserted above the catch-all by default.
	if wide["position"].(float64) != 1 {
		t.Fatalf("default insert position = %v, want 1 (above the catch-all)", wide["position"])
	}
	submitOK(h, s.ClientKey, sub("p", "9.9.9.0/24", "1h", "wide"))
	h.Admin(200, "PATCH", "/v1/admin/realms/"+s.Realm+"/rules/prefix/"+wide["id"].(string)+"?confirm=true", map[string]any{"position": 2})
	if res := results(t, h.Submit(s.ClientKey, sub("q", "9.9.8.0/24", "1h", "wide"))); res["wide"]["code"] != "prefix_too_broad" {
		t.Fatalf("after move: %v", res["wide"])
	}
}

func TestPrefixRuleSeededLimit(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("authentik")
	res := results(t, h.Submit(s.ClientKey, sub("p", "2a00:1450:4001::/48", "1d", "g")))
	g := res["g"]
	if g["code"] != "prefix_too_broad" || g["limit"].(map[string]any)["min_prefix_len"].(float64) != 64 {
		t.Fatalf("got %v", g)
	}
	submitOK(h, s.ClientKey, sub("p", "2a00:1450:4001:1::/64", "1d", "g"))
}

func TestTTLRules(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("authentik")
	g := results(t, h.Submit(s.ClientKey, sub("p", "8.8.8.8", "31d", "g")))["g"]
	if g["code"] != "ttl_exceeded" || g["limit"].(map[string]any)["max_ttl"] != "30d" {
		t.Fatalf("over max: %v", g)
	}
	g = results(t, h.Submit(s.ClientKey, sub("p", "8.8.8.8", "unlimited", "g")))["g"]
	if g["code"] != "ttl_exceeded" {
		t.Fatalf("unlimited under finite max: %v", g)
	}
	submitOK(h, s.ClientKey, sub("p", "8.8.8.8", "30d", "g"))
	h.ClearRules(s.Realm, "ttl")
	resp := submitOK(h, s.ClientKey, sub("p", "8.8.4.4", "unlimited", "g"))
	if e := resp["entries"].([]any)[0].(map[string]any); e["expires_at"] != nil {
		t.Fatalf("unlimited entry has expires_at %v", e["expires_at"])
	}
	// Invalid TTLs are 400.
	for _, bad := range []string{"0s", "1w", "3651d", "1h30m", "-1h", ""} {
		if r := h.Submit(s.ClientKey, sub("p", "8.8.4.4", bad, "g")); r.Status != 400 {
			t.Errorf("ttl %q: %d", bad, r.Status)
		}
	}
}

func TestCapRules(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("authentik")

	// One prefix in three groups counts once.
	h.AddRule(s.Realm, "cap", map[string]any{"user": "*", "group": "*", "max_prefixes": 1})
	submitOK(h, s.ClientKey, sub("alice", "8.8.8.1", "1d", "a", "b", "c"))
	if res := results(t, h.Submit(s.ClientKey, sub("alice", "8.8.8.2", "1d", "a"))); res["a"]["code"] != "cap_exceeded" {
		t.Fatalf("second prefix under cap 1: %v", res["a"])
	}

	// A fourth distinct prefix under a limit of 3 is rejected.
	h.ClearRules(s.Realm, "cap")
	h.AddRule(s.Realm, "cap", map[string]any{"user": "*", "group": "*", "max_prefixes": 3})
	submitOK(h, s.ClientKey, sub("bob", "8.8.8.11", "1d", "a"))
	submitOK(h, s.ClientKey, sub("bob", "8.8.8.12", "1d", "b"))
	submitOK(h, s.ClientKey, sub("bob", "8.8.8.13", "1d", "a"))
	// Re-submitting a held prefix does not add to the count.
	submitOK(h, s.ClientKey, sub("bob", "8.8.8.13", "2d", "a", "b"))
	res := results(t, h.Submit(s.ClientKey, sub("bob", "8.8.8.14", "1d", "c")))
	if res["c"]["code"] != "cap_exceeded" || res["c"]["limit"].(map[string]any)["max_prefixes"].(float64) != 3 {
		t.Fatalf("fourth prefix: %v", res["c"])
	}

	// Entries decided by a different cap rule do not count.
	h.AddRule(s.Realm, "cap", map[string]any{"user": "*", "group": "vip", "max_prefixes": 1, "position": 1})
	submitOK(h, s.ClientKey, sub("carol", "8.8.9.1", "1d", "vip"))
	submitOK(h, s.ClientKey, sub("carol", "8.8.9.2", "1d", "basic"))
	submitOK(h, s.ClientKey, sub("carol", "8.8.9.3", "1d", "basic"))
	submitOK(h, s.ClientKey, sub("carol", "8.8.9.4", "1d", "basic"))
	if res := results(t, h.Submit(s.ClientKey, sub("carol", "8.8.9.5", "1d", "basic"))); res["basic"]["code"] != "cap_exceeded" {
		t.Fatalf("basic over 3: %v", res["basic"])
	}
	if res := results(t, h.Submit(s.ClientKey, sub("carol", "8.8.9.6", "1d", "vip"))); res["vip"]["code"] != "cap_exceeded" {
		t.Fatalf("vip over 1: %v", res["vip"])
	}
	// Expired entries do not count.
	h.Exec(`UPDATE entries SET expires_at = now() - interval '1 second' WHERE username = 'carol' AND grp = 'vip'`)
	submitOK(h, s.ClientKey, sub("carol", "8.8.9.6", "1d", "vip"))
}

func TestRealmSeeding(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, map[string]string{
		"IPVALET_DEFAULT_TTL": "7d", "IPVALET_DEFAULT_PREFIX_V4": "24", "IPVALET_DEFAULT_PREFIX_V6": "56"})
	h.CreateRealm("seeded")
	ip := h.RulesOf("seeded", "ip")
	want := append(append(append([]string{}, rules.ReservedV4...), rules.ReservedV6...), "0.0.0.0/0", "::/0")
	if len(ip) != 27 {
		t.Fatalf("%d IP rules, want 27", len(ip))
	}
	for i, r := range ip {
		action := "deny"
		if i >= 25 {
			action = "accept"
		}
		if r["prefix"] != want[i] || r["action"] != action || r["position"].(float64) != float64(i+1) ||
			r["user"] != "*" || r["group"] != "*" || r["description"] != "seeded default" {
			t.Errorf("IP rule %d = %v, want %s %s", i+1, r, action, want[i])
		}
	}
	p := h.RulesOf("seeded", "prefix")
	if len(p) != 1 || p[0]["min_len_v4"].(float64) != 24 || p[0]["min_len_v6"].(float64) != 56 {
		t.Errorf("prefix rules = %v", p)
	}
	ttl := h.RulesOf("seeded", "ttl")
	if len(ttl) != 1 || ttl[0]["max_ttl"] != "7d" {
		t.Errorf("TTL rules = %v", ttl)
	}
	if c := h.RulesOf("seeded", "cap"); len(c) != 0 {
		t.Errorf("cap rules = %v", c)
	}
	// Changing the defaults later does not alter existing rules: a second instance with
	// other defaults seeds new realms only.
	inst := testutil.StartInstance(t, testutil.Config(t, h.DBURL, map[string]string{"IPVALET_DEFAULT_TTL": "1d"}))
	testutil.DoURL(t, httpClient(), inst.URL, "POST", "/v1/admin/realms", h.AdminKey, map[string]any{"name": "later"})
	if ttl := h.RulesOf("seeded", "ttl"); ttl[0]["max_ttl"] != "7d" {
		t.Errorf("existing realm changed: %v", ttl)
	}
	if ttl := h.RulesOf("later", "ttl"); ttl[0]["max_ttl"] != "1d" {
		t.Errorf("new realm: %v", ttl)
	}
}

func TestWarnings(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("authentik")

	// A rule placed after the IPv4 catch-all is shadowed, but still created.
	r := h.Admin(201, "POST", "/v1/admin/realms/"+s.Realm+"/rules/ip", map[string]any{
		"user": "patrick", "group": "*", "prefix": "1.2.3.0/24", "action": "deny", "position": 27})
	found := false
	for _, w := range r["warnings"].([]any) {
		m := w.(map[string]any)
		if m["code"] == "rule_shadowed" && m["rule_id"] == r["id"] {
			found = true
		}
	}
	if !found {
		t.Fatalf("no rule_shadowed warning: %v", r["warnings"])
	}
	// A rule above the catch-all is not.
	r = h.Admin(201, "POST", "/v1/admin/realms/"+s.Realm+"/rules/ip", map[string]any{
		"user": "patrick", "group": "*", "prefix": "1.2.4.0/24", "action": "deny"})
	for _, w := range r["warnings"].([]any) {
		if w.(map[string]any)["rule_id"] == r["id"] {
			t.Fatalf("unexpected warning: %v", w)
		}
	}

	sr := h.Admin(201, "POST", "/v1/admin/workers/"+s.WorkerID+"/subscriptions", map[string]any{
		"realm": "*", "user": "patrick", "group": "*"})
	ws := sr["warnings"].([]any)
	if len(ws) != 1 || ws[0].(map[string]any)["code"] != "cross_realm_selector" {
		t.Fatalf("subscription warnings = %v", ws)
	}
	sr = h.Admin(201, "POST", "/v1/admin/workers/"+s.WorkerID+"/subscriptions", map[string]any{
		"realm": "*", "user": "*", "group": "*"})
	if ws := sr["warnings"].([]any); len(ws) != 0 {
		t.Fatalf("realm * with user * warned: %v", ws)
	}
}

package e2e

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Two rules: staff go to office (whose own TTL rule allows staff 1 day),
// vpn-users go to vpn for a week by one click, 30 days at most, and may
// enter addresses (vpn caps each user at 2 addresses).
func rulesEnv(extra map[string]string) map[string]string {
	m := map[string]string{
		"IPVALET_SSO_RULE_STAFF": "group=staff realm=office max_ttl=7d",
		"IPVALET_SSO_RULE_VPN":   "group=vpn-users realm=vpn max_ttl=30d ttl=7d manual=yes",
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func with(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// detect asks the detection endpoint, as the page's script does, from addr.
func detect(t *testing.T, s site, token, addr string) map[string]string {
	t.Helper()
	req, _ := http.NewRequest("GET", s.detect+"?t="+url.QueryEscape(token), nil)
	req.Header.Set("Origin", s.base)
	req.Header.Set("X-Forwarded-For", addr)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != s.base {
		t.Fatalf("Access-Control-Allow-Origin %q, want %q", got, s.base)
	}
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	out["status"] = resp.Status
	return out
}

func TestRegisterAndRevoke(t *testing.T) {
	if env.skip != "" {
		t.Skip(env.skip)
	}
	idp := newFakeOIDC(t)
	s := startSite(t, with(idp.env(), rulesEnv(nil)))
	idp.signInAs("ann", "staff", "vpn-users", "unrelated")
	b := newBrowser(t, "8.8.8.8")

	// Visiting signs in through the IdP and lands on the page, which shows
	// the connection's address and asks the IPv6-only host for the other.
	home := b.get(s.base + "/")
	if home.status != 200 || !strings.HasPrefix(home.url, s.base) {
		t.Fatalf("%d %s", home.status, home.url)
	}
	mustContain(t, home, "Your addresses", "ann", "8.8.8.8", `data-detect-url="`+s.detect+`"`,
		"Registers them in office for 7 days and in vpn for 7 days.", "Enter an address", "You have no registered addresses",
		"vpn : one click keeps addresses for 7 days; you may also enter addresses, kept for up to 30 days.")

	got := detect(t, s, detectToken(t, home), "2a00:1450:4001:80b::1234")
	if got["family"] != "ipv6" || got["address"] != "2a00:1450:4001:80b::1234" || got["proof"] == "" {
		t.Fatalf("detect: %v", got)
	}

	// One click registers both addresses in both realms. office's own TTL
	// rule allows staff only a day, so office is asked again for that.
	p := b.post(s.base+"/register", s.base, url.Values{"subnet_v4": {"32"}, "subnet_v6": {"64"}, "proof": {got["proof"]}})
	mustContain(t, p, "Registered", "8.8.8.8/32 in office, until", "(for 1 day, the longest office allows)",
		"8.8.8.8/32 in vpn, until", "2a00:1450:4001:80b::/64 in office", "2a00:1450:4001:80b::/64 in vpn")
	es := entries(t, "ann")
	if len(es) != 4 {
		t.Fatalf("%d entries: %v", len(es), es)
	}
	for _, e := range es {
		exp, _ := time.Parse(time.RFC3339, e["expires_at"].(string))
		left := time.Until(exp)
		want := 7 * 24 * time.Hour
		if e["realm"] == "office" {
			want = 24 * time.Hour
		}
		if left > want || left < want-time.Hour || e["group"] != map[string]string{"office": "staff", "vpn": "vpn-users"}[e["realm"].(string)] {
			t.Fatalf("entry %v: %s left", e, left)
		}
	}
	mustContain(t, p, "8.8.8.8/32", "2a00:1450:4001:80b::/64", "Revoke")

	// Manual entry: vpn caps ann at 2 addresses, which she has.
	p = b.post(s.base+"/register/manual", s.base, url.Values{"address": {"1.1.1.1"}, "ttl": {"30d"}})
	mustContain(t, p, "Nothing was registered", "1.1.1.1/32 in vpn: You already have the most addresses vpn allows (2). Revoke one below")
	// The site's own limits come first.
	p = b.post(s.base+"/register/manual", s.base, url.Values{"address": {"1.1.0.0/16"}, "ttl": {"1d"}})
	mustContain(t, p, "IPv4 subnets may be at most /24 here; /16 is wider.")
	p = b.post(s.base+"/register/manual", s.base, url.Values{"address": {"1.1.1.1"}, "ttl": {"90d"}})
	mustContain(t, p, "Choose how long to keep the address, up to 30 days.")
	p = b.post(s.base+"/register/manual", s.base, url.Values{"address": {"not an address"}, "ttl": {"1d"}})
	mustContain(t, p, "not an address is not an address.")

	// Revoking an address removes it everywhere, which frees a place.
	p = b.post(s.base+"/revoke", s.base, url.Values{"prefix": {"8.8.8.8/32"}})
	mustContain(t, p, "Revoked 8.8.8.8/32 from office and vpn.")
	mustNotContain(t, p, "8.8.8.8/32 office")
	p = b.post(s.base+"/register/manual", s.base, url.Values{"address": {"1.1.1.1"}, "ttl": {"3d"}})
	mustContain(t, p, "Registered", "1.1.1.1/32 in vpn, until")
	mustNotContain(t, p, "1.1.1.1/32 in office")
	p = b.post(s.base+"/revoke", s.base, url.Values{"prefix": {"8.8.8.8/32"}})
	mustContain(t, p, "Nothing was revoked", "8.8.8.8/32 is not registered for you.")

	// A subnet the site allows but the realms do not (/32 is their limit).
	p = b.post(s.base+"/register", s.base, url.Values{"subnet_v4": {"28"}})
	mustContain(t, p, "Nothing was registered", "8.8.8.0/28 in office: office accepts IPv4 subnets no wider than /32. Choose /32 or narrower.")

	// Signing out ends the session.
	p = b.post(s.base+"/logout", s.base, nil)
	mustContain(t, p, "Signed out")
}

func TestNoAccess(t *testing.T) {
	if env.skip != "" {
		t.Skip(env.skip)
	}
	idp := newFakeOIDC(t)
	s := startSite(t, with(idp.env(), rulesEnv(nil)))
	idp.signInAs("eve", "guests")
	b := newBrowser(t, "8.8.8.8")
	p := b.get(s.base + "/")
	if p.status != http.StatusForbidden {
		t.Fatalf("%d", p.status)
	}
	mustContain(t, p, "No access", "You are signed in as eve, but your account is not allowed to register addresses here.")
	// No session was made: posting is sent to sign in again, and refused again.
	p = b.post(s.base+"/register", s.base, url.Values{})
	if p.status != http.StatusForbidden {
		t.Fatalf("%d", p.status)
	}
}

func TestUserRuleAndUserinfoGroups(t *testing.T) {
	if env.skip != "" {
		t.Skip(env.skip)
	}
	idp := newFakeOIDC(t)
	idp.mu.Lock()
	idp.groupsInUserinfo = true
	idp.mu.Unlock()
	s := startSite(t, with(idp.env(), rulesEnv(map[string]string{
		"IPVALET_SSO_RULE_BOSS": "user=boss realm=office as=management max_ttl=unlimited ttl=12h",
	})))
	// Groups only in userinfo still count.
	idp.signInAs("carl", "vpn-users")
	b := newBrowser(t, "9.9.9.9")
	p := b.get(s.base + "/")
	mustContain(t, p, "Registers them in vpn for 7 days.")
	mustNotContain(t, p, "office")
	// A user rule needs no group; its entries carry the rule's group.
	idp.signInAs("boss")
	b = newBrowser(t, "9.9.9.10")
	p = b.get(s.base + "/")
	mustContain(t, p, "office for 12 hours.", "one click keeps addresses for 12 hours.")
	mustNotContain(t, p, "Enter an address")
	p = b.post(s.base+"/register", s.base, url.Values{})
	mustContain(t, p, "9.9.9.10/32 in office")
	if es := entries(t, "boss"); len(es) != 1 || es[0]["group"] != "management" {
		t.Fatalf("%v", es)
	}
}

func TestDetectionProofs(t *testing.T) {
	if env.skip != "" {
		t.Skip(env.skip)
	}
	idp := newFakeOIDC(t)
	s := startSite(t, with(idp.env(), rulesEnv(nil)))
	idp.signInAs("dora", "vpn-users")
	dora := newBrowser(t, "8.8.4.4")
	home := dora.get(s.base + "/")
	if got := detect(t, s, "forged", "2a00:1450:4001:80b::1"); got["status"] != "403 Forbidden" || got["proof"] != "" {
		t.Fatalf("forged token: %v", got)
	}
	// Someone else's proof is no use: it is tied to their session.
	idp.signInAs("finn", "vpn-users")
	finn := newBrowser(t, "8.8.4.5")
	finnsProof := detect(t, s, detectToken(t, finn.get(s.base+"/")), "2a00:1450:4001:80b::5")["proof"]
	p := dora.post(s.base+"/register", s.base, url.Values{"proof": {finnsProof, "garbage"}})
	mustContain(t, p, "8.8.4.4/32 in vpn", "An address detected earlier had expired and was left out.")
	mustNotContain(t, p, "2a00:1450:4001:80b::")
	// Dora's own proof works.
	proof := detect(t, s, detectToken(t, home), "2a00:1450:4001:80b::4")["proof"]
	p = dora.post(s.base+"/register", s.base, url.Values{"proof": {proof}})
	mustContain(t, p, "2a00:1450:4001:80b::/64 in vpn")
}

func TestCrossSiteAndUntrustedProxies(t *testing.T) {
	if env.skip != "" {
		t.Skip(env.skip)
	}
	idp := newFakeOIDC(t)
	s := startSite(t, with(idp.env(), rulesEnv(map[string]string{"IPVALET_SSO_TRUSTED_PROXIES": "none"})))
	idp.signInAs("gus", "vpn-users")
	b := newBrowser(t, "8.8.8.8")
	home := b.get(s.base + "/")
	// With no trusted proxy, X-Forwarded-For is ignored: the address is the
	// connection's own, which the realm's IP rules refuse.
	mustContain(t, home, "127.0.0.1")
	mustNotContain(t, home, "8.8.8.8")
	p := b.post(s.base+"/register", s.base, url.Values{})
	mustContain(t, p, "127.0.0.1/32 in vpn: vpn does not accept this address.")
	// A form posted from another site is refused.
	p = b.post(s.base+"/register", "https://evil.example", url.Values{})
	if p.status != http.StatusForbidden {
		t.Fatalf("%d", p.status)
	}
	mustContain(t, p, "Request refused")
}

// Two rules for one realm: the most permissive wins, once.
func TestSameRealmMostPermissive(t *testing.T) {
	if env.skip != "" {
		t.Skip(env.skip)
	}
	idp := newFakeOIDC(t)
	s := startSite(t, with(idp.env(), map[string]string{
		"IPVALET_SSO_RULE_USERS":  "group=users realm=office max_ttl=12h",
		"IPVALET_SSO_RULE_ADMINS": "group=admins realm=office max_ttl=24h manual=yes",
	}))
	idp.signInAs("patrick", "users", "admins")
	b := newBrowser(t, "8.8.8.9")
	p := b.get(s.base + "/")
	mustContain(t, p, "Registers them in office for 1 day.", "Enter an address",
		"office : one click keeps addresses for 1 day; you may also enter addresses, kept for up to 1 day.")
	p = b.post(s.base+"/register", s.base, url.Values{})
	mustContain(t, p, "Registered", "8.8.8.9/32 in office, until")
	es := entries(t, "patrick")
	if len(es) != 1 || es[0]["group"] != "admins" {
		t.Fatalf("want one entry in admins: %v", es)
	}
	exp, _ := time.Parse(time.RFC3339, es[0]["expires_at"].(string))
	if left := time.Until(exp); left > 24*time.Hour || left < 23*time.Hour {
		t.Fatalf("%s left", left)
	}
	p = b.post(s.base+"/register/manual", s.base, url.Values{"address": {"1.0.0.1"}, "ttl": {"1d"}})
	mustContain(t, p, "1.0.0.1/32 in office, until")

	// A member of users alone gets that rule: 12 hours, no manual entry.
	idp.signInAs("uma", "users")
	b = newBrowser(t, "8.8.8.10")
	p = b.get(s.base + "/")
	mustContain(t, p, "Registers them in office for 12 hours.")
	mustNotContain(t, p, "Enter an address")
	p = b.post(s.base+"/register/manual", s.base, url.Values{"address": {"1.0.0.2"}, "ttl": {"1h"}})
	if p.status != http.StatusForbidden {
		t.Fatalf("manual entry without a manual rule: %d", p.status)
	}
}

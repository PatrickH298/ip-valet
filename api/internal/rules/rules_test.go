package rules

import (
	"net/netip"
	"testing"
	"time"
)

func TestNormalizePrefix(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7/24":         "203.0.113.0/24",
		"::ffff:203.0.113.7":     "203.0.113.7/32",
		"::ffff:203.0.113.7/112": "203.0.0.0/16",
		"::ffff:0:0/96":          "0.0.0.0/0",
		"198.51.100.1":           "198.51.100.1/32",
		"2001:db8::1":            "2001:db8::1/128",
		"2001:DB8::/32":          "2001:db8::/32",
		"0.0.0.0/0":              "0.0.0.0/0",
	}
	for in, want := range cases {
		got, err := NormalizePrefix(in)
		if err != nil || got.String() != want {
			t.Errorf("%s: got %v %v, want %s", in, got, err, want)
		}
	}
	for _, bad := range []string{"fe80::1%eth0", "fe80::%eth0/64", "::ffff:0:0/80", "1.2.3.4/33", "01.2.3.4", "x", ""} {
		if _, err := NormalizePrefix(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParseTTL(t *testing.T) {
	ok := map[string]int64{"3600s": 3600, "90m": 5400, "36h": 129600, "30d": 2592000, "3650d": MaxTTLSeconds}
	for in, want := range ok {
		got, err := ParseTTL(in)
		if err != nil || got.Seconds != want || got.Unlimited {
			t.Errorf("%s: %+v %v", in, got, err)
		}
	}
	if got, err := ParseTTL("unlimited"); err != nil || !got.Unlimited {
		t.Errorf("unlimited: %+v %v", got, err)
	}
	for _, bad := range []string{"0s", "3651d", "87601h", "1h30m", "1w", "-1d", "1.5h", "", " 1d", "1D"} {
		if _, err := ParseTTL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for secs, want := range map[int64]string{86400: "1d", 3600: "1h", 5400: "90m", 61: "61s", 172800: "2d"} {
		if got := FormatSeconds(secs); got != want {
			t.Errorf("FormatSeconds(%d) = %s, want %s", secs, got, want)
		}
	}
}

func TestNames(t *testing.T) {
	for _, s := range []string{"authentik", "a", "a.b_c-d", "0"} {
		if !ValidRealm(s) {
			t.Errorf("realm %q rejected", s)
		}
	}
	for _, s := range []string{"", "A", "-a", "a b", "*", string(make([]byte, 64))} {
		if ValidRealm(s) {
			t.Errorf("realm %q accepted", s)
		}
	}
	for _, s := range []string{"Patrick", "a b", "ü", "x*"} {
		if !ValidIdent(s) {
			t.Errorf("ident %q rejected", s)
		}
	}
	long := make([]rune, 257)
	for i := range long {
		long[i] = 'é'
	}
	for _, s := range []string{"", "*", "a\nb", "\x7f", string(long), string(long[:256]) + "x"} {
		if ValidIdent(s) {
			t.Errorf("ident %q accepted", s)
		}
	}
	if !ValidIdent(string(long[:256])) {
		t.Error("256 runes rejected")
	}
}

func ipRule(prefix, action string, user *string) IPRule {
	return IPRule{Base: Base{Realm: "r", User: user}, Prefix: netip.MustParsePrefix(prefix), Action: action}
}

func subj(prefix string) Subject {
	return Subject{Realm: "r", User: "u", Group: "g", Prefix: netip.MustParsePrefix(prefix)}
}

func TestCheckIP(t *testing.T) {
	s := Set{IP: []IPRule{ipRule("10.0.0.0/8", ActionDeny, nil), ipRule("0.0.0.0/0", ActionAccept, nil)}}
	if f := s.CheckIP(subj("8.0.0.0/6")); f == nil || f.Code != CodeIPDenied {
		t.Error("8.0.0.0/6 accepted")
	}
	if f := s.CheckIP(subj("1.2.3.4/32")); f != nil {
		t.Error("1.2.3.4 rejected")
	}
	if f := s.CheckIP(subj("2001:db8::/64")); f == nil {
		t.Error("IPv6 accepted by IPv4 rules")
	}
	partial := Set{IP: []IPRule{ipRule("1.2.3.0/24", ActionAccept, nil)}}
	if f := partial.CheckIP(subj("1.2.0.0/16")); f == nil {
		t.Error("partly covered prefix accepted")
	}
	if f := (&Set{}).CheckIP(subj("1.2.3.4/32")); f == nil {
		t.Error("empty list accepted")
	}
	other := "someone"
	sel := Set{IP: []IPRule{ipRule("0.0.0.0/0", ActionDeny, &other), ipRule("0.0.0.0/0", ActionAccept, nil)}}
	if f := sel.CheckIP(subj("1.2.3.4/32")); f != nil {
		t.Error("a rule for another user decided")
	}
}

func TestCheckCap(t *testing.T) {
	vip := "vip"
	s := Set{Cap: []CapRule{
		{Base: Base{Realm: "r", Group: &vip}, MaxPrefixes: 1},
		{Base: Base{Realm: "r"}, MaxPrefixes: 2},
	}}
	held := []Held{
		{Group: "vip", Prefix: netip.MustParsePrefix("9.9.9.1/32")},
		{Group: "g", Prefix: netip.MustParsePrefix("9.9.9.2/32")},
		{Group: "h", Prefix: netip.MustParsePrefix("9.9.9.2/32")},
	}
	if f := s.CheckCap(subj("9.9.9.3/32"), held); f != nil {
		t.Errorf("second distinct prefix under the */* rule rejected: %+v", f)
	}
	held = append(held, Held{Group: "g", Prefix: netip.MustParsePrefix("9.9.9.3/32")})
	if f := s.CheckCap(subj("9.9.9.4/32"), held); f == nil || *f.Limit.MaxPrefixes != 2 {
		t.Errorf("third distinct prefix accepted: %+v", f)
	}
	if f := s.CheckCap(subj("9.9.9.2/32"), held); f != nil {
		t.Error("re-submitting a held prefix counted twice")
	}
}

func TestRemainingTTL(t *testing.T) {
	day := int64(86400)
	s := Set{TTL: []TTLRule{{Base: Base{Realm: "r"}, MaxTTLSeconds: &day}}}
	now := time.Now()
	in2d := now.Add(48 * time.Hour)
	in1h := now.Add(time.Hour)
	if f := s.CheckRemainingTTL(subj("1.1.1.1/32"), &in2d, now); f == nil || f.MaxTTLSeconds != day {
		t.Error("2d remaining under a 1d max accepted")
	}
	if f := s.CheckRemainingTTL(subj("1.1.1.1/32"), &in1h, now); f != nil {
		t.Error("1h remaining rejected")
	}
	if f := s.CheckRemainingTTL(subj("1.1.1.1/32"), nil, now); f == nil {
		t.Error("unlimited accepted under a finite max")
	}
}

func TestShadowAndInsertPosition(t *testing.T) {
	p := func(s string) *netip.Prefix { x := netip.MustParsePrefix(s); return &x }
	u := "u"
	list := []Item{
		{ID: "a", Prefix: p("10.0.0.0/8")},
		{ID: "b", Prefix: p("0.0.0.0/0")},
		{ID: "c", Prefix: p("::/0")},
		{ID: "d", User: &u, Prefix: p("10.1.0.0/16")},
		{ID: "e", User: &u, Prefix: p("2001:db8::/32")},
	}
	w := ShadowWarnings(list)
	if len(w) != 2 || w[0].RuleID != "d" || w[0].ShadowedBy != "a" || w[1].RuleID != "e" || w[1].ShadowedBy != "c" {
		t.Fatalf("warnings = %+v", w)
	}
	if got := DefaultInsertPosition(list); got != 2 {
		t.Fatalf("insert position %d, want 2", got)
	}
	if got := DefaultInsertPosition(list[:1]); got != 2 {
		t.Fatalf("no catch-all: insert position %d, want 2", got)
	}
	if ShadowWarnings([]Item{{ID: "x", User: &u}, {ID: "y"}}) != nil {
		t.Fatal("specific rule shadows a broader one")
	}
	seed := Seed("r", SeedDefaults{TTLSeconds: 1, PrefixV4: 32, PrefixV6: 64})
	items := make([]Item, len(seed.IP))
	for i := range seed.IP {
		items[i] = Item{User: seed.IP[i].User, Group: seed.IP[i].Group, Prefix: &seed.IP[i].Prefix}
	}
	if w := ShadowWarnings(items); w != nil {
		t.Fatalf("seeded rules shadow each other: %+v", w)
	}
	if DefaultInsertPosition(items) != 26 {
		t.Fatal("seeded catch-all not at 26")
	}
}

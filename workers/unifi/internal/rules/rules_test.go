package rules

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	r, err := Parse("OFFICE", `realm=home user="Zoë Smith" group=fwusers family=both addresses=Both ipv4_list=office-v4 ipv6_list=office-v6`)
	if err != nil {
		t.Fatal(err)
	}
	want := Rule{Name: "OFFICE", Realm: "home", User: "Zoë Smith", Group: "fwusers", Family: "both", Addresses: "both",
		IPv4List: "office-v4", IPv6List: "office-v6"}
	if r != want {
		t.Fatalf("%+v", r)
	}
	r, err = Parse("V4", "realm=home family=ipv4 ipv4_list=a")
	if err != nil || r.User != "*" || r.Group != "*" || r.Addresses != "public" {
		t.Fatalf("defaults: %+v %v", r, err)
	}
	for in, want := range map[string]string{
		"":                                "realm is required",
		"realm=* ipv4_list=a ipv6_list=b": "* is not allowed",
		"realm=r":                         "ipv4_list is required",
		"realm=r family=ipv6 ipv6_list=b ipv4_list=a":   "ipv4_list is set",
		"realm=r family=v4 ipv4_list=a":                 "family must be",
		"realm=r addresses=all ipv4_list=a ipv6_list=b": "addresses must be",
		"realm=r color=red":                             "unknown key",
		"realm=r realm=s":                               "given twice",
		`realm=r user="open`:                            "unterminated quote",
		"just words":                                    "key=value",
	} {
		if _, err := Parse("X", in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%q) = %v, want %q", in, err, want)
		}
	}
}

func TestClassify(t *testing.T) {
	for in, want := range map[string]Kind{
		"8.8.8.8/32":     Public,
		"8.8.8.0/24":     Public,
		"2a00:1450::/64": Public,
		"10.1.2.3/32":    Private,
		"192.168.0.0/16": Private,
		"100.64.1.1/32":  Private,
		"fd12:3456::/64": Private,
		"127.0.0.1/32":   Never,
		"169.254.1.1/32": Never,
		"192.0.2.1/32":   Never,
		"224.0.0.1/32":   Never,
		"fe80::1/128":    Never,
		"2001:db8::/32":  Never,
		"0.0.0.0/0":      Never,  // spans reserved space
		"8.0.0.0/7":      Public, // 8.0.0.0-9.255.255.255
		"8.0.0.0/6":      Never,
		"::/0":           Never,
	} {
		if got := Classify(netip.MustParsePrefix(in)); got != want {
			t.Errorf("Classify(%s) = %v, want %v", in, got, want)
		}
	}
}

func entry(prefix, realm, user, group string, exp *time.Time) Entry {
	return Entry{Prefix: netip.MustParsePrefix(prefix), Realm: realm, User: user, Group: group, ExpiresAt: exp}
}

func TestBuild(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	past, soon, later := now.Add(-time.Minute), now.Add(time.Hour), now.Add(2*time.Hour)
	mustRule := func(name, s string) Rule {
		r, err := Parse(name, s)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	rules := []Rule{
		mustRule("STAFF", "realm=home group=staff ipv4_list=staff4 ipv6_list=staff6"),
		mustRule("ALL", "realm=home ipv4_list=all4 family=ipv4"),
		mustRule("LAB", "realm=lab addresses=private ipv4_list=lab4 ipv6_list=lab6"),
	}
	entries := []Entry{
		entry("8.8.8.8/32", "home", "ann", "staff", &later),     // STAFF + ALL
		entry("8.8.8.8/32", "home", "bob", "guests", &soon),     // ALL again (deduplicated)
		entry("2a00:1450::/64", "home", "ann", "staff", nil),    // STAFF v6
		entry("2a00:1450:1::/64", "home", "bob", "guests", nil), // ALL is ipv4 only
		entry("9.9.9.9/32", "home", "cat", "staff", &past),      // expired: ignored
		entry("10.0.0.5/32", "lab", "dan", "x", nil),            // LAB private
		entry("1.1.1.1/32", "lab", "dan", "x", nil),             // LAB takes private only
		entry("1.0.0.1/32", "other", "eve", "x", nil),           // no rule
		entry("127.0.0.1/32", "home", "ann", "staff", nil),      // reserved
		entry("8.8.0.0/16", "home", "ann", "staff", nil),        // too broad
	}
	plan := Build(entries, rules, Floor{MinV4: 24, MinV6: 48}, now)
	lists := map[string]string{}
	for k, ps := range plan.Lists {
		var s []string
		for _, p := range ps {
			s = append(s, p.String())
		}
		lists[k] = strings.Join(s, ",")
	}
	for k, want := range map[string]string{
		"staff4": "8.8.8.8/32", "staff6": "2a00:1450::/64", "all4": "8.8.8.8/32",
		"lab4": "10.0.0.5/32", "lab6": "",
	} {
		if got, ok := lists[k]; !ok || got != want {
			t.Errorf("list %s = %q (present %v), want %q", k, got, ok, want)
		}
	}
	got := map[string]string{}
	for _, r := range plan.Rejections {
		got[r.Prefix.String()] = r.Code
		if len(r.Detail) == 0 || len(r.Detail) > 200 {
			t.Errorf("detail %q", r.Detail)
		}
	}
	want := map[string]string{
		"2a00:1450:1::/64": "family_unsupported",
		"1.1.1.1/32":       "address_not_allowed",
		"1.0.0.1/32":       "no_matching_rule",
		"127.0.0.1/32":     "address_not_allowed",
		"8.8.0.0/16":       "prefix_too_broad",
	}
	if len(got) != len(want) {
		t.Fatalf("rejections %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("rejection %s = %q, want %q", k, got[k], v)
		}
	}
	if plan.NextExpiry == nil || !plan.NextExpiry.Equal(soon) {
		t.Errorf("next expiry %v, want %v", plan.NextExpiry, soon)
	}
	// A prefix that one entry places is not rejected because of another.
	plan = Build([]Entry{entry("8.8.4.4/32", "other", "x", "y", nil), entry("8.8.4.4/32", "home", "x", "staff", nil)},
		rules, Floor{MinV4: 24, MinV6: 48}, now)
	if len(plan.Rejections) != 0 {
		t.Fatalf("rejections %v", plan.Rejections)
	}
}

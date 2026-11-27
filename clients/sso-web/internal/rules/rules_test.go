package rules

import (
	"strings"
	"testing"
)

func mustParse(t *testing.T, name, s string) Rule {
	t.Helper()
	r, err := Parse(name, s)
	if err != nil {
		t.Fatalf("%s: %v", s, err)
	}
	return r
}

func TestParse(t *testing.T) {
	r := mustParse(t, "STAFF", `group=staff realm=office max_ttl=12h`)
	if r.Realm != "office" || r.User != "*" || r.Group != "staff" || r.As != "" || r.Manual {
		t.Fatalf("%+v", r)
	}
	if r.MaxTTL.String() != "12h" || r.TTL.String() != "12h" {
		t.Fatalf("ttl defaults to max_ttl: %v %v", r.MaxTTL, r.TTL)
	}
	r = mustParse(t, "ME", `user="Zoë Smith" realm=home as=owners max_ttl=unlimited ttl=30d manual=yes`)
	if r.User != "Zoë Smith" || r.Group != "*" || r.As != "owners" || !r.MaxTTL.Unlimited || r.TTL.String() != "30d" || !r.Manual {
		t.Fatalf("%+v", r)
	}

	bad := map[string]string{
		``:                                         "realm is required",
		`realm=* max_ttl=1h as=x`:                  "one realm",
		`realm=Office group=a max_ttl=1h`:          "not a realm name",
		`realm=r group=a`:                          "max_ttl is required",
		`realm=r max_ttl=1h`:                       "as is required",
		`realm=r user=bob max_ttl=1h`:              "as is required",
		`realm=r group=a as=* max_ttl=1h`:          "as must be",
		`realm=r group=a max_ttl=1h ttl=2h`:        "longer than max_ttl",
		`realm=r group=a max_ttl=1w`:               "max_ttl",
		`realm=r group=a max_ttl=3651d`:            "at most 3650d",
		`realm=r group=a max_ttl=1h manual=maybe`:  "manual must be",
		`realm=r group=a max_ttl=1h colour=blue`:   "unknown key",
		`realm=r group=a realm=s max_ttl=1h`:       "given twice",
		`realm=r group="unterminated max_ttl=1h`:   "unterminated",
		`realm=r group=a max_ttl=1h ttl=unlimited`: "longer than max_ttl",
		`realm=r group=a max_ttl=1h stray`:         "key=value",
	}
	for in, want := range bad {
		if _, err := Parse("X", in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want an error containing %q", in, err, want)
		}
	}
}

func TestGrants(t *testing.T) {
	rs := []Rule{
		mustParse(t, "A", `group=a realm=realm-a max_ttl=8h`),
		mustParse(t, "B", `group=b realm=realm-b max_ttl=30d ttl=7d manual=yes`),
		mustParse(t, "BOSS", `user=boss realm=realm-a as=management max_ttl=unlimited manual=yes`),
		mustParse(t, "ALL", `realm=lobby as=everyone max_ttl=1h`),
	}
	// A member of a and b gets both realms, plus the any-group rule.
	gs := Grants(rs, Identity{User: "ann", Groups: []string{"a", "b", "z"}})
	if len(gs) != 3 || gs[0].Realm != "lobby" || gs[1].Realm != "realm-a" || gs[2].Realm != "realm-b" {
		t.Fatalf("%+v", gs)
	}
	if gs[0].Group != "everyone" || gs[1].Group != "a" || gs[2].Group != "b" || !gs[2].Manual || gs[1].Manual {
		t.Fatalf("%+v", gs)
	}
	// A user rule applies without groups.
	gs = Grants(rs, Identity{User: "boss"})
	if len(gs) != 2 || gs[1].Group != "management" || !gs[1].MaxTTL.Unlimited {
		t.Fatalf("%+v", gs)
	}
	if got := Realms(Grants(rs, Identity{User: "ann", Groups: []string{"a", "b"}})); strings.Join(got, ",") != "lobby,realm-a,realm-b" {
		t.Fatal(got)
	}
	if len(Manual(Grants(rs, Identity{User: "ann", Groups: []string{"a"}}))) != 0 {
		t.Fatal("manual entry granted without a manual rule")
	}
	// Without the any-group rule, someone who matches nothing gets nothing.
	if gs := Grants(rs[:3], Identity{User: "eve", Groups: []string{"c"}}); len(gs) != 0 {
		t.Fatalf("%+v", gs)
	}
}

// Several rules for one realm give one grant: the most permissive wins.
func TestGrantsSameRealm(t *testing.T) {
	rs := []Rule{
		mustParse(t, "ADMINS", `group=admins realm=office max_ttl=24h manual=yes`),
		mustParse(t, "USERS", `group=users realm=office max_ttl=12h`),
	}
	want := func(gs []Grant, group, maxTTL, ttl string, manual bool, rules string) {
		t.Helper()
		if len(gs) != 1 {
			t.Fatalf("%d grants: %+v", len(gs), gs)
		}
		g := gs[0]
		if g.Realm != "office" || g.Group != group || g.MaxTTL.String() != maxTTL || g.TTL.String() != ttl ||
			g.Manual != manual || strings.Join(g.Rules, ",") != rules {
			t.Fatalf("%+v", g)
		}
	}
	// patrick is in both: 24 hours, manual entry, entries in admins.
	want(Grants(rs, Identity{User: "patrick", Groups: []string{"users", "admins"}}), "admins", "1d", "1d", true, "ADMINS,USERS")
	// Only in users: that rule alone.
	want(Grants(rs, Identity{User: "uma", Groups: []string{"users"}}), "users", "12h", "12h", false, "USERS")

	// Each limit is the most permissive of all the rules, and the group is
	// the one with the longest max_ttl, then manual entry, then ttl, then name.
	rs = []Rule{
		mustParse(t, "LONG", `group=long realm=office max_ttl=30d ttl=1d`),
		mustParse(t, "MANUAL", `group=manual realm=office max_ttl=12h manual=yes`),
		mustParse(t, "LONGTTL", `group=longttl realm=office max_ttl=7d ttl=7d`),
	}
	want(Grants(rs, Identity{User: "x", Groups: []string{"long", "manual", "longttl"}}), "long", "30d", "7d", true, "LONG,LONGTTL,MANUAL")
	want(Grants(rs, Identity{User: "x", Groups: []string{"manual", "longttl"}}), "longttl", "7d", "7d", true, "LONGTTL,MANUAL")
	rs = []Rule{
		mustParse(t, "B", `group=b realm=office max_ttl=7d`),
		mustParse(t, "A", `group=a realm=office max_ttl=7d manual=yes`),
		mustParse(t, "C", `group=c realm=office max_ttl=7d manual=yes`),
	}
	want(Grants(rs, Identity{User: "x", Groups: []string{"a", "b", "c"}}), "a", "7d", "7d", true, "A,C,B")
	// The same group from two rules merges as before.
	rs = []Rule{
		mustParse(t, "B", `group=b realm=office max_ttl=30d ttl=7d manual=yes`),
		mustParse(t, "B2", `group=b2 realm=office as=b max_ttl=90d ttl=1d`),
	}
	want(Grants(rs, Identity{User: "bea", Groups: []string{"b", "b2"}}), "b", "90d", "7d", true, "B2,B")
}

func TestTTL(t *testing.T) {
	for in, want := range map[string]string{"90m": "90m", "120m": "2h", "48h": "2d", "86400s": "1d", "unlimited": "unlimited", " 5d ": "5d"} {
		got, err := ParseTTL(in)
		if err != nil || got.String() != want {
			t.Errorf("%q: %v %v, want %s", in, got, err, want)
		}
	}
	for _, in := range []string{"", "0h", "1w", "-1h", "1.5h", "3651d", "1h30m"} {
		if _, err := ParseTTL(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
	h, d := Seconds(3600), Seconds(86400)
	if !Longer(d, h) || Longer(h, d) || !Longer(Unlimited, d) || Longer(d, Unlimited) || Longer(Unlimited, Unlimited) {
		t.Fatal("Longer")
	}
	if Shortest(Unlimited, h) != h || Longest(h, Unlimited) != Unlimited {
		t.Fatal("Shortest/Longest")
	}
	if Seconds(7200).Human() != "2 hours" || Seconds(86400).Human() != "1 day" || Unlimited.Human() != "no time limit" {
		t.Fatal(Seconds(7200).Human(), Seconds(86400).Human())
	}
}

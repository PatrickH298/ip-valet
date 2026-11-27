package web

import (
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/ipvalet"
	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/rules"
)

func TestSubnets(t *testing.T) {
	if got := subnets(32, 28, 32); len(got) != 5 || got[0] != 32 || got[4] != 28 {
		t.Fatal(got)
	}
	got := subnets(128, 56, 64)
	want := []int{128, 64, 60, 56}
	if len(got) != len(want) {
		t.Fatal(got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatal(got)
		}
	}
	// An unusual default or limit is offered too.
	if got := subnets(128, 50, 62); got[1] != 64 || got[2] != 62 || got[len(got)-1] != 50 {
		t.Fatal(got)
	}
}

func TestTTLOptions(t *testing.T) {
	d30, _ := rules.ParseTTL("30d")
	d7, _ := rules.ParseTTL("7d")
	opts := ttlOptions(d30, d7)
	if opts[0].Value != "1h" || opts[len(opts)-1].Value != "30d" {
		t.Fatalf("%+v", opts)
	}
	selected := 0
	for _, o := range opts {
		if o.Selected {
			selected++
			if o.Value != "7d" {
				t.Fatalf("%+v", o)
			}
		}
	}
	if selected != 1 {
		t.Fatalf("%+v", opts)
	}
	// An odd maximum and unlimited are offered as themselves.
	h36, _ := rules.ParseTTL("36h")
	if opts := ttlOptions(h36, h36); opts[len(opts)-1].Value != "36h" || opts[len(opts)-2].Value != "1d" {
		t.Fatalf("%+v", opts)
	}
	if opts := ttlOptions(rules.Unlimited, d7); opts[len(opts)-1].Label != "no time limit" {
		t.Fatalf("%+v", opts)
	}
}

func TestParseManual(t *testing.T) {
	s := &Server{Options: Options{DefaultSubnetV4: 32, DefaultSubnetV6: 64, MaxSubnetV4: 24, MaxSubnetV6: 48}}
	ok := map[string]string{
		"203.0.113.7":            "203.0.113.7/32",
		" 203.0.113.7/28 ":       "203.0.113.0/28",
		"2001:db8::1":            "2001:db8::/64",
		"2001:db8:1:2::/56":      "2001:db8:1::/56",
		"::ffff:203.0.113.7":     "203.0.113.7/32",
		"::ffff:203.0.113.0/120": "203.0.113.0/24",
	}
	for in, want := range ok {
		p, problem := s.parseManual(in)
		if problem != "" || p.String() != want {
			t.Errorf("%q: %v %q, want %s", in, p, problem, want)
		}
	}
	bad := map[string]string{
		"":               "Enter an address",
		"example.com":    "is not an address",
		"203.0.113.0/16": "IPv4 subnets may be at most /24",
		"2001:db8::/32":  "IPv6 subnets may be at most /48",
		"fe80::1%eth0":   "is not an address",
		"0.0.0.0":        "cannot be registered",
		"ff02::1":        "cannot be registered",
		"203.0.113.0/33": "is not an address or subnet",
	}
	for in, want := range bad {
		if _, problem := s.parseManual(in); !strings.Contains(problem, want) {
			t.Errorf("%q: %q, want %q", in, problem, want)
		}
	}
}

func TestWorkerDetail(t *testing.T) {
	e := ipvalet.Entry{Prefix: "2a00:1450::/64", State: "partial", Workers: []ipvalet.WorkerState{
		{Label: "Home", State: "active"},
		{Label: "Office", State: "rejected", Code: "family_unsupported"},
		{Label: "Lab", State: "rejected", Code: "something_new"},
	}}
	if got := workerDetail(e); got != "Office does not take IPv6 addresses. Lab did not accept it (something_new)." {
		t.Fatal(got)
	}
	e.State = "active"
	if got := workerDetail(e); got != "" {
		t.Fatal(got)
	}
	for code, want := range map[string]string{
		"prefix_too_broad": "does not accept a subnet this wide", "address_not_allowed": "does not accept this kind of address",
		"capacity_exceeded": "is full", "no_matching_rule": "is not set up to take this address",
		"invalid": "could not use this address", "": "did not accept it",
	} {
		if got := workerReason(code, "IPv4"); got != want {
			t.Errorf("%s: %q", code, got)
		}
	}
}

func TestExplain(t *testing.T) {
	s := &Server{Options: Options{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	two, thirtyTwo := 2, 32
	v4 := netip.MustParsePrefix("203.0.113.7/32")
	rejected := func(code string, limit *ipvalet.Limit) error {
		return &ipvalet.Error{Status: 422, Code: "submission_rejected",
			Results: []ipvalet.GroupResult{{Group: "staff", Code: code, Limit: limit}}}
	}
	cases := []struct {
		err  error
		code string
		want string
	}{
		{rejected("cap_exceeded", &ipvalet.Limit{MaxPrefixes: &two}), "cap_exceeded", "the most addresses office allows (2). Revoke one"},
		{rejected("ttl_exceeded", &ipvalet.Limit{MaxTTL: "1d"}), "ttl_exceeded", "office allows addresses for at most 1 day"},
		{rejected("prefix_too_broad", &ipvalet.Limit{MinPrefixLen: &thirtyTwo}), "prefix_too_broad", "IPv4 subnets no wider than /32"},
		{rejected("ip_denied", nil), "ip_denied", "office does not accept this address"},
		{rejected("no_subscriber", nil), "no_subscriber", "Nothing in office uses IPv4 addresses yet"},
		{&ipvalet.Error{Status: 403, Code: "realm_not_allowed"}, "realm_not_allowed", "may not register addresses in office"},
		{&ipvalet.Error{Status: 401, Code: "unauthorized"}, "unauthorized", "cannot use the registration service"},
		{&ipvalet.Error{Status: 0, Err: io.EOF}, "unavailable", "unavailable right now"},
		{&ipvalet.Error{Status: 503, Code: "unavailable"}, "unavailable", "unavailable right now"},
	}
	for _, tc := range cases {
		code, msg := s.explain(tc.err, "office", v4)
		if code != tc.code || !strings.Contains(msg, tc.want) {
			t.Errorf("%v: %s %q, want %s %q", tc.err, code, msg, tc.code, tc.want)
		}
	}
	if limit, ok := ttlLimit(rejected("ttl_exceeded", &ipvalet.Limit{MaxTTL: "12h"})); !ok || limit.String() != "12h" {
		t.Fatal(limit, ok)
	}
	if _, ok := ttlLimit(rejected("cap_exceeded", nil)); ok {
		t.Fatal("cap_exceeded read as a TTL limit")
	}
}

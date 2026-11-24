package state

import (
	"net/netip"
	"testing"
	"time"
)

func TestEntryStatePendingBeforeRejected(t *testing.T) {
	p := netip.MustParsePrefix("8.8.8.8/32")
	tg := Target{ID: "t", Label: "T", IPv4: true, AppliedRevision: 5, Subs: []Subscription{{}}}
	rej := Rejections{}
	rej.Add("t", p, "target_full")
	now := time.Now()

	e := Entry{Realm: "r", User: "u", Group: "g", Prefix: p, Revision: 6}
	if st, _ := EntryState(&e, []Target{tg}, rej, now); st != Pending {
		t.Fatalf("an old rejection decided a newer entry: %s", st)
	}
	e.Revision = 5
	if st, per := EntryState(&e, []Target{tg}, rej, now); st != Rejected || per[0].Code != "target_full" {
		t.Fatalf("got %s %+v", st, per)
	}
	// subscriptions_revision makes old entries pending on a newly subscribed target.
	tg.SubscriptionsRevision = 7
	if st, _ := EntryState(&e, []Target{tg}, Rejections{}, now); st != Pending {
		t.Fatalf("new subscription: %s", st)
	}
	tg.AppliedRevision = 7
	if st, _ := EntryState(&e, []Target{tg}, Rejections{}, now); st != Active {
		t.Fatalf("caught up: %s", st)
	}
	// Family mismatch: unrouted.
	e.Prefix = netip.MustParsePrefix("2001:db8::/64")
	if st, _ := EntryState(&e, []Target{tg}, Rejections{}, now); st != Unrouted {
		t.Fatalf("family: %s", st)
	}
}

func TestETag(t *testing.T) {
	exp := time.Date(2026, 11, 25, 17, 0, 0, 123000, time.UTC)
	items := []DesiredItem{{Prefix: netip.MustParsePrefix("8.8.8.8/32"), ExpiresAt: &exp}, {Prefix: netip.MustParsePrefix("2001:db8::/64")}}
	a := ETag([]string{"ipv4", "ipv6"}, items)
	if a != ETag([]string{"ipv4", "ipv6"}, items) || len(a) != 66 || a[0] != '"' {
		t.Fatalf("ETag %s", a)
	}
	if a == ETag([]string{"ipv4"}, items) || a == ETag([]string{"ipv4", "ipv6"}, items[:1]) {
		t.Fatal("ETag ignores families or items")
	}
}

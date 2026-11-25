package state

import (
	"net/netip"
	"testing"
	"time"
)

func TestEntryStatePendingBeforeRejected(t *testing.T) {
	p := netip.MustParsePrefix("8.8.8.8/32")
	tg := Worker{ID: "t", Label: "T", IPv4: true, AppliedRevision: 5, Subs: []Subscription{{}}}
	rej := Rejections{}
	rej.Add("t", p, "capacity_exceeded")
	now := time.Now()

	e := Entry{Realm: "r", User: "u", Group: "g", Prefix: p, Revision: 6}
	if st, _ := EntryState(&e, []Worker{tg}, rej, nil, now); st != Pending {
		t.Fatalf("an old rejection decided a newer entry: %s", st)
	}
	e.Revision = 5
	if st, per := EntryState(&e, []Worker{tg}, rej, nil, now); st != Rejected || per[0].Code != "capacity_exceeded" {
		t.Fatalf("got %s %+v", st, per)
	}
	// subscriptions_revision makes old entries pending on a newly subscribed worker.
	tg.SubscriptionsRevision = 7
	if st, _ := EntryState(&e, []Worker{tg}, Rejections{}, nil, now); st != Pending {
		t.Fatalf("new subscription: %s", st)
	}
	tg.AppliedRevision = 7
	if st, _ := EntryState(&e, []Worker{tg}, Rejections{}, nil, now); st != Active {
		t.Fatalf("caught up: %s", st)
	}
	// Family mismatch: unrouted.
	e.Prefix = netip.MustParsePrefix("2001:db8::/64")
	if st, _ := EntryState(&e, []Worker{tg}, Rejections{}, nil, now); st != Unrouted {
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

func TestRemovalConfirmationUsesRecords(t *testing.T) {
	p := netip.MustParsePrefix("8.8.8.8/32")
	now := time.Now()
	realm := "r"
	// The worker no longer matches the entry: its subscription was deleted at revision 7.
	tg := Worker{ID: "t", Label: "T", IPv4: true, AppliedRevision: 6}
	other := Worker{ID: "o", Label: "O", IPv4: true, AppliedRevision: 9, Subs: []Subscription{{Realm: &realm}}}
	del := int64(8)
	e := Entry{ID: "e", Realm: "r", User: "u", Group: "g", Prefix: p, Revision: 5, DeletedRevision: &del}
	rem := Removals{}
	rem.Add("e", "t", 8)

	st, per := EntryState(&e, []Worker{other, tg}, Rejections{}, rem, now)
	if st != Removing || len(per) != 1 || per[0].Worker.ID != "t" || per[0].State != Removing {
		t.Fatalf("deleted, worker on record behind: %s %+v", st, per)
	}
	tg.AppliedRevision = 8
	if st, per := EntryState(&e, []Worker{other, tg}, Rejections{}, rem, now); st != Removed || per[0].State != Removed {
		t.Fatalf("deleted, confirmed: %s %+v", st, per)
	}
	if st, per := EntryState(&e, []Worker{other, tg}, Rejections{}, nil, now); st != Removed || len(per) != 0 {
		t.Fatalf("deleted with no record: %s %+v", st, per)
	}

	// A live entry still on record for a worker it no longer matches: listed as
	// removing until that worker confirms, without changing the overall state.
	live := Entry{ID: "e", Realm: "r", User: "u", Group: "g", Prefix: p, Revision: 5}
	tg.AppliedRevision = 6
	rem = Removals{}
	rem.Add("e", "t", 7)
	st, per = EntryState(&live, []Worker{other, tg}, Rejections{}, rem, now)
	if st != Active || len(per) != 2 || per[0].State != Active || per[1].State != Removing {
		t.Fatalf("live, removing from one worker: %s %+v", st, per)
	}
	if st, per := EntryState(&live, []Worker{tg}, Rejections{}, rem, now); st != Unrouted || len(per) != 1 {
		t.Fatalf("unrouted, removing: %s %+v", st, per)
	}
	tg.AppliedRevision = 7
	if _, per := EntryState(&live, []Worker{other, tg}, Rejections{}, rem, now); len(per) != 1 {
		t.Fatalf("confirmed worker still listed: %+v", per)
	}

	// Expired: a worker on record confirms by revision or by generated_at.
	exp := now.Add(-time.Minute)
	expired := Entry{ID: "e", Realm: "r", User: "u", Group: "g", Prefix: p, Revision: 5, ExpiresAt: &exp}
	tg.AppliedRevision = 6
	if st, _ := EntryState(&expired, []Worker{tg}, Rejections{}, rem, now); st != Removing {
		t.Fatalf("expired, unconfirmed: %s", st)
	}
	gen := now
	tg.AppliedGeneratedAt = &gen
	if st, _ := EntryState(&expired, []Worker{tg}, Rejections{}, rem, now); st != Expired {
		t.Fatalf("expired, confirmed by generated_at: %s", st)
	}
}

package auth

import (
	"net/netip"
	"testing"
	"time"
)

func TestNetworkOf(t *testing.T) {
	for in, want := range map[string]string{
		"198.51.100.7":         "198.51.100.7/32",
		"::ffff:198.51.100.7":  "198.51.100.7/32",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::1": "2001:db8:1:2::/64",
	} {
		if got := NetworkOf(netip.MustParseAddr(in)).String(); got != want {
			t.Errorf("NetworkOf(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestFailureThrottle(t *testing.T) {
	th := NewFailureThrottle(3)
	a := netip.MustParseAddr("2001:db8::1")
	b := netip.MustParseAddr("2001:db8::2") // same /64
	c := netip.MustParseAddr("2001:db8:0:1::1")
	if _, blocked := th.Blocked(a); blocked {
		t.Fatal("blocked before any failure")
	}
	if th.Fail(a) || th.Fail(b) {
		t.Fatal("budget spent too early")
	}
	if !th.Fail(a) {
		t.Fatal("third failure did not spend the budget")
	}
	wait, blocked := th.Blocked(b)
	if !blocked || wait <= 0 || wait > 20*time.Second {
		t.Fatalf("same /64: blocked=%v wait=%v", blocked, wait)
	}
	if _, blocked := th.Blocked(c); blocked {
		t.Fatal("another /64 blocked")
	}
	th.Evict(time.Now().Add(idleAfter + time.Second))
	if _, blocked := th.Blocked(a); blocked {
		t.Fatal("still blocked after eviction")
	}
	off := NewFailureThrottle(0)
	for i := 0; i < 100; i++ {
		off.Fail(a)
	}
	if _, blocked := off.Blocked(a); blocked {
		t.Fatal("a disabled throttle blocked")
	}
}

package auth

import (
	"context"
	"errors"
	"io"
	"log/slog"
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

func TestFailureThrottleMemoryBound(t *testing.T) {
	th := newFailureThrottle(1, 3)
	ips := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"}
	for _, ip := range ips {
		th.Fail(netip.MustParseAddr(ip))
	}
	if th.Len() != 3 {
		t.Fatalf("tracking %d networks, cap 3", th.Len())
	}
	// The network that failed longest ago was forgotten; the newest are still blocked.
	if _, blocked := th.Blocked(netip.MustParseAddr(ips[0])); blocked {
		t.Fatal("oldest network still tracked")
	}
	if _, blocked := th.Blocked(netip.MustParseAddr(ips[3])); !blocked {
		t.Fatal("newest network not blocked")
	}
	// A repeat failure refreshes a network, so it is not the next to go.
	th.Fail(netip.MustParseAddr(ips[1]))
	th.Fail(netip.MustParseAddr("192.0.2.5"))
	if _, blocked := th.Blocked(netip.MustParseAddr(ips[1])); !blocked {
		t.Fatal("recently failing network was evicted")
	}
	if _, blocked := th.Blocked(netip.MustParseAddr(ips[2])); blocked {
		t.Fatal("least recently failing network kept")
	}
}

func TestKeyIndexRefusesWithoutDatabase(t *testing.T) {
	// No pool: any database access would panic. Unknown ids and wrong
	// secrets must be refused from memory alone.
	a := NewAuthenticator(nil, "", nil, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	real, _ := NewKey()
	a.RememberKey(real.ID, real.Hash())
	other, _ := NewKey()
	for _, k := range []Key{other, {ID: real.ID, Secret: other.Secret}} {
		_, err := a.Authenticate(context.Background(), "Bearer "+k.String(), KindClient, netip.MustParseAddr("192.0.2.9"))
		var ae *Error
		if !errors.As(err, &ae) || ae.Status != 401 {
			t.Fatalf("%s: %v", k.ID, err)
		}
	}
}

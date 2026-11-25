package auth

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func hash(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func TestSessions(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	s := NewSessions(30*time.Minute, 2*time.Hour)
	s.now = func() time.Time { return now }
	id := s.Create("alice")
	if len(id) < 40 {
		t.Fatalf("short id %q", id)
	}
	if id2 := s.Create("alice"); id2 == id {
		t.Fatal("ids repeat")
	}
	// Kept alive by use, up to the maximum.
	for range 5 {
		now = now.Add(20 * time.Minute)
		if name, ok := s.Get(id); !ok || name != "alice" {
			t.Fatalf("at %v: %q %v", now, name, ok)
		}
	}
	now = now.Add(25 * time.Minute) // 2h05m after creation
	if _, ok := s.Get(id); ok {
		t.Fatal("session outlived its maximum")
	}
	id = s.Create("bob")
	now = now.Add(31 * time.Minute)
	if _, ok := s.Get(id); ok {
		t.Fatal("idle session still valid")
	}
	id = s.Create("carol")
	s.Delete(id)
	if _, ok := s.Get(id); ok {
		t.Fatal("deleted session still valid")
	}
	now = now.Add(3 * time.Hour)
	s.Sweep()
	if n := s.Len(); n != 0 {
		t.Fatalf("%d sessions after a sweep", n)
	}
}

func TestThrottle(t *testing.T) {
	th := NewThrottle(3)
	a := netip.MustParseAddr("198.51.100.7")
	for i := range 3 {
		if _, blocked := th.Blocked(a); blocked {
			t.Fatalf("blocked after %d failures", i)
		}
		th.Fail(a)
	}
	if _, blocked := th.Blocked(a); !blocked {
		t.Fatal("not blocked after 3 failures")
	}
	if _, blocked := th.Blocked(netip.MustParseAddr("198.51.100.8")); blocked {
		t.Fatal("a neighbour is blocked")
	}
	// IPv6 is counted per /64.
	for range 3 {
		th.Fail(netip.MustParseAddr("2001:db8:1:2::1"))
	}
	if _, blocked := th.Blocked(netip.MustParseAddr("2001:db8:1:2:ffff::9")); !blocked {
		t.Fatal("same /64 not blocked")
	}
	if _, blocked := NewThrottle(0).Blocked(a); blocked {
		t.Fatal("disabled throttle blocks")
	}
}

func TestClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	req := func(peer string, xff ...string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = peer
		for _, v := range xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		return r
	}
	for _, c := range []struct {
		r    *http.Request
		want string
	}{
		{req("203.0.113.5:1234"), "203.0.113.5"},
		{req("203.0.113.5:1234", "198.51.100.1"), "203.0.113.5"}, // untrusted peer: header ignored
		{req("10.0.0.2:1234", "198.51.100.1"), "198.51.100.1"},
		{req("10.0.0.2:1234", "6.6.6.6, 198.51.100.1, 10.0.0.3"), "198.51.100.1"},
		{req("10.0.0.2:1234", "garbage"), "10.0.0.2"},
	} {
		if got := ClientIP(c.r, trusted).String(); got != c.want {
			t.Errorf("%s %v: %s, want %s", c.r.RemoteAddr, c.r.Header.Values("X-Forwarded-For"), got, c.want)
		}
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{
		"/realms":               "/realms",
		"/entries?realm=home":   "/entries?realm=home",
		"":                      "/",
		"https://evil.example":  "/",
		"//evil.example/x":      "/",
		"/\\evil.example":       "/",
		"/x\r\nSet-Cookie: a=b": "/",
		"javascript:alert(1)":   "/",
	} {
		if got := SafeNext(in); got != want {
			t.Errorf("SafeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

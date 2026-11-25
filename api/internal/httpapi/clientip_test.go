package httpapi

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("fd00::/8")}
	cases := []struct {
		peer, xff, want string
		untrusted       bool
	}{
		{"198.51.100.7:1234", "", "198.51.100.7", false},
		{"198.51.100.7:1234", "203.0.113.9", "198.51.100.7", true}, // untrusted peer: header ignored
		{"10.0.0.2:1234", "203.0.113.9", "203.0.113.9", false},
		{"10.0.0.2:1234", "1.1.1.1, 203.0.113.9", "203.0.113.9", false},  // prepended hop ignored
		{"10.0.0.2:1234", "203.0.113.9, 10.0.0.3", "203.0.113.9", false}, // trusted hops skipped
		{"10.0.0.2:1234", "", "10.0.0.2", false},
		{"10.0.0.2:1234", "garbage", "10.0.0.2", false},
		{"[fd00::1]:443", "2001:db8::5", "2001:db8::5", false},
		{"[::ffff:10.0.0.2]:80", "::ffff:203.0.113.9", "203.0.113.9", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.peer
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		got, untrusted := clientIP(r, trusted)
		if got.String() != c.want || untrusted != c.untrusted {
			t.Errorf("peer %s xff %q: got %s %v, want %s %v", c.peer, c.xff, got, untrusted, c.want, c.untrusted)
		}
	}
}

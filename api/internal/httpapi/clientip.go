package httpapi

import (
	"net/http"
	"net/netip"
	"strings"
)

// clientIP returns the caller's address. The connection's peer is the caller
// unless it is a trusted proxy; then X-Forwarded-For is read from the right,
// skipping trusted proxies, and the first other address is the caller. An
// untrusted peer cannot choose its address by sending the header.
func clientIP(r *http.Request, trusted []netip.Prefix) (ip netip.Addr, forwardedFromUntrusted bool) {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	ip = peer.Addr().Unmap().WithZone("")
	xff := r.Header.Values("X-Forwarded-For")
	if !isTrusted(ip, trusted) {
		return ip, len(xff) > 0
	}
	var hops []string
	for _, v := range xff {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return ip, false // a malformed hop: keep the last address we can vouch for
		}
		a = a.Unmap().WithZone("")
		ip = a
		if !isTrusted(a, trusted) {
			return a, false
		}
	}
	return ip, false
}

func isTrusted(ip netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

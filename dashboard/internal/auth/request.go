package auth

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
)

// Identity is the person signed in.
type Identity struct {
	Name string
}

type ctxKey int

const (
	identityKey ctxKey = iota
	clientIPKey
)

// WithIdentity stores the signed-in person in ctx.
func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

// IdentityFrom returns the signed-in person, or nil.
func IdentityFrom(ctx context.Context) *Identity {
	id, _ := ctx.Value(identityKey).(*Identity)
	return id
}

// WithClientIP stores the caller's address in ctx.
func WithClientIP(ctx context.Context, ip netip.Addr) context.Context {
	return context.WithValue(ctx, clientIPKey, ip)
}

// ClientIPFrom returns the caller's address stored by WithClientIP.
func ClientIPFrom(ctx context.Context) netip.Addr {
	ip, _ := ctx.Value(clientIPKey).(netip.Addr)
	return ip
}

// ClientIP returns the caller's address. The connection's peer is the caller
// unless it is a trusted proxy; then X-Forwarded-For is read from the right,
// skipping trusted proxies, and the first other address is the caller.
func ClientIP(r *http.Request, trusted []netip.Prefix) netip.Addr {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	ip := peer.Addr().Unmap().WithZone("")
	if !isTrusted(ip, trusted) {
		return ip
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return ip // a malformed hop: keep the last address we can vouch for
		}
		ip = a.Unmap().WithZone("")
		if !isTrusted(ip, trusted) {
			return ip
		}
	}
	return ip
}

func isTrusted(ip netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// SafeNext returns next if it is a path on this site, otherwise "/". It keeps
// a sign-in page from sending people to another site.
func SafeNext(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") ||
		strings.ContainsAny(next, "\\\r\n\t") {
		return "/"
	}
	return next
}

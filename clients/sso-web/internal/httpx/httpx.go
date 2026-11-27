// Package httpx holds request helpers: the caller's address behind trusted
// proxies, whether a request came over HTTPS, when cookies are Secure, and
// safe redirect targets.
package httpx

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// AllNetworks trusts every peer.
var AllNetworks = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}

// ParseTrustedProxies reads a trusted-proxy setting: unset, empty or "*"
// trusts every peer's X-Forwarded-For (the default; all reports that);
// "none" trusts none, so the connection's peer is always the client;
// otherwise a comma-separated list of IP addresses and CIDR prefixes.
func ParseTrustedProxies(s string) (nets []netip.Prefix, all bool, err error) {
	switch s = strings.TrimSpace(s); strings.ToLower(s) {
	case "", "*":
		return AllNetworks, true, nil
	case "none":
		return nil, false, nil
	}
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		p, err := ParseNet(f)
		if err != nil {
			return nil, false, fmt.Errorf("%q is not an IP address or CIDR prefix (or use * or none)", f)
		}
		nets = append(nets, p)
	}
	return nets, false, nil
}

// ParseNet parses an IP address (as a single-address prefix) or a CIDR prefix.
func ParseNet(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), max(p.Bits()-96, 0))
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap().WithZone("")
	return netip.PrefixFrom(a, a.BitLen()), nil
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

// Peer returns the connection's own peer address.
func Peer(r *http.Request) netip.Addr {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return peer.Addr().Unmap().WithZone("")
}

func isTrusted(ip netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// IsTrusted reports whether ip is one of the trusted proxies.
func IsTrusted(ip netip.Addr, trusted []netip.Prefix) bool { return isTrusted(ip, trusted) }

// RequestIsHTTPS reports whether r came over HTTPS: TLS to this server,
// X-Forwarded-Proto https from a trusted peer, or an https Origin (which
// browsers send on every form post, and which a page cannot forge).
func RequestIsHTTPS(r *http.Request, trusted []netip.Prefix) bool {
	if r.TLS != nil {
		return true
	}
	if o, err := url.Parse(r.Header.Get("Origin")); err == nil && o.Scheme == "https" {
		return true
	}
	proto, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Proto"), ",")
	if !strings.EqualFold(strings.TrimSpace(proto), "https") {
		return false
	}
	return isTrusted(Peer(r), trusted)
}

// CookieMode says when cookies are marked Secure.
type CookieMode string

const (
	// CookiesAuto marks cookies Secure when the request came over HTTPS.
	CookiesAuto CookieMode = "auto"
	// CookiesSecure always marks cookies Secure.
	CookiesSecure CookieMode = "true"
	// CookiesPlain never marks cookies Secure.
	CookiesPlain CookieMode = "false"
)

type ctxKey int

const (
	httpsKey ctxKey = iota
	clientIPKey
)

// WithRequest records the caller's address and whether the request came
// over HTTPS in ctx.
func WithRequest(ctx context.Context, ip netip.Addr, https bool) context.Context {
	return context.WithValue(context.WithValue(ctx, clientIPKey, ip), httpsKey, https)
}

// ClientIPFrom returns the caller's address stored by WithRequest.
func ClientIPFrom(ctx context.Context) netip.Addr {
	ip, _ := ctx.Value(clientIPKey).(netip.Addr)
	return ip
}

// Secure reports whether cookies set in answer to r are marked Secure.
func (m CookieMode) Secure(r *http.Request) bool {
	switch m {
	case CookiesSecure:
		return true
	case CookiesPlain:
		return false
	}
	if v, ok := r.Context().Value(httpsKey).(bool); ok {
		return v
	}
	return RequestIsHTTPS(r, nil)
}

// SafeNext returns next if it is a path on this site, otherwise "/". It keeps
// a sign-in round trip from sending people to another site.
func SafeNext(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") ||
		strings.ContainsAny(next, "\\\r\n\t") {
		return "/"
	}
	return next
}

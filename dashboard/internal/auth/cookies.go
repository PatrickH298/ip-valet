package auth

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// CookieMode says when cookies are marked Secure.
type CookieMode string

const (
	// CookiesAuto marks cookies Secure when the request came over HTTPS:
	// TLS to the dashboard itself, X-Forwarded-Proto https from a trusted
	// proxy, or a page whose Origin is https.
	CookiesAuto CookieMode = "auto"
	// CookiesSecure always marks cookies Secure; browsers then keep them
	// only over HTTPS and on localhost.
	CookiesSecure CookieMode = "true"
	// CookiesPlain never marks cookies Secure.
	CookiesPlain CookieMode = "false"
)

type httpsKey struct{}

// WithHTTPS records in ctx whether the request came over HTTPS.
func WithHTTPS(ctx context.Context, https bool) context.Context {
	return context.WithValue(ctx, httpsKey{}, https)
}

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
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	return err == nil && isTrusted(peer.Addr().Unmap(), trusted)
}

// Secure reports whether cookies set in answer to r are marked Secure.
func (m CookieMode) Secure(r *http.Request) bool {
	switch m {
	case CookiesSecure:
		return true
	case CookiesPlain:
		return false
	}
	if v, ok := r.Context().Value(httpsKey{}).(bool); ok {
		return v
	}
	return RequestIsHTTPS(r, nil)
}

// Session cookie names. A Secure cookie takes the __Host- prefix, which
// browsers accept only from a secure origin, for the whole host and path /.
const (
	secureSessionCookie = "__Host-ipvalet-session"
	plainSessionCookie  = "ipvalet-session"
)

func sessionCookieName(secure bool) string {
	if secure {
		return secureSessionCookie
	}
	return plainSessionCookie
}

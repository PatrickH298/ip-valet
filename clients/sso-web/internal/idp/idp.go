// Package idp signs people in with an external identity provider, over
// OpenID Connect or SAML 2.0, and reports who they are: a user name and
// their groups. What they may do is decided elsewhere (package rules).
package idp

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/httpx"
	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/seal"
)

// Identity is a person as the IdP describes them.
type Identity struct {
	User   string
	Groups []string
}

// Provider is one way of signing in.
type Provider interface {
	// Name names the provider in logs and pages ("OpenID Connect", "SAML").
	Name() string
	// Begin sends the browser to the IdP. After signing in, it comes back to
	// the provider's endpoint, which calls Env.Done with next.
	Begin(w http.ResponseWriter, r *http.Request, next string)
	// Routes adds the provider's endpoints (callback, assertion consumer).
	Routes(mux *http.ServeMux)
	// CrossSitePosts lists endpoints the IdP posts to from its own site,
	// which cross-origin protection must let through.
	CrossSitePosts() []string
	// Check contacts the IdP: discovery for OpenID Connect, metadata for SAML.
	Check(ctx context.Context) error
}

// Env is what providers need from the site.
type Env struct {
	PublicURL *url.URL
	Sealer    *seal.Sealer
	Cookies   httpx.CookieMode
	Log       *slog.Logger
	HTTP      *http.Client // for calls to the IdP
	// Done is called once the IdP has vouched for a person.
	Done func(w http.ResponseWriter, r *http.Request, id Identity, next string)
	// Fail shows an error page.
	Fail func(w http.ResponseWriter, r *http.Request, status int, title, message string)
}

// loginTTL bounds a round trip through the IdP.
const loginTTL = 10 * time.Minute

// stateCookie names the cookie that ties a round trip to the browser that
// began it. A Secure cookie takes the __Host- prefix.
func stateCookie(secure bool, name string) string {
	if secure {
		return "__Host-ipvalet-sso-" + name
	}
	return "ipvalet-sso-" + name
}

func setStateCookie(w http.ResponseWriter, secure bool, name, value string, sameSite http.SameSite) {
	http.SetCookie(w, &http.Cookie{
		Name: stateCookie(secure, name), Value: value, Path: "/", MaxAge: int(loginTTL / time.Second),
		HttpOnly: true, Secure: secure, SameSite: sameSite,
	})
}

func clearStateCookie(w http.ResponseWriter, secure bool, name string, sameSite http.SameSite) {
	http.SetCookie(w, &http.Cookie{
		Name: stateCookie(secure, name), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: secure, SameSite: sameSite,
	})
}

// readStateCookie finds the round-trip cookie under either name: the
// request that began it may have been plain HTTP or HTTPS.
func readStateCookie(r *http.Request, name string) (string, bool) {
	for _, secure := range []bool{true, false} {
		if c, err := r.Cookie(stateCookie(secure, name)); err == nil && c.Value != "" {
			return c.Value, secure
		}
	}
	return "", false
}

// client is the HTTP client for calls to the IdP.
func (e Env) client() *http.Client {
	if e.HTTP != nil {
		return e.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

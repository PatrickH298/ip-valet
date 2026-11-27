package idp

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/config"
	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/httpx"
)

// OIDC signs people in with OpenID Connect: the authorization code flow
// with PKCE, state and nonce. The user name and groups come from the ID
// token, or from the userinfo endpoint when the token lacks them.
type OIDC struct {
	cfg config.OIDC
	env Env

	mu       sync.Mutex
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
}

// NewOIDC returns an OpenID Connect provider. It discovers the IdP when
// first needed, and again until discovery succeeds.
func NewOIDC(cfg config.OIDC, env Env) *OIDC { return &OIDC{cfg: cfg, env: env} }

// Name implements Provider.
func (o *OIDC) Name() string { return "OpenID Connect" }

// CrossSitePosts implements Provider: the IdP returns with a GET.
func (o *OIDC) CrossSitePosts() []string { return nil }

// Routes implements Provider.
func (o *OIDC) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/callback", o.callback)
}

// Check implements Provider.
func (o *OIDC) Check(ctx context.Context) error {
	_, _, err := o.discover(ctx)
	return err
}

func (o *OIDC) ctx(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, o.env.client())
}

func (o *OIDC) discover(ctx context.Context) (*oauth2.Config, *oidc.IDTokenVerifier, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.provider != nil {
		return o.oauth, o.verifier, nil
	}
	p, err := oidc.NewProvider(o.ctx(ctx), o.cfg.Issuer)
	if err != nil {
		return nil, nil, fmt.Errorf("discovering %s: %w", o.cfg.Issuer, err)
	}
	o.provider = p
	o.verifier = p.Verifier(&oidc.Config{ClientID: o.cfg.ClientID})
	o.oauth = &oauth2.Config{
		ClientID: o.cfg.ClientID, ClientSecret: o.cfg.ClientSecret, Endpoint: p.Endpoint(),
		RedirectURL: o.env.PublicURL.String() + "/auth/callback", Scopes: o.cfg.Scopes,
	}
	return o.oauth, o.verifier, nil
}

type oidcState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Next     string `json:"x"`
}

const oidcCookie = "oidc"

// Begin implements Provider.
func (o *OIDC) Begin(w http.ResponseWriter, r *http.Request, next string) {
	oc, _, err := o.discover(r.Context())
	if err != nil {
		o.env.Log.Error("cannot reach the OpenID Connect provider", "error", err.Error())
		o.env.Fail(w, r, http.StatusBadGateway, "Sign-in unavailable",
			"The sign-in service could not be reached. Try again in a moment.")
		return
	}
	st := oidcState{State: random(), Nonce: random(), Verifier: oauth2.GenerateVerifier(), Next: next}
	sealed, err := o.env.Sealer.Seal("oidc-login", loginTTL, st)
	if err != nil {
		o.env.Fail(w, r, http.StatusInternalServerError, "Something went wrong", "Sign-in could not start.")
		return
	}
	// Lax: the IdP returns with a top-level GET, which carries Lax cookies.
	setStateCookie(w, o.env.Cookies.Secure(r), oidcCookie, sealed, http.SameSiteLaxMode)
	http.Redirect(w, r, oc.AuthCodeURL(st.State, oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier)),
		http.StatusSeeOther)
}

func (o *OIDC) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	raw, secure := readStateCookie(r, oidcCookie)
	clearStateCookie(w, secure, oidcCookie, http.SameSiteLaxMode)
	var st oidcState
	if raw == "" || o.env.Sealer.Open("oidc-login", raw, &st) != nil {
		o.env.Log.Warn("OpenID Connect callback without a valid sign-in in progress",
			"client_ip", httpx.ClientIPFrom(r.Context()).String())
		o.env.Fail(w, r, http.StatusBadRequest, "Sign-in expired",
			"This sign-in was started too long ago, or in another browser. Sign in again.")
		return
	}
	if e := q.Get("error"); e != "" {
		o.env.Log.Warn("the OpenID Connect provider refused sign-in", "error", e, "description", q.Get("error_description"))
		msg := "The sign-in service did not sign you in (" + e + ")."
		if d := q.Get("error_description"); d != "" {
			msg = "The sign-in service did not sign you in: " + d
		}
		o.env.Fail(w, r, http.StatusForbidden, "Not signed in", msg)
		return
	}
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(st.State)) != 1 {
		o.env.Log.Warn("OpenID Connect callback with the wrong state", "client_ip", httpx.ClientIPFrom(r.Context()).String())
		o.env.Fail(w, r, http.StatusBadRequest, "Sign-in failed", "The sign-in response did not match this browser's request. Sign in again.")
		return
	}
	id, err := o.identify(r.Context(), q.Get("code"), st)
	if err != nil {
		o.env.Log.Error("OpenID Connect sign-in failed", "error", err.Error())
		o.env.Fail(w, r, http.StatusBadGateway, "Sign-in failed",
			"The sign-in service's answer could not be used. Try again; if it keeps happening, tell your administrator.")
		return
	}
	o.env.Done(w, r, id, st.Next)
}

func (o *OIDC) identify(ctx context.Context, code string, st oidcState) (Identity, error) {
	oc, verifier, err := o.discover(ctx)
	if err != nil {
		return Identity{}, err
	}
	ctx = o.ctx(ctx)
	tok, err := oc.Exchange(ctx, code, oauth2.VerifierOption(st.Verifier))
	if err != nil {
		return Identity{}, fmt.Errorf("exchanging the code: %w", err)
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		return Identity{}, errors.New("the token response has no id_token")
	}
	idt, err := verifier.Verify(ctx, rawID)
	if err != nil {
		return Identity{}, fmt.Errorf("verifying the ID token: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(st.Nonce)) != 1 {
		return Identity{}, errors.New("the ID token's nonce does not match")
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("reading the ID token: %w", err)
	}
	user, haveUser := stringClaim(claims, o.cfg.UsernameClaim)
	groups, haveGroups := listClaim(claims, o.cfg.GroupsClaim)
	if !haveUser || !haveGroups {
		// Many IdPs keep profile and group claims out of the ID token.
		o.mu.Lock()
		p := o.provider
		o.mu.Unlock()
		ui, err := p.UserInfo(ctx, oauth2.StaticTokenSource(tok))
		if err == nil {
			var uc map[string]any
			if err := ui.Claims(&uc); err == nil {
				if !haveUser {
					user, haveUser = stringClaim(uc, o.cfg.UsernameClaim)
				}
				if !haveGroups {
					groups, haveGroups = listClaim(uc, o.cfg.GroupsClaim)
				}
			}
		} else {
			o.env.Log.Debug("userinfo request failed", "error", err.Error())
		}
	}
	if !haveUser {
		return Identity{}, fmt.Errorf("neither the ID token nor userinfo has a %q claim (IPVALET_SSO_OIDC_USERNAME_CLAIM)", o.cfg.UsernameClaim)
	}
	if !haveGroups {
		o.env.Log.Info("the IdP sent no groups claim; only user rules can match", "user", user,
			"claim", o.cfg.GroupsClaim)
	}
	return Identity{User: user, Groups: groups}, nil
}

// claim finds name in claims; a dotted name such as realm_access.roles
// reaches into nested objects when no claim has the whole name.
func claim(claims map[string]any, name string) (any, bool) {
	if v, ok := claims[name]; ok {
		return v, true
	}
	cur := any(claims)
	for _, part := range strings.Split(name, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[part]; !ok {
			return nil, false
		}
	}
	return cur, true
}

func stringClaim(claims map[string]any, name string) (string, bool) {
	v, ok := claim(claims, name)
	if !ok {
		return "", false
	}
	switch s := v.(type) {
	case string:
		return s, s != ""
	case float64:
		return fmt.Sprint(s), true
	}
	return "", false
}

// listClaim reads a list of strings, or a single string, as groups.
func listClaim(claims map[string]any, name string) ([]string, bool) {
	v, ok := claim(claims, name)
	if !ok {
		return nil, false
	}
	switch l := v.(type) {
	case []any:
		var out []string
		for _, x := range l {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out, true
	case string:
		if l == "" {
			return nil, true
		}
		return []string{l}, true
	}
	return nil, false
}

func random() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

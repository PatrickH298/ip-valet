package e2e

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeOIDC is a minimal OpenID Connect provider: discovery, an authorize
// endpoint that signs in whoever the test names, a token endpoint that
// checks the client and PKCE, RS256 ID tokens, JWKS and userinfo.
type fakeOIDC struct {
	srv      *httptest.Server
	key      *rsa.PrivateKey
	clientID string
	secret   string

	mu               sync.Mutex
	user             string
	groups           []string
	groupsInUserinfo bool // keep groups out of the ID token, as many IdPs do
	codes            map[string]oidcCode
	tokens           map[string]map[string]any
}

type oidcCode struct {
	nonce, challenge, redirect string
	claims                     map[string]any
}

func newFakeOIDC(t *testing.T) *fakeOIDC {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeOIDC{key: key, clientID: "ip-valet", secret: "s3cret", codes: map[string]oidcCode{},
		tokens: map[string]map[string]any{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("GET /authorize", f.authorize)
	mux.HandleFunc("POST /token", f.token)
	mux.HandleFunc("GET /jwks", f.jwks)
	mux.HandleFunc("GET /userinfo", f.userinfo)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// signInAs sets who the next sign-in is.
func (f *fakeOIDC) signInAs(user string, groups ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.user, f.groups = user, groups
}

// env is the sso-web configuration for this provider.
func (f *fakeOIDC) env() map[string]string {
	return map[string]string{
		"IPVALET_SSO_PROVIDER":           "oidc",
		"IPVALET_SSO_OIDC_ISSUER":        f.srv.URL,
		"IPVALET_SSO_OIDC_CLIENT_ID":     f.clientID,
		"IPVALET_SSO_OIDC_CLIENT_SECRET": f.secret,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeOIDC) discovery(w http.ResponseWriter, _ *http.Request) {
	u := f.srv.URL
	writeJSON(w, 200, map[string]any{
		"issuer": u, "authorization_endpoint": u + "/authorize", "token_endpoint": u + "/token",
		"jwks_uri": u + "/jwks", "userinfo_endpoint": u + "/userinfo", "response_types_supported": []string{"code"},
		"subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported": []string{"S256"},
	})
}

func (f *fakeOIDC) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != f.clientID || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" ||
		q.Get("code_challenge") == "" || q.Get("nonce") == "" || !strings.Contains(q.Get("scope"), "openid") {
		http.Error(w, "bad authorization request: "+r.URL.RawQuery, http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	claims := map[string]any{"sub": "sub-" + f.user, "preferred_username": f.user}
	if f.groups != nil {
		claims["groups"] = f.groups
	}
	code := randomString()
	f.codes[code] = oidcCode{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri"),
		claims: claims}
	f.mu.Unlock()
	back, _ := url.Parse(q.Get("redirect_uri"))
	bq := back.Query()
	bq.Set("code", code)
	bq.Set("state", q.Get("state"))
	back.RawQuery = bq.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound)
}

func (f *fakeOIDC) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != f.clientID || secret != f.secret {
		writeJSON(w, 401, map[string]any{"error": "invalid_client"})
		return
	}
	f.mu.Lock()
	c, found := f.codes[r.PostForm.Get("code")]
	delete(f.codes, r.PostForm.Get("code"))
	groupsInUserinfo := f.groupsInUserinfo
	f.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !found || r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("redirect_uri") != c.redirect ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge {
		writeJSON(w, 400, map[string]any{"error": "invalid_grant"})
		return
	}
	now := time.Now()
	idClaims := map[string]any{"iss": f.srv.URL, "aud": f.clientID, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"nonce": c.nonce}
	for k, v := range c.claims {
		if k == "groups" && groupsInUserinfo {
			continue
		}
		idClaims[k] = v
	}
	access := randomString()
	f.mu.Lock()
	f.tokens[access] = c.claims
	f.mu.Unlock()
	writeJSON(w, 200, map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 300,
		"id_token": f.sign(idClaims)})
}

func (f *fakeOIDC) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := f.key.PublicKey
	writeJSON(w, 200, map[string]any{"keys": []any{map[string]any{
		"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

func (f *fakeOIDC) userinfo(w http.ResponseWriter, r *http.Request) {
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	f.mu.Lock()
	claims, ok := f.tokens[tok]
	f.mu.Unlock()
	if !ok {
		writeJSON(w, 401, map[string]any{"error": "invalid_token"})
		return
	}
	writeJSON(w, 200, claims)
}

// sign makes an RS256 JWT.
func (f *fakeOIDC) sign(claims map[string]any) string {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	input := enc(map[string]any{"alg": "RS256", "kid": "k1", "typ": "JWT"}) + "." + enc(claims)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		panic(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func randomString() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

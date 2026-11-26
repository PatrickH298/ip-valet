package auth

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestMain(m *testing.M) {
	bcryptCost = bcrypt.MinCost
	os.Exit(m.Run())
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestStoreDefaultAndSave(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	lg := s.Login()
	if !s.IsDefault() || lg.Method != MethodForm || lg.Username != "admin" {
		t.Fatalf("default login %+v %v", lg, s.IsDefault())
	}
	if _, err := os.Stat(filepath.Join(dir, loginFile)); !os.IsNotExist(err) {
		t.Fatal("the default login was written to disk")
	}
	if err := s.Save(Login{Method: MethodBasic, Username: "ops", Hash: hash(t, "new password")}); err != nil {
		t.Fatal(err)
	}
	if s.IsDefault() {
		t.Fatal("still default after saving")
	}
	fi, err := os.Stat(filepath.Join(dir, loginFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("saved file: %v %v", fi, err)
	}
	// It survives a restart.
	s2, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if lg := s2.Login(); s2.IsDefault() || lg.Method != MethodBasic || lg.Username != "ops" {
		t.Fatalf("reopened %+v", lg)
	}
	// reset-login brings the default back.
	if err := ResetLogin(dir); err != nil {
		t.Fatal(err)
	}
	if err := ResetLogin(dir); err != nil {
		t.Fatal("second reset:", err)
	}
	if s3, err := OpenStore(dir); err != nil || !s3.IsDefault() {
		t.Fatalf("after reset: %v", err)
	}
	// Invalid logins are refused, not silently replaced by the default.
	if err := s.Save(Login{Method: "oidc", Username: "ops", Hash: hash(t, "x")}); err == nil {
		t.Fatal("unknown method saved")
	}
	_ = os.WriteFile(filepath.Join(dir, loginFile), []byte(`{"method":"form","username":"a","password_hash":"plain"}`), 0o600)
	if _, err := OpenStore(dir); err == nil || !strings.Contains(err.Error(), "reset-login") {
		t.Fatalf("broken login file: %v", err)
	}
	if _, err := OpenStore(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing directory accepted")
	}
}

func TestValidPassword(t *testing.T) {
	for pw, ok := range map[string]bool{
		"short":                 false,
		"long enough!":          true,
		strings.Repeat("x", 73): false,
		"ops-and-ops":           false, // the user name
		"ünïcödé-pässwörd":      true,
	} {
		if err := ValidPassword(pw, "ops-and-ops"); (err == nil) != ok {
			t.Errorf("ValidPassword(%q) = %v", pw, err)
		}
	}
}

type harness struct {
	t     *testing.T
	l     *Local
	mux   *http.ServeMux
	view  LoginView
	ip    netip.Addr
	jar   []*http.Cookie
	extra http.Header
}

func newHarness(t *testing.T, login *Login) *harness {
	t.Helper()
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if login != nil {
		if err := s.Save(*login); err != nil {
			t.Fatal(err)
		}
	}
	h := &harness{t: t, mux: http.NewServeMux(), ip: netip.MustParseAddr("192.0.2.1")}
	h.l = &Local{Store: s, Sessions: NewSessions(time.Hour, time.Hour), Throttle: NewThrottle(3), Cookies: CookiesSecure,
		Log: discard(), Render: func(w http.ResponseWriter, r *http.Request, status int, v LoginView) {
			h.view = v
			w.WriteHeader(status)
		}}
	h.l.Routes(h.mux)
	return h
}

func (h *harness) req(method, path string, form url.Values) *http.Request {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, path, body)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, c := range h.jar {
		r.AddCookie(c)
	}
	for k, v := range h.extra {
		r.Header[k] = v
	}
	return r.WithContext(WithClientIP(r.Context(), h.ip))
}

// serve sends r to the provider's routes and keeps the cookies it sets.
func (h *harness) serve(r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.mux.ServeHTTP(w, r)
	for _, c := range w.Result().Cookies() {
		h.jar = append(h.jar[:0:0], c)
		if c.MaxAge < 0 {
			h.jar = nil
		}
	}
	return w
}

func (h *harness) signIn(name, pw string) *httptest.ResponseRecorder {
	return h.serve(h.req("POST", "/login", url.Values{"name": {name}, "password": {pw}, "next": {"/workers"}}))
}

func (h *harness) who() string {
	if id := h.l.Identify(h.req("GET", "/", nil)); id != nil {
		return id.Name
	}
	return ""
}

func TestDefaultLoginAndChange(t *testing.T) {
	h := newHarness(t, nil)
	h.serve(h.req("GET", "/login", nil))
	if !h.view.Default {
		t.Fatal("the sign-in page does not say the default login is in use")
	}
	if w := h.signIn("admin", "admin"); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/workers" {
		t.Fatalf("default sign-in: %d %s", w.Code, w.Header().Get("Location"))
	}
	c := h.jar[0]
	if c.Name != "__Host-ipvalet-session" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode ||
		c.Path != "/" || c.Domain != "" {
		t.Fatalf("cookie %+v", c)
	}
	if h.who() != "admin" {
		t.Fatal("not signed in")
	}
	// A second session, elsewhere.
	other := h.l.Sessions.Create("admin")

	change := func(c Change) error {
		w := httptest.NewRecorder()
		err := h.l.ChangeLogin(w, h.req("POST", "/account", nil), c)
		if err == nil {
			for _, ck := range w.Result().Cookies() {
				h.jar = []*http.Cookie{ck}
			}
		}
		return err
	}
	for name, tc := range map[string]struct {
		c     Change
		field string
	}{
		"wrong current":  {Change{Current: "nope", Method: MethodForm, Username: "admin", NewPassword: "long enough!", Confirm: "long enough!"}, "current"},
		"keep default":   {Change{Current: "admin", Method: MethodForm, Username: "admin"}, "new_password"},
		"too short":      {Change{Current: "admin", Method: MethodForm, Username: "admin", NewPassword: "short", Confirm: "short"}, "new_password"},
		"mismatch":       {Change{Current: "admin", Method: MethodForm, Username: "admin", NewPassword: "long enough!", Confirm: "long enough?"}, "confirm"},
		"bad name":       {Change{Current: "admin", Method: MethodForm, Username: "a:b", NewPassword: "long enough!", Confirm: "long enough!"}, "username"},
		"unknown method": {Change{Current: "admin", Method: "oidc", Username: "admin", NewPassword: "long enough!", Confirm: "long enough!"}, "method"},
	} {
		err := change(tc.c)
		ce, ok := err.(ChangeErrors)
		if !ok || ce[tc.field] == "" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if !h.l.Store.IsDefault() {
		t.Fatal("a refused change was saved")
	}
	if err := change(Change{Current: "admin", Method: MethodForm, Username: "ops", NewPassword: "a better password",
		Confirm: "a better password"}); err != nil {
		t.Fatal(err)
	}
	if h.l.Store.IsDefault() || h.who() != "ops" {
		t.Fatalf("after the change: default %v, signed in as %q", h.l.Store.IsDefault(), h.who())
	}
	if _, ok := h.l.Sessions.Get(other); ok {
		t.Fatal("another session survived the change")
	}
	h.jar = nil
	if w := h.signIn("admin", "admin"); w.Code != http.StatusUnauthorized {
		t.Fatalf("old login: %d", w.Code)
	}
	if w := h.signIn("ops", "a better password"); w.Code != http.StatusSeeOther {
		t.Fatalf("new login: %d", w.Code)
	}
	// Changing only the user name keeps the password.
	if err := change(Change{Current: "a better password", Method: MethodForm, Username: "root"}); err != nil {
		t.Fatal(err)
	}
	h.jar = nil
	if w := h.signIn("root", "a better password"); w.Code != http.StatusSeeOther {
		t.Fatalf("renamed login: %d", w.Code)
	}
	var saved Login
	b, _ := os.ReadFile(h.l.Store.path)
	_ = json.Unmarshal(b, &saved)
	if strings.Contains(string(b), "a better password") || saved.Username != "root" {
		t.Fatalf("saved file %s", b)
	}
}

func TestFormSignInGuards(t *testing.T) {
	h := newHarness(t, &Login{Method: MethodForm, Username: "ops", Hash: hash(t, "a good password")})
	// A session planted before sign-in is replaced, not adopted.
	planted := h.l.Sessions.Create("ops")
	h.jar = []*http.Cookie{{Name: secureSessionCookie, Value: planted}}
	h.signIn("ops", "a good password")
	if _, ok := h.l.Sessions.Get(planted); ok || h.jar[0].Value == planted {
		t.Fatal("the planted session survived sign-in")
	}
	// An open redirect is refused.
	w := h.serve(h.req("POST", "/login", url.Values{"name": {"ops"}, "password": {"a good password"},
		"next": {"//evil.example"}}))
	if w.Header().Get("Location") != "/" {
		t.Fatalf("next: %s", w.Header().Get("Location"))
	}
	// A plain-HTTP page elsewhere than localhost cannot keep a Secure cookie: say so.
	h.extra = http.Header{"Origin": {"http://192.168.1.10:8090"}}
	if w := h.signIn("ops", "a good password"); w.Code != http.StatusBadRequest || !strings.Contains(h.view.Error, "HTTPS") {
		t.Fatalf("plain HTTP: %d %q", w.Code, h.view.Error)
	}
	h.extra = http.Header{"Origin": {"http://localhost:8090"}}
	if w := h.signIn("ops", "a good password"); w.Code != http.StatusSeeOther {
		t.Fatalf("localhost: %d", w.Code)
	}
	h.extra = nil
	// Three failures spend the budget; then even the right password waits.
	for range 3 {
		if w := h.signIn("ops", "wrong"); w.Code != http.StatusUnauthorized {
			t.Fatalf("wrong password: %d", w.Code)
		}
	}
	w = h.signIn("ops", "a good password")
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" || h.view.RetryAfter < 1 {
		t.Fatalf("throttled: %d %+v", w.Code, h.view)
	}
	// Sign-out ends the session.
	h.ip = netip.MustParseAddr("192.0.2.200")
	h.signIn("ops", "a good password")
	h.serve(h.req("POST", "/logout", nil))
	if h.who() != "" {
		t.Fatal("still signed in after sign-out")
	}
}

func TestBasicMethod(t *testing.T) {
	h := newHarness(t, &Login{Method: MethodBasic, Username: "ops", Hash: hash(t, "a good password")})
	basic := func(name, pw string) *http.Request {
		r := h.req("GET", "/", nil)
		if name != "" {
			r.SetBasicAuth(name, pw)
		}
		return r
	}
	if h.l.CanSignOut() {
		t.Fatal("basic auth offers sign-out")
	}
	if id := h.l.Identify(basic("ops", "a good password")); id == nil || id.Name != "ops" {
		t.Fatalf("identify: %+v", id)
	}
	if h.l.Identify(basic("", "")) != nil || h.l.Identify(basic("ops", "nope")) != nil {
		t.Fatal("identified with bad credentials")
	}
	w := httptest.NewRecorder()
	h.l.Challenge(w, basic("", ""))
	if w.Code != 401 || !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "Basic ") {
		t.Fatalf("challenge %d %v", w.Code, w.Header())
	}
	// The sign-in page is not used.
	if w := h.serve(h.req("GET", "/login", nil)); w.Code != http.StatusSeeOther {
		t.Fatalf("/login with basic auth: %d", w.Code)
	}
	// A password change ends cached credentials at once.
	if err := h.l.ChangeLogin(httptest.NewRecorder(), basic("ops", "a good password"),
		Change{Current: "a good password", Method: MethodBasic, Username: "ops", NewPassword: "another password",
			Confirm: "another password"}); err != nil {
		t.Fatal(err)
	}
	if h.l.Identify(basic("ops", "a good password")) != nil {
		t.Fatal("old credentials still accepted from the cache")
	}
	if h.l.Identify(basic("ops", "another password")) == nil {
		t.Fatal("new credentials refused")
	}
	// Two more failures spend the budget (one was spent above): then nothing is checked.
	h.l.Identify(basic("ops", "x"))
	h.l.Identify(basic("ops", "y"))
	if h.l.Identify(basic("ops", "another password")) != nil {
		t.Fatal("identified while throttled")
	}
	w = httptest.NewRecorder()
	h.l.Challenge(w, basic("ops", "another password"))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("throttled challenge %d", w.Code)
	}
}

func TestCookieModes(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	req := func(peer string, header ...string) *http.Request {
		r := httptest.NewRequest("POST", "/login", nil)
		r.RemoteAddr = peer
		for i := 0; i+1 < len(header); i += 2 {
			r.Header.Set(header[i], header[i+1])
		}
		return r
	}
	for _, c := range []struct {
		r     *http.Request
		https bool
	}{
		{req("192.0.2.1:1"), false},
		{req("192.0.2.1:1", "Origin", "http://192.0.2.9:8090"), false},
		{req("192.0.2.1:1", "Origin", "https://dash.example"), true},
		{req("10.0.0.2:1", "X-Forwarded-Proto", "https"), true},
		{req("192.0.2.1:1", "X-Forwarded-Proto", "https"), false}, // not from a trusted proxy
	} {
		if got := RequestIsHTTPS(c.r, trusted); got != c.https {
			t.Errorf("%s %v: https %v", c.r.RemoteAddr, c.r.Header, got)
		}
	}
	plain := req("192.0.2.1:1")
	tls := req("192.0.2.1:1", "Origin", "https://dash.example")
	for _, c := range []struct {
		mode   CookieMode
		r      *http.Request
		secure bool
	}{
		{CookiesAuto, plain, false}, {CookiesAuto, tls, true},
		{CookiesSecure, plain, true}, {CookiesPlain, tls, false},
		{"", tls, true}, // the zero value is auto
	} {
		if got := c.mode.Secure(c.r); got != c.secure {
			t.Errorf("mode %q https %v: secure %v", c.mode, c.r == tls, got)
		}
	}

	// In auto mode, sign-in over plain HTTP sets a plain cookie, which identifies.
	h := newHarness(t, &Login{Method: MethodForm, Username: "ops", Hash: hash(t, "a good password")})
	h.l.Cookies = CookiesAuto
	h.signIn("ops", "a good password")
	if len(h.jar) != 1 || h.jar[0].Name != plainSessionCookie || h.jar[0].Secure {
		t.Fatalf("plain HTTP cookie %+v", h.jar)
	}
	if h.who() != "ops" {
		t.Fatal("the plain cookie does not identify")
	}
}

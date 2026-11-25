package auth

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
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

func TestParseUsers(t *testing.T) {
	file := "# admins\n\nalice:" + hash(t, "a-pass") + "\nZoë Smith:" +
		strings.Replace(hash(t, "z-pass"), "$2a$", "$2y$", 1) + "\n"
	u, err := ParseUsers(strings.NewReader(file))
	if err != nil {
		t.Fatal(err)
	}
	if u.Len() != 2 {
		t.Fatalf("%d users", u.Len())
	}
	for _, c := range []struct {
		name, pw string
		ok       bool
	}{
		{"alice", "a-pass", true},
		{"Zoë Smith", "z-pass", true}, // htpasswd -B writes $2y$
		{"alice", "z-pass", false},
		{"Alice", "a-pass", false},
		{"nobody", "a-pass", false},
		{"alice", "", false},
	} {
		if got := u.Check(c.name, c.pw); got != c.ok {
			t.Errorf("Check(%q, %q) = %v", c.name, c.pw, got)
		}
	}

	for name, bad := range map[string]string{
		"no colon":      "alice\n",
		"md5":           "alice:$apr1$abc$def\n",
		"sha1":          "alice:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=\n",
		"duplicate":     "alice:" + hash(t, "x") + "\nalice:" + hash(t, "y") + "\n",
		"empty":         "# nobody\n",
		"bad name":      "al\x01ice:" + hash(t, "x") + "\n",
		"broken bcrypt": "alice:$2a$10$tooshort\n",
	} {
		if _, err := ParseUsers(strings.NewReader(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestHashLine(t *testing.T) {
	line, err := HashLine("bob", "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	u, err := ParseUsers(strings.NewReader(line))
	if err != nil {
		t.Fatal(err)
	}
	if !u.Check("bob", "correct horse") {
		t.Fatal("the line does not check")
	}
	for _, c := range [][2]string{{"", "pw"}, {"a:b", "pw"}, {"bob", ""}, {"bob", strings.Repeat("x", 73)}} {
		if _, err := HashLine(c[0], c[1]); err == nil {
			t.Errorf("HashLine(%q, %q) accepted", c[0], c[1])
		}
	}
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

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestFormSignIn(t *testing.T) {
	users, _ := ParseUsers(strings.NewReader("alice:" + hash(t, "pw")))
	var lastView LoginView
	f := &Form{Users: users, Sessions: NewSessions(time.Hour, time.Hour), Throttle: NewThrottle(2), Secure: true,
		Log: discard(), Render: func(w http.ResponseWriter, r *http.Request, status int, v LoginView) {
			lastView = v
			w.WriteHeader(status)
		}}
	mux := http.NewServeMux()
	f.Routes(mux)
	post := func(form url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r = r.WithContext(WithClientIP(r.Context(), netip.MustParseAddr("192.0.2.1")))
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}

	// A session planted before sign-in is replaced, not adopted.
	planted := f.Sessions.Create("alice")
	w := post(url.Values{"name": {"alice"}, "password": {"pw"}, "next": {"/workers"}},
		&http.Cookie{Name: f.CookieName(), Value: planted})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/workers" {
		t.Fatalf("sign-in: %d %s", w.Code, w.Header().Get("Location"))
	}
	c := w.Result().Cookies()[0]
	if c.Name != "__Host-ipvalet-session" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode ||
		c.Path != "/" || c.Domain != "" || c.Value == planted {
		t.Fatalf("cookie %+v", c)
	}
	if _, ok := f.Sessions.Get(planted); ok {
		t.Fatal("the planted session survived sign-in")
	}

	// An open redirect is refused.
	w = post(url.Values{"name": {"alice"}, "password": {"pw"}, "next": {"//evil.example"}}, nil)
	if w.Header().Get("Location") != "/" {
		t.Fatalf("next: %s", w.Header().Get("Location"))
	}

	// Two failures spend the budget; then even the right password waits.
	for range 2 {
		if w := post(url.Values{"name": {"alice"}, "password": {"wrong"}}, nil); w.Code != http.StatusUnauthorized {
			t.Fatalf("wrong password: %d", w.Code)
		}
	}
	w = post(url.Values{"name": {"alice"}, "password": {"pw"}}, nil)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" || lastView.RetryAfter < 1 {
		t.Fatalf("throttled: %d %q %+v", w.Code, w.Header().Get("Retry-After"), lastView)
	}
}

func TestBasic(t *testing.T) {
	users, _ := ParseUsers(strings.NewReader("alice:" + hash(t, "pw")))
	b := &Basic{Users: users, Throttle: NewThrottle(2), Log: discard()}
	ip := netip.MustParseAddr("192.0.2.9")
	req := func(user, pw string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		if user != "" {
			r.SetBasicAuth(user, pw)
		}
		return r.WithContext(WithClientIP(r.Context(), ip))
	}
	if b.Identify(req("", "")) != nil {
		t.Fatal("identified without credentials")
	}
	if id := b.Identify(req("alice", "pw")); id == nil || id.Name != "alice" {
		t.Fatalf("identify: %+v", id)
	}
	if id := b.Identify(req("alice", "pw")); id == nil {
		t.Fatal("cached identity lost")
	}
	w := httptest.NewRecorder()
	b.Challenge(w, req("", ""))
	if w.Code != http.StatusUnauthorized || !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "Basic ") {
		t.Fatalf("challenge: %d %v", w.Code, w.Header())
	}
	for range 2 {
		if b.Identify(req("alice", "nope")) != nil {
			t.Fatal("wrong password accepted")
		}
	}
	// Throttled: even the right (cached) password is not checked.
	if b.Identify(req("alice", "pw")) != nil {
		t.Fatal("identified while throttled")
	}
	w = httptest.NewRecorder()
	b.Challenge(w, req("alice", "pw"))
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("throttled challenge: %d %v", w.Code, w.Header())
	}
}

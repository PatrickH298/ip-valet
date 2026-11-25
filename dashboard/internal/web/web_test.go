package web

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/PatrickH298/ip-valet/dashboard/internal/auth"
)

type nobody struct{}

func (nobody) Identify(*http.Request) *auth.Identity            { return nil }
func (nobody) Challenge(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(401) }
func (nobody) Routes(*http.ServeMux)                            {}
func (nobody) CanSignOut() bool                                 { return false }

func newTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(Options{Auth: nobody{}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestFlashIsSigned(t *testing.T) {
	s := newTestServer(t)
	w := httptest.NewRecorder()
	s.redirect(w, httptest.NewRequest("POST", "/x", nil), "/realms", &flash{Kind: "ok", Lines: []string{"Saved."}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/realms" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	c := w.Result().Cookies()[0]
	read := func(value string) *flash {
		r := httptest.NewRequest("GET", "/realms", nil)
		r.AddCookie(&http.Cookie{Name: c.Name, Value: value})
		return s.takeFlash(httptest.NewRecorder(), r)
	}
	if f := read(c.Value); f == nil || f.Lines[0] != "Saved." {
		t.Fatalf("flash %+v", f)
	}
	body, sig, _ := strings.Cut(c.Value, ".")
	if f := read(body[:len(body)-2] + "xx." + sig); f != nil {
		t.Fatalf("tampered flash accepted: %+v", f)
	}
	if f := read(body); f != nil {
		t.Fatal("unsigned flash accepted")
	}
	// Another server's key does not verify.
	if f := newTestServer(t).takeFlash(httptest.NewRecorder(), func() *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(c)
		return r
	}()); f != nil {
		t.Fatal("flash from another key accepted")
	}
}

func TestRedirectStaysOnSite(t *testing.T) {
	s := newTestServer(t)
	w := httptest.NewRecorder()
	s.redirect(w, httptest.NewRequest("POST", "/x", nil), "//evil.example", nil)
	if w.Header().Get("Location") != "/" {
		t.Fatalf("Location %q", w.Header().Get("Location"))
	}
}

func TestHidden(t *testing.T) {
	got := hidden(url.Values{"b": {"2"}, "a": {"1", "<x>"}, "confirm": {"yes"}}, "confirm")
	want := [][2]string{{"a", "1"}, {"a", "<x>"}, {"b", "2"}}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%v", got)
		}
	}
}

func TestSignedOutPagesChallenge(t *testing.T) {
	s := newTestServer(t)
	h := s.Handler()
	for _, path := range []string{"/", "/realms", "/keys"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 401 {
			t.Errorf("%s: %d", path, w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
	if w.Code != 200 {
		t.Fatalf("healthz: %d", w.Code)
	}
}

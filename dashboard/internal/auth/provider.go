package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// Provider is a way of signing in. Every provider yields the same Identity,
// so pages never depend on how someone signed in. An OpenID Connect provider
// fits the same shape: Routes adds its login and callback, Identify reads the
// session it creates, and Challenge redirects to its login.
type Provider interface {
	// Identify returns the person signed in on r, or nil.
	Identify(r *http.Request) *Identity
	// Challenge answers a request that has nobody signed in.
	Challenge(w http.ResponseWriter, r *http.Request)
	// Routes registers the provider's own handlers, such as a sign-in page.
	Routes(mux *http.ServeMux)
	// CanSignOut reports whether pages should offer a sign-out button that
	// posts to /logout.
	CanSignOut() bool
}

// LoginView is what the sign-in page shows.
type LoginView struct {
	Name       string // the name submitted, to fill the form again
	Next       string // where to go after signing in
	Error      string
	RetryAfter int // seconds, when the network is throttled
}

// LoginRenderer writes the sign-in page.
type LoginRenderer func(w http.ResponseWriter, r *http.Request, status int, v LoginView)

// Form signs people in with a name and password posted from a sign-in page,
// then keeps them signed in with a session cookie.
type Form struct {
	Users    *Users
	Sessions *Sessions
	Throttle *Throttle
	Secure   bool // Secure cookie with the __Host- prefix; needs HTTPS
	Log      *slog.Logger
	Render   LoginRenderer
}

// CookieName is the session cookie's name.
func (f *Form) CookieName() string {
	if f.Secure {
		return "__Host-ipvalet-session"
	}
	return "ipvalet-session"
}

func (f *Form) Identify(r *http.Request) *Identity {
	c, err := r.Cookie(f.CookieName())
	if err != nil || c.Value == "" {
		return nil
	}
	name, ok := f.Sessions.Get(c.Value)
	if !ok {
		return nil
	}
	return &Identity{Name: name}
}

func (f *Form) Challenge(w http.ResponseWriter, r *http.Request) {
	next := "/"
	if r.Method == http.MethodGet {
		next = r.URL.RequestURI()
	}
	target := "/login"
	if next != "/" {
		target += "?next=" + url.QueryEscape(next)
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (f *Form) CanSignOut() bool { return true }

func (f *Form) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", f.loginPage)
	mux.HandleFunc("POST /login", f.login)
	mux.HandleFunc("POST /logout", f.logout)
}

func (f *Form) loginPage(w http.ResponseWriter, r *http.Request) {
	next := SafeNext(r.URL.Query().Get("next"))
	if f.Identify(r) != nil {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	f.Render(w, r, http.StatusOK, LoginView{Next: next})
}

func (f *Form) login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	name, password := r.PostForm.Get("name"), r.PostForm.Get("password")
	next := SafeNext(r.PostForm.Get("next"))
	ip := ClientIPFrom(r.Context())
	if wait, blocked := f.Throttle.Blocked(ip); blocked {
		secs := retrySeconds(wait)
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		f.Render(w, r, http.StatusTooManyRequests, LoginView{Name: name, Next: next, RetryAfter: secs,
			Error: fmt.Sprintf("Too many failed sign-ins from your network. Try again in %d seconds.", secs)})
		return
	}
	if !f.Users.Check(name, password) {
		f.failed(ip, name)
		f.Render(w, r, http.StatusUnauthorized, LoginView{Name: name, Next: next, Error: "Wrong user name or password."})
		return
	}
	// A new id at every sign-in, so a cookie planted beforehand is worthless.
	if old, err := r.Cookie(f.CookieName()); err == nil {
		f.Sessions.Delete(old.Value)
	}
	id := f.Sessions.Create(name)
	http.SetCookie(w, &http.Cookie{Name: f.CookieName(), Value: id, Path: "/", HttpOnly: true, Secure: f.Secure,
		SameSite: http.SameSiteLaxMode})
	f.Log.Info("signed in", "user", name, "client_ip", ip.String())
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (f *Form) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(f.CookieName()); err == nil {
		if name, ok := f.Sessions.Get(c.Value); ok {
			f.Log.Info("signed out", "user", name, "client_ip", ClientIPFrom(r.Context()).String())
		}
		f.Sessions.Delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: f.CookieName(), Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: f.Secure, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (f *Form) failed(ip netip.Addr, name string) {
	f.Log.Warn("sign-in failed", "user", name, "client_ip", ip.String())
	if f.Throttle.Fail(ip) {
		f.Log.Warn("sign-in attempts from this network are refused until its budget refills",
			"network", NetworkOf(ip).String())
	}
}

// Basic signs people in with HTTP basic auth on every request. Successful
// checks are remembered for a few minutes so bcrypt does not run on every
// page. Browsers keep the credentials until they close, so there is no
// sign-out.
type Basic struct {
	Users    *Users
	Throttle *Throttle
	Log      *slog.Logger

	once  sync.Once
	mu    sync.Mutex
	key   []byte                 // HMAC key for the cache, so it holds nothing guessable
	cache map[[32]byte]time.Time // HMAC(name, password) -> valid until
	now   func() time.Time
}

const (
	basicCacheFor = 5 * time.Minute
	basicCacheMax = 1000
)

func (b *Basic) init() {
	b.once.Do(func() {
		b.key = randomBytes(32)
		b.cache = map[[32]byte]time.Time{}
		if b.now == nil {
			b.now = time.Now
		}
	})
}

func (b *Basic) Identify(r *http.Request) *Identity {
	b.init()
	name, password, ok := r.BasicAuth()
	if !ok {
		return nil
	}
	ip := ClientIPFrom(r.Context())
	if _, blocked := b.Throttle.Blocked(ip); blocked {
		return nil
	}
	mac := hmac.New(sha256.New, b.key)
	mac.Write([]byte(name))
	mac.Write([]byte{0})
	mac.Write([]byte(password))
	var sum [32]byte
	copy(sum[:], mac.Sum(nil))
	now := b.now()
	b.mu.Lock()
	until, cached := b.cache[sum]
	b.mu.Unlock()
	if cached && now.Before(until) {
		return &Identity{Name: name}
	}
	if !b.Users.Check(name, password) {
		b.Log.Warn("sign-in failed", "user", name, "client_ip", ip.String())
		if b.Throttle.Fail(ip) {
			b.Log.Warn("sign-in attempts from this network are refused until its budget refills",
				"network", NetworkOf(ip).String())
		}
		return nil
	}
	b.mu.Lock()
	if len(b.cache) >= basicCacheMax {
		clear(b.cache)
	}
	b.cache[sum] = now.Add(basicCacheFor)
	b.mu.Unlock()
	return &Identity{Name: name}
}

func (b *Basic) Challenge(w http.ResponseWriter, r *http.Request) {
	if wait, blocked := b.Throttle.Blocked(ClientIPFrom(r.Context())); blocked {
		w.Header().Set("Retry-After", strconv.Itoa(retrySeconds(wait)))
		http.Error(w, "Too many failed sign-ins from your network. Try again later.", http.StatusTooManyRequests)
		return
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="ip-valet dashboard", charset="UTF-8"`)
	http.Error(w, "Sign in to use the ip-valet dashboard.", http.StatusUnauthorized)
}

func (b *Basic) Routes(*http.ServeMux) {}

func (b *Basic) CanSignOut() bool { return false }

func retrySeconds(d time.Duration) int {
	return max(1, int(math.Ceil(d.Seconds())))
}

package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Provider is a way of signing in. Every provider yields the same Identity,
// so pages never depend on how someone signed in. External sign-in (OpenID
// Connect) fits the same shape: Routes adds its login and callback, Identify
// reads the session it creates, and Challenge redirects to its login.
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
	RetryAfter int  // seconds, when the network is throttled
	Default    bool // the default login is still in use
}

// LoginRenderer writes the sign-in page.
type LoginRenderer func(w http.ResponseWriter, r *http.Request, status int, v LoginView)

// Local signs in the one local login, by form or by basic auth as the login
// says. Form sign-in keeps a session cookie; basic auth checks every request
// and remembers good credentials for a few minutes, so bcrypt does not run
// on every page.
type Local struct {
	Store    *Store
	Sessions *Sessions
	Throttle *Throttle
	Secure   bool // Secure cookie with the __Host- prefix; needs HTTPS
	Log      *slog.Logger
	Render   LoginRenderer

	once  sync.Once
	mu    sync.Mutex
	key   []byte                 // HMAC key for the basic-auth cache, so it holds nothing guessable
	cache map[[32]byte]time.Time // HMAC(name, password) -> valid until
}

const (
	basicCacheFor = 5 * time.Minute
	basicCacheMax = 1000
)

func (l *Local) init() {
	l.once.Do(func() {
		l.key = randomBytes(32)
		l.cache = map[[32]byte]time.Time{}
	})
}

// CookieName is the session cookie's name.
func (l *Local) CookieName() string {
	if l.Secure {
		return "__Host-ipvalet-session"
	}
	return "ipvalet-session"
}

// check reports whether name and password are the login's. It always costs
// one bcrypt comparison.
func (l *Local) check(name, password string) bool {
	lg := l.Store.Login()
	pwOK := bcrypt.CompareHashAndPassword([]byte(lg.Hash), []byte(password)) == nil
	nameOK := subtle.ConstantTimeCompare([]byte(name), []byte(lg.Username)) == 1
	return pwOK && nameOK
}

func (l *Local) failed(ip netip.Addr, name string) {
	l.Log.Warn("sign-in failed", "user", name, "client_ip", ip.String())
	if l.Throttle.Fail(ip) {
		l.Log.Warn("sign-in attempts from this network are refused until its budget refills",
			"network", NetworkOf(ip).String())
	}
}

// Identify implements Provider.
func (l *Local) Identify(r *http.Request) *Identity {
	lg := l.Store.Login()
	if lg.Method == MethodBasic {
		return l.identifyBasic(r, lg.Username)
	}
	c, err := r.Cookie(l.CookieName())
	if err != nil || c.Value == "" {
		return nil
	}
	name, ok := l.Sessions.Get(c.Value)
	if !ok || name != lg.Username {
		return nil
	}
	return &Identity{Name: name}
}

func (l *Local) identifyBasic(r *http.Request, username string) *Identity {
	l.init()
	name, password, ok := r.BasicAuth()
	if !ok {
		return nil
	}
	ip := ClientIPFrom(r.Context())
	if _, blocked := l.Throttle.Blocked(ip); blocked {
		return nil
	}
	mac := hmac.New(sha256.New, l.key)
	mac.Write([]byte(name))
	mac.Write([]byte{0})
	mac.Write([]byte(password))
	var sum [32]byte
	copy(sum[:], mac.Sum(nil))
	now := time.Now()
	l.mu.Lock()
	until, cached := l.cache[sum]
	l.mu.Unlock()
	if cached && now.Before(until) && name == username {
		return &Identity{Name: name}
	}
	if !l.check(name, password) {
		l.failed(ip, name)
		return nil
	}
	l.mu.Lock()
	if len(l.cache) >= basicCacheMax {
		clear(l.cache)
	}
	l.cache[sum] = now.Add(basicCacheFor)
	l.mu.Unlock()
	return &Identity{Name: name}
}

// Challenge implements Provider.
func (l *Local) Challenge(w http.ResponseWriter, r *http.Request) {
	if l.Store.Login().Method == MethodBasic {
		if wait, blocked := l.Throttle.Blocked(ClientIPFrom(r.Context())); blocked {
			w.Header().Set("Retry-After", strconv.Itoa(retrySeconds(wait)))
			http.Error(w, "Too many failed sign-ins from your network. Try again later.", http.StatusTooManyRequests)
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="ip-valet dashboard", charset="UTF-8"`)
		http.Error(w, "Sign in to use the ip-valet dashboard.", http.StatusUnauthorized)
		return
	}
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

// CanSignOut implements Provider: browsers keep basic-auth credentials
// until they close, so only form sign-in can sign out.
func (l *Local) CanSignOut() bool { return l.Store.Login().Method == MethodForm }

// Routes implements Provider.
func (l *Local) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", l.loginPage)
	mux.HandleFunc("POST /login", l.login)
	mux.HandleFunc("POST /logout", l.logout)
}

func (l *Local) loginPage(w http.ResponseWriter, r *http.Request) {
	next := SafeNext(r.URL.Query().Get("next"))
	if l.Store.Login().Method != MethodForm || l.Identify(r) != nil {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	l.Render(w, r, http.StatusOK, LoginView{Next: next, Default: l.Store.IsDefault()})
}

func (l *Local) login(w http.ResponseWriter, r *http.Request) {
	if l.Store.Login().Method != MethodForm {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	name, password := r.PostForm.Get("name"), r.PostForm.Get("password")
	v := LoginView{Name: name, Next: SafeNext(r.PostForm.Get("next")), Default: l.Store.IsDefault()}
	if l.Secure && plainHTTPOrigin(r) {
		v.Error = "This page was loaded over plain HTTP, so your browser would not keep the sign-in cookie. " +
			"Open the dashboard over HTTPS (or http://localhost), or set IPVALET_DASHBOARD_SECURE_COOKIES=false."
		l.Render(w, r, http.StatusBadRequest, v)
		return
	}
	ip := ClientIPFrom(r.Context())
	if wait, blocked := l.Throttle.Blocked(ip); blocked {
		v.RetryAfter = retrySeconds(wait)
		w.Header().Set("Retry-After", strconv.Itoa(v.RetryAfter))
		v.Error = fmt.Sprintf("Too many failed sign-ins from your network. Try again in %d seconds.", v.RetryAfter)
		l.Render(w, r, http.StatusTooManyRequests, v)
		return
	}
	if !l.check(name, password) {
		l.failed(ip, name)
		v.Error = "Wrong user name or password."
		l.Render(w, r, http.StatusUnauthorized, v)
		return
	}
	// A new id at every sign-in, so a cookie planted beforehand is worthless.
	if old, err := r.Cookie(l.CookieName()); err == nil {
		l.Sessions.Delete(old.Value)
	}
	l.startSession(w, name)
	l.Log.Info("signed in", "user", name, "client_ip", ip.String())
	http.Redirect(w, r, v.Next, http.StatusSeeOther)
}

func (l *Local) startSession(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: l.CookieName(), Value: l.Sessions.Create(name), Path: "/", HttpOnly: true,
		Secure: l.Secure, SameSite: http.SameSiteLaxMode})
}

func (l *Local) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: l.CookieName(), Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: l.Secure, SameSite: http.SameSiteLaxMode})
}

func (l *Local) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(l.CookieName()); err == nil {
		if name, ok := l.Sessions.Get(c.Value); ok {
			l.Log.Info("signed out", "user", name, "client_ip", ClientIPFrom(r.Context()).String())
		}
		l.Sessions.Delete(c.Value)
	}
	l.clearCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// Change is a request to change the login, from the Account page.
type Change struct {
	Current     string // the current password, always required
	Method      string
	Username    string
	NewPassword string // empty keeps the password, except while it is the default
	Confirm     string
}

// ChangeErrors maps form fields to what is wrong with them.
type ChangeErrors map[string]string

func (e ChangeErrors) Error() string { return "the login was not changed" }

// ChangeLogin checks and saves a new login, then signs out every session.
// With form sign-in, the person making the change gets a new session; with
// basic auth, their browser asks for the new credentials.
func (l *Local) ChangeLogin(w http.ResponseWriter, r *http.Request, c Change) error {
	ip := ClientIPFrom(r.Context())
	if wait, blocked := l.Throttle.Blocked(ip); blocked {
		return ChangeErrors{"current": fmt.Sprintf("too many failed attempts; try again in %d seconds",
			retrySeconds(wait))}
	}
	cur := l.Store.Login()
	if bcrypt.CompareHashAndPassword([]byte(cur.Hash), []byte(c.Current)) != nil {
		l.failed(ip, cur.Username)
		return ChangeErrors{"current": "wrong password"}
	}
	errs := ChangeErrors{}
	next := Login{Method: c.Method, Username: strings.TrimSpace(c.Username), Hash: cur.Hash}
	if next.Method != MethodForm && next.Method != MethodBasic {
		errs["method"] = "choose form or basic"
	}
	if err := ValidName(next.Username); err != nil {
		errs["username"] = err.Error()
	}
	switch {
	case c.NewPassword == "" && l.Store.IsDefault():
		errs["new_password"] = "choose a new password to replace the default one"
	case c.NewPassword == "":
	default:
		if err := ValidPassword(c.NewPassword, next.Username); err != nil {
			errs["new_password"] = err.Error()
		} else if c.Confirm != c.NewPassword {
			errs["confirm"] = "does not match the new password"
		}
	}
	if len(errs) > 0 {
		return errs
	}
	if c.NewPassword != "" {
		h, err := HashPassword(c.NewPassword)
		if err != nil {
			return err
		}
		next.Hash = h
	}
	if err := l.Store.Save(next); err != nil {
		return err
	}
	l.Sessions.Clear()
	l.init()
	l.mu.Lock()
	clear(l.cache)
	l.mu.Unlock()
	if next.Method == MethodForm {
		l.startSession(w, next.Username)
	} else {
		l.clearCookie(w)
	}
	l.Log.Info("login changed", "user", next.Username, "previous_user", cur.Username, "method", next.Method,
		"password_changed", c.NewPassword != "", "client_ip", ip.String())
	return nil
}

// plainHTTPOrigin reports whether a browser posted from a plain-HTTP page on
// a host other than localhost, where it will not keep a Secure cookie.
func plainHTTPOrigin(r *http.Request) bool {
	o, err := url.Parse(r.Header.Get("Origin"))
	if err != nil || o.Scheme != "http" {
		return false
	}
	h := o.Hostname()
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return false
	}
	if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
		return false
	}
	return true
}

func retrySeconds(d time.Duration) int {
	return max(1, int(math.Ceil(d.Seconds())))
}

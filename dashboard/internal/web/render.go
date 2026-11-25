package web

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/PatrickH298/ip-valet/dashboard/internal/api"
	"github.com/PatrickH298/ip-valet/dashboard/internal/auth"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// styleVersion changes whenever the stylesheet does, so browsers may cache it forever.
var styleVersion = func() string {
	b, _ := staticFS.ReadFile("static/style.css")
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:6])
}()

func staticHandler() http.Handler {
	sub, _ := fs.Sub(staticFS, "static")
	files := http.StripPrefix("/static/", http.FileServerFS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("v") == styleVersion {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}

func (s *Server) parseTemplates() error {
	names, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return err
	}
	s.pages = map[string]*template.Template{}
	for _, n := range names {
		base := path.Base(n)
		if base == "layout.html" || base == "partials.html" {
			continue
		}
		t, err := template.New("layout.html").Funcs(s.funcs()).
			ParseFS(templateFS, "templates/layout.html", "templates/partials.html", n)
		if err != nil {
			return fmt.Errorf("%s: %w", base, err)
		}
		s.pages[strings.TrimSuffix(base, ".html")] = t
	}
	return nil
}

// view is what every page template receives.
type view struct {
	Title      string
	Section    string // highlighted in the navigation
	User       *auth.Identity
	CanSignOut bool
	Flash      *flash
	Style      string
	Version    string
	Data       any
}

// render writes a page. It consumes any flash message waiting in a cookie.
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, page, title, section string, data any) {
	t := s.pages[page]
	if t == nil {
		panic("no template " + page)
	}
	v := view{Title: title, Section: section, User: auth.IdentityFrom(r.Context()), CanSignOut: s.Auth.CanSignOut(),
		Style: "/static/style.css?v=" + styleVersion, Version: s.Version, Data: data}
	if f := s.takeFlash(w, r); f != nil {
		v.Flash = f
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout.html", v); err != nil {
		s.Log.Error("rendering page", "page", page, "error", err.Error())
		http.Error(w, "The page could not be rendered.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

type errorView struct {
	Heading string
	Message string
}

func (s *Server) errorPage(w http.ResponseWriter, r *http.Request, status int, heading, message string) {
	s.render(w, r, status, "error", heading, "", errorView{Heading: heading, Message: message})
}

// LoginRenderer renders the sign-in page for the form provider.
func (s *Server) LoginRenderer() auth.LoginRenderer {
	return func(w http.ResponseWriter, r *http.Request, status int, v auth.LoginView) {
		s.render(w, r, status, "login", "Sign in", "", v)
	}
}

// --- flash messages, carried across a redirect in a signed cookie

type flash struct {
	Kind  string   `json:"k"` // ok, warn or error
	Lines []string `json:"l"`
}

const flashCookie = "ipvalet-flash"

func (s *Server) sign(b []byte) string {
	m := hmac.New(sha256.New, s.flashKey)
	m.Write(b)
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// redirect sends the browser to target (a path on this site) after a
// change, with an optional message for the next page.
func (s *Server) redirect(w http.ResponseWriter, r *http.Request, target string, f *flash) {
	if f != nil && len(f.Lines) > 0 {
		for len(f.Lines) > 1 {
			if b, _ := json.Marshal(f); len(b) <= 2500 {
				break
			}
			f.Lines = f.Lines[:len(f.Lines)-1]
		}
		b, _ := json.Marshal(f)
		if len(b) > 2500 {
			b, _ = json.Marshal(&flash{Kind: f.Kind, Lines: []string{"Done."}})
		}
		val := base64.RawURLEncoding.EncodeToString(b) + "." + s.sign(b)
		http.SetCookie(w, &http.Cookie{Name: flashCookie, Value: val, Path: "/", HttpOnly: true,
			Secure: s.Cookies.Secure(r), SameSite: http.SameSiteLaxMode, MaxAge: 60})
	}
	http.Redirect(w, r, auth.SafeNext(target), http.StatusSeeOther)
}

func (s *Server) takeFlash(w http.ResponseWriter, r *http.Request) *flash {
	c, err := r.Cookie(flashCookie)
	if err != nil {
		return nil
	}
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: s.Cookies.Secure(r), SameSite: http.SameSiteLaxMode})
	body, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		return nil
	}
	b, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil || !hmac.Equal([]byte(sig), []byte(s.sign(b))) {
		return nil
	}
	var f flash
	if json.Unmarshal(b, &f) != nil {
		return nil
	}
	return &f
}

// done builds the message shown after a change: what happened, what the
// impact check enforced, and any warnings.
func done(msg string, x api.Extras) *flash {
	f := &flash{Kind: "ok", Lines: []string{msg}}
	if x.Enforced != nil && (x.Enforced.Removed > 0 || x.Enforced.Shortened > 0) {
		f.Lines = append(f.Lines, fmt.Sprintf("Entries removed: %d. Entries shortened: %d.",
			x.Enforced.Removed, x.Enforced.Shortened))
	}
	for _, wn := range x.Warnings {
		f.Kind = "warn"
		f.Lines = append(f.Lines, "Warning: "+wn.Message)
	}
	return f
}

// --- forms

// Form is a posted form, kept to fill the page again when the API refuses it.
type Form struct {
	Values url.Values
	Errors map[string]string // by field name, which matches the API's field names
	Error  string            // about the form as a whole
}

func newForm(v url.Values) *Form { return &Form{Values: v, Errors: map[string]string{}} }

// Get returns a field's value.
func (f *Form) Get(k string) string {
	if f == nil {
		return ""
	}
	return f.Values.Get(k)
}

// GetOr returns a field's value, or def when the form is empty.
func (f *Form) GetOr(k, def string) string {
	if f == nil || f.Values == nil {
		return def
	}
	return f.Values.Get(k)
}

// Checked reports whether a checkbox was ticked.
func (f *Form) Checked(k string) bool { return f != nil && f.Values.Get(k) == "on" }

// Has reports whether a multi-valued field holds v.
func (f *Form) Has(k, v string) bool {
	if f == nil {
		return false
	}
	for _, x := range f.Values[k] {
		if x == v {
			return true
		}
	}
	return false
}

// Err returns a field's error.
func (f *Form) Err(k string) string {
	if f == nil {
		return ""
	}
	return f.Errors[k]
}

// HasErrors reports whether the form failed.
func (f *Form) HasErrors() bool { return f != nil && (f.Error != "" || len(f.Errors) > 0) }

// refused fills the form from an API refusal of the request (400 or 409).
// It reports false for any other error, which the caller passes on.
func (f *Form) refused(err error) bool {
	var ae *api.Error
	if !errors.As(err, &ae) {
		return false
	}
	switch {
	case ae.Status == http.StatusBadRequest:
		for k, v := range ae.Fields {
			f.Errors[k] = v
		}
		if len(ae.Fields) == 0 {
			f.Error = describe(ae)
		}
		return true
	case ae.Code == "conflict":
		f.Error = "Something with that name already exists."
		return true
	}
	return false
}

// hidden lists a form's fields, except skip, for re-posting from a
// confirmation page.
func hidden(v url.Values, skip ...string) [][2]string {
	var out [][2]string
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
outer:
	for _, k := range keys {
		for _, sk := range skip {
			if k == sk {
				continue outer
			}
		}
		for _, val := range v[k] {
			out = append(out, [2]string{k, val})
		}
	}
	return out
}

// --- template functions

func (s *Server) funcs() template.FuncMap {
	return template.FuncMap{
		"ts":     s.formatTime,
		"ago":    relTime,
		"str":    func(p *string) string { return deref(p) },
		"num":    func(p *int, none string) string { return numOr(p, none) },
		"sel":    func(v string) string { return selector(v) },
		"join":   strings.Join,
		"short":  shortID,
		"json":   compactJSON,
		"add":    func(a, b int) int { return a + b },
		"plural": plural,
		"isTime": func(p *time.Time) bool { return p != nil },
		"now":    time.Now,
		"before": func(a *time.Time, b time.Time) bool { return a != nil && a.Before(b) },
		"query":  queryURL,
		"title":  titleCase,
		"dict":   dict,
		"effect": effectText,
		"single": func(list string) string { return listInfo[list][2] },
	}
}

// effectText says in words which rule an affected entry breaks.
func effectText(e string) string {
	switch e {
	case "unrouted":
		return "no worker matches it any more"
	case "ip_denied":
		return "an IP rule denies it"
	case "prefix_too_broad":
		return "its prefix is too broad"
	case "ttl_exceeded":
		return "its lifetime is too long"
	case "cap_exceeded":
		return "its user is over a cap"
	}
	return e
}

// dict builds a map from key, value pairs, for passing several values to a
// shared template.
func dict(kv ...any) (map[string]any, error) {
	if len(kv)%2 != 0 {
		return nil, errors.New("dict: odd number of arguments")
	}
	m := make(map[string]any, len(kv)/2)
	for i := 0; i < len(kv); i += 2 {
		k, ok := kv[i].(string)
		if !ok {
			return nil, errors.New("dict: keys must be strings")
		}
		m[k] = kv[i+1]
	}
	return m, nil
}

func (s *Server) formatTime(v any) string {
	var t time.Time
	switch x := v.(type) {
	case time.Time:
		t = x
	case *time.Time:
		if x == nil {
			return "—"
		}
		t = *x
	default:
		return ""
	}
	if t.IsZero() {
		return "—"
	}
	return t.In(s.Location).Format("2006-01-02 15:04:05 MST")
}

func relTime(v any) string {
	var t time.Time
	switch x := v.(type) {
	case time.Time:
		t = x
	case *time.Time:
		if x == nil {
			return "never"
		}
		t = *x
	default:
		return ""
	}
	d := time.Since(t)
	future := d < 0
	if future {
		d = -d
	}
	var s string
	switch {
	case d < time.Minute:
		s = "moments"
	case d < time.Hour:
		s = plural(int(d/time.Minute), "minute", "minutes")
	case d < 48*time.Hour:
		s = plural(int(d/time.Hour), "hour", "hours")
	default:
		s = plural(int(d/(24*time.Hour)), "day", "days")
	}
	if future {
		return "in " + s
	}
	return s + " ago"
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func numOr(p *int, none string) string {
	if p == nil {
		return none
	}
	return strconv.Itoa(*p)
}

func selector(v string) string {
	if v == "*" {
		return "any"
	}
	return v
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func compactJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil || string(b) == "{}" || string(b) == "null" {
		return ""
	}
	return string(b)
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// queryURL builds base?k=v&... from pairs, leaving out empty values.
func queryURL(base string, kv ...string) string {
	q := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			q.Set(kv[i], kv[i+1])
		}
	}
	if len(q) == 0 {
		return base
	}
	return base + "?" + q.Encode()
}

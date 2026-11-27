package web

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/httpx"
	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/idp"
	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/ipvalet"
	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/rules"
)

// Session cookie names. A Secure cookie takes the __Host- prefix.
const (
	secureSessionCookie = "__Host-ipvalet-sso-session"
	plainSessionCookie  = "ipvalet-sso-session"
)

func (s *Server) session(r *http.Request) (Session, bool) {
	for _, name := range []string{secureSessionCookie, plainSessionCookie} {
		if c, err := r.Cookie(name); err == nil && c.Value != "" {
			if sess, ok := s.Sessions.Get(c.Value); ok {
				return sess, true
			}
		}
	}
	return Session{}, false
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, id string) {
	secure := s.Cookies.Secure(r)
	name := plainSessionCookie
	if secure {
		name = secureSessionCookie
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: id, Path: "/", HttpOnly: true, Secure: secure,
		SameSite: http.SameSiteLaxMode})
}

func clearSessionCookies(w http.ResponseWriter) {
	for _, c := range []*http.Cookie{
		{Name: secureSessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode},
		{Name: plainSessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode},
	} {
		http.SetCookie(w, c)
	}
}

// login sends the person to the IdP, unless they are signed in already.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	next := httpx.SafeNext(r.URL.Query().Get("next"))
	if _, ok := s.session(r); ok {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	s.Provider.Begin(w, r, next)
}

// SignedIn is called once the IdP vouches for a person. Only people some
// rule takes get a session; anyone else is refused.
func (s *Server) SignedIn(w http.ResponseWriter, r *http.Request, id idp.Identity, next string) {
	ip := httpx.ClientIPFrom(r.Context()).String()
	if !rules.ValidName(id.User) {
		s.Log.Warn("sign-in refused: the user name cannot be used in the API", "user", id.User, "client_ip", ip)
		s.Fail(w, r, http.StatusForbidden, "No access",
			"Your user name cannot be used here (it must be 1 to 256 characters without control characters).")
		return
	}
	var groups []string
	for _, g := range id.Groups {
		if rules.Referenced(s.Rules, g) && !slices.Contains(groups, g) {
			groups = append(groups, g)
		}
	}
	grants := rules.Grants(s.Rules, rules.Identity{User: id.User, Groups: groups})
	if len(grants) == 0 {
		s.Log.Warn("sign-in refused: no rule takes this user or their groups", "user", id.User,
			"groups", strings.Join(id.Groups, ","), "client_ip", ip)
		s.noAccess(w, r, id.User)
		return
	}
	sid := s.Sessions.Create(id.User, groups)
	s.setSessionCookie(w, r, sid)
	s.Log.Info("signed in", "user", id.User, "groups", strings.Join(groups, ","),
		"realms", strings.Join(rules.Realms(grants), ","), "provider", s.Provider.Name(), "client_ip", ip)
	http.Redirect(w, r, httpx.SafeNext(next), http.StatusSeeOther)
}

func (s *Server) noAccess(w http.ResponseWriter, r *http.Request, user string) {
	clearSessionCookies(w)
	s.render(w, http.StatusForbidden, "message", "No access", "", messageView{
		Heading: "No access",
		Message: fmt.Sprintf("You are signed in as %s, but your account is not allowed to register addresses here. "+
			"If you need access, ask your administrator to add you to a group that has it.", user),
	})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if sess, ok := s.session(r); ok {
		s.Sessions.Delete(sess.ID)
		s.Log.Info("signed out", "user", sess.User)
	}
	clearSessionCookies(w)
	if s.LogoutURL != nil {
		http.Redirect(w, r, s.LogoutURL.String(), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/signed-out", http.StatusSeeOther)
}

func (s *Server) signedOut(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusOK, "message", "Signed out", "", messageView{
		Heading: "Signed out",
		Message: "You are signed out of this site. You may still be signed in to your organisation's sign-in service.",
		Link:    "Sign in again", LinkTo: "/",
	})
}

// --- the page

type slot struct {
	Family    string // ipv4 or ipv6
	Label     string // IPv4 or IPv6
	Addr      string // detected so far; "" = not yet
	Private   bool   // Addr is a private address
	DetectURL string // the script asks this host for the address
	Field     string // the subnet field's name
	Subnets   []int
	Default   int
}

type placeView struct {
	ID         string // the entry, for live updates
	Where      string
	State      string
	StateLabel string
	Expires    string
	Detail     string
}

type addressView struct {
	Prefix  string
	Places  []placeView
	updated time.Time
}

type ttlOption struct {
	Value, Label string
	Selected     bool
}

type manualView struct {
	TTLs                 []ttlOption
	DefaultV4, DefaultV6 int
	MaxV4, MaxV6         int
	Where                string
}

type homeView struct {
	User        string
	Message     template.HTML // the administrator's message, if any
	AutoSummary string        // where one click registers, and for how long
	Flash       *flash
	V4, V6      slot
	Token       string
	Manual      *manualView
	Addresses   []addressView
	ListError   string
}

func (s *Server) home(w http.ResponseWriter, r *http.Request, sess Session, grants []rules.Grant) {
	conn := httpx.ClientIPFrom(r.Context())
	v := homeView{User: sess.User, Message: s.message, Flash: s.Sessions.TakeFlash(sess.ID), Token: s.detectToken(sess)}
	v.V4 = slot{Family: "ipv4", Label: "IPv4", Field: "subnet_v4",
		Subnets: subnets(32, s.MaxSubnetV4, s.DefaultSubnetV4), Default: s.DefaultSubnetV4}
	v.V6 = slot{Family: "ipv6", Label: "IPv6", Field: "subnet_v6",
		Subnets: subnets(128, s.MaxSubnetV6, s.DefaultSubnetV6), Default: s.DefaultSubnetV6}
	private := conn.IsValid() && rules.IsPrivate(netip.PrefixFrom(conn, conn.BitLen()))
	switch {
	case conn.Is4():
		v.V4.Addr, v.V4.Private = conn.String(), private
	case conn.Is6():
		v.V6.Addr, v.V6.Private = conn.String(), private
	}
	if v.V4.Addr == "" && s.DetectV4 != nil {
		v.V4.DetectURL = s.DetectV4.String()
	}
	if v.V6.Addr == "" && s.DetectV6 != nil {
		v.V6.DetectURL = s.DetectV6.String()
	}
	where := placeNamer(grants)
	var auto []string
	for _, g := range grants {
		auto = append(auto, "in "+where(g.Realm, g.Group)+" for "+g.TTL.Human())
	}
	v.AutoSummary = "Registers them " + joinAnd(auto) + "."
	if manual := rules.Manual(grants); len(manual) > 0 {
		longest, def := manual[0].MaxTTL, manual[0].TTL
		var places []string
		for _, g := range manual {
			longest, def = rules.Longest(longest, g.MaxTTL), rules.Longest(def, g.TTL)
			places = append(places, where(g.Realm, g.Group))
		}
		v.Manual = &manualView{TTLs: ttlOptions(longest, def), DefaultV4: s.DefaultSubnetV4, DefaultV6: s.DefaultSubnetV6,
			MaxV4: s.MaxSubnetV4, MaxV6: s.MaxSubnetV6, Where: joinAnd(places)}
	}
	v.Addresses, v.ListError = s.addresses(r.Context(), sess.User, grants)
	s.render(w, http.StatusOK, "home", "Your addresses", sess.User, v)
}

type statusEntry struct {
	ID     string `json:"id"`
	State  string `json:"state"`
	Label  string `json:"label"`
	Detail string `json:"detail"`
}

// status answers GET /status with the state of each of the person's
// entries, for the page's script to update itself while workers apply them.
func (s *Server) status(w http.ResponseWriter, r *http.Request, sess Session, grants []rules.Grant) {
	addrs, problem := s.addresses(r.Context(), sess.User, grants)
	w.Header().Set("Content-Type", "application/json")
	if problem != "" {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": problem})
		return
	}
	entries := []statusEntry{}
	for _, a := range addrs {
		for _, p := range a.Places {
			entries = append(entries, statusEntry{ID: p.ID, State: p.State, Label: p.StateLabel, Detail: p.Detail})
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"entries": entries})
}

// addresses lists the person's live entries in the realms they may use,
// one row per address.
func (s *Server) addresses(ctx context.Context, user string, grants []rules.Grant) ([]addressView, string) {
	where := placeNamer(grants)
	byPrefix := map[string]*addressView{}
	for _, realm := range rules.Realms(grants) {
		entries, err := s.API.Entries(ctx, realm, user, "")
		if err != nil {
			_, msg := s.explain(err, realm, netip.Prefix{})
			return nil, "Your registered addresses cannot be shown right now: " + msg
		}
		for _, e := range entries {
			if e.User != user {
				continue
			}
			a := byPrefix[e.Prefix]
			if a == nil {
				a = &addressView{Prefix: e.Prefix}
				byPrefix[e.Prefix] = a
			}
			if e.UpdatedAt.After(a.updated) {
				a.updated = e.UpdatedAt
			}
			p := placeView{ID: e.ID, Where: where(e.Realm, e.Group), State: e.State, StateLabel: stateLabel(e.State),
				Expires: "No time limit", Detail: workerDetail(e)}
			if e.ExpiresAt != nil {
				p.Expires = "Until " + s.when(*e.ExpiresAt)
			}
			a.Places = append(a.Places, p)
		}
	}
	out := make([]addressView, 0, len(byPrefix))
	for _, a := range byPrefix {
		slices.SortFunc(a.Places, func(x, y placeView) int { return cmp.Compare(x.Where, y.Where) })
		out = append(out, *a)
	}
	slices.SortFunc(out, func(x, y addressView) int {
		if c := y.updated.Compare(x.updated); c != 0 {
			return c
		}
		return cmp.Compare(x.Prefix, y.Prefix)
	})
	return out, ""
}

// placeNamer names a realm and group for people: the realm alone, or with
// the group when the person has more than one group in that realm.
func placeNamer(grants []rules.Grant) func(realm, group string) string {
	groups := map[string][]string{}
	for _, g := range grants {
		groups[g.Realm] = append(groups[g.Realm], g.Group)
	}
	return func(realm, group string) string {
		if gs := groups[realm]; len(gs) == 1 && gs[0] == group {
			return realm
		}
		return realm + " (" + group + ")"
	}
}

// workerDetail says why workers refused an entry, when some did.
func workerDetail(e ipvalet.Entry) string {
	if e.State != "partial" && e.State != "rejected" {
		return ""
	}
	family := "IPv4"
	if p, err := netip.ParsePrefix(e.Prefix); err == nil && p.Addr().Is6() {
		family = "IPv6"
	}
	var parts []string
	for _, wk := range e.Workers {
		if wk.State == "rejected" {
			parts = append(parts, wk.Label+" "+workerReason(wk.Code, family)+".")
		}
	}
	return strings.Join(parts, " ")
}

// workerReason explains a worker's rejection code in words.
func workerReason(code, family string) string {
	switch code {
	case "prefix_too_broad":
		return "does not accept a subnet this wide"
	case "address_not_allowed":
		return "does not accept this kind of address"
	case "family_unsupported":
		return "does not take " + family + " addresses"
	case "capacity_exceeded":
		return "is full"
	case "no_matching_rule":
		return "is not set up to take this address"
	case "invalid":
		return "could not use this address"
	case "":
		return "did not accept it"
	}
	return "did not accept it (" + code + ")"
}

func stateLabel(state string) string {
	switch state {
	case "active":
		return "Active"
	case "pending":
		return "Being applied"
	case "partial":
		return "Partly applied"
	case "rejected":
		return "Refused"
	case "unrouted":
		return "Not in use"
	case "removing":
		return "Being removed"
	}
	return state
}

// subnets lists the prefix lengths offered, narrowest first: every length
// for IPv4, and the usual ones for IPv6.
func subnets(bits, widest, def int) []int {
	var out []int
	if bits == 32 {
		for n := 32; n >= widest; n-- {
			out = append(out, n)
		}
		return out
	}
	for _, n := range []int{128, 64, 60, 56, 52, 48, 44, 40, 36, 32} {
		if n >= widest {
			out = append(out, n)
		}
	}
	for _, n := range []int{def, widest} {
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	slices.SortFunc(out, func(a, b int) int { return b - a })
	return out
}

// ttlOptions lists lifetimes up to longest, selecting def.
func ttlOptions(longest, def rules.TTL) []ttlOption {
	var choices []rules.TTL
	for _, s := range []string{"1h", "4h", "12h", "1d", "3d", "7d", "14d", "30d", "90d", "365d"} {
		t, _ := rules.ParseTTL(s)
		if !rules.Longer(t, longest) {
			choices = append(choices, t)
		}
	}
	for _, t := range []rules.TTL{def, longest} {
		if !slices.Contains(choices, t) {
			choices = append(choices, t)
		}
	}
	slices.SortFunc(choices, func(a, b rules.TTL) int {
		switch {
		case rules.Longer(a, b):
			return 1
		case rules.Longer(b, a):
			return -1
		}
		return 0
	})
	var out []ttlOption
	for _, t := range choices {
		out = append(out, ttlOption{Value: t.String(), Label: t.Human(), Selected: t == def})
	}
	return out
}

func joinAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

// --- changes

func (s *Server) done(w http.ResponseWriter, r *http.Request, sess Session, f *flash) {
	s.Sessions.SetFlash(sess.ID, f)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func failFlash(title, line string) *flash {
	return &flash{Kind: "error", Title: title, Lines: []flashLine{{Text: line}}}
}

// registerDetected registers the detected addresses in every realm the
// person may use, each for its one-click lifetime.
func (s *Server) registerDetected(w http.ResponseWriter, r *http.Request, sess Session, grants []rules.Grant) {
	if err := r.ParseForm(); err != nil {
		s.Fail(w, r, http.StatusBadRequest, "Request refused", "The form could not be read.")
		return
	}
	v4, v6, stale := s.detected(r, sess)
	var prefixes []netip.Prefix
	if v4.IsValid() {
		prefixes = append(prefixes, netip.PrefixFrom(v4, subnetField(r, "subnet_v4", s.MaxSubnetV4, 32, s.DefaultSubnetV4)).Masked())
	}
	if v6.IsValid() {
		prefixes = append(prefixes, netip.PrefixFrom(v6, subnetField(r, "subnet_v6", s.MaxSubnetV6, 128, s.DefaultSubnetV6)).Masked())
	}
	if len(prefixes) == 0 {
		s.done(w, r, sess, failFlash("Nothing was registered", "No address was detected."))
		return
	}
	f := s.summarize(s.register(r.Context(), sess.User, grants, prefixes, func(g rules.Grant) rules.TTL { return g.TTL }, true),
		placeNamer(grants))
	if stale {
		f.Lines = append(f.Lines, flashLine{Text: "An address detected earlier had expired and was left out. " +
			"Reload the page to detect it again."})
		if f.Kind == "ok" {
			f.Kind = "warn"
		}
	}
	s.done(w, r, sess, f)
}

// subnetField reads a prefix length within [widest, bits], or def.
func subnetField(r *http.Request, name string, widest, bits, def int) int {
	n, err := strconv.Atoi(strings.TrimPrefix(strings.TrimSpace(r.PostForm.Get(name)), "/"))
	if err != nil || n < widest || n > bits {
		return def
	}
	return n
}

// registerManual registers an address the person typed in, in the realms
// where they may do that.
func (s *Server) registerManual(w http.ResponseWriter, r *http.Request, sess Session, grants []rules.Grant) {
	manual := rules.Manual(grants)
	if len(manual) == 0 {
		s.Fail(w, r, http.StatusForbidden, "Not allowed", "Your account may not enter addresses by hand.")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.Fail(w, r, http.StatusBadRequest, "Request refused", "The form could not be read.")
		return
	}
	p, problem := s.parseManual(r.PostForm.Get("address"))
	if problem != "" {
		s.done(w, r, sess, failFlash("Nothing was registered", problem))
		return
	}
	longest := manual[0].MaxTTL
	for _, g := range manual {
		longest = rules.Longest(longest, g.MaxTTL)
	}
	ttl, err := rules.ParseTTL(r.PostForm.Get("ttl"))
	if err != nil || rules.Longer(ttl, longest) {
		s.done(w, r, sess, failFlash("Nothing was registered", "Choose how long to keep the address, up to "+longest.Human()+"."))
		return
	}
	outcomes := s.register(r.Context(), sess.User, manual, []netip.Prefix{p},
		func(g rules.Grant) rules.TTL { return rules.Shortest(ttl, g.MaxTTL) }, false)
	for i, o := range outcomes {
		for _, g := range manual {
			if g.Realm == o.Realm && g.Group == o.Group && o.OK && rules.Longer(ttl, g.MaxTTL) {
				outcomes[i].Note = "for " + g.MaxTTL.Human() + ", the longest you may choose in " + g.Realm
			}
		}
	}
	s.done(w, r, sess, s.summarize(outcomes, placeNamer(grants)))
}

// parseManual reads a typed address or subnet, or says what is wrong.
func (s *Server) parseManual(raw string) (netip.Prefix, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Prefix{}, "Enter an address."
	}
	var p netip.Prefix
	if strings.Contains(raw, "/") {
		var err error
		if p, err = netip.ParsePrefix(raw); err != nil {
			return netip.Prefix{}, raw + " is not an address or subnet."
		}
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), max(p.Bits()-96, 0))
		}
	} else {
		a, err := netip.ParseAddr(raw)
		if err != nil || a.Zone() != "" {
			return netip.Prefix{}, raw + " is not an address."
		}
		a = a.Unmap()
		def := s.DefaultSubnetV6
		if a.Is4() {
			def = s.DefaultSubnetV4
		}
		p = netip.PrefixFrom(a, def)
	}
	a := p.Addr()
	if a.IsUnspecified() || a.IsMulticast() {
		return netip.Prefix{}, raw + " cannot be registered."
	}
	widest, label := s.MaxSubnetV6, "IPv6"
	if a.Is4() {
		widest, label = s.MaxSubnetV4, "IPv4"
	}
	if p.Bits() < widest {
		return netip.Prefix{}, fmt.Sprintf("%s subnets may be at most /%d here; /%d is wider.", label, widest, p.Bits())
	}
	return p.Masked(), ""
}

// revoke deletes the person's entries for one address in every realm they
// may use.
func (s *Server) revoke(w http.ResponseWriter, r *http.Request, sess Session, grants []rules.Grant) {
	if err := r.ParseForm(); err != nil {
		s.Fail(w, r, http.StatusBadRequest, "Request refused", "The form could not be read.")
		return
	}
	p, err := netip.ParsePrefix(strings.TrimSpace(r.PostForm.Get("prefix")))
	if err != nil {
		s.done(w, r, sess, failFlash("Nothing was revoked", "That is not an address."))
		return
	}
	p = p.Masked()
	var removed, problems []string
	for _, realm := range rules.Realms(grants) {
		entries, err := s.API.Entries(r.Context(), realm, sess.User, p.String())
		if err != nil {
			_, msg := s.explain(err, realm, p)
			problems = append(problems, realm+": "+msg)
			continue
		}
		gone := false
		for _, e := range entries {
			if e.User != sess.User || e.Prefix != p.String() {
				continue // only the person's own entries for this address
			}
			if _, err := s.API.DeleteEntry(r.Context(), e.ID); err != nil {
				if ae, ok := ipvalet.AsError(err); ok && ae.Status == http.StatusNotFound {
					continue // already gone
				}
				_, msg := s.explain(err, realm, p)
				problems = append(problems, realm+": "+msg)
				continue
			}
			gone = true
			s.Log.Info("revoked", "user", sess.User, "realm", realm, "group", e.Group, "prefix", e.Prefix)
		}
		if gone {
			removed = append(removed, realm)
		}
	}
	f := &flash{Kind: "ok", Title: "Revoked"}
	switch {
	case len(removed) > 0:
		f.Lines = append(f.Lines, flashLine{OK: true, Text: fmt.Sprintf("Revoked %s from %s. It may take a moment to "+
			"stop working.", p, joinAnd(removed))})
	case len(problems) == 0:
		f.Kind, f.Title = "warn", "Nothing was revoked"
		f.Lines = append(f.Lines, flashLine{Text: p.String() + " is not registered for you."})
	}
	for _, msg := range problems {
		f.Lines = append(f.Lines, flashLine{Text: msg})
		f.Kind = map[bool]string{true: "warn", false: "error"}[len(removed) > 0]
		if len(removed) == 0 {
			f.Title = "Nothing was revoked"
		}
	}
	s.done(w, r, sess, f)
}

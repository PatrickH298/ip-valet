// Package rules decides where a signed-in person may register addresses. A
// rule takes people by IdP user name and group (each a name or *), and names
// the realm their addresses go to, the group the entries carry in the API,
// the longest lifetime allowed (max_ttl), the lifetime a one-click
// registration asks for (ttl) and whether they may type in addresses
// themselves (manual). A person gets a grant from every rule that takes
// them; nobody else may sign in.
package rules

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Wildcard matches any user or group.
const Wildcard = "*"

// Rule grants matching people a realm.
type Rule struct {
	Name   string // from IPVALET_SSO_RULE_<NAME>, for logs
	Realm  string // an API realm; never *
	User   string // an IdP user name or *
	Group  string // an IdP group or *
	As     string // the group entries carry in the API; defaults to Group
	MaxTTL TTL    // the longest lifetime a person may ask for
	TTL    TTL    // the lifetime a one-click registration asks for; at most MaxTTL
	Manual bool   // the person may type in addresses
}

// Identity is a signed-in person as the IdP describes them.
type Identity struct {
	User   string
	Groups []string
}

// Grant is a realm and API group a person may register addresses in.
type Grant struct {
	Realm  string
	Group  string // the group the entries carry in the API
	MaxTTL TTL
	TTL    TTL
	Manual bool
	Rules  []string // the rules that grant it
}

// Key identifies a grant: one realm and API group.
func (g Grant) Key() string { return g.Realm + "\x00" + g.Group }

// Matches reports whether r takes id, and the API group its entries carry.
func (r Rule) Matches(id Identity) (string, bool) {
	if r.User != Wildcard && r.User != id.User {
		return "", false
	}
	if r.Group == Wildcard {
		return r.As, true
	}
	if !slices.Contains(id.Groups, r.Group) {
		return "", false
	}
	if r.As != "" {
		return r.As, true
	}
	return r.Group, true
}

// Grants returns what id may do, merged per realm and API group: several
// rules granting the same pair give the longest lifetimes, and manual entry
// if any of them allows it. They are sorted by realm, then group.
func Grants(rs []Rule, id Identity) []Grant {
	byKey := map[string]*Grant{}
	for _, r := range rs {
		group, ok := r.Matches(id)
		if !ok {
			continue
		}
		g := Grant{Realm: r.Realm, Group: group}
		cur := byKey[g.Key()]
		if cur == nil {
			g.MaxTTL, g.TTL, g.Manual, g.Rules = r.MaxTTL, r.TTL, r.Manual, []string{r.Name}
			byKey[g.Key()] = &g
			continue
		}
		cur.MaxTTL = Longest(cur.MaxTTL, r.MaxTTL)
		cur.TTL = Longest(cur.TTL, r.TTL)
		cur.Manual = cur.Manual || r.Manual
		cur.Rules = append(cur.Rules, r.Name)
	}
	out := make([]Grant, 0, len(byKey))
	for _, g := range byKey {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Realm != out[j].Realm {
			return out[i].Realm < out[j].Realm
		}
		return out[i].Group < out[j].Group
	})
	return out
}

// Realms lists the distinct realms of gs, in order.
func Realms(gs []Grant) []string {
	var out []string
	for _, g := range gs {
		if !slices.Contains(out, g.Realm) {
			out = append(out, g.Realm)
		}
	}
	return out
}

// Manual returns the grants that allow manual entry.
func Manual(gs []Grant) []Grant {
	var out []Grant
	for _, g := range gs {
		if g.Manual {
			out = append(out, g)
		}
	}
	return out
}

// Referenced reports whether any rule names group, so that only groups that
// matter need keeping.
func Referenced(rs []Rule, group string) bool {
	for _, r := range rs {
		if r.Group == group {
			return true
		}
	}
	return false
}

// Parse reads a rule from its environment value: space-separated key=value
// pairs, where a value with spaces is double-quoted. Keys: realm and max_ttl
// (required); user and group (default *); as (required when group is *);
// ttl (default max_ttl); manual (default no).
func Parse(name, s string) (Rule, error) {
	r := Rule{Name: name, User: Wildcard, Group: Wildcard}
	pairs, err := splitPairs(s)
	if err != nil {
		return r, err
	}
	seen := map[string]bool{}
	var maxTTL, ttl, manual string
	for _, kv := range pairs {
		k, v := kv[0], kv[1]
		if seen[k] {
			return r, fmt.Errorf("%s is given twice", k)
		}
		seen[k] = true
		switch k {
		case "realm":
			r.Realm = v
		case "user":
			r.User = v
		case "group":
			r.Group = v
		case "as":
			r.As = v
		case "max_ttl":
			maxTTL = v
		case "ttl":
			ttl = v
		case "manual":
			manual = strings.ToLower(v)
		default:
			return r, fmt.Errorf("unknown key %q (want realm, user, group, as, max_ttl, ttl, manual)", k)
		}
	}
	switch {
	case r.Realm == "":
		return r, errors.New("realm is required")
	case r.Realm == Wildcard:
		return r, errors.New("realm must name one realm; * is not allowed")
	case !ValidRealm(r.Realm):
		return r, fmt.Errorf("realm %q is not a realm name (lower-case letters, digits, '.', '_' and '-')", r.Realm)
	case r.User != Wildcard && !ValidName(r.User):
		return r, errors.New("user must be * or a name of 1 to 256 characters without control characters")
	case r.Group != Wildcard && !ValidName(r.Group):
		return r, errors.New("group must be * or a name of 1 to 256 characters without control characters")
	case seen["as"] && !ValidName(r.As):
		return r, errors.New("as must be a group name of 1 to 256 characters without control characters (not *)")
	case r.Group == Wildcard && r.As == "":
		return r, errors.New("as is required when group is * (it names the group the entries carry in the API)")
	case maxTTL == "":
		return r, errors.New("max_ttl is required (for example max_ttl=12h, or max_ttl=unlimited)")
	}
	if r.MaxTTL, err = ParseTTL(maxTTL); err != nil {
		return r, fmt.Errorf("max_ttl %v", err)
	}
	r.TTL = r.MaxTTL
	if ttl != "" {
		if r.TTL, err = ParseTTL(ttl); err != nil {
			return r, fmt.Errorf("ttl %v", err)
		}
		if Longer(r.TTL, r.MaxTTL) {
			return r, fmt.Errorf("ttl %s is longer than max_ttl %s", r.TTL, r.MaxTTL)
		}
	}
	switch manual {
	case "", "no", "false":
	case "yes", "true":
		r.Manual = true
	default:
		return r, errors.New("manual must be yes or no")
	}
	return r, nil
}

var realmPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ValidRealm reports whether s is a realm name the API accepts.
func ValidRealm(s string) bool { return realmPattern.MatchString(s) }

// ValidName reports whether s is a user or group name the API accepts: 1 to
// 256 characters of UTF-8, no control characters, and never *.
func ValidName(s string) bool {
	if s == Wildcard || !utf8.ValidString(s) {
		return false
	}
	if n := utf8.RuneCountInString(s); n < 1 || n > 256 {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

// --- lifetimes

// TTL is a lifetime in the API's syntax: a number of seconds, minutes,
// hours or days (at most 3650 days), or unlimited.
type TTL struct {
	Unlimited bool
	Seconds   int64
}

// MaxTTLSeconds is the longest finite lifetime, 3650 days.
const MaxTTLSeconds = 3650 * 86400

// Unlimited is a lifetime without end.
var Unlimited = TTL{Unlimited: true}

var ttlPattern = regexp.MustCompile(`^([0-9]{1,12})([smhd])$`)

// ParseTTL parses "unlimited" or a positive duration with unit s, m, h or
// d, at most 3650d.
func ParseTTL(s string) (TTL, error) {
	s = strings.TrimSpace(s)
	if s == "unlimited" {
		return Unlimited, nil
	}
	m := ttlPattern.FindStringSubmatch(s)
	if m == nil {
		return TTL{}, fmt.Errorf("%q must be unlimited or a duration such as 90m, 12h or 30d", s)
	}
	n, _ := strconv.ParseInt(m[1], 10, 64)
	mult := map[string]int64{"s": 1, "m": 60, "h": 3600, "d": 86400}[m[2]]
	if n <= 0 || n > MaxTTLSeconds/mult {
		return TTL{}, fmt.Errorf("%q must be longer than zero and at most 3650d", s)
	}
	return TTL{Seconds: n * mult}, nil
}

// Seconds returns a finite lifetime of n seconds.
func Seconds(n int64) TTL { return TTL{Seconds: n} }

// String renders t in the API's syntax, in the largest exact unit.
func (t TTL) String() string {
	switch {
	case t.Unlimited:
		return "unlimited"
	case t.Seconds%86400 == 0:
		return strconv.FormatInt(t.Seconds/86400, 10) + "d"
	case t.Seconds%3600 == 0:
		return strconv.FormatInt(t.Seconds/3600, 10) + "h"
	case t.Seconds%60 == 0:
		return strconv.FormatInt(t.Seconds/60, 10) + "m"
	}
	return strconv.FormatInt(t.Seconds, 10) + "s"
}

// Human renders t for people: "12 hours", "30 days", "no time limit".
func (t TTL) Human() string {
	unit := func(n int64, one string) string {
		if n == 1 {
			return "1 " + one
		}
		return strconv.FormatInt(n, 10) + " " + one + "s"
	}
	switch {
	case t.Unlimited:
		return "no time limit"
	case t.Seconds%86400 == 0:
		return unit(t.Seconds/86400, "day")
	case t.Seconds%3600 == 0:
		return unit(t.Seconds/3600, "hour")
	case t.Seconds%60 == 0:
		return unit(t.Seconds/60, "minute")
	}
	return unit(t.Seconds, "second")
}

// Duration is t as a time.Duration; 0 when unlimited.
func (t TTL) Duration() time.Duration {
	if t.Unlimited {
		return 0
	}
	return time.Duration(t.Seconds) * time.Second
}

// Longer reports whether a lasts longer than b.
func Longer(a, b TTL) bool {
	switch {
	case a.Unlimited:
		return !b.Unlimited
	case b.Unlimited:
		return false
	}
	return a.Seconds > b.Seconds
}

// Longest returns the longer of a and b.
func Longest(a, b TTL) TTL {
	if Longer(b, a) {
		return b
	}
	return a
}

// Shortest returns the shorter of a and b.
func Shortest(a, b TTL) TTL {
	if Longer(a, b) {
		return b
	}
	return a
}

// splitPairs splits space-separated key=value pairs; a value may be
// double-quoted (Go syntax) to hold spaces.
func splitPairs(s string) ([][2]string, error) {
	var out [][2]string
	i := 0
	for {
		for i < len(s) && unicode.IsSpace(rune(s[i])) {
			i++
		}
		if i >= len(s) {
			return out, nil
		}
		eq := strings.IndexByte(s[i:], '=')
		if eq <= 0 {
			return nil, fmt.Errorf("want key=value pairs, got %q", s[i:])
		}
		key := strings.ToLower(s[i : i+eq])
		if strings.IndexFunc(key, unicode.IsSpace) >= 0 {
			return nil, fmt.Errorf("want key=value pairs, got %q", s[i:i+eq])
		}
		i += eq + 1
		var val string
		if i < len(s) && s[i] == '"' {
			end := i + 1
			for end < len(s) && s[end] != '"' {
				if s[end] == '\\' {
					end++
				}
				end++
			}
			if end >= len(s) {
				return nil, fmt.Errorf("unterminated quote in %s", key)
			}
			v, err := strconv.Unquote(s[i : end+1])
			if err != nil {
				return nil, fmt.Errorf("bad quoted value for %s: %v", key, err)
			}
			val, i = v, end+1
		} else {
			start := i
			for i < len(s) && !unicode.IsSpace(rune(s[i])) {
				i++
			}
			val = s[start:i]
		}
		out = append(out, [2]string{key, val})
	}
}

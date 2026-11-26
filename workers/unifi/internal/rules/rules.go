// Package rules decides which UniFi list each entry goes into. A rule takes
// entries by realm (exact), user and group (a name or *), address family
// and address kind (public, private or both), and names the IPv4 and IPv6
// lists that receive them. An entry goes into the lists of every rule that
// takes it. Before any rule, the safety floor refuses addresses that never
// belong in a firewall list and prefixes broader than allowed.
package rules

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Families a rule takes.
const (
	FamilyIPv4 = "ipv4"
	FamilyIPv6 = "ipv6"
	FamilyBoth = "both"
)

// Address kinds a rule takes.
const (
	AddrPublic  = "public"
	AddrPrivate = "private"
	AddrBoth    = "both"
)

// Rule routes matching entries into UniFi lists.
type Rule struct {
	Name      string // from IPVALET_UNIFI_RULE_<NAME>, for logs
	Realm     string // exact; never *
	User      string // a name or *
	Group     string // a name or *
	Family    string // ipv4, ipv6 or both
	Addresses string // public, private or both
	IPv4List  string // list id or name; set when Family takes IPv4
	IPv6List  string // list id or name; set when Family takes IPv6
}

func (r Rule) takesFamily(v6 bool) bool {
	if v6 {
		return r.Family != FamilyIPv4
	}
	return r.Family != FamilyIPv6
}

func (r Rule) takesKind(k Kind) bool {
	switch r.Addresses {
	case AddrPublic:
		return k == Public
	case AddrPrivate:
		return k == Private
	}
	return k == Public || k == Private
}

func (r Rule) selects(realm, user, group string) bool {
	return r.Realm == realm && (r.User == "*" || r.User == user) && (r.Group == "*" || r.Group == group)
}

// List returns the list the rule sends a family to.
func (r Rule) List(v6 bool) string {
	if v6 {
		return r.IPv6List
	}
	return r.IPv4List
}

// Parse reads a rule from its environment value: space-separated key=value
// pairs, where a value with spaces is double-quoted. Keys: realm (required),
// user and group (default *), family (default both), addresses (default
// public), ipv4_list and ipv6_list (each required when family takes it).
func Parse(name, s string) (Rule, error) {
	r := Rule{Name: name, User: "*", Group: "*", Family: FamilyBoth, Addresses: AddrPublic}
	pairs, err := splitPairs(s)
	if err != nil {
		return r, err
	}
	seen := map[string]bool{}
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
		case "family":
			r.Family = strings.ToLower(v)
		case "addresses":
			r.Addresses = strings.ToLower(v)
		case "ipv4_list":
			r.IPv4List = v
		case "ipv6_list":
			r.IPv6List = v
		default:
			return r, fmt.Errorf("unknown key %q (want realm, user, group, family, addresses, ipv4_list, ipv6_list)", k)
		}
	}
	switch {
	case r.Realm == "":
		return r, fmt.Errorf("realm is required")
	case r.Realm == "*":
		return r, fmt.Errorf("realm must name one realm; * is not allowed")
	case r.User == "" || r.Group == "":
		return r, fmt.Errorf("user and group must be a name or *")
	}
	switch r.Family {
	case FamilyIPv4, FamilyIPv6, FamilyBoth:
	default:
		return r, fmt.Errorf("family must be ipv4, ipv6 or both")
	}
	switch r.Addresses {
	case AddrPublic, AddrPrivate, AddrBoth:
	default:
		return r, fmt.Errorf("addresses must be public, private or both")
	}
	if r.takesFamily(false) && r.IPv4List == "" {
		return r, fmt.Errorf("ipv4_list is required when family is %s", r.Family)
	}
	if r.takesFamily(true) && r.IPv6List == "" {
		return r, fmt.Errorf("ipv6_list is required when family is %s", r.Family)
	}
	if !r.takesFamily(false) && r.IPv4List != "" {
		return r, fmt.Errorf("ipv4_list is set but family is %s", r.Family)
	}
	if !r.takesFamily(true) && r.IPv6List != "" {
		return r, fmt.Errorf("ipv6_list is set but family is %s", r.Family)
	}
	return r, nil
}

// splitPairs splits `a=1 b="x y"` into pairs.
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

// --- addresses

// Kind classifies a prefix.
type Kind int

const (
	// Never: reserved space that never belongs in an allow list (loopback,
	// link-local, documentation, multicast...), or a prefix that spans
	// reserved and other space.
	Never Kind = iota
	// Private: inside RFC 1918, shared address space (100.64.0.0/10) or
	// IPv6 unique local addresses (fc00::/7).
	Private
	// Public: outside every reserved range.
	Public
)

func (k Kind) String() string {
	switch k {
	case Public:
		return "public"
	case Private:
		return "private"
	}
	return "reserved"
}

var (
	privateRanges = prefixes("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
	// The reserved ranges the API's seeded IP rules deny, mirrored here.
	reservedRanges = prefixes(
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/8", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16",
		"3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10", "ff00::/8",
	)
)

func prefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// Classify says whether p is public, private or reserved.
func Classify(p netip.Prefix) Kind {
	p = p.Masked()
	for _, r := range privateRanges {
		if r.Bits() <= p.Bits() && r.Contains(p.Addr()) {
			return Private
		}
	}
	for _, r := range reservedRanges {
		if r.Overlaps(p) {
			return Never
		}
	}
	return Public
}

// --- planning

// Floor is the safety floor: the broadest prefix accepted per family.
type Floor struct {
	MinV4 int
	MinV6 int
}

// Entry is one desired-state entry.
type Entry struct {
	Prefix    netip.Prefix
	ExpiresAt *time.Time
	Realm     string
	User      string
	Group     string
}

// Rejection is a prefix that is in no list, and why.
type Rejection struct {
	Prefix netip.Prefix
	Code   string
	Detail string
}

// Plan is what the lists should hold: list reference to prefixes, plus the
// prefixes that go into no list. Every list any rule names appears in Lists,
// possibly empty.
type Plan struct {
	Lists      map[string][]netip.Prefix
	Rejections []Rejection
	NextExpiry *time.Time // the earliest expiry still in the future
}

// reason ranks why an entry went into no list; lower is reported first.
type reason struct {
	rank   int
	code   string
	detail string
}

// Build places every live entry (unexpired at now) into the lists of the
// rules that take it. A prefix is rejected only when none of its entries
// went into any list; then the most telling reason among them is reported.
func Build(entries []Entry, rules []Rule, floor Floor, now time.Time) Plan {
	plan := Plan{Lists: map[string][]netip.Prefix{}}
	for _, r := range rules {
		if r.takesFamily(false) {
			plan.Lists[r.IPv4List] = nil
		}
		if r.takesFamily(true) {
			plan.Lists[r.IPv6List] = nil
		}
	}
	inList := map[string]map[netip.Prefix]bool{}
	placed := map[netip.Prefix]bool{}
	why := map[netip.Prefix]reason{}
	var order []netip.Prefix
	note := func(p netip.Prefix, r reason) {
		if old, ok := why[p]; !ok || r.rank < old.rank {
			why[p] = r
		}
	}
	for _, e := range entries {
		if e.ExpiresAt != nil && !e.ExpiresAt.After(now) {
			continue
		}
		if e.ExpiresAt != nil && (plan.NextExpiry == nil || e.ExpiresAt.Before(*plan.NextExpiry)) {
			t := *e.ExpiresAt
			plan.NextExpiry = &t
		}
		p := e.Prefix.Masked()
		if _, seen := why[p]; !seen && !placed[p] {
			order = append(order, p)
		}
		v6 := p.Addr().Is6()
		kind := Classify(p)
		if kind == Never {
			note(p, reason{0, "address_not_allowed", fmt.Sprintf("%s is reserved address space, never applied", p)})
			continue
		}
		min := floor.MinV4
		if v6 {
			min = floor.MinV6
		}
		if p.Bits() < min {
			note(p, reason{1, "prefix_too_broad", fmt.Sprintf("broader than /%d, the broadest this worker applies", min)})
			continue
		}
		matched := false
		for _, r := range rules {
			if !r.selects(e.Realm, e.User, e.Group) {
				continue
			}
			matched = true
			switch {
			case !r.takesFamily(v6):
				note(p, reason{2, "family_unsupported", fmt.Sprintf("rule %s takes only %s", r.Name, r.Family)})
			case !r.takesKind(kind):
				note(p, reason{3, "address_not_allowed", fmt.Sprintf("rule %s takes only %s addresses; this one is %s",
					r.Name, r.Addresses, kind)})
			default:
				list := r.List(v6)
				if inList[list] == nil {
					inList[list] = map[netip.Prefix]bool{}
				}
				if !inList[list][p] {
					inList[list][p] = true
					plan.Lists[list] = append(plan.Lists[list], p)
				}
				placed[p] = true
			}
		}
		if !matched {
			note(p, reason{4, "no_matching_rule", fmt.Sprintf("no rule takes realm %s, user %s, group %s",
				e.Realm, e.User, e.Group)})
		}
	}
	for _, p := range order {
		if placed[p] {
			continue
		}
		r := why[p]
		plan.Rejections = append(plan.Rejections, Rejection{Prefix: p, Code: r.code, Detail: truncate(r.detail, 200)})
	}
	for k := range plan.Lists {
		ps := plan.Lists[k]
		sort.Slice(ps, func(i, j int) bool { return ps[i].String() < ps[j].String() })
	}
	return plan
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return s[:cut]
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

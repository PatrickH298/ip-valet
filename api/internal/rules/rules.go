package rules

import (
	"fmt"
	"net/netip"
	"time"
)

// Rule list names, as used in URLs.
const (
	ListIP     = "ip"
	ListPrefix = "prefix"
	ListTTL    = "ttl"
	ListCap    = "cap"
)

// Lists is every rule list, in evaluation order.
var Lists = []string{ListIP, ListPrefix, ListTTL, ListCap}

// Submission result codes, in check order.
const (
	CodeRealmNotAllowed = "realm_not_allowed"
	CodeInvalidPrefix   = "invalid_prefix"
	CodeNoSubscriber    = "no_subscriber"
	CodeIPDenied        = "ip_denied"
	CodePrefixTooBroad  = "prefix_too_broad"
	CodeTTLExceeded     = "ttl_exceeded"
	CodeCapExceeded     = "cap_exceeded"
)

// Impact effect for an entry that no target matches any more.
const EffectUnrouted = "unrouted"

// IP rule actions.
const (
	ActionAccept = "accept"
	ActionDeny   = "deny"
)

// Base holds the columns every rule list shares.
type Base struct {
	ID          string
	Realm       string
	User        *string // nil = *
	Group       *string // nil = *
	Position    int
	Description *string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Matches is the selector test shared by subscriptions and rules.
func Matches(selRealm, selUser, selGroup *string, realm, user, group string) bool {
	return (selRealm == nil || *selRealm == realm) &&
		(selUser == nil || *selUser == user) &&
		(selGroup == nil || *selGroup == group)
}

func (b *Base) matches(s Subject) bool {
	return Matches(&b.Realm, b.User, b.Group, s.Realm, s.User, s.Group)
}

// IPRule accepts or denies prefixes.
type IPRule struct {
	Base
	Prefix netip.Prefix
	Action string
}

// PrefixRule limits how broad a prefix may be, per family. nil = no limit.
type PrefixRule struct {
	Base
	MinLenV4 *int
	MinLenV6 *int
}

// TTLRule limits the TTL. MaxTTLSeconds nil = unlimited allowed.
type TTLRule struct {
	Base
	MaxTTLSeconds *int64
}

// CapRule limits the number of distinct prefixes per user.
type CapRule struct {
	Base
	MaxPrefixes int
}

// Set is a realm's four rule lists, each ordered by position.
type Set struct {
	IP     []IPRule
	Prefix []PrefixRule
	TTL    []TTLRule
	Cap    []CapRule
}

// Subject is what a rule is evaluated against.
type Subject struct {
	Realm, User, Group string
	Prefix             netip.Prefix
}

// Limit carries the limit that a failed check enforced.
type Limit struct {
	MaxTTL       *string `json:"max_ttl,omitempty"`
	MinPrefixLen *int    `json:"min_prefix_len,omitempty"`
	MaxPrefixes  *int    `json:"max_prefixes,omitempty"`
}

// Failure is a failed check.
type Failure struct {
	Code  string
	Limit *Limit
	// MaxTTLSeconds is set for ttl_exceeded: the rule's max (never nil there).
	MaxTTLSeconds int64
}

// CheckIP: the first rule whose selector matches and whose prefix overlaps decides.
func (s *Set) CheckIP(sub Subject) *Failure {
	p := sub.Prefix
	for i := range s.IP {
		r := &s.IP[i]
		if !r.matches(sub) {
			continue
		}
		if r.Prefix.Addr().Is4() != p.Addr().Is4() || !r.Prefix.Overlaps(p) {
			continue
		}
		if r.Action == ActionDeny {
			return &Failure{Code: CodeIPDenied}
		}
		if r.Prefix.Bits() <= p.Bits() && r.Prefix.Contains(p.Addr()) {
			return nil
		}
		return &Failure{Code: CodeIPDenied} // an ACCEPT that only partly covers the prefix
	}
	return &Failure{Code: CodeIPDenied} // no rule matched: default deny
}

// CheckPrefix: the first selector match's limit for the prefix's family; no rule = ok.
func (s *Set) CheckPrefix(sub Subject) *Failure {
	for i := range s.Prefix {
		r := &s.Prefix[i]
		if !r.matches(sub) {
			continue
		}
		limit := r.MinLenV6
		if sub.Prefix.Addr().Is4() {
			limit = r.MinLenV4
		}
		if limit != nil && sub.Prefix.Bits() < *limit {
			n := *limit
			return &Failure{Code: CodePrefixTooBroad, Limit: &Limit{MinPrefixLen: &n}}
		}
		return nil
	}
	return nil
}

// TTLRuleFor returns the first TTL rule matching sub, or nil.
func (s *Set) TTLRuleFor(sub Subject) *TTLRule {
	for i := range s.TTL {
		if s.TTL[i].matches(sub) {
			return &s.TTL[i]
		}
	}
	return nil
}

func ttlFailure(max int64) *Failure {
	m := FormatSeconds(max)
	return &Failure{Code: CodeTTLExceeded, Limit: &Limit{MaxTTL: &m}, MaxTTLSeconds: max}
}

// CheckTTL checks a requested TTL.
func (s *Set) CheckTTL(sub Subject, ttl TTL) *Failure {
	r := s.TTLRuleFor(sub)
	if r == nil || r.MaxTTLSeconds == nil {
		return nil
	}
	if ttl.Unlimited || ttl.Seconds > *r.MaxTTLSeconds {
		return ttlFailure(*r.MaxTTLSeconds)
	}
	return nil
}

// CheckRemainingTTL checks an existing entry: its remaining lifetime
// (nil expiry = unlimited) must not exceed the max.
func (s *Set) CheckRemainingTTL(sub Subject, expiresAt *time.Time, now time.Time) *Failure {
	r := s.TTLRuleFor(sub)
	if r == nil || r.MaxTTLSeconds == nil {
		return nil
	}
	if expiresAt == nil || expiresAt.Sub(now) > time.Duration(*r.MaxTTLSeconds)*time.Second {
		return ttlFailure(*r.MaxTTLSeconds)
	}
	return nil
}

// CapIndex returns the index of the first cap rule matching sub, or -1.
func (s *Set) CapIndex(sub Subject) int {
	for i := range s.Cap {
		if s.Cap[i].matches(sub) {
			return i
		}
	}
	return -1
}

// Held is one of a user's live, unexpired entries in the realm.
type Held struct {
	Group  string
	Prefix netip.Prefix
}

// CheckCap: S = {candidate prefix} ∪ {prefix of every held entry of the same
// (realm, user) whose own first-matching cap rule is the candidate's}.
func (s *Set) CheckCap(sub Subject, held []Held) *Failure {
	c := s.CapIndex(sub)
	if c < 0 {
		return nil
	}
	set := map[netip.Prefix]struct{}{sub.Prefix: {}}
	for _, h := range held {
		hs := Subject{Realm: sub.Realm, User: sub.User, Group: h.Group, Prefix: h.Prefix}
		if s.CapIndex(hs) == c {
			set[h.Prefix] = struct{}{}
		}
	}
	if max := s.Cap[c].MaxPrefixes; len(set) > max {
		return &Failure{Code: CodeCapExceeded, Limit: &Limit{MaxPrefixes: &max}}
	}
	return nil
}

// CheckRules runs the IP, prefix, TTL and cap checks in order and returns the first failure.
func (s *Set) CheckRules(sub Subject, ttl TTL, held []Held) *Failure {
	if f := s.CheckIP(sub); f != nil {
		return f
	}
	if f := s.CheckPrefix(sub); f != nil {
		return f
	}
	if f := s.CheckTTL(sub, ttl); f != nil {
		return f
	}
	return s.CheckCap(sub, held)
}

// SeedDescription is the description given to seeded rules.
const SeedDescription = "seeded default"

// ReservedV4 and ReservedV6 are the ranges denied by a new realm's IP rules, in order.
var (
	ReservedV4 = []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	}
	ReservedV6 = []string{
		"::/8", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16",
		"3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10", "ff00::/8",
	}
)

// SeedDefaults are the IPVALET_DEFAULT_* values used when a realm is created.
type SeedDefaults struct {
	TTLSeconds int64
	PrefixV4   int
	PrefixV6   int
}

// Seed returns the default rules for a new realm.
func Seed(realm string, d SeedDefaults) Set {
	desc := SeedDescription
	base := func(pos int) Base {
		return Base{Realm: realm, Position: pos, Description: &desc}
	}
	var s Set
	pos := 1
	for _, list := range [][]string{ReservedV4, ReservedV6} {
		for _, c := range list {
			s.IP = append(s.IP, IPRule{Base: base(pos), Prefix: netip.MustParsePrefix(c), Action: ActionDeny})
			pos++
		}
	}
	s.IP = append(s.IP,
		IPRule{Base: base(pos), Prefix: netip.MustParsePrefix("0.0.0.0/0"), Action: ActionAccept},
		IPRule{Base: base(pos + 1), Prefix: netip.MustParsePrefix("::/0"), Action: ActionAccept},
	)
	v4, v6, ttl := d.PrefixV4, d.PrefixV6, d.TTLSeconds
	s.Prefix = []PrefixRule{{Base: base(1), MinLenV4: &v4, MinLenV6: &v6}}
	s.TTL = []TTLRule{{Base: base(1), MaxTTLSeconds: &ttl}}
	return s
}

// Item is the shape shared by every rule list for position and warning logic.
type Item struct {
	ID     string
	User   *string
	Group  *string
	Prefix *netip.Prefix // IP rules only
}

// IsCatchAll reports whether a rule is its list's catch-all: user and group
// "*" and, for IP rules, a /0 prefix.
func (it Item) IsCatchAll() bool {
	return it.User == nil && it.Group == nil && (it.Prefix == nil || it.Prefix.Bits() == 0)
}

// DefaultInsertPosition is where a rule without a position goes: immediately
// before the first catch-all, or at the end. Positions are 1-based.
func DefaultInsertPosition(list []Item) int {
	for i, it := range list {
		if it.IsCatchAll() {
			return i + 1
		}
	}
	return len(list) + 1
}

// Warning is a non-blocking notice returned with admin responses.
type Warning struct {
	Code           string `json:"code"`
	Message        string `json:"message"`
	RuleID         string `json:"rule_id,omitempty"`
	ShadowedBy     string `json:"shadowed_by,omitempty"`
	SubscriptionID string `json:"subscription_id,omitempty"`
}

// Warning codes.
const (
	WarnRuleShadowed       = "rule_shadowed"
	WarnCrossRealmSelector = "cross_realm_selector"
)

func fieldCovers(earlier, later *string) bool {
	return earlier == nil || (later != nil && *earlier == *later)
}

// covers reports whether a always decides before b could: its selector
// covers b's and, for IP rules, its prefix contains b's in the same family.
func covers(a, b Item) bool {
	if !fieldCovers(a.User, b.User) || !fieldCovers(a.Group, b.Group) {
		return false
	}
	if a.Prefix == nil || b.Prefix == nil {
		return a.Prefix == nil && b.Prefix == nil
	}
	ap, bp := *a.Prefix, *b.Prefix
	return ap.Addr().Is4() == bp.Addr().Is4() && ap.Bits() <= bp.Bits() && ap.Contains(bp.Addr())
}

// ShadowWarnings returns a rule_shadowed warning for every rule in the ordered
// list that an earlier rule always decides first.
func ShadowWarnings(list []Item) []Warning {
	var out []Warning
	for i := 1; i < len(list); i++ {
		for j := 0; j < i; j++ {
			if covers(list[j], list[i]) {
				out = append(out, Warning{
					Code: WarnRuleShadowed,
					Message: fmt.Sprintf("rule at position %d is shadowed by the rule at position %d, which always decides first",
						i+1, j+1),
					RuleID:     list[i].ID,
					ShadowedBy: list[j].ID,
				})
				break
			}
		}
	}
	return out
}

// CrossRealmWarning returns a warning for a subscription with realm "*" and a
// specific user or group, or nil.
func CrossRealmWarning(id string, realm, user, group *string) *Warning {
	if realm == nil && (user != nil || group != nil) {
		return &Warning{
			Code:           WarnCrossRealmSelector,
			Message:        `realm "*" with a specific user or group matches that name in every realm, where it may be a different person`,
			SubscriptionID: id,
		}
	}
	return nil
}

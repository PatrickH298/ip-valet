// Package rules holds the pure domain logic: name, TTL and prefix
// normalisation, selector matching, rule evaluation, realm seeding and
// rule warnings. Nothing here touches the database.
package rules

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Wildcard is the API spelling of a selector field that matches anything.
const Wildcard = "*"

var realmPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ValidRealm reports whether s is a valid realm name.
func ValidRealm(s string) bool { return realmPattern.MatchString(s) }

// ValidIdent reports whether s is a valid user or group name: 1 to 256
// characters, no control characters, and never "*".
func ValidIdent(s string) bool {
	if s == Wildcard || !utf8.ValidString(s) {
		return false
	}
	n := utf8.RuneCountInString(s)
	if n < 1 || n > 256 {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// ParseRealmSelector turns an API selector value into a stored one: "*" is nil.
func ParseRealmSelector(s string) (*string, error) {
	if s == Wildcard {
		return nil, nil
	}
	if !ValidRealm(s) {
		return nil, errors.New(`must be "*" or a realm name`)
	}
	return &s, nil
}

// ParseIdentSelector turns an API user or group selector into a stored one: "*" is nil.
func ParseIdentSelector(s string) (*string, error) {
	if s == Wildcard {
		return nil, nil
	}
	if !ValidIdent(s) {
		return nil, errors.New(`must be "*" or a name of 1 to 256 characters without control characters`)
	}
	return &s, nil
}

// SelectorString renders a stored selector field for the API: nil is "*".
func SelectorString(p *string) string {
	if p == nil {
		return Wildcard
	}
	return *p
}

// TTL is a requested or maximum lifetime. Unlimited is represented by Unlimited.
type TTL struct {
	Unlimited bool
	Seconds   int64
}

// MaxTTLSeconds is 3650 days.
const MaxTTLSeconds = 3650 * 86400

var ttlPattern = regexp.MustCompile(`^([0-9]{1,12})([smhd])$`)

// ParseTTL parses "unlimited" or a positive duration with unit s, m, h or d, at most 3650d.
func ParseTTL(s string) (TTL, error) {
	if s == "unlimited" {
		return TTL{Unlimited: true}, nil
	}
	m := ttlPattern.FindStringSubmatch(s)
	if m == nil {
		return TTL{}, errors.New(`must be "unlimited" or a positive duration such as 3600s, 90m, 36h or 30d`)
	}
	n, _ := strconv.ParseInt(m[1], 10, 64)
	mult := map[string]int64{"s": 1, "m": 60, "h": 3600, "d": 86400}[m[2]]
	if n <= 0 || n > MaxTTLSeconds/mult {
		return TTL{}, errors.New("must be greater than zero and at most 3650d")
	}
	return TTL{Seconds: n * mult}, nil
}

// String renders the TTL in the largest unit that divides it evenly.
func (t TTL) String() string {
	if t.Unlimited {
		return "unlimited"
	}
	return FormatSeconds(t.Seconds)
}

// FormatSeconds renders seconds as Nd, Nh, Nm or Ns, whichever is largest and exact.
func FormatSeconds(s int64) string {
	switch {
	case s%86400 == 0:
		return strconv.FormatInt(s/86400, 10) + "d"
	case s%3600 == 0:
		return strconv.FormatInt(s/3600, 10) + "h"
	case s%60 == 0:
		return strconv.FormatInt(s/60, 10) + "m"
	}
	return strconv.FormatInt(s, 10) + "s"
}

// FormatMaxTTL renders a stored max_ttl_seconds (nil = unlimited).
func FormatMaxTTL(p *int64) string {
	if p == nil {
		return "unlimited"
	}
	return FormatSeconds(*p)
}

// NormalizePrefix parses an address or prefix and returns its canonical form:
// IPv4-mapped IPv6 becomes IPv4, host bits are cleared, zones are rejected.
func NormalizePrefix(s string) (netip.Prefix, error) {
	var p netip.Prefix
	if strings.Contains(s, "/") {
		var err error
		p, err = netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid prefix")
		}
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("invalid address")
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("zoned addresses are not allowed")
	}
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, fmt.Errorf("an IPv4-mapped prefix must be /96 or longer")
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked(), nil
}

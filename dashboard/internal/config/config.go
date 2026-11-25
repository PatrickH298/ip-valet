// Package config reads the dashboard configuration from environment
// variables. There is no configuration file.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Config is the validated dashboard configuration.
type Config struct {
	ListenAddr string

	APIURL     *url.URL // the API server's admin listener, without a trailing slash
	APIKey     string   // the admin key the dashboard uses
	APITimeout time.Duration

	Auth          string // AuthForm or AuthBasic
	UsersFile     string
	SecureCookies bool
	SessionIdle   time.Duration
	SessionMax    time.Duration

	LoginFailuresPerMinute int            // per client network; 0 = off
	TrustedProxies         []netip.Prefix // peers whose X-Forwarded-For is believed

	Location        *time.Location
	ShutdownTimeout time.Duration
	LogLevel        slog.Level
}

// Sign-in methods.
const (
	AuthForm  = "form"
	AuthBasic = "basic"
)

// Getenv looks up an environment variable; os.LookupEnv in production.
type Getenv func(string) (string, bool)

// ReadFile reads a file; os.ReadFile in production.
type ReadFile func(string) ([]byte, error)

// FromEnvironment loads the configuration from the process environment.
func FromEnvironment() (Config, error) {
	return Load(os.LookupEnv, os.ReadFile)
}

var keyPattern = regexp.MustCompile(`^ipv_[a-z2-7]{16}_[a-z2-7]{52}$`)

type loader struct {
	get  Getenv
	read ReadFile
	errs []error
}

func (l *loader) fail(name, format string, args ...any) {
	l.errs = append(l.errs, fmt.Errorf("%s: %s", name, fmt.Sprintf(format, args...)))
}

func (l *loader) raw(name, def string) string {
	if v, ok := l.get(name); ok {
		return v
	}
	return def
}

// secret returns a secret variable from NAME or NAME_FILE (one trailing newline trimmed).
func (l *loader) secret(name string) (string, bool) {
	v, okV := l.get(name)
	f, okF := l.get(name + "_FILE")
	switch {
	case okV && okF:
		l.fail(name, "set either %s or %s_FILE, not both", name, name)
		return "", false
	case okF:
		b, err := l.read(f)
		if err != nil {
			l.fail(name+"_FILE", "cannot read file: %v", err)
			return "", false
		}
		s := strings.TrimSuffix(string(b), "\n")
		return strings.TrimSuffix(s, "\r"), true
	case okV:
		return v, true
	}
	return "", false
}

func (l *loader) positiveDuration(name, def string) time.Duration {
	d, err := ParseDuration(l.raw(name, def))
	switch {
	case err != nil:
		l.fail(name, "%v", err)
	case d <= 0:
		l.fail(name, "must be greater than zero")
	}
	return d
}

func (l *loader) intRange(name, def string, lo, hi int) int {
	n, err := strconv.Atoi(strings.TrimSpace(l.raw(name, def)))
	if err != nil || n < lo || n > hi {
		l.fail(name, "must be an integer between %d and %d", lo, hi)
		return 0
	}
	return n
}

func (l *loader) boolean(name, def string) bool {
	b, err := strconv.ParseBool(strings.TrimSpace(l.raw(name, def)))
	if err != nil {
		l.fail(name, "must be true or false")
	}
	return b
}

// Load builds a Config from getenv, reading _FILE variants with read.
func Load(getenv Getenv, read ReadFile) (Config, error) {
	l := &loader{get: getenv, read: read}
	var c Config

	c.ListenAddr = l.raw("IPVALET_DASHBOARD_LISTEN_ADDR", ":8090")
	if c.ListenAddr == "" {
		l.fail("IPVALET_DASHBOARD_LISTEN_ADDR", "must not be empty")
	}

	switch raw := strings.TrimSpace(l.raw("IPVALET_DASHBOARD_API_URL", "")); {
	case raw == "":
		l.fail("IPVALET_DASHBOARD_API_URL", "required (the API server's admin listener, for example http://api:8081)")
	default:
		u, err := url.Parse(strings.TrimSuffix(raw, "/"))
		switch {
		case err != nil:
			l.fail("IPVALET_DASHBOARD_API_URL", "%v", err)
		case u.Scheme != "http" && u.Scheme != "https":
			l.fail("IPVALET_DASHBOARD_API_URL", "must be an http or https URL")
		case u.Host == "":
			l.fail("IPVALET_DASHBOARD_API_URL", "must name a host")
		case u.User != nil || u.RawQuery != "" || u.Fragment != "":
			l.fail("IPVALET_DASHBOARD_API_URL", "must not carry credentials, a query or a fragment")
		default:
			c.APIURL = u
		}
	}
	if k, ok := l.secret("IPVALET_DASHBOARD_API_KEY"); ok {
		k = strings.TrimSpace(k)
		if !keyPattern.MatchString(k) {
			l.fail("IPVALET_DASHBOARD_API_KEY", "must be an ip-valet key (ipv_<16 base32>_<52 base32>)")
		}
		c.APIKey = k
	} else if _, viaFile := l.get("IPVALET_DASHBOARD_API_KEY_FILE"); !viaFile {
		// (An unreadable _FILE has already been reported.)
		l.fail("IPVALET_DASHBOARD_API_KEY", "required (an admin key; IPVALET_DASHBOARD_API_KEY_FILE is preferred)")
	}
	c.APITimeout = l.positiveDuration("IPVALET_DASHBOARD_API_TIMEOUT", "10s")

	c.Auth = strings.ToLower(strings.TrimSpace(l.raw("IPVALET_DASHBOARD_AUTH", AuthForm)))
	switch c.Auth {
	case AuthForm, AuthBasic:
		c.UsersFile = l.raw("IPVALET_DASHBOARD_USERS_FILE", "")
		if c.UsersFile == "" {
			l.fail("IPVALET_DASHBOARD_USERS_FILE", "required with IPVALET_DASHBOARD_AUTH=%s", c.Auth)
		}
	default:
		l.fail("IPVALET_DASHBOARD_AUTH", "must be form or basic")
	}
	c.SecureCookies = l.boolean("IPVALET_DASHBOARD_SECURE_COOKIES", "true")
	c.SessionIdle = l.positiveDuration("IPVALET_DASHBOARD_SESSION_IDLE", "30m")
	c.SessionMax = l.positiveDuration("IPVALET_DASHBOARD_SESSION_MAX", "12h")
	if c.SessionIdle > c.SessionMax && c.SessionMax > 0 {
		l.fail("IPVALET_DASHBOARD_SESSION_IDLE", "must not be longer than IPVALET_DASHBOARD_SESSION_MAX")
	}

	c.LoginFailuresPerMinute = l.intRange("IPVALET_DASHBOARD_LOGIN_FAILURES_PER_MINUTE", "10", 0, 100000)
	for _, f := range strings.Split(l.raw("IPVALET_DASHBOARD_TRUSTED_PROXIES", ""), ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		p, err := ParseNet(f)
		if err != nil {
			l.fail("IPVALET_DASHBOARD_TRUSTED_PROXIES", "%q is not an IP address or CIDR prefix", f)
			continue
		}
		c.TrustedProxies = append(c.TrustedProxies, p)
	}

	loc, err := time.LoadLocation(l.raw("IPVALET_DASHBOARD_TIMEZONE", "UTC"))
	if err != nil {
		l.fail("IPVALET_DASHBOARD_TIMEZONE", "unknown time zone")
	}
	c.Location = loc
	c.ShutdownTimeout = l.positiveDuration("IPVALET_DASHBOARD_SHUTDOWN_TIMEOUT", "15s")

	switch lv := strings.ToLower(l.raw("IPVALET_DASHBOARD_LOG_LEVEL", "info")); lv {
	case "debug":
		c.LogLevel = slog.LevelDebug
	case "info":
		c.LogLevel = slog.LevelInfo
	case "warn":
		c.LogLevel = slog.LevelWarn
	case "error":
		c.LogLevel = slog.LevelError
	default:
		l.fail("IPVALET_DASHBOARD_LOG_LEVEL", "must be debug, info, warn or error")
	}
	if len(l.errs) > 0 {
		return Config{}, errors.Join(l.errs...)
	}
	return c, nil
}

// ParseNet parses an IP address (as a single-address prefix) or a CIDR prefix.
func ParseNet(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), max(p.Bits()-96, 0))
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap().WithZone("")
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// ParseDuration parses Go duration syntax plus a "d" suffix for whole days ("30d").
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.ParseInt(days, 10, 64)
		if err != nil || n < 0 || n > 106751 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return d, nil
}

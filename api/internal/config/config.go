// Package config reads the server configuration from environment variables.
// There is no configuration file.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/PatrickH298/ip-valet/api/internal/auth"
)

// Config is the validated server configuration.
type Config struct {
	DatabaseURL     string
	DBMaxConns      int32
	ListenAddr      string
	AdminListenAddr string // "" = admin routes on ListenAddr
	MetricsAddr     string

	// Environment admin key: only its id and hash are held.
	AdminKeyID     string
	AdminKeyHash   []byte
	AdminKeySource string // "", "env" (IPVALET_ADMIN_KEY), "file" or "hash"

	DefaultTTL      time.Duration
	DefaultPrefixV4 int
	DefaultPrefixV6 int

	// Abuse protection.
	AuthFailuresPerMinute int            // failed-authentication budget per client network; 0 = off
	TrustedProxies        []netip.Prefix // peers whose X-Forwarded-For is believed
	MaxStreamsPerKey      int            // concurrent event streams per key, per instance

	RetentionEntries    time.Duration
	RetentionAudit      time.Duration
	PurgeInterval       time.Duration
	SSEHeartbeat        time.Duration
	ClientEventsRecheck time.Duration
	MaxBodyBytes        int64
	ShutdownTimeout     time.Duration
	LogLevel            slog.Level
}

// MaxTTL is the longest TTL accepted anywhere: 3650 days.
const MaxTTL = 3650 * 24 * time.Hour

// Getenv looks up an environment variable; os.LookupEnv in production.
type Getenv func(string) (string, bool)

// ReadFile reads a file; os.ReadFile in production.
type ReadFile func(string) ([]byte, error)

// FromEnvironment loads the configuration from the process environment.
func FromEnvironment() (Config, error) {
	return Load(os.LookupEnv, os.ReadFile)
}

type loader struct {
	get  Getenv
	read ReadFile
	errs []error
}

func (l *loader) fail(name, format string, args ...any) {
	l.errs = append(l.errs, fmt.Errorf("%s: %s", name, fmt.Sprintf(format, args...)))
}

// raw returns a plain variable's value, or def when unset.
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
		s := string(b)
		s = strings.TrimSuffix(s, "\n")
		s = strings.TrimSuffix(s, "\r")
		return s, true
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
	s := l.raw(name, def)
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < lo || n > hi {
		l.fail(name, "must be an integer between %d and %d", lo, hi)
		return 0
	}
	return n
}

// Load builds a Config from getenv, reading _FILE variants with read.
func Load(getenv Getenv, read ReadFile) (Config, error) {
	l := &loader{get: getenv, read: read}
	var c Config

	if v, ok := l.secret("IPVALET_DATABASE_URL"); ok && v != "" {
		c.DatabaseURL = v
	} else if len(l.errs) == 0 {
		l.fail("IPVALET_DATABASE_URL", "required")
	}
	c.DBMaxConns = int32(l.intRange("IPVALET_DB_MAX_CONNS", "10", 1, 1000))
	c.ListenAddr = l.raw("IPVALET_LISTEN_ADDR", ":8080")
	if c.ListenAddr == "" {
		l.fail("IPVALET_LISTEN_ADDR", "must not be empty")
	}
	c.MetricsAddr = l.raw("IPVALET_METRICS_ADDR", ":9090")
	c.AdminListenAddr = l.raw("IPVALET_ADMIN_LISTEN_ADDR", ":8081")
	if c.AdminListenAddr != "" && c.AdminListenAddr == c.ListenAddr {
		l.fail("IPVALET_ADMIN_LISTEN_ADDR", "must differ from IPVALET_LISTEN_ADDR; set it empty to serve admin routes there")
	}

	adminKey, haveKey := l.secret("IPVALET_ADMIN_KEY")
	adminHash, haveHash := l.get("IPVALET_ADMIN_KEY_HASH")
	switch {
	case haveKey && haveHash:
		l.fail("IPVALET_ADMIN_KEY_HASH", "set either IPVALET_ADMIN_KEY (or _FILE) or IPVALET_ADMIN_KEY_HASH, not both")
	case haveKey:
		k, err := auth.ParseKey(strings.TrimSpace(adminKey))
		if err != nil {
			l.fail("IPVALET_ADMIN_KEY", "%v", err)
		} else {
			c.AdminKeyID, c.AdminKeyHash = k.ID, k.Hash()
			c.AdminKeySource = "env"
			if _, viaFile := l.get("IPVALET_ADMIN_KEY_FILE"); viaFile {
				c.AdminKeySource = "file"
			}
		}
	case haveHash:
		id, h, err := auth.ParseHashLine(strings.TrimSpace(adminHash))
		if err != nil {
			l.fail("IPVALET_ADMIN_KEY_HASH", "%v", err)
		} else {
			c.AdminKeyID, c.AdminKeyHash = id, h
			c.AdminKeySource = "hash"
		}
	}

	c.DefaultTTL = l.positiveDuration("IPVALET_DEFAULT_TTL", "30d")
	if c.DefaultTTL > MaxTTL {
		l.fail("IPVALET_DEFAULT_TTL", "must be at most 3650d")
	}
	if c.DefaultTTL%time.Second != 0 {
		l.fail("IPVALET_DEFAULT_TTL", "must be a whole number of seconds")
	}
	c.DefaultPrefixV4 = l.intRange("IPVALET_DEFAULT_PREFIX_V4", "32", 0, 32)
	c.DefaultPrefixV6 = l.intRange("IPVALET_DEFAULT_PREFIX_V6", "64", 0, 128)
	c.AuthFailuresPerMinute = l.intRange("IPVALET_AUTH_FAILURES_PER_MINUTE", "10", 0, 100000)
	c.MaxStreamsPerKey = l.intRange("IPVALET_MAX_STREAMS_PER_KEY", "4", 1, 10000)
	if tp, err := ParseTrustedProxies(l.raw("IPVALET_TRUSTED_PROXIES", "")); err != nil {
		l.fail("IPVALET_TRUSTED_PROXIES", "%v", err)
	} else {
		c.TrustedProxies = tp
	}
	c.RetentionEntries = l.positiveDuration("IPVALET_RETENTION_ENTRIES", "90d")
	c.RetentionAudit = l.positiveDuration("IPVALET_RETENTION_AUDIT", "365d")
	c.PurgeInterval = l.positiveDuration("IPVALET_PURGE_INTERVAL", "1h")
	c.SSEHeartbeat = l.positiveDuration("IPVALET_SSE_HEARTBEAT", "20s")
	c.ClientEventsRecheck = l.positiveDuration("IPVALET_CLIENT_EVENTS_RECHECK", "30s")
	c.MaxBodyBytes = int64(l.intRange("IPVALET_MAX_BODY_BYTES", "65536", 1, 1<<30))
	c.ShutdownTimeout = l.positiveDuration("IPVALET_SHUTDOWN_TIMEOUT", "15s")

	switch lv := strings.ToLower(l.raw("IPVALET_LOG_LEVEL", "info")); lv {
	case "debug":
		c.LogLevel = slog.LevelDebug
	case "info":
		c.LogLevel = slog.LevelInfo
	case "warn":
		c.LogLevel = slog.LevelWarn
	case "error":
		c.LogLevel = slog.LevelError
	default:
		l.fail("IPVALET_LOG_LEVEL", "must be debug, info, warn or error")
	}
	if len(l.errs) > 0 {
		return Config{}, errors.Join(l.errs...)
	}
	return c, nil
}

// AllNetworks trusts every peer.
var AllNetworks = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}

// ParseTrustedProxies reads a trusted-proxy setting: unset, empty or "*"
// trusts every peer's X-Forwarded-For (the default); "none" trusts none, so
// the connection's peer is always the client; otherwise a comma-separated
// list of IP addresses and CIDR prefixes.
func ParseTrustedProxies(s string) ([]netip.Prefix, error) {
	switch s = strings.TrimSpace(s); strings.ToLower(s) {
	case "", "*":
		return AllNetworks, nil
	case "none":
		return nil, nil
	}
	var out []netip.Prefix
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		p, err := ParseNet(f)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP address or CIDR prefix (or use * or none)", f)
		}
		out = append(out, p)
	}
	return out, nil
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

// Package config reads the sso-web configuration from environment variables.
// There is no configuration file.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/httpx"
	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/rules"
)

// Sign-in providers.
const (
	ProviderOIDC = "oidc"
	ProviderSAML = "saml"
)

// OIDC configures OpenID Connect sign-in.
type OIDC struct {
	Issuer        string
	ClientID      string
	ClientSecret  string // empty for a public client (PKCE only)
	Scopes        []string
	UsernameClaim string
	GroupsClaim   string
}

// SAML configures SAML 2.0 sign-in.
type SAML struct {
	MetadataURL       *url.URL // the IdP's metadata, fetched at start
	Metadata          []byte   // or the IdP's metadata itself
	EntityID          string
	UsernameAttribute string // empty: the subject's NameID
	GroupsAttribute   string
	KeyPEM, CertPEM   string // optional SP key pair, to sign requests and decrypt assertions
}

// Config is the validated configuration.
type Config struct {
	ListenAddr       string
	DetectListenAddr string   // a second listener serving only address detection; "" = none
	PublicURL        *url.URL // where people reach the site, without a trailing slash
	Title            string
	Message          string // shown at the top of the page; "" = none

	APIURL     *url.URL // the API server's main listener
	APIKey     string   // a client key
	APITimeout time.Duration

	Provider string
	OIDC     OIDC
	SAML     SAML

	Rules []rules.Rule

	DetectV4URL, DetectV6URL *url.URL // family-only addresses of the detection endpoint

	DefaultSubnetV4, DefaultSubnetV6 int // prefix length offered first
	MaxSubnetV4, MaxSubnetV6         int // widest subnet a person may register, as a prefix length

	Cookies        httpx.CookieMode
	SessionIdle    time.Duration
	SessionMax     time.Duration
	TrustedProxies []netip.Prefix
	TrustAll       bool // every peer's X-Forwarded-For is believed (the default)
	LogoutURL      *url.URL

	Location        *time.Location
	ShutdownTimeout time.Duration
	LogLevel        slog.Level
}

// Getenv looks up an environment variable; os.LookupEnv in production.
type Getenv func(string) (string, bool)

// ReadFile reads a file; os.ReadFile in production.
type ReadFile func(string) ([]byte, error)

// Environ lists NAME=value pairs; os.Environ in production.
type Environ func() []string

// MaxMessage is the longest IPVALET_SSO_MESSAGE, in characters.
const MaxMessage = 4000

// RulePrefix starts the name of every rule variable.
const RulePrefix = "IPVALET_SSO_RULE_"

// FromEnvironment loads the configuration from the process environment.
func FromEnvironment() (Config, error) {
	return Load(os.LookupEnv, os.ReadFile, os.Environ)
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

// secret returns a variable from NAME or NAME_FILE (one trailing newline trimmed).
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

func (l *loader) required(name, why string) string {
	v := strings.TrimSpace(l.raw(name, ""))
	if v == "" {
		l.fail(name, "required (%s)", why)
	}
	return v
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

// httpURL parses an absolute http or https URL without credentials, query
// or fragment, and without a trailing slash.
func (l *loader) httpURL(name, raw string, pathAllowed bool) *url.URL {
	u, err := url.Parse(strings.TrimSuffix(strings.TrimSpace(raw), "/"))
	switch {
	case err != nil:
		l.fail(name, "%v", err)
	case u.Scheme != "http" && u.Scheme != "https":
		l.fail(name, "must be an http or https URL")
	case u.Host == "":
		l.fail(name, "must name a host")
	case u.User != nil || u.RawQuery != "" || u.Fragment != "":
		l.fail(name, "must not carry credentials, a query or a fragment")
	case !pathAllowed && u.Path != "":
		l.fail(name, "must not have a path (the site is served from /)")
	default:
		return u
	}
	return nil
}

// Load builds a Config from getenv, reading _FILE variants with read and
// finding rules with environ.
func Load(getenv Getenv, read ReadFile, environ Environ) (Config, error) {
	l := &loader{get: getenv, read: read}
	var c Config

	c.ListenAddr = l.raw("IPVALET_SSO_LISTEN_ADDR", ":8091")
	if c.ListenAddr == "" {
		l.fail("IPVALET_SSO_LISTEN_ADDR", "must not be empty")
	}
	c.DetectListenAddr = strings.TrimSpace(l.raw("IPVALET_SSO_DETECT_LISTEN_ADDR", ""))
	if raw := l.required("IPVALET_SSO_PUBLIC_URL", "where people reach this site, for example https://ip.example.com"); raw != "" {
		c.PublicURL = l.httpURL("IPVALET_SSO_PUBLIC_URL", raw, false)
	}
	c.Title = strings.TrimSpace(l.raw("IPVALET_SSO_TITLE", "ip-valet"))
	if c.Title == "" {
		l.fail("IPVALET_SSO_TITLE", "must not be empty")
	}
	if msg, ok := l.secret("IPVALET_SSO_MESSAGE"); ok {
		c.Message = strings.TrimSpace(strings.ReplaceAll(msg, "\r\n", "\n"))
		switch {
		case !utf8.ValidString(c.Message):
			l.fail("IPVALET_SSO_MESSAGE", "must be UTF-8 text")
		case utf8.RuneCountInString(c.Message) > MaxMessage:
			l.fail("IPVALET_SSO_MESSAGE", "must be at most %d characters", MaxMessage)
		}
	}

	if raw := l.required("IPVALET_SSO_API_URL", "the API server's main listener, for example http://api:8080"); raw != "" {
		c.APIURL = l.httpURL("IPVALET_SSO_API_URL", raw, true)
	}
	if k, ok := l.secret("IPVALET_SSO_API_KEY"); ok {
		k = strings.TrimSpace(k)
		if !keyPattern.MatchString(k) {
			l.fail("IPVALET_SSO_API_KEY", "must be an ip-valet key (ipv_<16 base32>_<52 base32>)")
		}
		c.APIKey = k
	} else if _, viaFile := l.get("IPVALET_SSO_API_KEY_FILE"); !viaFile {
		l.fail("IPVALET_SSO_API_KEY", "required (a client key whose client is bound to every realm the rules name)")
	}
	c.APITimeout = l.positiveDuration("IPVALET_SSO_API_TIMEOUT", "10s")

	c.Provider = strings.ToLower(l.required("IPVALET_SSO_PROVIDER", "oidc or saml"))
	switch c.Provider {
	case ProviderOIDC:
		l.loadOIDC(&c)
	case ProviderSAML:
		l.loadSAML(&c)
	case "":
	default:
		l.fail("IPVALET_SSO_PROVIDER", "must be oidc or saml")
	}

	// One rule per IPVALET_SSO_RULE_<NAME>, in name order.
	var names []string
	for _, kv := range environ() {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, RulePrefix) && len(name) > len(RulePrefix) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		v, _ := getenv(name)
		r, err := rules.Parse(strings.TrimPrefix(name, RulePrefix), v)
		if err != nil {
			l.fail(name, "%v", err)
			continue
		}
		c.Rules = append(c.Rules, r)
	}
	if len(names) == 0 {
		l.fail(RulePrefix+"<NAME>", "at least one rule is required (for example group=staff realm=office max_ttl=12h)")
	}

	if raw := strings.TrimSpace(l.raw("IPVALET_SSO_DETECT_V4_URL", "")); raw != "" {
		c.DetectV4URL = l.detectURL("IPVALET_SSO_DETECT_V4_URL", raw, c.PublicURL)
	}
	if raw := strings.TrimSpace(l.raw("IPVALET_SSO_DETECT_V6_URL", "")); raw != "" {
		c.DetectV6URL = l.detectURL("IPVALET_SSO_DETECT_V6_URL", raw, c.PublicURL)
	}
	c.MaxSubnetV4 = l.intRange("IPVALET_SSO_MAX_SUBNET_V4", "24", 0, 32)
	c.MaxSubnetV6 = l.intRange("IPVALET_SSO_MAX_SUBNET_V6", "48", 0, 128)
	c.DefaultSubnetV4 = l.intRange("IPVALET_SSO_DEFAULT_SUBNET_V4", "32", 0, 32)
	c.DefaultSubnetV6 = l.intRange("IPVALET_SSO_DEFAULT_SUBNET_V6", "64", 0, 128)
	if c.DefaultSubnetV4 < c.MaxSubnetV4 {
		l.fail("IPVALET_SSO_DEFAULT_SUBNET_V4", "/%d is wider than IPVALET_SSO_MAX_SUBNET_V4 (/%d)", c.DefaultSubnetV4, c.MaxSubnetV4)
	}
	if c.DefaultSubnetV6 < c.MaxSubnetV6 {
		l.fail("IPVALET_SSO_DEFAULT_SUBNET_V6", "/%d is wider than IPVALET_SSO_MAX_SUBNET_V6 (/%d)", c.DefaultSubnetV6, c.MaxSubnetV6)
	}

	switch v := httpx.CookieMode(strings.ToLower(strings.TrimSpace(l.raw("IPVALET_SSO_SECURE_COOKIES", "auto")))); v {
	case httpx.CookiesAuto, httpx.CookiesSecure, httpx.CookiesPlain:
		c.Cookies = v
	default:
		l.fail("IPVALET_SSO_SECURE_COOKIES", "must be auto, true or false")
	}
	c.SessionIdle = l.positiveDuration("IPVALET_SSO_SESSION_IDLE", "1h")
	c.SessionMax = l.positiveDuration("IPVALET_SSO_SESSION_MAX", "12h")
	if c.SessionIdle > c.SessionMax && c.SessionMax > 0 {
		l.fail("IPVALET_SSO_SESSION_IDLE", "must not be longer than IPVALET_SSO_SESSION_MAX")
	}
	if tp, all, err := httpx.ParseTrustedProxies(l.raw("IPVALET_SSO_TRUSTED_PROXIES", "")); err != nil {
		l.fail("IPVALET_SSO_TRUSTED_PROXIES", "%v", err)
	} else {
		c.TrustedProxies, c.TrustAll = tp, all
	}
	if raw := strings.TrimSpace(l.raw("IPVALET_SSO_LOGOUT_URL", "")); raw != "" {
		c.LogoutURL = l.httpURL("IPVALET_SSO_LOGOUT_URL", raw, true)
	}

	loc, err := time.LoadLocation(l.raw("IPVALET_SSO_TIMEZONE", "UTC"))
	if err != nil {
		l.fail("IPVALET_SSO_TIMEZONE", "unknown time zone")
	}
	c.Location = loc
	c.ShutdownTimeout = l.positiveDuration("IPVALET_SSO_SHUTDOWN_TIMEOUT", "15s")
	switch lv := strings.ToLower(l.raw("IPVALET_SSO_LOG_LEVEL", "info")); lv {
	case "debug":
		c.LogLevel = slog.LevelDebug
	case "info":
		c.LogLevel = slog.LevelInfo
	case "warn":
		c.LogLevel = slog.LevelWarn
	case "error":
		c.LogLevel = slog.LevelError
	default:
		l.fail("IPVALET_SSO_LOG_LEVEL", "must be debug, info, warn or error")
	}
	if len(l.errs) > 0 {
		return Config{}, errors.Join(l.errs...)
	}
	return c, nil
}

func (l *loader) loadOIDC(c *Config) {
	o := &c.OIDC
	if raw := l.required("IPVALET_SSO_OIDC_ISSUER", "the IdP's issuer URL"); raw != "" {
		if u := l.httpURL("IPVALET_SSO_OIDC_ISSUER", raw, true); u != nil {
			// The issuer must match the IdP's exactly, trailing slash included.
			o.Issuer = strings.TrimSpace(raw)
		}
	}
	o.ClientID = l.required("IPVALET_SSO_OIDC_CLIENT_ID", "the client id registered at the IdP")
	o.ClientSecret, _ = l.secret("IPVALET_SSO_OIDC_CLIENT_SECRET")
	o.ClientSecret = strings.TrimSpace(o.ClientSecret)
	o.Scopes = strings.Fields(l.raw("IPVALET_SSO_OIDC_SCOPES", "openid profile email groups"))
	hasOpenID := false
	for _, s := range o.Scopes {
		hasOpenID = hasOpenID || s == "openid"
	}
	if !hasOpenID {
		l.fail("IPVALET_SSO_OIDC_SCOPES", "must include openid")
	}
	o.UsernameClaim = strings.TrimSpace(l.raw("IPVALET_SSO_OIDC_USERNAME_CLAIM", "preferred_username"))
	o.GroupsClaim = strings.TrimSpace(l.raw("IPVALET_SSO_OIDC_GROUPS_CLAIM", "groups"))
	if o.UsernameClaim == "" {
		l.fail("IPVALET_SSO_OIDC_USERNAME_CLAIM", "must not be empty")
	}
	if o.GroupsClaim == "" {
		l.fail("IPVALET_SSO_OIDC_GROUPS_CLAIM", "must not be empty")
	}
}

func (l *loader) loadSAML(c *Config) {
	s := &c.SAML
	md, haveMD := l.secret("IPVALET_SSO_SAML_IDP_METADATA")
	mdURL := strings.TrimSpace(l.raw("IPVALET_SSO_SAML_IDP_METADATA_URL", ""))
	switch {
	case haveMD && mdURL != "":
		l.fail("IPVALET_SSO_SAML_IDP_METADATA_URL", "set either it or IPVALET_SSO_SAML_IDP_METADATA(_FILE), not both")
	case mdURL != "":
		s.MetadataURL = l.httpURL("IPVALET_SSO_SAML_IDP_METADATA_URL", mdURL, true)
	case haveMD:
		if strings.TrimSpace(md) == "" {
			l.fail("IPVALET_SSO_SAML_IDP_METADATA", "is empty")
		}
		s.Metadata = []byte(md)
	default:
		if _, viaFile := l.get("IPVALET_SSO_SAML_IDP_METADATA_FILE"); !viaFile {
			l.fail("IPVALET_SSO_SAML_IDP_METADATA_URL", "required (or IPVALET_SSO_SAML_IDP_METADATA_FILE with the IdP's metadata XML)")
		}
	}
	s.EntityID = strings.TrimSpace(l.raw("IPVALET_SSO_SAML_ENTITY_ID", ""))
	if s.EntityID == "" && c.PublicURL != nil {
		s.EntityID = c.PublicURL.String() + "/saml/metadata"
	}
	s.UsernameAttribute = strings.TrimSpace(l.raw("IPVALET_SSO_SAML_USERNAME_ATTRIBUTE", ""))
	s.GroupsAttribute = strings.TrimSpace(l.raw("IPVALET_SSO_SAML_GROUPS_ATTRIBUTE", "groups"))
	if s.GroupsAttribute == "" {
		l.fail("IPVALET_SSO_SAML_GROUPS_ATTRIBUTE", "must not be empty")
	}
	key, haveKey := l.secret("IPVALET_SSO_SAML_SP_KEY")
	cert, haveCert := l.secret("IPVALET_SSO_SAML_SP_CERT")
	if haveKey != haveCert {
		l.fail("IPVALET_SSO_SAML_SP_KEY", "set both IPVALET_SSO_SAML_SP_KEY and IPVALET_SSO_SAML_SP_CERT, or neither")
	}
	s.KeyPEM, s.CertPEM = key, cert
}

func (l *loader) detectURL(name, raw string, public *url.URL) *url.URL {
	u := l.httpURL(name, raw, true)
	if u == nil {
		return nil
	}
	if public != nil && public.Scheme == "https" && u.Scheme != "https" {
		l.fail(name, "must be https, like IPVALET_SSO_PUBLIC_URL (browsers block http requests from an https page)")
		return nil
	}
	if public != nil && u.Host == public.Host {
		l.fail(name, "must be a host other than IPVALET_SSO_PUBLIC_URL's, one reachable over a single address family")
		return nil
	}
	return u
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

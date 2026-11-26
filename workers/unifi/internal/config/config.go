// Package config reads the UniFi worker's configuration from environment
// variables. There is no configuration file.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/PatrickH298/ip-valet/workers/unifi/internal/rules"
)

// Config is the validated configuration.
type Config struct {
	APIURL *url.URL // the ip-valet API's main listener
	APIKey string   // the worker key

	ControllerURL *url.URL // the UniFi Network integration API
	ControllerKey string
	Site          string // site id or name
	VerifyTLS     bool

	Rules       []rules.Rule
	CreateLists bool
	Floor       rules.Floor

	SyncInterval time.Duration
	Timeout      time.Duration
	DataDir      string // "" keeps desired state in memory only
	Instance     string
	LogLevel     slog.Level
}

// RulePrefix starts the name of every rule variable.
const RulePrefix = "IPVALET_UNIFI_RULE_"

// Getenv looks up an environment variable; os.LookupEnv in production.
type Getenv func(string) (string, bool)

// ReadFile reads a file; os.ReadFile in production.
type ReadFile func(string) ([]byte, error)

// Environ lists NAME=value pairs; os.Environ in production.
type Environ func() []string

// FromEnvironment loads the configuration from the process environment.
func FromEnvironment() (Config, error) {
	return Load(os.LookupEnv, os.ReadFile, os.Environ, os.Hostname)
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

// secret returns NAME, or the contents of the file NAME_FILE names.
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

func (l *loader) url(name string, required bool) *url.URL {
	raw := strings.TrimSpace(l.raw(name, ""))
	if raw == "" {
		if required {
			l.fail(name, "required")
		}
		return nil
	}
	u, err := url.Parse(strings.TrimSuffix(raw, "/"))
	switch {
	case err != nil:
		l.fail(name, "%v", err)
	case u.Scheme != "http" && u.Scheme != "https":
		l.fail(name, "must be an http or https URL")
	case u.Host == "":
		l.fail(name, "must name a host")
	case u.User != nil || u.RawQuery != "" || u.Fragment != "":
		l.fail(name, "must not carry credentials, a query or a fragment")
	default:
		return u
	}
	return nil
}

func (l *loader) duration(name, def string, min time.Duration) time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(l.raw(name, def)))
	switch {
	case err != nil:
		l.fail(name, "invalid duration (for example 30s, 5m)")
	case d < min:
		l.fail(name, "must be at least %s", min)
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

// Load builds a Config.
func Load(getenv Getenv, read ReadFile, environ Environ, hostname func() (string, error)) (Config, error) {
	l := &loader{get: getenv, read: read}
	var c Config

	c.APIURL = l.url("IPVALET_UNIFI_API_URL", true)
	if k, ok := l.secret("IPVALET_UNIFI_API_KEY"); ok {
		c.APIKey = strings.TrimSpace(k)
		if !keyPattern.MatchString(c.APIKey) {
			l.fail("IPVALET_UNIFI_API_KEY", "must be an ip-valet worker key (ipv_<16 base32>_<52 base32>)")
		}
	} else if _, viaFile := l.get("IPVALET_UNIFI_API_KEY_FILE"); !viaFile {
		l.fail("IPVALET_UNIFI_API_KEY", "required (the worker key from the ip-valet API)")
	}

	c.ControllerURL = l.url("IPVALET_UNIFI_CONTROLLER_URL", true)
	if k, ok := l.secret("IPVALET_UNIFI_CONTROLLER_KEY"); ok {
		c.ControllerKey = strings.TrimSpace(k)
		if c.ControllerKey == "" {
			l.fail("IPVALET_UNIFI_CONTROLLER_KEY", "must not be empty")
		}
	} else if _, viaFile := l.get("IPVALET_UNIFI_CONTROLLER_KEY_FILE"); !viaFile {
		l.fail("IPVALET_UNIFI_CONTROLLER_KEY", "required (a UniFi Network API key)")
	}
	c.Site = strings.TrimSpace(l.raw("IPVALET_UNIFI_SITE", "Default"))
	if c.Site == "" {
		l.fail("IPVALET_UNIFI_SITE", "must not be empty")
	}
	c.VerifyTLS = l.boolean("IPVALET_UNIFI_VERIFY_TLS", "true")
	if !c.VerifyTLS && c.ControllerURL != nil && strings.EqualFold(c.ControllerURL.Hostname(), "api.ui.com") {
		l.fail("IPVALET_UNIFI_VERIFY_TLS", "must be true for the cloud connector (api.ui.com)")
	}

	// One rule per IPVALET_UNIFI_RULE_<NAME>, in name order.
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
		l.fail(RulePrefix+"<NAME>", "at least one rule is required")
	}
	c.CreateLists = l.boolean("IPVALET_UNIFI_CREATE_LISTS", "true")
	c.Floor.MinV4 = l.intRange("IPVALET_UNIFI_MIN_PREFIX_V4", "24", 0, 32)
	c.Floor.MinV6 = l.intRange("IPVALET_UNIFI_MIN_PREFIX_V6", "48", 0, 128)

	c.SyncInterval = l.duration("IPVALET_UNIFI_SYNC_INTERVAL", "1m", 5*time.Second)
	c.Timeout = l.duration("IPVALET_UNIFI_TIMEOUT", "15s", time.Second)
	c.DataDir = l.raw("IPVALET_UNIFI_DATA_DIR", "/data")
	c.Instance = strings.TrimSpace(l.raw("IPVALET_UNIFI_INSTANCE", ""))
	if c.Instance == "" {
		if h, err := hostname(); err == nil && h != "" {
			c.Instance = h
		} else {
			c.Instance = "unifi"
		}
	}
	if len(c.Instance) > 128 {
		l.fail("IPVALET_UNIFI_INSTANCE", "must be at most 128 characters")
	}

	switch lv := strings.ToLower(l.raw("IPVALET_UNIFI_LOG_LEVEL", "info")); lv {
	case "debug":
		c.LogLevel = slog.LevelDebug
	case "info":
		c.LogLevel = slog.LevelInfo
	case "warn":
		c.LogLevel = slog.LevelWarn
	case "error":
		c.LogLevel = slog.LevelError
	default:
		l.fail("IPVALET_UNIFI_LOG_LEVEL", "must be debug, info, warn or error")
	}
	if len(l.errs) > 0 {
		return Config{}, errors.Join(l.errs...)
	}
	return c, nil
}

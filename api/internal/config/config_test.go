package config

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PatrickH298/ip-valet/api/internal/auth"
)

func env(m map[string]string) Getenv {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func files(m map[string]string) ReadFile {
	return func(p string) ([]byte, error) {
		if v, ok := m[p]; ok {
			return []byte(v), nil
		}
		return nil, os.ErrNotExist
	}
}

func TestDefaults(t *testing.T) {
	c, err := Load(env(map[string]string{"IPVALET_DATABASE_URL": "postgres://x"}), files(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.DBMaxConns != 10 || c.ListenAddr != ":8080" || c.MetricsAddr != ":9090" || c.DefaultTTL != 30*24*time.Hour ||
		c.DefaultPrefixV4 != 32 || c.DefaultPrefixV6 != 64 || c.AuthFailuresPerMinute != 10 || c.AdminListenAddr != ":8081" || c.AdminKeySource != "" || c.MaxStreamsPerKey != 4 || c.TrustedProxies != nil ||
		c.RetentionEntries != 90*24*time.Hour || c.RetentionAudit != 365*24*time.Hour || c.PurgeInterval != time.Hour ||
		c.SSEHeartbeat != 20*time.Second || c.ClientEventsRecheck != 30*time.Second || c.MaxBodyBytes != 65536 ||
		c.ShutdownTimeout != 15*time.Second || c.AdminKeyID != "" {
		t.Fatalf("defaults = %+v", c)
	}
}

func TestSecretsAndErrors(t *testing.T) {
	key, _ := auth.NewKey()
	c, err := Load(env(map[string]string{
		"IPVALET_DATABASE_URL_FILE": "/run/db", "IPVALET_ADMIN_KEY_FILE": "/run/key", "IPVALET_METRICS_ADDR": "",
	}), files(map[string]string{"/run/db": "postgres://from-file\n", "/run/key": key.String() + "\n"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.DatabaseURL != "postgres://from-file" || c.AdminKeyID != key.ID || string(c.AdminKeyHash) != string(key.Hash()) || c.MetricsAddr != "" {
		t.Fatalf("got %+v", c)
	}

	bad := []map[string]string{
		{},
		{"IPVALET_DATABASE_URL": "x", "IPVALET_DATABASE_URL_FILE": "/run/db"},
		{"IPVALET_DATABASE_URL": "x", "IPVALET_DEFAULT_TTL": "0s"},
		{"IPVALET_DATABASE_URL": "x", "IPVALET_DEFAULT_TTL": "3651d"},
		{"IPVALET_DATABASE_URL": "x", "IPVALET_DEFAULT_PREFIX_V4": "33"},
		{"IPVALET_DATABASE_URL": "x", "IPVALET_LOG_LEVEL": "loud"},
		{"IPVALET_DATABASE_URL": "x", "IPVALET_PURGE_INTERVAL": "soon"},
		{"IPVALET_DATABASE_URL": "x", "IPVALET_ADMIN_KEY": "nope"},
		{"IPVALET_DATABASE_URL": "x", "IPVALET_ADMIN_KEY_HASH": "abc:def"},
		{"IPVALET_DATABASE_URL": "x", "IPVALET_ADMIN_KEY": key.String(), "IPVALET_ADMIN_KEY_HASH": auth.HashLine(key)},
	}
	for _, m := range bad {
		_, err := Load(env(m), files(map[string]string{"/run/db": "x"}))
		if err == nil {
			t.Errorf("%v accepted", m)
			continue
		}
		// The message names the variable.
		named := false
		for k := range m {
			if strings.Contains(err.Error(), strings.TrimSuffix(k, "_FILE")) {
				named = true
			}
		}
		if len(m) > 0 && !named {
			t.Errorf("%v: error %q does not name the variable", m, err)
		}
	}
	if _, err := Load(env(map[string]string{"IPVALET_DATABASE_URL_FILE": "/missing"}), files(nil)); err == nil ||
		!strings.Contains(err.Error(), "IPVALET_DATABASE_URL_FILE") {
		t.Errorf("missing file: %v", err)
	}
}

func TestAdminSettings(t *testing.T) {
	key, _ := auth.NewKey()
	for want, m := range map[string]map[string]string{
		"env":  {"IPVALET_ADMIN_KEY": key.String()},
		"file": {"IPVALET_ADMIN_KEY_FILE": "/run/key"},
		"hash": {"IPVALET_ADMIN_KEY_HASH": auth.HashLine(key)},
	} {
		m["IPVALET_DATABASE_URL"] = "x"
		c, err := Load(env(m), files(map[string]string{"/run/key": key.String()}))
		if err != nil || c.AdminKeySource != want {
			t.Errorf("%s: source %q, err %v", want, c.AdminKeySource, err)
		}
	}
	if _, err := Load(env(map[string]string{"IPVALET_DATABASE_URL": "x", "IPVALET_ADMIN_LISTEN_ADDR": ":8080"}), files(nil)); err == nil {
		t.Error("admin listener on the API address accepted")
	}
	c, err := Load(env(map[string]string{"IPVALET_DATABASE_URL": "x", "IPVALET_ADMIN_LISTEN_ADDR": ""}), files(nil))
	if err != nil || c.AdminListenAddr != "" {
		t.Errorf("empty admin listener: %q %v", c.AdminListenAddr, err)
	}
}

func TestTrustedProxies(t *testing.T) {
	c, err := Load(env(map[string]string{"IPVALET_DATABASE_URL": "x",
		"IPVALET_TRUSTED_PROXIES": " 10.0.0.5, 172.16.0.0/12 ,fd00::/8,::ffff:192.0.2.1"}), files(nil))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range c.TrustedProxies {
		got = append(got, p.String())
	}
	if strings.Join(got, " ") != "10.0.0.5/32 172.16.0.0/12 fd00::/8 192.0.2.1/32" {
		t.Fatalf("trusted proxies = %v", got)
	}
	if _, err := Load(env(map[string]string{"IPVALET_DATABASE_URL": "x", "IPVALET_TRUSTED_PROXIES": "proxy.local"}), files(nil)); err == nil ||
		!strings.Contains(err.Error(), "IPVALET_TRUSTED_PROXIES") {
		t.Fatalf("hostname accepted: %v", err)
	}
}

func TestParseDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{"90s": 90 * time.Second, "15m": 15 * time.Minute, "36h": 36 * time.Hour,
		"30d": 30 * 24 * time.Hour, "1h30m": 90 * time.Minute} {
		if got, err := ParseDuration(in); err != nil || got != want {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "d", "1.5d", "-1d", "x"} {
		if _, err := ParseDuration(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

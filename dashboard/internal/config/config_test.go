package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const testKey = "ipv_aaaaaaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func load(env map[string]string, files map[string]string) (Config, error) {
	return Load(func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	}, func(p string) ([]byte, error) {
		if v, ok := files[p]; ok {
			return []byte(v), nil
		}
		return nil, errors.New("no such file")
	})
}

func base() map[string]string {
	return map[string]string{
		"IPVALET_DASHBOARD_API_URL":    "http://api:8081/",
		"IPVALET_DASHBOARD_API_KEY":    testKey,
		"IPVALET_DASHBOARD_USERS_FILE": "/run/secrets/users",
	}
}

func TestDefaults(t *testing.T) {
	c, err := load(base(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != ":8090" || c.APIURL.String() != "http://api:8081" || c.APIKey != testKey ||
		c.Auth != AuthForm || !c.SecureCookies || c.SessionIdle != 30*time.Minute || c.SessionMax != 12*time.Hour ||
		c.LoginFailuresPerMinute != 10 || c.Location != time.UTC || c.APITimeout != 10*time.Second {
		t.Fatalf("defaults: %+v", c)
	}
}

func TestKeyFromFile(t *testing.T) {
	env := base()
	delete(env, "IPVALET_DASHBOARD_API_KEY")
	env["IPVALET_DASHBOARD_API_KEY_FILE"] = "/run/secrets/key"
	c, err := load(env, map[string]string{"/run/secrets/key": testKey + "\n"})
	if err != nil || c.APIKey != testKey {
		t.Fatalf("%q %v", c.APIKey, err)
	}
	env["IPVALET_DASHBOARD_API_KEY"] = testKey
	if _, err := load(env, map[string]string{"/run/secrets/key": testKey}); err == nil {
		t.Fatal("both the key and its _FILE accepted")
	}
}

func TestInvalid(t *testing.T) {
	for name, tc := range map[string]struct {
		set  map[string]string
		drop []string
		want string
	}{
		"no API URL":        {drop: []string{"IPVALET_DASHBOARD_API_URL"}, want: "IPVALET_DASHBOARD_API_URL: required"},
		"API URL scheme":    {set: map[string]string{"IPVALET_DASHBOARD_API_URL": "ftp://api"}, want: "http or https"},
		"API URL with user": {set: map[string]string{"IPVALET_DASHBOARD_API_URL": "http://u:p@api:8081"}, want: "credentials"},
		"no key":            {drop: []string{"IPVALET_DASHBOARD_API_KEY"}, want: "IPVALET_DASHBOARD_API_KEY: required"},
		"bad key":           {set: map[string]string{"IPVALET_DASHBOARD_API_KEY": "secret"}, want: "must be an ip-valet key"},
		"auth method":       {set: map[string]string{"IPVALET_DASHBOARD_AUTH": "oidc"}, want: "must be form or basic"},
		"no users file":     {drop: []string{"IPVALET_DASHBOARD_USERS_FILE"}, want: "IPVALET_DASHBOARD_USERS_FILE: required"},
		"cookies":           {set: map[string]string{"IPVALET_DASHBOARD_SECURE_COOKIES": "maybe"}, want: "true or false"},
		"idle over max": {set: map[string]string{"IPVALET_DASHBOARD_SESSION_IDLE": "2h", "IPVALET_DASHBOARD_SESSION_MAX": "1h"},
			want: "must not be longer"},
		"proxy":     {set: map[string]string{"IPVALET_DASHBOARD_TRUSTED_PROXIES": "10.0.0.1, nope"}, want: `"nope"`},
		"time zone": {set: map[string]string{"IPVALET_DASHBOARD_TIMEZONE": "Mars/Olympus"}, want: "unknown time zone"},
		"log level": {set: map[string]string{"IPVALET_DASHBOARD_LOG_LEVEL": "loud"}, want: "debug, info, warn or error"},
	} {
		t.Run(name, func(t *testing.T) {
			env := base()
			for k, v := range tc.set {
				env[k] = v
			}
			for _, k := range tc.drop {
				delete(env, k)
			}
			_, err := load(env, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want %q", err, tc.want)
			}
		})
	}
}

func TestSettings(t *testing.T) {
	env := base()
	env["IPVALET_DASHBOARD_AUTH"] = "Basic"
	env["IPVALET_DASHBOARD_TRUSTED_PROXIES"] = "10.0.0.1, 172.16.0.0/12"
	env["IPVALET_DASHBOARD_TIMEZONE"] = "Europe/Berlin"
	env["IPVALET_DASHBOARD_SECURE_COOKIES"] = "false"
	c, err := load(env, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Auth != AuthBasic || len(c.TrustedProxies) != 2 || c.Location.String() != "Europe/Berlin" || c.SecureCookies {
		t.Fatalf("%+v", c)
	}
}

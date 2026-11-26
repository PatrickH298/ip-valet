package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const key = "ipv_aaaaaaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func load(env map[string]string, files map[string]string) (Config, error) {
	return Load(func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	}, func(p string) ([]byte, error) {
		if v, ok := files[p]; ok {
			return []byte(v), nil
		}
		return nil, errors.New("no such file")
	}, func() []string {
		var out []string
		for k, v := range env {
			out = append(out, k+"="+v)
		}
		return out
	}, func() (string, error) { return "host-1", nil })
}

func base() map[string]string {
	return map[string]string{
		"IPVALET_UNIFI_API_URL":        "http://api:8080/",
		"IPVALET_UNIFI_API_KEY":        key,
		"IPVALET_UNIFI_CONTROLLER_URL": "https://192.168.1.1/proxy/network/integration",
		"IPVALET_UNIFI_CONTROLLER_KEY": "unifi-key",
		"IPVALET_UNIFI_RULE_B":         "realm=home family=ipv4 ipv4_list=b4",
		"IPVALET_UNIFI_RULE_A":         "realm=home group=staff ipv4_list=a4 ipv6_list=a6",
	}
}

func TestDefaults(t *testing.T) {
	c, err := load(base(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.APIURL.String() != "http://api:8080" || c.Site != "Default" || !c.VerifyTLS || !c.CreateLists ||
		c.Floor.MinV4 != 24 || c.Floor.MinV6 != 48 || c.SyncInterval != time.Minute || c.Timeout != 15*time.Second ||
		c.DataDir != "/data" || c.Instance != "host-1" {
		t.Fatalf("%+v", c)
	}
	if len(c.Rules) != 2 || c.Rules[0].Name != "A" || c.Rules[1].Name != "B" {
		t.Fatalf("rules %+v", c.Rules)
	}
}

func TestSecretsFromFiles(t *testing.T) {
	env := base()
	delete(env, "IPVALET_UNIFI_API_KEY")
	delete(env, "IPVALET_UNIFI_CONTROLLER_KEY")
	env["IPVALET_UNIFI_API_KEY_FILE"] = "/run/secrets/worker"
	env["IPVALET_UNIFI_CONTROLLER_KEY_FILE"] = "/run/secrets/unifi"
	c, err := load(env, map[string]string{"/run/secrets/worker": key + "\n", "/run/secrets/unifi": "k\n"})
	if err != nil || c.APIKey != key || c.ControllerKey != "k" {
		t.Fatalf("%q %q %v", c.APIKey, c.ControllerKey, err)
	}
}

func TestInvalid(t *testing.T) {
	for name, tc := range map[string]struct {
		set  map[string]string
		drop []string
		want string
	}{
		"no api url":   {drop: []string{"IPVALET_UNIFI_API_URL"}, want: "IPVALET_UNIFI_API_URL: required"},
		"bad key":      {set: map[string]string{"IPVALET_UNIFI_API_KEY": "nope"}, want: "worker key"},
		"no unifi key": {drop: []string{"IPVALET_UNIFI_CONTROLLER_KEY"}, want: "IPVALET_UNIFI_CONTROLLER_KEY: required"},
		"no rules":     {drop: []string{"IPVALET_UNIFI_RULE_A", "IPVALET_UNIFI_RULE_B"}, want: "at least one rule"},
		"bad rule":     {set: map[string]string{"IPVALET_UNIFI_RULE_C": "realm=*"}, want: "IPVALET_UNIFI_RULE_C"},
		"cloud no verify": {set: map[string]string{"IPVALET_UNIFI_CONTROLLER_URL": "https://api.ui.com/v1/connector/consoles/x/proxy/network/integration",
			"IPVALET_UNIFI_VERIFY_TLS": "false"}, want: "cloud connector"},
		"floor":    {set: map[string]string{"IPVALET_UNIFI_MIN_PREFIX_V4": "33"}, want: "IPVALET_UNIFI_MIN_PREFIX_V4"},
		"interval": {set: map[string]string{"IPVALET_UNIFI_SYNC_INTERVAL": "1s"}, want: "at least 5s"},
	} {
		t.Run(name, func(t *testing.T) {
			env := base()
			for k, v := range tc.set {
				env[k] = v
			}
			for _, k := range tc.drop {
				delete(env, k)
			}
			if _, err := load(env, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%v, want %q", err, tc.want)
			}
		})
	}
	// A local console with a self-signed certificate may skip verification.
	env := base()
	env["IPVALET_UNIFI_VERIFY_TLS"] = "false"
	if c, err := load(env, nil); err != nil || c.VerifyTLS {
		t.Fatalf("local console without TLS checks: %v", err)
	}
}

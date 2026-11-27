package config

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/httpx"
)

const key = "ipv_aaaaaaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func load(t *testing.T, env map[string]string, files map[string]string) (Config, error) {
	t.Helper()
	get := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	read := func(p string) ([]byte, error) {
		if v, ok := files[p]; ok {
			return []byte(v), nil
		}
		return nil, os.ErrNotExist
	}
	environ := func() []string {
		var out []string
		for k, v := range env {
			out = append(out, k+"="+v)
		}
		return out
	}
	return Load(get, read, environ)
}

func base() map[string]string {
	return map[string]string{
		"IPVALET_SSO_PUBLIC_URL":     "https://ip.example.com/",
		"IPVALET_SSO_API_URL":        "http://api:8080",
		"IPVALET_SSO_API_KEY":        key,
		"IPVALET_SSO_PROVIDER":       "oidc",
		"IPVALET_SSO_OIDC_ISSUER":    "https://idp.example.com/application/o/ip/",
		"IPVALET_SSO_OIDC_CLIENT_ID": "ip-valet",
		"IPVALET_SSO_RULE_STAFF":     "group=staff realm=office max_ttl=12h",
	}
}

func TestDefaults(t *testing.T) {
	c, err := load(t, base(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != ":8091" || c.DetectListenAddr != "" || c.PublicURL.String() != "https://ip.example.com" || c.Title != "ip-valet" {
		t.Fatalf("%+v", c)
	}
	if c.OIDC.Issuer != "https://idp.example.com/application/o/ip/" || c.OIDC.ClientSecret != "" ||
		strings.Join(c.OIDC.Scopes, " ") != "openid profile email groups" || c.OIDC.UsernameClaim != "preferred_username" ||
		c.OIDC.GroupsClaim != "groups" {
		t.Fatalf("%+v", c.OIDC)
	}
	if c.DefaultSubnetV4 != 32 || c.DefaultSubnetV6 != 64 || c.MaxSubnetV4 != 24 || c.MaxSubnetV6 != 48 {
		t.Fatalf("subnets %+v", c)
	}
	if !c.TrustAll || len(c.TrustedProxies) != 2 || c.Cookies != httpx.CookiesAuto || len(c.Rules) != 1 || c.Rules[0].Name != "STAFF" {
		t.Fatalf("%+v", c)
	}
}

func TestSAMLAndDetection(t *testing.T) {
	env := base()
	env["IPVALET_SSO_PROVIDER"] = "saml"
	env["IPVALET_SSO_SAML_IDP_METADATA_FILE"] = "/md.xml"
	env["IPVALET_SSO_DETECT_V4_URL"] = "https://v4.ip.example.com/detect"
	env["IPVALET_SSO_DETECT_V6_URL"] = "https://v6.ip.example.com"
	env["IPVALET_SSO_DETECT_LISTEN_ADDR"] = ":8092"
	env["IPVALET_SSO_TRUSTED_PROXIES"] = "10.0.0.0/8, 192.0.2.1"
	c, err := load(t, env, map[string]string{"/md.xml": "<EntityDescriptor/>\n"})
	if err != nil {
		t.Fatal(err)
	}
	if string(c.SAML.Metadata) != "<EntityDescriptor/>" || c.SAML.EntityID != "https://ip.example.com/saml/metadata" ||
		c.SAML.GroupsAttribute != "groups" || c.SAML.UsernameAttribute != "" {
		t.Fatalf("%+v", c.SAML)
	}
	if c.DetectV4URL.String() != "https://v4.ip.example.com/detect" || c.DetectV6URL.String() != "https://v6.ip.example.com" ||
		c.DetectListenAddr != ":8092" || c.TrustAll || len(c.TrustedProxies) != 2 {
		t.Fatalf("%+v", c)
	}
}

func TestMessage(t *testing.T) {
	c, err := load(t, base(), nil)
	if err != nil || c.Message != "" {
		t.Fatalf("%q %v", c.Message, err)
	}
	env := base()
	env["IPVALET_SSO_MESSAGE"] = "  Welcome to ip-valet  "
	if c, err = load(t, env, nil); err != nil || c.Message != "Welcome to ip-valet" {
		t.Fatalf("%q %v", c.Message, err)
	}
	env = base()
	env["IPVALET_SSO_MESSAGE_FILE"] = "/message.txt"
	if c, err = load(t, env, map[string]string{"/message.txt": "Welcome.\r\nThen go to https://intranet.example.com\n"}); err != nil ||
		c.Message != "Welcome.\nThen go to https://intranet.example.com" {
		t.Fatalf("%q %v", c.Message, err)
	}
	env = base()
	env["IPVALET_SSO_MESSAGE"] = strings.Repeat("é", MaxMessage+1)
	if _, err = load(t, env, nil); err == nil || !strings.Contains(err.Error(), "at most 4000 characters") {
		t.Fatal(err)
	}
}

func TestErrors(t *testing.T) {
	cases := []struct {
		set  map[string]string
		want string
	}{
		{map[string]string{"IPVALET_SSO_PUBLIC_URL": ""}, "IPVALET_SSO_PUBLIC_URL: required"},
		{map[string]string{"IPVALET_SSO_PUBLIC_URL": "https://ip.example.com/sub"}, "must not have a path"},
		{map[string]string{"IPVALET_SSO_API_KEY": "nope"}, "must be an ip-valet key"},
		{map[string]string{"IPVALET_SSO_PROVIDER": "ldap"}, "must be oidc or saml"},
		{map[string]string{"IPVALET_SSO_OIDC_SCOPES": "profile"}, "must include openid"},
		{map[string]string{"IPVALET_SSO_RULE_STAFF": "group=staff realm=office"}, "IPVALET_SSO_RULE_STAFF: max_ttl is required"},
		{map[string]string{"IPVALET_SSO_DETECT_V4_URL": "http://v4.ip.example.com"}, "must be https"},
		{map[string]string{"IPVALET_SSO_DETECT_V6_URL": "https://ip.example.com/detect"}, "a host other than"},
		{map[string]string{"IPVALET_SSO_DEFAULT_SUBNET_V4": "16"}, "wider than IPVALET_SSO_MAX_SUBNET_V4"},
		{map[string]string{"IPVALET_SSO_MAX_SUBNET_V6": "129"}, "between 0 and 128"},
		{map[string]string{"IPVALET_SSO_TRUSTED_PROXIES": "proxy"}, "not an IP address"},
		{map[string]string{"IPVALET_SSO_SESSION_IDLE": "13h"}, "must not be longer"},
		{map[string]string{"IPVALET_SSO_PROVIDER": "saml"}, "IPVALET_SSO_SAML_IDP_METADATA_URL: required"},
	}
	for _, tc := range cases {
		env := base()
		for k, v := range tc.set {
			env[k] = v
		}
		_, err := load(t, env, nil)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: got %v, want %q", tc.set, err, tc.want)
		}
	}
	// No rules at all.
	env := base()
	delete(env, "IPVALET_SSO_RULE_STAFF")
	if _, err := load(t, env, nil); err == nil || !strings.Contains(err.Error(), "at least one rule") {
		t.Fatal(err)
	}
	// Every problem is reported at once.
	env = base()
	env["IPVALET_SSO_API_URL"] = "ftp://x"
	env["IPVALET_SSO_LOG_LEVEL"] = "loud"
	_, err := load(t, env, nil)
	if n := len(strings.Split(err.Error(), "\n")); n != 2 || !errors.Is(err, err) {
		t.Fatalf("%d errors: %v", n, err)
	}
}

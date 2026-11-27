package app

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/config"
)

func run(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	env := Env{Stdout: &out, Stderr: &errOut,
		Config: func() (config.Config, error) { return config.Config{}, errors.New("IPVALET_SSO_PUBLIC_URL: required") }}
	code := Main(context.Background(), args, env)
	return code, out.String(), errOut.String()
}

func TestMain(t *testing.T) {
	if code, out, _ := run("version"); code != 0 || !strings.HasPrefix(out, "ipvalet-sso-web dev") {
		t.Fatal(code, out)
	}
	if code, out, _ := run("help"); code != 0 || !strings.Contains(out, "check") {
		t.Fatal(code, out)
	}
	if code, _, errOut := run("bogus"); code != 2 || !strings.Contains(errOut, "usage") {
		t.Fatal(code, errOut)
	}
	if code, _, errOut := run("version", "extra"); code != 2 || !strings.Contains(errOut, "usage") {
		t.Fatal(code, errOut)
	}
	for _, cmd := range []string{"serve", "check"} {
		if code, _, errOut := run(cmd); code != 1 || !strings.Contains(errOut, "configuration: IPVALET_SSO_PUBLIC_URL") {
			t.Fatal(cmd, code, errOut)
		}
	}
	if !privateHost("api") || !privateHost("10.0.0.5") || !privateHost("db.internal") || privateHost("api.example.com") {
		t.Fatal("privateHost")
	}
}

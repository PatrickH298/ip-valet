package app

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/PatrickH298/ip-valet/dashboard/internal/auth"
)

func TestResetLogin(t *testing.T) {
	dir := t.TempDir()
	st, err := auth.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Save(auth.Login{Method: auth.MethodForm, Username: "ops",
		Hash: "$2a$04$abcdefghijklmnopqrstuuOw1ah6S5eEcIu6Hw9IJCgvWWWnIDmV2"}); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	env := Env{Stdout: &out, Stderr: &errOut, Getenv: func(k string) (string, bool) {
		if k == "IPVALET_DASHBOARD_DATA_DIR" {
			return dir, true
		}
		return "", false
	}}
	if code := Main(context.Background(), []string{"reset-login"}, env); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "admin") {
		t.Fatalf("output %q", out.String())
	}
	st, err = auth.OpenStore(dir)
	if err != nil || !st.IsDefault() {
		t.Fatalf("after reset-login: default %v, %v", st != nil && st.IsDefault(), err)
	}
	if code := Main(context.Background(), []string{"reset-login", "extra"}, env); code != 2 {
		t.Fatalf("extra argument: exit %d", code)
	}
}

func TestKeyID(t *testing.T) {
	if id := keyID("ipv_aaaaaaaaaaaaaaaa_bbbb"); id != "aaaaaaaaaaaaaaaa" {
		t.Fatal(id)
	}
	for h, want := range map[string]bool{"api": true, "10.1.2.3": true, "localhost": true, "db.internal": true,
		"api.example.com": false, "8.8.8.8": false} {
		if privateHost(h) != want {
			t.Errorf("privateHost(%q) != %v", h, want)
		}
	}
}

package app

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/PatrickH298/ip-valet/dashboard/internal/auth"
)

func TestHashPassword(t *testing.T) {
	var out, errOut bytes.Buffer
	env := Env{Stdin: strings.NewReader("s3cret pass\n"), Stdout: &out, Stderr: &errOut}
	if code := Main(context.Background(), []string{"hash-password", "Zoë"}, env); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	u, err := auth.ParseUsers(strings.NewReader(out.String()))
	if err != nil {
		t.Fatal(err)
	}
	if !u.Check("Zoë", "s3cret pass") {
		t.Fatal("the printed line does not check")
	}
	if code := Main(context.Background(), []string{"hash-password"}, env); code != 2 {
		t.Fatalf("no name: exit %d", code)
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

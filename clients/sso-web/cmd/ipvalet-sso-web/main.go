// Command ipvalet-sso-web is the ip-valet SSO web client: people sign in
// through an OpenID Connect or SAML identity provider and register their
// addresses in the realms their user and groups allow.
package main

import (
	"context"
	"os"

	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/app"
)

func main() {
	os.Exit(app.Main(context.Background(), os.Args[1:], app.OS()))
}

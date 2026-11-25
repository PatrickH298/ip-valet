// Command ipvalet-api is the ip-valet API server.
package main

import (
	"context"
	"os"

	"github.com/PatrickH298/ip-valet/api/internal/app"
)

func main() {
	os.Exit(app.Main(context.Background(), os.Args[1:], app.OS()))
}

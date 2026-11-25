// Command ipvalet-dashboard is the ip-valet admin dashboard: a web interface
// for the API server's admin API.
package main

import (
	"context"
	"os"

	"github.com/PatrickH298/ip-valet/dashboard/internal/app"
)

func main() {
	os.Exit(app.Main(context.Background(), os.Args[1:], app.OS()))
}

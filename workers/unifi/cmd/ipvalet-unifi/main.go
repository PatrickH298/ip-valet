// Command ipvalet-unifi is the ip-valet UniFi worker: it keeps UniFi
// traffic matching lists in line with the addresses registered in ip-valet.
package main

import (
	"context"
	"os"

	"github.com/PatrickH298/ip-valet/workers/unifi/internal/app"
)

func main() {
	os.Exit(app.Main(context.Background(), os.Args[1:], app.OS()))
}

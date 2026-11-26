// Package app wires the UniFi worker together and runs its commands.
package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/PatrickH298/ip-valet/workers/unifi/internal/config"
	"github.com/PatrickH298/ip-valet/workers/unifi/internal/ipvalet"
	"github.com/PatrickH298/ip-valet/workers/unifi/internal/unifi"
	"github.com/PatrickH298/ip-valet/workers/unifi/internal/worker"
)

// Build information, set with -ldflags -X.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// Env is what Main needs from the process.
type Env struct {
	Stdout, Stderr io.Writer
	Config         func() (config.Config, error)
}

// OS returns the real process environment.
func OS() Env { return Env{Stdout: os.Stdout, Stderr: os.Stderr, Config: config.FromEnvironment} }

const usage = `usage: ipvalet-unifi [command]

commands:
  run      keep the UniFi lists in line with ip-valet (default)
  check    show what a run would change, changing nothing
  version  print the version
`

// Main runs a command and returns the exit code.
func Main(ctx context.Context, args []string, env Env) int {
	cmd := "run"
	if len(args) > 0 {
		cmd = args[0]
	}
	if len(args) > 1 {
		fmt.Fprint(env.Stderr, usage)
		return 2
	}
	switch cmd {
	case "version":
		fmt.Fprintf(env.Stdout, "ipvalet-unifi %s (commit %s, built %s)\n", Version, Commit, Date)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(env.Stdout, usage)
		return 0
	case "run", "check":
	default:
		fmt.Fprint(env.Stderr, usage)
		return 2
	}
	cfg, err := env.Config()
	if err != nil {
		fmt.Fprintln(env.Stderr, "configuration:", err)
		return 1
	}
	logOut := env.Stdout
	if cmd == "check" {
		logOut = env.Stderr
	}
	log := slog.New(slog.NewJSONHandler(logOut, &slog.HandlerOptions{Level: cfg.LogLevel}))
	w, err := New(cfg, log)
	if err != nil {
		log.Error("starting", "error", err.Error())
		return 1
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cmd == "check" {
		if err := w.Check(ctx, env.Stdout); err != nil {
			fmt.Fprintln(env.Stderr, "check:", err)
			return 1
		}
		return 0
	}
	if cfg.DataDir != "" {
		if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
			log.Warn("cannot use IPVALET_UNIFI_DATA_DIR; desired state is kept in memory only", "error", err.Error(),
				"uid", os.Getuid(), "gid", os.Getgid())
			cfg.DataDir = ""
		}
	}
	log.Info("starting", "version", Version, "instance", cfg.Instance, "rules", len(cfg.Rules),
		"api", cfg.APIURL.Redacted(), "controller", cfg.ControllerURL.Redacted(), "site", cfg.Site)
	if err := w.Run(ctx); err != nil {
		log.Error("stopped", "error", err.Error())
		return 1
	}
	log.Info("stopped")
	return 0
}

// New builds a worker from configuration.
func New(cfg config.Config, log *slog.Logger) (*worker.Worker, error) {
	return worker.New(worker.Options{
		Config:  cfg,
		API:     ipvalet.New(cfg.APIURL, cfg.APIKey, cfg.Timeout),
		UniFi:   unifi.New(cfg.ControllerURL, cfg.ControllerKey, cfg.VerifyTLS, cfg.Timeout, log),
		Log:     log,
		Version: Version,
	})
}

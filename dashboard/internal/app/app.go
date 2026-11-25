// Package app wires the dashboard together and runs its commands.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/PatrickH298/ip-valet/dashboard/internal/api"
	"github.com/PatrickH298/ip-valet/dashboard/internal/auth"
	"github.com/PatrickH298/ip-valet/dashboard/internal/config"
	"github.com/PatrickH298/ip-valet/dashboard/internal/web"
)

// Build information, set with -ldflags -X.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// Env is what Main needs from the process, so tests can supply their own.
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Getenv config.Getenv
	Config func() (config.Config, error)
}

// OS returns the real process environment.
func OS() Env {
	return Env{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.LookupEnv,
		Config: config.FromEnvironment}
}

const usage = `usage: ipvalet-dashboard [command]

commands:
  serve        serve the dashboard (default)
  reset-login  forget the saved login, so the dashboard starts again from the
               default (form sign-in as admin, password admin); then restart it
  version      print the version
`

// Main runs a command and returns the exit code.
func Main(ctx context.Context, args []string, env Env) int {
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "serve":
		if len(args) != 0 {
			fmt.Fprint(env.Stderr, usage)
			return 2
		}
		return serve(ctx, env)
	case "reset-login":
		if len(args) != 0 {
			fmt.Fprint(env.Stderr, usage)
			return 2
		}
		dir := config.DataDir(env.Getenv)
		if err := auth.ResetLogin(dir); err != nil {
			fmt.Fprintln(env.Stderr, "reset-login:", err)
			return 1
		}
		fmt.Fprintf(env.Stdout, "The saved login in %s is gone. Restart the dashboard, sign in as %s with password %s, "+
			"and choose a new password.\n", dir, auth.DefaultUsername, auth.DefaultPassword)
		return 0
	case "version":
		fmt.Fprintf(env.Stdout, "ipvalet-dashboard %s (commit %s, built %s)\n", Version, Commit, Date)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(env.Stdout, usage)
		return 0
	}
	fmt.Fprint(env.Stderr, usage)
	return 2
}

func serve(ctx context.Context, env Env) int {
	cfg, err := env.Config()
	if err != nil {
		fmt.Fprintln(env.Stderr, "configuration:", err)
		return 1
	}
	log := slog.New(slog.NewJSONHandler(env.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	d, err := Start(ctx, cfg, log)
	if err != nil {
		log.Error("starting", "error", err.Error())
		return 1
	}
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Error("listening", "addr", cfg.ListenAddr, "error", err.Error())
		return 1
	}
	log.Info("serving", "addr", ln.Addr().String(), "version", Version, "api", cfg.APIURL.Redacted())
	if err := d.Serve(ctx, ln, cfg.ShutdownTimeout); err != nil {
		log.Error("serving", "error", err.Error())
		return 1
	}
	return 0
}

// Dashboard is a configured dashboard, ready to serve.
type Dashboard struct {
	Handler  http.Handler
	Sessions *auth.Sessions
	Throttle *auth.Throttle
	log      *slog.Logger
}

// Start reads the login, checks the API server and builds the handler. An
// API server that cannot be reached is only a warning, since it may start
// later; one that refuses the dashboard's key is an error.
func Start(ctx context.Context, cfg config.Config, log *slog.Logger) (*Dashboard, error) {
	store, err := auth.OpenStore(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("IPVALET_DASHBOARD_DATA_DIR: %w", err)
	}
	client := api.New(cfg.APIURL, cfg.APIKey, cfg.APITimeout)
	d := &Dashboard{Throttle: auth.NewThrottle(cfg.LoginFailuresPerMinute),
		Sessions: auth.NewSessions(cfg.SessionIdle, cfg.SessionMax), log: log}

	if !cfg.SecureCookies {
		log.Warn("IPVALET_DASHBOARD_SECURE_COOKIES is false: serve the dashboard over HTTPS anyway, " +
			"or passwords and session cookies cross the network in the clear")
	}
	if cfg.APIURL.Scheme == "http" && !privateHost(cfg.APIURL.Hostname()) {
		log.Warn("IPVALET_DASHBOARD_API_URL uses plain HTTP to a host that does not look private; " +
			"the admin key crosses the network in the clear")
	}
	checkCtx, cancel := context.WithTimeout(ctx, cfg.APITimeout)
	defer cancel()
	if _, err := client.Health(checkCtx); err != nil {
		var ae *api.Error
		switch {
		case errors.As(err, &ae) && (ae.Status == http.StatusUnauthorized || ae.Status == http.StatusForbidden):
			return nil, fmt.Errorf("the API server refused IPVALET_DASHBOARD_API_KEY (%s); it must be an active admin key", ae.Code)
		case errors.As(err, &ae) && ae.Status == http.StatusNotFound:
			return nil, fmt.Errorf("the API server answered 404 for the admin API; IPVALET_DASHBOARD_API_URL must " +
				"point at its admin listener (port 8081 by default), not the public one")
		default:
			log.Warn("the API server is not answering yet; pages will say so until it does", "error", err.Error())
		}
	}

	w, err := web.New(web.Options{API: client, Log: log, Location: cfg.Location, TrustedProxies: cfg.TrustedProxies,
		SecureCookies: cfg.SecureCookies, SelfKeyID: keyID(cfg.APIKey), Version: Version})
	if err != nil {
		return nil, err
	}
	local := &auth.Local{Store: store, Sessions: d.Sessions, Throttle: d.Throttle, Secure: cfg.SecureCookies,
		Log: log, Render: w.LoginRenderer()}
	w.Auth, w.Local = local, local
	d.Handler = w.Handler()
	if store.IsDefault() {
		log.Warn("the dashboard still has its default login; sign in as " + auth.DefaultUsername + " with password " +
			auth.DefaultPassword + " and choose a new password")
	} else {
		lg := store.Login()
		log.Info("login loaded", "user", lg.Username, "method", lg.Method)
	}
	return d, nil
}

// Serve serves on ln until ctx ends, then shuts down gracefully.
func (d *Dashboard) Serve(ctx context.Context, ln net.Listener, grace time.Duration) error {
	srv := &http.Server{
		Handler:           d.Handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(d.log.Handler(), slog.LevelWarn),
	}
	go d.sweep(ctx)
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	d.log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		return err
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// sweep drops ended sessions and idle throttle state every minute.
func (d *Dashboard) sweep(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			d.Sessions.Sweep()
			d.Throttle.Evict(now)
		}
	}
}

// keyID is the id part of an ipv_<id>_<secret> key.
func keyID(key string) string {
	parts := strings.Split(key, "_")
	if len(parts) != 3 {
		return ""
	}
	return parts[1]
}

// privateHost reports whether h is a name or address that is unlikely to be
// reached across the internet: a single-label name (a Compose service), a
// .local/.internal/.lan name, or a loopback or private address.
func privateHost(h string) bool {
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}
	if !strings.Contains(h, ".") || h == "localhost" {
		return true
	}
	for _, suffix := range []string{".local", ".internal", ".lan", ".home.arpa"} {
		if strings.HasSuffix(h, suffix) {
			return true
		}
	}
	return false
}

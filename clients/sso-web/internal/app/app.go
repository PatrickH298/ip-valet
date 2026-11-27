// Package app wires sso-web together and runs its commands.
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

	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/config"
	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/idp"
	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/ipvalet"
	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/rules"
	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/seal"
	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/web"
)

// Build information, set with -ldflags -X.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// Env is what Main needs from the process, so tests can supply their own.
type Env struct {
	Stdout io.Writer
	Stderr io.Writer
	Config func() (config.Config, error)
}

// OS returns the real process environment.
func OS() Env {
	return Env{Stdout: os.Stdout, Stderr: os.Stderr, Config: config.FromEnvironment}
}

const usage = `usage: ipvalet-sso-web [command]

commands:
  serve    serve the site (default)
  check    check the configuration, the identity provider and the API key,
           and list the rules
  version  print the version
`

// Main runs a command and returns the exit code.
func Main(ctx context.Context, args []string, env Env) int {
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	if len(args) != 0 && cmd != "help" {
		fmt.Fprint(env.Stderr, usage)
		return 2
	}
	switch cmd {
	case "serve":
		return serve(ctx, env)
	case "check":
		return check(ctx, env)
	case "version":
		fmt.Fprintf(env.Stdout, "ipvalet-sso-web %s (commit %s, built %s)\n", Version, Commit, Date)
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
	site, err := Start(ctx, cfg, log)
	if err != nil {
		log.Error("starting", "error", err.Error())
		return 1
	}
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Error("listening", "addr", cfg.ListenAddr, "error", err.Error())
		return 1
	}
	var detectLn net.Listener
	if cfg.DetectListenAddr != "" {
		if detectLn, err = net.Listen("tcp", cfg.DetectListenAddr); err != nil {
			log.Error("listening", "addr", cfg.DetectListenAddr, "error", err.Error())
			return 1
		}
		log.Info("serving address detection", "addr", detectLn.Addr().String())
	}
	log.Info("serving", "addr", ln.Addr().String(), "version", Version, "public_url", cfg.PublicURL.String(),
		"provider", cfg.Provider, "rules", len(cfg.Rules), "api", cfg.APIURL.Redacted())
	if err := site.Serve(ctx, ln, detectLn, cfg.ShutdownTimeout); err != nil {
		log.Error("serving", "error", err.Error())
		return 1
	}
	return 0
}

// Site is a configured site, ready to serve.
type Site struct {
	Handler  http.Handler // the site
	Detect   http.Handler // address detection alone, for its own port
	Sessions *web.Sessions
	log      *slog.Logger
}

// Start builds the site and checks what it depends on. An identity
// provider or API server that cannot be reached is only a warning, since it
// may start later; an API server that refuses the client key is an error.
func Start(ctx context.Context, cfg config.Config, log *slog.Logger) (*Site, error) {
	if cfg.TrustAll {
		log.Warn("IPVALET_SSO_TRUSTED_PROXIES is not set, so every peer's X-Forwarded-For header is believed: " +
			"anyone who can reach this site directly can make it detect, and register, any address they like. " +
			"Set it to your reverse proxy's address or subnet, or to none when there is no proxy")
	}
	if cfg.APIURL.Scheme == "http" && !privateHost(cfg.APIURL.Hostname()) {
		log.Warn("IPVALET_SSO_API_URL uses plain HTTP to a host that does not look private; " +
			"the client key crosses the network in the clear")
	}
	if cfg.DetectV4URL == nil && cfg.DetectV6URL == nil {
		log.Info("no detection hosts are set (IPVALET_SSO_DETECT_V4_URL, IPVALET_SSO_DETECT_V6_URL); " +
			"only the address of each person's own connection is detected")
	}
	sealer := seal.New()
	client := ipvalet.New(cfg.APIURL, cfg.APIKey, cfg.APITimeout)
	site := &Site{Sessions: web.NewSessions(cfg.SessionIdle, cfg.SessionMax), log: log}
	w, err := web.New(web.Options{
		API: client, Sessions: site.Sessions, Sealer: sealer, Rules: cfg.Rules, Log: log, Location: cfg.Location,
		PublicURL: cfg.PublicURL, Title: cfg.Title, Message: cfg.Message, DetectV4: cfg.DetectV4URL, DetectV6: cfg.DetectV6URL,
		DefaultSubnetV4: cfg.DefaultSubnetV4, DefaultSubnetV6: cfg.DefaultSubnetV6,
		MaxSubnetV4: cfg.MaxSubnetV4, MaxSubnetV6: cfg.MaxSubnetV6,
		Cookies: cfg.Cookies, TrustedProxies: cfg.TrustedProxies, TrustAll: cfg.TrustAll, LogoutURL: cfg.LogoutURL,
		Version: Version,
	})
	if err != nil {
		return nil, err
	}
	provider, err := newProvider(cfg, idp.Env{PublicURL: cfg.PublicURL, Sealer: sealer, Cookies: cfg.Cookies, Log: log,
		Done: w.SignedIn, Fail: w.Fail})
	if err != nil {
		return nil, err
	}
	w.Provider = provider

	checkCtx, cancel := context.WithTimeout(ctx, cfg.APITimeout)
	defer cancel()
	if err := provider.Check(checkCtx); err != nil {
		log.Warn("the identity provider is not answering yet; sign-in will retry it", "error", err.Error())
	}
	for _, problem := range checkRealms(checkCtx, client, cfg.Rules) {
		if problem.fatal {
			return nil, errors.New(problem.text)
		}
		log.Log(ctx, problem.level, problem.text)
	}
	site.Handler, site.Detect = w.Handler(), w.DetectHandler()
	return site, nil
}

func newProvider(cfg config.Config, env idp.Env) (idp.Provider, error) {
	if cfg.Provider == config.ProviderSAML {
		return idp.NewSAML(cfg.SAML, env)
	}
	return idp.NewOIDC(cfg.OIDC, env), nil
}

type problem struct {
	text  string
	level slog.Level
	fatal bool
}

// checkRealms checks that the client key may use every realm the rules name.
func checkRealms(ctx context.Context, client *ipvalet.Client, rs []rules.Rule) []problem {
	var out []problem
	seen := map[string]bool{}
	for _, r := range rs {
		if seen[r.Realm] {
			continue
		}
		seen[r.Realm] = true
		err := client.CheckRealm(ctx, r.Realm)
		ae, isAPI := ipvalet.AsError(err)
		switch {
		case err == nil:
		case isAPI && ae.Status == http.StatusUnauthorized:
			return append(out, problem{fatal: true,
				text: fmt.Sprintf("the API server refused IPVALET_SSO_API_KEY (%s); it must be an active client key", ae.Code)})
		case isAPI && ae.Code == "realm_not_allowed":
			out = append(out, problem{level: slog.LevelError, text: fmt.Sprintf("the client key's client is not bound to "+
				"realm %q, so registrations there fail (rule %s); bind the client to it in the dashboard", r.Realm, r.Name)})
		case isAPI && ae.Status == 0 || isAPI && ae.Status >= 500:
			return append(out, problem{level: slog.LevelWarn,
				text: "the API server is not answering yet: " + err.Error()})
		default:
			out = append(out, problem{level: slog.LevelWarn, text: fmt.Sprintf("checking realm %q: %v", r.Realm, err)})
		}
	}
	return out
}

// check is the check command: configuration, rules, the IdP and the API.
func check(ctx context.Context, env Env) int {
	cfg, err := env.Config()
	if err != nil {
		fmt.Fprintln(env.Stderr, "configuration:", err)
		return 1
	}
	out := env.Stdout
	fmt.Fprintf(out, "Configuration is valid. Provider: %s. Site: %s\n\nRules:\n", cfg.Provider, cfg.PublicURL)
	for _, r := range cfg.Rules {
		who := []string{}
		if r.User != rules.Wildcard {
			who = append(who, "user "+r.User)
		}
		if r.Group != rules.Wildcard {
			who = append(who, "group "+r.Group)
		}
		if len(who) == 0 {
			who = append(who, "everyone who signs in")
		}
		as := r.Group
		if r.As != "" {
			as = r.As
		}
		manual := ""
		if r.Manual {
			manual = ", may enter addresses"
		}
		fmt.Fprintf(out, "  %s: %s → realm %s as group %s; one click %s, at most %s%s\n",
			r.Name, strings.Join(who, " and "), r.Realm, as, r.TTL, r.MaxTTL, manual)
	}
	failed := false
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	sealer := seal.New()
	provider, err := newProvider(cfg, idp.Env{PublicURL: cfg.PublicURL, Sealer: sealer, Cookies: cfg.Cookies, Log: log})
	if err != nil {
		fmt.Fprintln(out, "\nIdentity provider: ", err)
		return 1
	}
	cctx, cancel := context.WithTimeout(ctx, 3*cfg.APITimeout)
	defer cancel()
	if err := provider.Check(cctx); err != nil {
		fmt.Fprintf(out, "\nIdentity provider: FAILED: %v\n", err)
		failed = true
	} else {
		fmt.Fprintf(out, "\nIdentity provider: OK (%s)\n", provider.Name())
	}
	client := ipvalet.New(cfg.APIURL, cfg.APIKey, cfg.APITimeout)
	problems := checkRealms(cctx, client, cfg.Rules)
	if len(problems) == 0 {
		fmt.Fprintln(out, "API: OK (the client key may use every realm the rules name)")
	}
	for _, p := range problems {
		fmt.Fprintln(out, "API: FAILED:", p.text)
		failed = true
	}
	if cfg.TrustAll {
		fmt.Fprintln(out, "\nWarning: IPVALET_SSO_TRUSTED_PROXIES is not set, so anyone who can reach the site directly "+
			"can forge the address it detects.")
	}
	if failed {
		return 1
	}
	return 0
}

// Serve serves the site on ln, and address detection on detectLn when it is
// not nil, until ctx ends; then it shuts down gracefully.
func (s *Site) Serve(ctx context.Context, ln, detectLn net.Listener, grace time.Duration) error {
	newServer := func(h http.Handler) *http.Server {
		return &http.Server{
			Handler:           h,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
			ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
		}
	}
	servers := []*http.Server{newServer(s.Handler)}
	listeners := []net.Listener{ln}
	if detectLn != nil {
		servers = append(servers, newServer(s.Detect))
		listeners = append(listeners, detectLn)
	}
	go s.sweep(ctx)
	errc := make(chan error, len(servers))
	for i, srv := range servers {
		go func() { errc <- srv.Serve(listeners[i]) }()
	}
	var first error
	select {
	case first = <-errc:
	case <-ctx.Done():
	}
	s.log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(sctx); err != nil && first == nil {
			first = err
		}
	}
	if first != nil && !errors.Is(first, http.ErrServerClosed) {
		return first
	}
	return nil
}

// sweep drops ended sessions every minute.
func (s *Site) sweep(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Sessions.Sweep()
		}
	}
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

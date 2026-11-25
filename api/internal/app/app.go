// Package app wires the server together and implements the subcommands.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/PatrickH298/ip-valet/api/internal/auth"
	"github.com/PatrickH298/ip-valet/api/internal/config"
	"github.com/PatrickH298/ip-valet/api/internal/db"
	"github.com/PatrickH298/ip-valet/api/internal/events"
	"github.com/PatrickH298/ip-valet/api/internal/httpapi"
	"github.com/PatrickH298/ip-valet/api/internal/jobs"
	"github.com/PatrickH298/ip-valet/api/internal/metrics"
)

// App is a running API instance.
type App struct {
	Config   config.Config
	Log      *slog.Logger
	Pool     *pgxpool.Pool
	Hub      *events.Hub
	Listener *db.Listener
	Auth     *auth.Authenticator
	Metrics  *metrics.Metrics
	API      *httpapi.Server
	Purger   *jobs.Purger

	cancel context.CancelFunc
	bg     sync.WaitGroup
}

// Start connects to the database (retrying for up to 60 s), runs
// migrations, starts the LISTEN connection and hub, and the background jobs.
func Start(ctx context.Context, cfg config.Config, log *slog.Logger) (*App, error) {
	pool, err := db.Connect(ctx, cfg.DatabaseURL, cfg.DBMaxConns, 60*time.Second, log)
	if err != nil {
		return nil, err
	}
	if err := db.Migrate(ctx, cfg.DatabaseURL, log); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrations: %w", err)
	}

	if cfg.MaxBodyBytes < httpapi.MaxStatusReportBytes {
		log.Warn("IPVALET_MAX_BODY_BYTES is below what a status report at its limits needs; "+
			"workers reporting many rejections may get 413", "max_body_bytes", cfg.MaxBodyBytes,
			"needed", httpapi.MaxStatusReportBytes)
	}
	a := &App{Config: cfg, Log: log, Pool: pool, Hub: events.NewHub()}
	bgCtx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel

	a.Listener = db.NewListener(cfg.DatabaseURL, log)
	a.Listener.OnChange = a.Hub.Changed
	a.Listener.OnStatus = a.Hub.Status
	a.Listener.OnReconnect = a.Hub.WakeAll
	if err := a.Listener.Start(bgCtx); err != nil {
		cancel()
		pool.Close()
		return nil, fmt.Errorf("LISTEN connection: %w", err)
	}

	a.Auth = auth.NewAuthenticator(pool, cfg.AdminKeyID, cfg.AdminKeyHash, cfg.AuthFailuresPerMinute, log)
	a.Metrics = metrics.New(pool, a.Hub, log)
	a.Auth.OnFailure = func(reason string) { a.Metrics.AuthFailed.WithLabelValues(reason).Inc() }
	a.API = httpapi.New(httpapi.Deps{Config: cfg, Pool: pool, Hub: a.Hub, Auth: a.Auth,
		Listener: a.Listener, Metrics: a.Metrics, Log: log})
	a.Purger = &jobs.Purger{Pool: pool, RetentionEntries: cfg.RetentionEntries, RetentionAudit: cfg.RetentionAudit,
		Interval: cfg.PurgeInterval, Log: log}

	a.bg.Add(2)
	go func() { defer a.bg.Done(); a.Auth.Run(bgCtx) }()
	go func() { defer a.bg.Done(); a.Purger.Run(bgCtx) }()
	return a, nil
}

// Close ends streams, stops the background jobs, closes the LISTEN
// connection and the pool.
func (a *App) Close() {
	a.API.CloseStreams()
	a.cancel()
	a.bg.Wait()
	<-a.Listener.Done()
	a.Pool.Close()
}

// NewHTTPServer returns an API server with the spec's timeouts.
func NewHTTPServer(addr string, h http.Handler, log *slog.Logger) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}

// MetricsHandler serves /metrics.
func (a *App) MetricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(a.Metrics.Registry, promhttp.HandlerOpts{}))
	return mux
}

// Serve runs the API and metrics listeners until ctx is cancelled, then shuts
// down: stop accepting, end SSE streams, wait for in-flight requests.
func (a *App) Serve(ctx context.Context) error {
	apiLn, err := net.Listen("tcp", a.Config.ListenAddr)
	if err != nil {
		return err
	}
	servers := []*http.Server{NewHTTPServer(a.Config.ListenAddr, a.API.Handler(), a.Log)}
	listeners := []net.Listener{apiLn}
	if a.Config.MetricsAddr != "" {
		mLn, err := net.Listen("tcp", a.Config.MetricsAddr)
		if err != nil {
			apiLn.Close()
			return err
		}
		ms := NewHTTPServer(a.Config.MetricsAddr, a.MetricsHandler(), a.Log)
		servers = append(servers, ms)
		listeners = append(listeners, mLn)
	}
	errc := make(chan error, len(servers))
	for i, srv := range servers {
		a.Log.Info("listening", "addr", listeners[i].Addr().String())
		go func() {
			if err := srv.Serve(listeners[i]); !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	}
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errc:
	}
	a.Log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), a.Config.ShutdownTimeout)
	defer cancel()
	var wg sync.WaitGroup
	for _, srv := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.Shutdown(sctx); err != nil {
				a.Log.Warn("shutdown did not finish in time", "addr", srv.Addr, "error", err.Error())
				srv.Close()
			}
		}()
	}
	a.API.CloseStreams()
	wg.Wait()
	return serveErr
}

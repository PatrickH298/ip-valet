package app

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/PatrickH298/ip-valet/api/internal/auth"
	"github.com/PatrickH298/ip-valet/api/internal/config"
	"github.com/PatrickH298/ip-valet/api/internal/db"
	"github.com/PatrickH298/ip-valet/api/internal/httpapi"
)

// Build information, set with -ldflags "-X ...".
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// IO carries the process's streams and environment, so commands are testable.
type IO struct {
	Stdin    io.Reader
	Stdout   io.Writer
	Stderr   io.Writer
	Getenv   config.Getenv
	ReadFile config.ReadFile
}

// OS returns the real process IO.
func OS() IO {
	return IO{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.LookupEnv, ReadFile: os.ReadFile}
}

const usage = `usage: ipvalet-api [command]

commands:
  serve (default)                                   run migrations, then serve HTTP
  migrate                                           run migrations and exit
  create-admin-key --name <name> [--expires <dur>]  insert an admin key and print it once
  hash-key                                          read a key on stdin, print IPVALET_ADMIN_KEY_HASH
  version                                           print version, commit and build date
`

// Main runs a subcommand and returns the exit code.
func Main(ctx context.Context, args []string, sio IO) int {
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = cmdServe(ctx, sio)
	case "migrate":
		err = cmdMigrate(ctx, sio)
	case "create-admin-key":
		err = cmdCreateAdminKey(ctx, args, sio)
	case "hash-key":
		err = cmdHashKey(sio)
	case "version":
		fmt.Fprintf(sio.Stdout, "ipvalet-api %s (commit %s, built %s)\n", Version, Commit, Date)
	case "help", "-h", "--help":
		fmt.Fprint(sio.Stdout, usage)
	default:
		fmt.Fprintf(sio.Stderr, "unknown command %q\n\n%s", cmd, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintf(sio.Stderr, "ipvalet-api %s: %v\n", cmd, err)
		return 1
	}
	return 0
}

func loadConfig(sio IO) (config.Config, *slog.Logger, error) {
	cfg, err := config.Load(sio.Getenv, sio.ReadFile)
	if err != nil {
		return cfg, nil, fmt.Errorf("invalid configuration:\n%w", err)
	}
	log := slog.New(slog.NewJSONHandler(sio.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	return cfg, log, nil
}

func cmdServe(ctx context.Context, sio IO) error {
	cfg, log, err := loadConfig(sio)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	log.Info("starting", "version", Version, "commit", Commit)
	a, err := Start(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer a.Close()
	if err := a.Serve(ctx); err != nil {
		return err
	}
	log.Info("stopped")
	return nil
}

func cmdMigrate(ctx context.Context, sio IO) error {
	cfg, log, err := loadConfig(sio)
	if err != nil {
		return err
	}
	pool, err := db.Connect(ctx, cfg.DatabaseURL, 2, 60*time.Second, log)
	if err != nil {
		return err
	}
	pool.Close()
	return db.Migrate(ctx, cfg.DatabaseURL, log)
}

func cmdCreateAdminKey(ctx context.Context, args []string, sio IO) error {
	fs := flag.NewFlagSet("create-admin-key", flag.ContinueOnError)
	fs.SetOutput(sio.Stderr)
	name := fs.String("name", "", "name for the key (required)")
	expires := fs.String("expires", "", "optional lifetime, e.g. 90d or 36h")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if strings.TrimSpace(*name) == "" || len(*name) > 128 {
		return errors.New("--name is required (at most 128 characters)")
	}
	var expiresAt *time.Time
	if *expires != "" {
		d, err := config.ParseDuration(*expires)
		if err != nil || d <= 0 {
			return fmt.Errorf("--expires: invalid duration %q", *expires)
		}
		t := time.Now().Add(d)
		expiresAt = &t
	}
	cfg, err := config.Load(sio.Getenv, sio.ReadFile)
	if err != nil {
		return fmt.Errorf("invalid configuration:\n%w", err)
	}
	// Logs go to stderr so stdout holds only the key.
	log := slog.New(slog.NewJSONHandler(sio.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	pool, err := db.Connect(ctx, cfg.DatabaseURL, 2, 60*time.Second, log)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.Migrate(ctx, cfg.DatabaseURL, log); err != nil {
		return err
	}
	key, err := httpapi.InsertKey(ctx, pool, auth.KindAdmin, nil, nil, *name, expiresAt)
	if err != nil {
		return err
	}
	if err := db.InsertAudit(ctx, pool, db.Audit{Actor: "system", Action: "key.create", ObjectType: "api_key",
		ObjectID: key.ID, Details: map[string]any{"kind": auth.KindAdmin, "name": *name, "via": "create-admin-key"}}); err != nil {
		return err
	}
	fmt.Fprintln(sio.Stdout, key.String())
	return nil
}

func cmdHashKey(sio IO) error {
	line, err := bufio.NewReader(sio.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	key, err := auth.ParseKey(strings.TrimSpace(line))
	if err != nil {
		return err
	}
	fmt.Fprintln(sio.Stdout, auth.HashLine(key))
	return nil
}

// Package db owns the Postgres pool, migrations, transactions, queries and the
// LISTEN loop.
package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver for goose
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/PatrickH298/ip-valet/api/migrations"
)

// Channels used with LISTEN/NOTIFY.
const (
	ChannelChanges = "ipvalet_changes"
	ChannelStatus  = "ipvalet_status"
	ChannelKeys    = "ipvalet_keys" // payload: the id of a key just created
)

// Advisory lock ids. The migration lock is goose's session lock; the purge
// lock is a transaction lock taken by the purge job.
const (
	MigrationLockID int64 = 0x69707661_6c657401 // "ipvalet\x01"
	PurgeLockID     int64 = 0x69707661_6c657402 // "ipvalet\x02"
)

// Querier is satisfied by *pgxpool.Pool, *pgxpool.Conn and pgx.Tx.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Connect opens the pool, retrying with backoff for up to retryFor.
func Connect(ctx context.Context, url string, maxConns int32, retryFor time.Duration, log *slog.Logger) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("IPVALET_DATABASE_URL: %w", redact(err))
	}
	cfg.MaxConns = maxConns
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, redact(err)
	}
	deadline := time.Now().Add(retryFor)
	backoff := 250 * time.Millisecond
	for {
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = pool.Ping(pctx)
		cancel()
		if err == nil {
			return pool, nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			pool.Close()
			return nil, fmt.Errorf("database unreachable: %w", redact(err))
		}
		log.Warn("database not reachable yet, retrying", "error", redact(err).Error(), "in", backoff.String())
		select {
		case <-ctx.Done():
			pool.Close()
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 5*time.Second)
	}
}

// redact drops connection details that pgconn may include in errors.
func redact(err error) error {
	var pgErr *pgconn.ConnectError
	if errors.As(err, &pgErr) {
		return errors.New("cannot connect to the database")
	}
	return err
}

// Migrate runs every pending migration under a Postgres session advisory
// lock, so concurrent instances wait their turn.
func Migrate(ctx context.Context, url string, log *slog.Logger) error {
	sqlDB, err := sql.Open("pgx", url)
	if err != nil {
		return redact(err)
	}
	defer sqlDB.Close()
	locker, err := lock.NewPostgresSessionLocker(lock.WithLockID(MigrationLockID), lock.WithLockTimeout(1, 600))
	if err != nil {
		return err
	}
	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, migrations.FS,
		goose.WithSessionLocker(locker), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		return err
	}
	results, err := p.Up(ctx)
	if err != nil {
		return redact(err)
	}
	for _, r := range results {
		log.Info("applied migration", "version", r.Source.Version, "duration", r.Duration.String())
	}
	return nil
}

// InTx runs fn in a transaction, committing when it returns nil.
func InTx(ctx context.Context, pool *pgxpool.Pool, opts pgx.TxOptions, fn func(pgx.Tx) error) error {
	tx, err := pool.BeginTx(ctx, opts)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck // no-op after commit
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Transaction options used throughout.
var (
	ReadCommitted = pgx.TxOptions{IsoLevel: pgx.ReadCommitted}
	SnapshotRead  = pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}
)

// LockCounter takes the revision counter's row lock, serialising every
// revision-bumping writer, and returns the current value.
func LockCounter(ctx context.Context, q Querier) (int64, error) {
	var v int64
	err := q.QueryRow(ctx, `SELECT value FROM revision_counter FOR UPDATE`).Scan(&v)
	return v, err
}

// Bump increments the counter and sends NOTIFY ipvalet_changes with the new
// value. The caller must hold the counter lock.
func Bump(ctx context.Context, q Querier) (int64, error) {
	var v int64
	if err := q.QueryRow(ctx, `UPDATE revision_counter SET value = value + 1 RETURNING value`).Scan(&v); err != nil {
		return 0, err
	}
	_, err := q.Exec(ctx, `SELECT pg_notify($1, $2)`, ChannelChanges, fmt.Sprint(v))
	return v, err
}

// CurrentRevision reads the counter without locking it.
func CurrentRevision(ctx context.Context, q Querier) (int64, error) {
	var v int64
	err := q.QueryRow(ctx, `SELECT value FROM revision_counter`).Scan(&v)
	return v, err
}

// Now returns the database's transaction time.
func Now(ctx context.Context, q Querier) (time.Time, error) {
	var t time.Time
	err := q.QueryRow(ctx, `SELECT now()`).Scan(&t)
	return t, err
}

// Revision lazily bumps the counter at most once per transaction.
type Revision struct {
	q   Querier
	rev int64
}

// NewRevision returns a lazy bumper for q, which must hold the counter lock.
func NewRevision(q Querier) *Revision { return &Revision{q: q} }

// Get bumps the counter on first use and returns the same value afterwards.
func (r *Revision) Get(ctx context.Context) (int64, error) {
	if r.rev != 0 {
		return r.rev, nil
	}
	v, err := Bump(ctx, r.q)
	if err != nil {
		return 0, err
	}
	r.rev = v
	return v, nil
}

// Bumped reports whether Get has bumped the counter.
func (r *Revision) Bumped() bool { return r.rev != 0 }

// IsUniqueViolation reports a unique-constraint violation.
func IsUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// IsForeignKeyViolation reports a foreign-key violation.
func IsForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

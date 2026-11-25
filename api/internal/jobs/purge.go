// Package jobs runs background jobs.
package jobs

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PatrickH298/ip-valet/api/internal/db"
)

const batchSize = 1000

// Purger deletes ended entries and old audit rows past retention.
type Purger struct {
	Pool             *pgxpool.Pool
	RetentionEntries time.Duration
	RetentionAudit   time.Duration
	Interval         time.Duration
	Log              *slog.Logger
}

// PurgeResult reports one run.
type PurgeResult struct {
	Skipped bool // another instance held the lock
	Entries int64
	Audit   int64
}

// Run purges every Interval until ctx is cancelled. The first run happens
// after one interval.
func (p *Purger) Run(ctx context.Context) {
	t := time.NewTicker(p.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			res, err := p.Once(ctx)
			switch {
			case err != nil && ctx.Err() == nil:
				p.Log.Error("purge failed", "error", err.Error())
			case res.Skipped:
				p.Log.Debug("purge skipped: another instance holds the lock")
			case err == nil:
				p.Log.Info("purge finished", "entries", res.Entries, "audit_rows", res.Audit)
			}
		}
	}
}

// Once runs one purge in a transaction holding a transaction-level advisory
// lock; if another instance holds it, the run is skipped.
func (p *Purger) Once(ctx context.Context) (PurgeResult, error) {
	var res PurgeResult
	err := db.InTx(ctx, p.Pool, db.ReadCommitted, func(tx pgx.Tx) error {
		var got bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, db.PurgeLockID).Scan(&got); err != nil {
			return err
		}
		if !got {
			res.Skipped = true
			return nil
		}
		entrySecs := int64(p.RetentionEntries / time.Second)
		for {
			tag, err := tx.Exec(ctx, `DELETE FROM entries WHERE id IN (
				SELECT id FROM entries
				WHERE deleted_at < now() - $1::bigint * interval '1 second'
				   OR (deleted_at IS NULL AND expires_at < now() - $1::bigint * interval '1 second')
				LIMIT $2)`, entrySecs, batchSize)
			if err != nil {
				return err
			}
			res.Entries += tag.RowsAffected()
			if tag.RowsAffected() < batchSize {
				break
			}
		}
		auditSecs := int64(p.RetentionAudit / time.Second)
		for {
			tag, err := tx.Exec(ctx, `DELETE FROM audit_log WHERE id IN (
				SELECT id FROM audit_log WHERE at < now() - $1::bigint * interval '1 second' LIMIT $2)`,
				auditSecs, batchSize)
			if err != nil {
				return err
			}
			res.Audit += tag.RowsAffected()
			if tag.RowsAffected() < batchSize {
				break
			}
		}
		return nil
	})
	return res, err
}

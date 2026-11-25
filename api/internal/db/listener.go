package db

import (
	"context"
	"log/slog"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
)

// Listener holds one dedicated connection running LISTEN on both channels.
type Listener struct {
	url string
	log *slog.Logger

	// OnChange is called with the revision from each ipvalet_changes notification.
	OnChange func(rev int64)
	// OnStatus is called with the worker id from each ipvalet_status notification.
	OnStatus func(workerID string)
	// OnKey is called with the key id from each ipvalet_keys notification.
	OnKey func(keyID string)
	// OnReconnect is called after the connection is re-established, since
	// notifications may have been missed while it was down.
	OnReconnect func()

	up   atomic.Bool
	done chan struct{}
}

// NewListener returns a listener for the database at url.
func NewListener(url string, log *slog.Logger) *Listener {
	return &Listener{url: url, log: log, done: make(chan struct{})}
}

// Up reports whether the LISTEN connection is currently established.
func (l *Listener) Up() bool { return l.up.Load() }

// Done is closed when Run returns.
func (l *Listener) Done() <-chan struct{} { return l.done }

// Start connects once (so startup fails fast on a bad URL) and then runs the
// loop in the background until ctx is cancelled.
func (l *Listener) Start(ctx context.Context) error {
	conn, err := l.connect(ctx)
	if err != nil {
		return err
	}
	go l.run(ctx, conn)
	return nil
}

func (l *Listener) connect(ctx context.Context) (*pgx.Conn, error) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(cctx, l.url)
	if err != nil {
		return nil, redact(err)
	}
	for _, ch := range []string{ChannelChanges, ChannelStatus, ChannelKeys} {
		if _, err := conn.Exec(cctx, "LISTEN "+pgx.Identifier{ch}.Sanitize()); err != nil {
			conn.Close(context.Background())
			return nil, err
		}
	}
	l.up.Store(true)
	return conn, nil
}

func (l *Listener) run(ctx context.Context, conn *pgx.Conn) {
	defer close(l.done)
	backoff := 250 * time.Millisecond
	for {
		if conn != nil {
			err := l.wait(ctx, conn)
			l.up.Store(false)
			cctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			conn.Close(cctx)
			cancel()
			conn = nil
			if ctx.Err() != nil {
				return
			}
			l.log.Warn("LISTEN connection lost, reconnecting", "error", redact(err).Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		c, err := l.connect(ctx)
		if err != nil {
			l.log.Warn("LISTEN reconnect failed", "error", err.Error(), "retry_in", backoff.String())
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		l.log.Info("LISTEN connection re-established")
		backoff = 250 * time.Millisecond
		conn = c
		if l.OnReconnect != nil {
			l.OnReconnect()
		}
	}
}

func (l *Listener) wait(ctx context.Context, conn *pgx.Conn) error {
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		switch n.Channel {
		case ChannelChanges:
			rev, err := strconv.ParseInt(n.Payload, 10, 64)
			if err == nil && l.OnChange != nil {
				l.OnChange(rev)
			}
		case ChannelStatus:
			if l.OnStatus != nil {
				l.OnStatus(n.Payload)
			}
		case ChannelKeys:
			if l.OnKey != nil {
				go l.OnKey(n.Payload)
			}
		}
	}
}

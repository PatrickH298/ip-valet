package acceptance

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PatrickH298/ip-valet/api/internal/app"
	"github.com/PatrickH298/ip-valet/api/internal/db"
	"github.com/PatrickH298/ip-valet/api/internal/jobs"
	"github.com/PatrickH298/ip-valet/api/internal/testutil"
)

func TestConcurrentStartupMigratesOnce(t *testing.T) {
	t.Parallel()
	dbURL := testutil.NewDatabase(t)
	cfg := testutil.Config(t, dbURL, nil)
	var (
		wg   sync.WaitGroup
		errs = make([]error, 2)
		apps = make([]*app.App, 2)
	)
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			apps[i], errs[i] = app.Start(ctx, cfg, testutil.Logger())
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("instance %d: %v", i, err)
		}
		defer apps[i].Close()
	}
	pool := pgxPool(t, dbURL)
	var applied, total int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FILTER (WHERE version_id = 1), count(*)
		FROM goose_db_version`).Scan(&applied, &total); err != nil {
		t.Fatal(err)
	}
	if applied != 1 {
		t.Fatalf("migration 1 recorded %d times (%d rows)", applied, total)
	}
}

func TestPurge(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("r")
	mk := func(prefix string) string {
		return firstEntryID(submitOK(h, s.ClientKey, sub("p", prefix, "1d", "g")))
	}
	oldDeleted, newDeleted := mk("8.8.8.1"), mk("8.8.8.2")
	oldExpired, newExpired := mk("8.8.8.3"), mk("8.8.8.4")
	live := mk("8.8.8.5")
	h.Exec(`UPDATE entries SET deleted_at = now() - interval '91 days', deleted_revision = 1, deleted_by = 't' WHERE id = $1`, oldDeleted)
	h.Exec(`UPDATE entries SET deleted_at = now() - interval '89 days', deleted_revision = 1, deleted_by = 't' WHERE id = $1`, newDeleted)
	h.Exec(`UPDATE entries SET expires_at = now() - interval '91 days' WHERE id = $1`, oldExpired)
	h.Exec(`UPDATE entries SET expires_at = now() - interval '89 days' WHERE id = $1`, newExpired)
	h.Exec(`UPDATE audit_log SET at = now() - interval '366 days' WHERE id = (SELECT min(id) FROM audit_log)`)
	auditBefore := countRows(h, `SELECT count(*) FROM audit_log`)

	p := &jobs.Purger{Pool: h.Pool, RetentionEntries: 90 * 24 * time.Hour, RetentionAudit: 365 * 24 * time.Hour,
		Interval: time.Hour, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	// Another instance holding the lock: this run is skipped.
	ctx := context.Background()
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, db.PurgeLockID); err != nil {
		t.Fatal(err)
	}
	res, err := p.Once(ctx)
	if err != nil || !res.Skipped {
		t.Fatalf("with the lock held: %+v %v", res, err)
	}
	if n := countRows(h, `SELECT count(*) FROM entries`); n != 5 {
		t.Fatalf("skipped run deleted entries: %d left", n)
	}
	_ = tx.Rollback(ctx)

	res, err = p.Once(ctx)
	if err != nil || res.Skipped || res.Entries != 2 || res.Audit != 1 {
		t.Fatalf("purge: %+v %v", res, err)
	}
	for _, id := range []string{oldDeleted, oldExpired} {
		if n := countRows(h, `SELECT count(*) FROM entries WHERE id = $1`, id); n != 0 {
			t.Errorf("%s not purged", id)
		}
	}
	for _, id := range []string{newDeleted, newExpired, live} {
		if n := countRows(h, `SELECT count(*) FROM entries WHERE id = $1`, id); n != 1 {
			t.Errorf("%s purged too early", id)
		}
	}
	if n := countRows(h, `SELECT count(*) FROM audit_log`); n != auditBefore-1 {
		t.Errorf("audit rows %d, want %d", n, auditBefore-1)
	}
}

func TestReadyz(t *testing.T) {
	t.Parallel()
	dbURL := testutil.NewDatabase(t)
	inst := testutil.StartInstance(t, testutil.Config(t, dbURL, nil))
	c := httpClient()
	get := func(path string) int {
		resp, err := c.Get(inst.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if s := get("/readyz"); s != 200 {
		t.Fatalf("readyz: %d", s)
	}
	if s := get("/healthz"); s != 200 {
		t.Fatalf("healthz: %d", s)
	}
	// Take the database away.
	admin := pgxPool(t, testutilBaseURL(t))
	u, _ := url.Parse(dbURL)
	name := pgx.Identifier{u.Path[1:]}.Sanitize()
	if _, err := admin.Exec(context.Background(), `DROP DATABASE `+name+` WITH (FORCE)`); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for get("/readyz") != http.StatusServiceUnavailable {
		if time.Now().After(deadline) {
			t.Fatal("readyz still 200 with the database gone")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if s := get("/healthz"); s != 200 {
		t.Fatalf("healthz with the database gone: %d", s)
	}
	// Authenticated routes report 503 unavailable.
	r := testutil.DoURL(t, c, inst.URL, "GET", "/v1/entries", "ipv_aaaaaaaaaaaaaaaa_"+
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil)
	if r.Status != 503 || r.Code(t) != "unavailable" {
		t.Fatalf("API with the database gone: %d %s", r.Status, r.Body)
	}
}

func testutilBaseURL(t *testing.T) string {
	t.Helper()
	return os.Getenv(testutil.EnvDatabaseURL)
}

func TestListenReconnect(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("r")
	ch, _ := openSSE(t, h.Inst.URL, "/v1/worker/events", s.WorkerKey)
	nextEvent(t, ch, 2*time.Second)

	// Kill the LISTEN connection; readiness drops, then recovers.
	h.Exec(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity
		WHERE datname = current_database() AND query LIKE 'LISTEN%'`)
	// Streams get a changed event after the reconnect, since notifications may have been missed.
	ev := nextEvent(t, ch, 5*time.Second)
	if ev.event != "changed" {
		t.Fatalf("after reconnect: %+v", ev)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !h.Inst.App.Listener.Up() {
		if time.Now().After(deadline) {
			t.Fatal("LISTEN connection did not come back")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if r := h.Do("GET", "/readyz", "", nil); r.Status != 200 {
		t.Fatalf("readyz after reconnect: %d", r.Status)
	}
	// Notifications flow again.
	submitOK(h, s.ClientKey, sub("p", "8.8.8.8", "1d", "g"))
	if ev := nextEvent(t, ch, 2*time.Second); ev.event != "changed" || ev.id != fmt.Sprint(h.Revision()) {
		t.Fatalf("after reconnect, submission: %+v", ev)
	}
}

func TestLastUsedAt(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("r")
	h.Must(200, "GET", "/v1/entries", s.ClientKey, nil)
	k := s.ClientKey[4:20]
	deadline := time.Now().Add(5 * time.Second)
	for {
		if v := h.Admin(200, "GET", "/v1/admin/keys/"+k, nil)["last_used_at"]; v != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("last_used_at never recorded")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

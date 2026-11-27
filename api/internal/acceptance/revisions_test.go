package acceptance

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/PatrickH298/ip-valet/api/internal/auth"
	"github.com/PatrickH298/ip-valet/api/internal/testutil"
)

type sseEvent struct {
	id, event, data string
	comment         bool
}

// openSSE connects to an event stream and delivers events and comments on a channel.
func openSSE(t *testing.T, base, path, key string) (<-chan sseEvent, *http.Response) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	req, _ := http.NewRequestWithContext(ctx, "GET", base+path, nil)
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("SSE %s: status %d", path, resp.StatusCode)
	}
	ch := make(chan sseEvent, 100)
	go func() {
		defer close(ch)
		defer resp.Body.Close()
		sc := bufio.NewScanner(resp.Body)
		var ev sseEvent
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				if ev.event != "" || ev.data != "" {
					ch <- ev
				}
				ev = sseEvent{}
			case strings.HasPrefix(line, ":"):
				ch <- sseEvent{comment: true, data: line}
			case strings.HasPrefix(line, "id: "):
				ev.id = strings.TrimPrefix(line, "id: ")
			case strings.HasPrefix(line, "event: "):
				ev.event = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				ev.data = strings.TrimPrefix(line, "data: ")
			}
		}
	}()
	return ch, resp
}

// nextEvent waits for the next non-comment event.
func nextEvent(t *testing.T, ch <-chan sseEvent, within time.Duration) sseEvent {
	t.Helper()
	deadline := time.After(within)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatal("stream closed")
			}
			if !ev.comment {
				return ev
			}
		case <-deadline:
			t.Fatalf("no event within %v", within)
		}
	}
}

func TestCommitOrderEqualsRevisionOrder(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("authentik")
	ctx := context.Background()

	// Writer A takes the counter lock and bumps it, but does not commit yet.
	txA, err := h.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var revA int64
	if err := txA.QueryRow(ctx, `SELECT value FROM revision_counter FOR UPDATE`).Scan(&revA); err != nil {
		t.Fatal(err)
	}
	if err := txA.QueryRow(ctx, `UPDATE revision_counter SET value = value + 1 RETURNING value`).Scan(&revA); err != nil {
		t.Fatal(err)
	}

	// Writer B, a submission, must wait on the counter lock.
	done := make(chan testutil.Resp, 1)
	go func() {
		done <- testutil.DoURL(t, httpClient(), h.Inst.URL, "POST", "/v1/submissions", s.ClientKey, sub("p", "8.8.8.8", "1d", "g"))
	}()
	waiting := false
	for i := 0; i < 50 && !waiting; i++ {
		time.Sleep(20 * time.Millisecond)
		var n int
		if err := h.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
			WHERE datname = current_database() AND wait_event_type = 'Lock'
			  AND query LIKE '%revision_counter%FOR UPDATE%'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		waiting = n > 0
	}
	if !waiting {
		t.Fatal("the submission is not waiting on the counter lock")
	}
	select {
	case r := <-done:
		t.Fatalf("submission finished while A held the lock: %d", r.Status)
	case <-time.After(200 * time.Millisecond):
	}
	if err := txA.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.Status != 201 {
		t.Fatalf("submission: %d %s", r.Status, r.Body)
	}
	e := adminEntry(h, firstEntryID(r.JSON(t)))
	if int64(e["revision"].(float64)) != revA+1 {
		t.Fatalf("B's revision %v, want %d (after A's %d)", e["revision"], revA+1, revA)
	}
}

func TestDesiredState(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	h.CreateRealm("r")
	h.ClearRules("r", "ttl")
	v4 := h.CreateWorker("v4", true, false)
	v6 := h.CreateWorker("v6", false, true)
	h.Subscribe(v4, "r", "*", "*")
	h.Subscribe(v6, "r", "*", "*")
	key := h.ClientKey(h.CreateClient("web", "r"))
	wk := h.WorkerKey(v4)

	submitOK(h, key, sub("p", "8.8.8.1", "1h", "g1"))
	submitOK(h, key, sub("p", "8.8.8.1", "2h", "g2"))
	submitOK(h, key, sub("p", "8.8.8.2", "1h", "g1"))
	submitOK(h, key, sub("p", "8.8.8.2", "unlimited", "g2"))
	expired := firstEntryID(submitOK(h, key, sub("p", "8.8.8.3", "1h", "g1")))
	h.Exec(`UPDATE entries SET expires_at = now() - interval '1 second' WHERE id = $1`, expired)
	deleted := firstEntryID(submitOK(h, key, sub("p", "8.8.8.4", "1h", "g1")))
	h.Must(200, "DELETE", "/v1/entries/"+deleted, key, nil)
	submitOK(h, key, sub("p", "2a00:1450::/64", "1h", "g1"))

	r := h.DesiredState(wk)
	if r.Status != 200 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	var ds struct {
		Revision     int64    `json:"revision"`
		GeneratedAt  string   `json:"generated_at"`
		NextChangeAt *string  `json:"next_change_at"`
		Families     []string `json:"families"`
		Entries      []struct {
			Prefix    string  `json:"prefix"`
			ExpiresAt *string `json:"expires_at"`
			Realm     string  `json:"realm"`
			User      string  `json:"user"`
			Group     string  `json:"group"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(r.Body, &ds); err != nil {
		t.Fatal(err)
	}
	if ds.Revision != h.Revision() || len(ds.Families) != 1 || ds.Families[0] != "ipv4" {
		t.Fatalf("revision/families: %+v", ds)
	}
	// One item per live, unexpired entry, with who it belongs to, ordered by
	// prefix, realm, user and group.
	want := [][4]string{{"8.8.8.1/32", "g1"}, {"8.8.8.1/32", "g2"}, {"8.8.8.2/32", "g1"}, {"8.8.8.2/32", "g2"}}
	if len(ds.Entries) != len(want) {
		t.Fatalf("entries = %s", r.Body)
	}
	for i, w := range want {
		e := ds.Entries[i]
		if e.Prefix != w[0] || e.Group != w[1] || e.Realm != "r" || e.User != "p" {
			t.Fatalf("entry %d = %+v, want %v", i, e, w)
		}
		exp := adminEntryByPrefix(h, w[0], w[1])["expires_at"]
		if (exp == nil) != (e.ExpiresAt == nil) || (exp != nil && *e.ExpiresAt != exp.(string)) {
			t.Fatalf("entry %d expiry %v, want %v", i, e.ExpiresAt, exp)
		}
	}
	if ds.Entries[3].ExpiresAt != nil {
		t.Fatalf("8.8.8.2 g2 should be unlimited: %v", *ds.Entries[3].ExpiresAt)
	}
	first := adminEntryByPrefix(h, "8.8.8.1/32", "g1")["expires_at"].(string)
	if ds.NextChangeAt == nil || *ds.NextChangeAt != first {
		t.Fatalf("next_change_at = %v, want the earliest expiry %s", ds.NextChangeAt, first)
	}
	if !strings.HasSuffix(ds.GeneratedAt, "Z") || len(ds.GeneratedAt) != len("2006-01-02T15:04:05.000000Z") {
		t.Fatalf("generated_at %q must be RFC 3339 UTC with microseconds", ds.GeneratedAt)
	}
	if r.Header.Get("IPValet-Revision") == "" || r.Header.Get("IPValet-Generated-At") != ds.GeneratedAt {
		t.Fatalf("headers: %v", r.Header)
	}
	// The IPv6 worker sees only the IPv6 entry.
	v6ds := h.DesiredState(h.WorkerKey(v6)).JSON(t)
	if items := v6ds["entries"].([]any); len(items) != 1 || items[0].(map[string]any)["prefix"] != "2a00:1450::/64" {
		t.Fatalf("v6 entries = %v", items)
	}
}

func adminEntryByPrefix(h *testutil.Harness, prefix, group string) map[string]any {
	h.T.Helper()
	m := h.Admin(200, "GET", "/v1/admin/entries?prefix="+prefix+"&group="+group, nil)
	items := m["items"].([]any)
	if len(items) != 1 {
		h.T.Fatalf("%d entries for %s %s", len(items), prefix, group)
	}
	return items[0].(map[string]any)
}

func TestDesiredStateETag(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	h.CreateRealm("r")
	a := h.CreateWorker("a", true, true)
	b := h.CreateWorker("b", true, true)
	h.Subscribe(a, "r", "*", "ga")
	h.Subscribe(b, "r", "*", "gb")
	key := h.ClientKey(h.CreateClient("web", "r"))
	wa := h.WorkerKey(a)
	submitOK(h, key, sub("p", "8.8.8.8", "1d", "ga"))

	first := h.DesiredState(wa)
	etag := first.Header.Get("ETag")
	if !strings.HasPrefix(etag, `"`) || len(etag) != 66 {
		t.Fatalf("ETag %q", etag)
	}
	nm := h.DesiredState(wa, "If-None-Match", etag)
	if nm.Status != 304 || len(nm.Body) != 0 {
		t.Fatalf("unchanged: %d %s", nm.Status, nm.Body)
	}
	rev1 := nm.Header.Get("IPValet-Revision")
	if rev1 == "" || nm.Header.Get("IPValet-Generated-At") == "" {
		t.Fatalf("304 headers: %v", nm.Header)
	}

	// A change to the other worker's entries bumps the revision but not this ETag.
	submitOK(h, key, sub("p", "8.8.4.4", "1d", "gb"))
	nm = h.DesiredState(wa, "If-None-Match", etag)
	if nm.Status != 304 {
		t.Fatalf("after another worker's change: %d", nm.Status)
	}
	if nm.Header.Get("IPValet-Revision") == rev1 {
		t.Fatal("IPValet-Revision did not advance")
	}
	// A change to this worker's entries changes it.
	submitOK(h, key, sub("p", "8.8.4.4", "1d", "ga"))
	if r := h.DesiredState(wa, "If-None-Match", etag); r.Status != 200 || r.Header.Get("ETag") == etag {
		t.Fatalf("after own change: %d", r.Status)
	}
}

func TestStatusReports(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("r")
	for i := 0; i < 5; i++ {
		submitOK(h, s.ClientKey, sub("p", "8.8.8."+string(rune('1'+i)), "1d", "g"))
	}
	ds := h.DesiredState(s.WorkerKey).JSON(t)
	gen := ds["generated_at"].(string)
	report := func(rev int64, extra map[string]any) map[string]any {
		body := map[string]any{"instance": "w1", "version": "1.0", "revision": rev}
		for k, v := range extra {
			body[k] = v
		}
		return h.Must(200, "POST", "/v1/worker/status", s.WorkerKey, body)
	}
	worker := func() map[string]any { return h.Admin(200, "GET", "/v1/admin/workers/"+s.WorkerID+"/health", nil) }

	out := report(5, map[string]any{"generated_at": gen, "rejected": []map[string]any{
		{"prefix": "8.8.8.1", "code": "address_not_allowed", "detail": "floor"}}})
	if out["applied_revision"].(float64) != 5 {
		t.Fatalf("applied = %v", out)
	}
	t1 := worker()
	if t1["applied_revision"].(float64) != 5 || len(t1["rejections"].([]any)) != 1 || t1["last_version"] != "1.0" {
		t.Fatalf("after report: %v", t1)
	}
	time.Sleep(10 * time.Millisecond)

	// Stale report: only last_seen_at changes.
	out = report(3, map[string]any{"generated_at": gen, "rejected": []map[string]any{}})
	if out["applied_revision"].(float64) != 5 {
		t.Fatalf("stale report lowered applied: %v", out)
	}
	t2 := worker()
	if t2["applied_revision"].(float64) != 5 || len(t2["rejections"].([]any)) != 1 || t2["last_seen_at"] == t1["last_seen_at"] {
		t.Fatalf("after stale report: %v", t2)
	}

	// Error report: applied state unchanged.
	out = report(5, map[string]any{"error": "controller timeout"})
	t3 := worker()
	if out["applied_revision"].(float64) != 5 || t3["last_error"] != "controller timeout" ||
		t3["applied_generated_at"] != t1["applied_generated_at"] || len(t3["rejections"].([]any)) != 1 {
		t.Fatalf("after error report: %v", t3)
	}

	// Invalid reports.
	for _, b := range []map[string]any{
		{"instance": "w", "revision": 999, "generated_at": gen},
		{"instance": "w", "revision": 1},
		{"instance": "w", "revision": 1, "generated_at": gen, "error": "x"},
		{"instance": "w", "revision": 1, "generated_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)},
		{"instance": "", "revision": 1, "generated_at": gen},
		{"instance": "w", "revision": 1, "generated_at": gen, "rejected": []map[string]any{{"prefix": "x", "code": "invalid"}}},
		{"instance": "w", "revision": 1, "generated_at": gen, "rejected": []map[string]any{{"prefix": "8.8.8.8", "code": "nope"}}},
	} {
		if r := h.Do("POST", "/v1/worker/status", s.WorkerKey, b); r.Status != 400 {
			t.Errorf("%v: %d %s", b, r.Status, r.Body)
		}
	}
}

// A worker's refusal is audited against the entries it refuses, once: a
// worker repeats its rejections on every sync.
func TestRejectionsAreAudited(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("r")
	submitOK(h, s.ClientKey, sub("ann", "8.8.8.8", "1d", "staff", "lab"))
	submitOK(h, s.ClientKey, sub("bob", "8.8.4.4", "1d", "staff"))
	gen := h.DesiredState(s.WorkerKey).JSON(t)["generated_at"].(string)
	report := func(rejected ...map[string]any) {
		if rejected == nil {
			rejected = []map[string]any{}
		}
		h.Must(200, "POST", "/v1/worker/status", s.WorkerKey, map[string]any{"instance": "w1", "revision": 2,
			"generated_at": gen, "rejected": rejected})
	}
	audit := func() []map[string]any {
		var out []map[string]any
		for _, it := range h.Admin(200, "GET", "/v1/admin/audit?action=entry.reject", nil)["items"].([]any) {
			out = append(out, it.(map[string]any))
		}
		return out
	}
	private := map[string]any{"prefix": "8.8.8.8", "code": "no_matching_rule", "detail": "no rule takes this address"}

	// One row per refused entry: ann's address is in two groups.
	report(private)
	rows := audit()
	if len(rows) != 2 {
		t.Fatalf("%d rows: %v", len(rows), rows)
	}
	for _, r := range rows {
		d := r["details"].(map[string]any)
		if r["object_type"] != "entry" || r["realm"] != "r" || r["user"] != "ann" || r["prefix"] != "8.8.8.8/32" ||
			d["code"] != "no_matching_rule" || d["detail"] != private["detail"] || d["worker"] != "home-r" ||
			d["worker_id"] != s.WorkerID || d["instance"] != "w1" {
			t.Fatalf("%v", r)
		}
	}
	// The same rejection again is not audited again.
	report(private)
	if n := len(audit()); n != 2 {
		t.Fatalf("repeat audited: %d rows", n)
	}
	// A new reason is.
	report(map[string]any{"prefix": "8.8.8.8", "code": "address_not_allowed"})
	if n := len(audit()); n != 4 {
		t.Fatalf("changed code: %d rows", n)
	}
	// A rejection that matches no live entry is audited against the worker.
	report(map[string]any{"prefix": "8.8.8.8", "code": "address_not_allowed"},
		map[string]any{"prefix": "9.9.9.9", "code": "invalid"})
	rows = audit()
	if len(rows) != 5 || rows[0]["object_type"] != "worker" || rows[0]["object_id"] != s.WorkerID ||
		rows[0]["prefix"] != "9.9.9.9/32" || rows[0]["realm"] != nil {
		t.Fatalf("%v", rows[0])
	}
	// Accepted, then refused again: audited again.
	report()
	report(private)
	if n := len(audit()); n != 7 {
		t.Fatalf("refused again: %d rows", n)
	}
}

func TestAppliedStates(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	h.CreateRealm("r")
	a := h.CreateWorker("alpha", true, true)
	b := h.CreateWorker("beta", true, true)
	subA := h.Subscribe(a, "r", "*", "*")
	key := h.ClientKey(h.CreateClient("web", "r"))
	wa, wb := h.WorkerKey(a), h.WorkerKey(b)

	id := firstEntryID(submitOK(h, key, sub("p", "8.8.8.8", "1d", "g")))
	if st, _ := entryState(h, id); st != "pending" {
		t.Fatalf("new entry: %s", st)
	}
	h.Apply(wa)
	if st, _ := entryState(h, id); st != "active" {
		t.Fatalf("after apply: %s", st)
	}

	// A new subscription makes the old entry pending on that worker, not active.
	h.Subscribe(b, "r", "*", "*")
	st, per := entryState(h, id)
	if st != "pending" || per["alpha"] != "active" || per["beta"] != "pending" {
		t.Fatalf("after new subscription: %s %v", st, per)
	}
	h.Apply(wb, map[string]any{"prefix": "8.8.8.8/32", "code": "capacity_exceeded"})
	st, per = entryState(h, id)
	if st != "partial" || per["beta"] != "rejected" {
		t.Fatalf("partial: %s %v", st, per)
	}
	client := h.Must(200, "GET", "/v1/entries/"+id, key, nil)
	for _, tv := range client["workers"].([]any) {
		m := tv.(map[string]any)
		if m["label"] == "Beta" && m["code"] != "capacity_exceeded" {
			t.Fatalf("client view lacks the rejection code: %v", m)
		}
		if _, leaked := m["last_seen_at"]; leaked {
			t.Fatal("client view leaks admin fields")
		}
	}
	h.Apply(wa, map[string]any{"prefix": "8.8.8.8/32", "code": "address_not_allowed"})
	if st, _ := entryState(h, id); st != "rejected" {
		t.Fatalf("rejected: %s", st)
	}
	h.Apply(wa)
	h.Apply(wb)

	// Unrouted after its subscriptions go (confirm, keep).
	id2 := firstEntryID(submitOK(h, key, sub("q", "8.8.4.4", "1d", "only-alpha")))
	h.Apply(wa)
	h.Apply(wb)
	h.Admin(200, "DELETE", "/v1/admin/subscriptions/"+subA+"?confirm=true", nil)
	// id2 is still matched by beta's subscription r/*/*, so remove that one too.
	for _, sv := range h.Admin(200, "GET", "/v1/admin/workers/"+b+"/subscriptions", nil)["items"].([]any) {
		h.Admin(200, "DELETE", "/v1/admin/subscriptions/"+sv.(map[string]any)["id"].(string)+"?confirm=true", nil)
	}
	if st, _ := entryState(h, id2); st != "unrouted" {
		t.Fatalf("unrouted: %s", st)
	}
}

func TestRemovalConfirmation(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("r")

	del := firstEntryID(submitOK(h, s.ClientKey, sub("p", "8.8.8.8", "1d", "g")))
	exp := firstEntryID(submitOK(h, s.ClientKey, sub("p", "8.8.4.4", "1d", "g")))
	h.Apply(s.WorkerKey)

	// Deleted: removing until the worker reports the deletion revision.
	h.Must(200, "DELETE", "/v1/entries/"+del, s.ClientKey, nil)
	delRev := adminEntry(h, del)
	if delRev["state"] != "removing" {
		t.Fatalf("deleted: %v", delRev["state"])
	}
	var deletedRevision int64
	if err := h.Pool.QueryRow(context.Background(), `SELECT deleted_revision FROM entries WHERE id = $1`, del).Scan(&deletedRevision); err != nil {
		t.Fatal(err)
	}
	ds := h.DesiredState(s.WorkerKey).JSON(t)
	h.Must(200, "POST", "/v1/worker/status", s.WorkerKey, map[string]any{"instance": "w", "revision": deletedRevision - 1,
		"generated_at": ds["generated_at"]})
	if st, _ := entryState(h, del); st != "removing" {
		t.Fatalf("before the deletion revision: %s", st)
	}
	h.Apply(s.WorkerKey)
	if st, per := entryState(h, del); st != "removed" || per["home-r"] != "removed" {
		t.Fatalf("after the deletion revision: %s %v", st, per)
	}

	// Expired: removing until applied_generated_at passes the expiry.
	h.Exec(`UPDATE entries SET expires_at = now() + interval '300 milliseconds' WHERE id = $1`, exp)
	time.Sleep(400 * time.Millisecond)
	if st, _ := entryState(h, exp); st != "removing" {
		t.Fatalf("expired, unconfirmed: %s", st)
	}
	h.Apply(s.WorkerKey)
	if st, per := entryState(h, exp); st != "expired" || per["home-r"] != "expired" {
		t.Fatalf("expired, confirmed: %s %v", st, per)
	}
}

func TestWorkerEventsFanOutAcrossInstances(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("r")
	second := testutil.StartInstance(t, testutil.Config(t, h.DBURL, nil))

	ch, resp := openSSE(t, second.URL, "/v1/worker/events", s.WorkerKey)
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type %q", ct)
	}
	if resp.Header.Get("Cache-Control") != "no-cache" || resp.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatalf("headers: %v", resp.Header)
	}
	rev := h.Revision()
	first := nextEvent(t, ch, 2*time.Second)
	if want := fmt.Sprint(rev); first.event != "changed" || first.id != want || first.data != `{"revision":`+want+`}` {
		t.Fatalf("initial event: %+v, want revision %d", first, rev)
	}
	start := time.Now()
	submitOK(h, s.ClientKey, sub("p", "8.8.8.8", "1d", "g"))
	ev := nextEvent(t, ch, time.Second)
	if want := fmt.Sprint(rev + 1); ev.event != "changed" || ev.id != want || ev.data != `{"revision":`+want+`}` {
		t.Fatalf("event after submission: %+v, want revision %s", ev, want)
	}
	t.Logf("event arrived %v after the submission was sent", time.Since(start))
}

func TestSSEOutlivesWriteTimeoutAndHeartbeats(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("r")
	inst := testutil.StartInstance(t, testutil.Config(t, h.DBURL, map[string]string{"IPVALET_SSE_HEARTBEAT": "200ms"}),
		func(srv *http.Server) {
			srv.WriteTimeout = 500 * time.Millisecond
			srv.ReadTimeout = 500 * time.Millisecond
		})
	ch, _ := openSSE(t, inst.URL, "/v1/worker/events", s.WorkerKey)
	nextEvent(t, ch, 2*time.Second)
	pings := 0
	deadline := time.After(1500 * time.Millisecond)
loop:
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatal("stream closed: the write or read deadline was not lifted")
			}
			if ev.comment && ev.data == ": ping" {
				pings++
			}
		case <-deadline:
			break loop
		}
	}
	if pings < 4 {
		t.Fatalf("%d pings in 1.5s", pings)
	}
	// Ordinary routes keep the write timeout; the stream still works after it.
	submitOK(h, s.ClientKey, sub("p", "8.8.8.8", "1d", "g"))
	if ev := nextEvent(t, ch, 2*time.Second); ev.event != "changed" {
		t.Fatalf("after 1.5s: %+v", ev)
	}
}

func TestClientEvents(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, map[string]string{"IPVALET_CLIENT_EVENTS_RECHECK": "200ms"})
	s := h.Basic("r")
	old := firstEntryID(submitOK(h, s.ClientKey, sub("p", "8.8.8.8", "1d", "g")))
	ch, _ := openSSE(t, h.Inst.URL, "/v1/events", s.ClientKey)

	// No baseline events.
	select {
	case ev := <-ch:
		if !ev.comment {
			t.Fatalf("baseline event sent: %+v", ev)
		}
	case <-time.After(300 * time.Millisecond):
	}
	h.Apply(s.WorkerKey)
	ev := nextEvent(t, ch, 2*time.Second)
	if ev.event != "entry" || ev.data != `{"id":"`+old+`","state":"active"}` {
		t.Fatalf("after apply: %+v", ev)
	}
	// Expiry is caught by the recheck timer.
	h.Exec(`UPDATE entries SET expires_at = now() + interval '200 milliseconds' WHERE id = $1`, old)
	ev = nextEvent(t, ch, 2*time.Second)
	if ev.data != `{"id":"`+old+`","state":"removing"}` {
		t.Fatalf("after expiry: %+v", ev)
	}
}

func TestStatusReportLimits(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("r")
	gen := h.DesiredState(s.WorkerKey).JSON(t)["generated_at"].(string)
	report := func(n, detailLen int) map[string]any {
		items := make([]map[string]any, n)
		for i := range items {
			items[i] = map[string]any{
				"prefix": fmt.Sprintf("ffff:ffff:ffff:ffff:ffff:ffff:ffff:%04x/128", 0x1000+i),
				"code":   "address_not_allowed", "detail": strings.Repeat("x", detailLen)}
		}
		return map[string]any{"instance": strings.Repeat("w", 128), "version": strings.Repeat("v", 64),
			"revision": h.Revision(), "generated_at": gen, "rejected": items}
	}
	// The largest valid report fits in the default body limit.
	largest := report(200, 200)
	body, _ := json.Marshal(largest)
	if len(body) > 65536 {
		t.Fatalf("the largest valid report is %d bytes", len(body))
	}
	h.Must(200, "POST", "/v1/worker/status", s.WorkerKey, largest)
	if n := len(h.Admin(200, "GET", "/v1/admin/workers/"+s.WorkerID+"/health", nil)["rejections"].([]any)); n != 200 {
		t.Fatalf("%d rejections stored", n)
	}
	for _, bad := range []map[string]any{report(201, 10), report(1, 201)} {
		if r := h.Do("POST", "/v1/worker/status", s.WorkerKey, bad); r.Status != 400 || r.Code(t) != "invalid_request" {
			t.Fatalf("over the limits: %d %s", r.Status, r.Body)
		}
	}
}

func TestEventStreamLimits(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, map[string]string{"IPVALET_MAX_STREAMS_PER_KEY": "2", "IPVALET_SSE_HEARTBEAT": "200ms"})
	s := h.Basic("r")
	first, _ := openSSE(t, h.Inst.URL, "/v1/worker/events", s.WorkerKey)
	openSSE(t, h.Inst.URL, "/v1/worker/events", s.WorkerKey)
	nextEvent(t, first, 2*time.Second)

	// A third stream on the same key is refused; another key for the worker is not.
	if r := h.Do("GET", "/v1/worker/events", s.WorkerKey, nil); r.Status != 429 || r.Code(t) != "too_many_streams" {
		t.Fatalf("third stream: %d %s", r.Status, r.Body)
	}
	openSSE(t, h.Inst.URL, "/v1/worker/events", h.WorkerKey(s.WorkerID))
	client, _ := openSSE(t, h.Inst.URL, "/v1/events", s.ClientKey)

	// Revoking a key ends its open streams within a heartbeat, with no change needed.
	wk, _ := auth.ParseKey(s.WorkerKey)
	ck, _ := auth.ParseKey(s.ClientKey)
	h.Admin(200, "POST", "/v1/admin/keys/"+wk.ID+"/revoke", nil)
	h.Admin(200, "POST", "/v1/admin/keys/"+ck.ID+"/revoke", nil)
	for name, ch := range map[string]<-chan sseEvent{"worker": first, "client": client} {
		deadline := time.After(2 * time.Second)
	drain:
		for {
			select {
			case _, ok := <-ch:
				if !ok {
					break drain
				}
			case <-deadline:
				t.Fatalf("%s stream still open after its key was revoked", name)
			}
		}
	}
}

// TestNoMatchingRule: a worker that routes by its own rules reports entries
// none of them takes as no_matching_rule, and clients see the code.
func TestNoMatchingRule(t *testing.T) {
	t.Parallel()
	h := testutil.New(t, nil)
	s := h.Basic("r")
	id := firstEntryID(submitOK(h, s.ClientKey, sub("p", "8.8.8.8", "1d", "g")))
	h.Apply(s.WorkerKey, map[string]any{"prefix": "8.8.8.8/32", "code": "no_matching_rule", "detail": "no rule for realm r"})
	e := h.Must(200, "GET", "/v1/entries/"+id, s.ClientKey, nil)
	w := e["workers"].([]any)[0].(map[string]any)
	if e["state"] != "rejected" || w["state"] != "rejected" || w["code"] != "no_matching_rule" {
		t.Fatalf("entry %v", e)
	}
}

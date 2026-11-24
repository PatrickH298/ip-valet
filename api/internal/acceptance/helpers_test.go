// Package acceptance holds the acceptance tests from the implementation
// spec. They run against a real Postgres named by IPVALET_TEST_DATABASE_URL.
package acceptance

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PatrickH298/ip-valet/api/internal/testutil"
)

func httpClient() *http.Client { return &http.Client{Timeout: 30 * time.Second} }

func pgxPool(t testing.TB, url string) *pgxpool.Pool {
	t.Helper()
	p, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

// adminEntry returns the admin view of an entry.
func adminEntry(h *testutil.Harness, id string) map[string]any {
	h.T.Helper()
	return h.Admin(200, "GET", "/v1/admin/entries/"+id, nil)
}

// entryState returns the overall state and per-target states keyed by target name.
func entryState(h *testutil.Harness, id string) (string, map[string]string) {
	h.T.Helper()
	e := adminEntry(h, id)
	per := map[string]string{}
	for _, t := range e["targets"].([]any) {
		m := t.(map[string]any)
		per[m["name"].(string)] = m["state"].(string)
	}
	return e["state"].(string), per
}

// submitOK submits and returns the response body, failing unless 201.
func submitOK(h *testutil.Harness, key string, body map[string]any) map[string]any {
	h.T.Helper()
	r := h.Submit(key, body)
	if r.Status != 201 {
		h.T.Fatalf("submission %v: %d %s", body, r.Status, r.Body)
	}
	return r.JSON(h.T)
}

// firstEntryID returns entries[0].id of a submission response.
func firstEntryID(resp map[string]any) string {
	return resp["entries"].([]any)[0].(map[string]any)["id"].(string)
}

// results returns a 422 body's results keyed by group.
func results(t testing.TB, r testutil.Resp) map[string]map[string]any {
	t.Helper()
	if r.Status != 422 || r.Code(t) != "submission_rejected" {
		t.Fatalf("want 422 submission_rejected, got %d %s", r.Status, r.Body)
	}
	out := map[string]map[string]any{}
	for _, it := range r.JSON(t)["error"].(map[string]any)["results"].([]any) {
		m := it.(map[string]any)
		out[m["group"].(string)] = m
	}
	return out
}

// sub builds a submission body.
func sub(user, prefix, ttl string, groups ...string) map[string]any {
	return map[string]any{"user": user, "groups": groups, "prefix": prefix, "ttl": ttl}
}

func countRows(h *testutil.Harness, sql string, args ...any) int {
	h.T.Helper()
	var n int
	if err := h.Pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		h.T.Fatal(err)
	}
	return n
}

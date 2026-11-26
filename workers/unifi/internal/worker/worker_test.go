package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PatrickH298/ip-valet/workers/unifi/internal/config"
	"github.com/PatrickH298/ip-valet/workers/unifi/internal/ipvalet"
	"github.com/PatrickH298/ip-valet/workers/unifi/internal/rules"
	"github.com/PatrickH298/ip-valet/workers/unifi/internal/unifi"
	"github.com/PatrickH298/ip-valet/workers/unifi/internal/unifi/unifitest"
)

const workerKey = "ipv_aaaaaaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// fakeAPI serves a worker's desired state and records its status reports.
type fakeAPI struct {
	*httptest.Server
	mu       sync.Mutex
	state    ipvalet.DesiredState
	down     bool
	reports  []ipvalet.Report
	requests int
}

func newFakeAPI() *fakeAPI {
	f := &fakeAPI{state: ipvalet.DesiredState{Revision: 1, GeneratedAt: "2026-01-01T12:00:00.000000Z",
		Families: []string{"ipv4", "ipv6"}, Entries: []ipvalet.Entry{}}}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.requests++
		if f.down {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+workerKey {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v1/worker/desired-state":
			b, _ := json.Marshal(f.state.Entries)
			etag := fmt.Sprintf(`"%d-%d"`, len(b), hash(b))
			w.Header().Set("ETag", etag)
			w.Header().Set("IPValet-Revision", fmt.Sprint(f.state.Revision))
			w.Header().Set("IPValet-Generated-At", f.state.GeneratedAt)
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			_ = json.NewEncoder(w).Encode(f.state)
		case "/v1/worker/status":
			var rep ipvalet.Report
			_ = json.NewDecoder(r.Body).Decode(&rep)
			f.reports = append(f.reports, rep)
			_, _ = w.Write([]byte(`{"applied_revision":1}`))
		default:
			http.NotFound(w, r)
		}
	}))
	return f
}

func hash(b []byte) uint32 {
	var h uint32 = 2166136261
	for _, c := range b {
		h = (h ^ uint32(c)) * 16777619
	}
	return h
}

func (f *fakeAPI) set(rev int64, entries ...ipvalet.Entry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state.Revision, f.state.Entries = rev, entries
}

func (f *fakeAPI) setDown(d bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = d
}

func (f *fakeAPI) lastReport(t *testing.T) ipvalet.Report {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reports) == 0 {
		t.Fatal("no status report")
	}
	return f.reports[len(f.reports)-1]
}

func (f *fakeAPI) reportCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reports)
}

func e(prefix, realm, user, group string, exp *time.Time) ipvalet.Entry {
	return ipvalet.Entry{Prefix: prefix, Realm: realm, User: user, Group: group, ExpiresAt: exp}
}

type harness struct {
	t   *testing.T
	api *fakeAPI
	ctl *unifitest.Server
	now time.Time
	cfg config.Config
	w   *Worker
}

func newHarness(t *testing.T, ruleSpecs ...string) *harness {
	t.Helper()
	h := &harness{t: t, api: newFakeAPI(), ctl: unifitest.New("unifi-key"),
		now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	t.Cleanup(h.api.Close)
	t.Cleanup(h.ctl.Close)
	apiURL, _ := url.Parse(h.api.URL)
	ctlURL, _ := url.Parse(h.ctl.URL)
	h.cfg = config.Config{APIURL: apiURL, APIKey: workerKey, ControllerURL: ctlURL, ControllerKey: "unifi-key",
		Site: "Default", VerifyTLS: true, CreateLists: true, Floor: rules.Floor{MinV4: 24, MinV6: 48},
		SyncInterval: time.Minute, Timeout: 5 * time.Second, DataDir: t.TempDir(), Instance: "test"}
	for i, s := range ruleSpecs {
		r, err := rules.Parse(fmt.Sprint("R", i), s)
		if err != nil {
			t.Fatal(err)
		}
		h.cfg.Rules = append(h.cfg.Rules, r)
	}
	h.w = h.newWorker()
	return h
}

func (h *harness) newWorker() *Worker {
	h.t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	uc := unifi.New(h.cfg.ControllerURL, h.cfg.ControllerKey, true, h.cfg.Timeout, log)
	uc.Backoff = func(int) time.Duration { return time.Millisecond }
	w, err := New(Options{Config: h.cfg, API: ipvalet.New(h.cfg.APIURL, h.cfg.APIKey, h.cfg.Timeout), UniFi: uc,
		Log: log, Version: "test", Now: func() time.Time { return h.now }})
	if err != nil {
		h.t.Fatal(err)
	}
	return w
}

func (h *harness) sync() Result {
	h.t.Helper()
	return h.w.Sync(context.Background())
}

func (h *harness) items(list string) string { return strings.Join(h.ctl.Items(list), " ") }

func TestSyncPlacesAndReports(t *testing.T) {
	h := newHarness(t,
		"realm=home group=staff ipv4_list=staff-v4 ipv6_list=staff-v6",
		"realm=home addresses=private family=ipv4 ipv4_list=lan-v4")
	later := h.now.Add(time.Hour)
	h.api.set(7,
		e("8.8.8.8/32", "home", "ann", "staff", &later),
		e("2a00:1450::/64", "home", "ann", "staff", nil),
		e("192.168.1.10/32", "home", "bob", "guests", nil),
		e("1.1.1.1/32", "home", "bob", "guests", nil), // lan-v4 takes only private; staff not bob's group
		e("9.9.9.9/32", "work", "cat", "x", nil),      // no rule for realm work
	)
	res := h.sync()
	if res.Err != nil || !res.FromAPI || !res.Reported {
		t.Fatalf("%+v", res)
	}
	for list, want := range map[string]string{
		"staff-v4": "8.8.8.8/32", "staff-v6": "2a00:1450::/64", "lan-v4": "192.168.1.10/32",
	} {
		if got := h.items(list); got != want {
			t.Errorf("%s = %q, want %q", list, got, want)
		}
	}
	rep := h.api.lastReport(t)
	if rep.Error != "" || rep.Revision != 7 || rep.GeneratedAt == "" || rep.Instance != "test" || rep.Version != "test" {
		t.Fatalf("report %+v", rep)
	}
	codes := map[string]string{}
	for _, r := range rep.Rejected {
		codes[r.Prefix] = r.Code
	}
	if codes["1.1.1.1/32"] != "address_not_allowed" || codes["9.9.9.9/32"] != "no_matching_rule" || len(codes) != 2 {
		t.Fatalf("rejections %+v", rep.Rejected)
	}
	if res.NextExpiry == nil || !res.NextExpiry.Equal(later) {
		t.Fatalf("next expiry %v", res.NextExpiry)
	}

	// Nothing changed: a 304, no writes, and a fresh report.
	puts := h.ctl.Puts
	res = h.sync()
	if res.Err != nil || len(res.Changed) != 0 || h.ctl.Puts != puts || h.api.reportCount() != 2 {
		t.Fatalf("second sync %+v, puts %d", res, h.ctl.Puts)
	}

	// A hand edit in the UniFi UI is undone.
	h.ctl.Edit(h.listID("staff-v4"), unifi.Item{Type: "IP_ADDRESS", Value: "4.4.4.4"})
	if res = h.sync(); res.Err != nil || len(res.Changed) != 1 || h.items("staff-v4") != "8.8.8.8/32" {
		t.Fatalf("after a hand edit: %+v %q", res, h.items("staff-v4"))
	}

	// When an entry expires the list falls back to its sentinel, never empty.
	h.now = later.Add(time.Second)
	if res = h.sync(); res.Err != nil || h.items("staff-v4") != "192.0.2.1/32" {
		t.Fatalf("after expiry: %+v %q", res, h.items("staff-v4"))
	}
}

func (h *harness) listID(name string) string {
	h.t.Helper()
	found, err := h.w.lists(context.Background())
	if err != nil || found[name] == nil {
		h.t.Fatalf("list %s: %v", name, err)
	}
	return found[name].ID
}

func TestExpiryWithoutTheAPI(t *testing.T) {
	h := newHarness(t, "realm=home family=ipv4 ipv4_list=v4")
	soon := h.now.Add(time.Minute)
	h.api.set(3, e("8.8.8.8/32", "home", "ann", "g", &soon), e("8.8.4.4/32", "home", "bob", "g", nil))
	if res := h.sync(); res.Err != nil {
		t.Fatal(res.Err)
	}
	if got := h.items("v4"); got != "8.8.4.4/32 8.8.8.8/32" {
		t.Fatalf("v4 = %q", got)
	}
	// The API goes away, and the worker restarts: the cache on disk still
	// lets it remove the expired entry on time.
	h.api.setDown(true)
	reports := h.api.reportCount()
	h.w = h.newWorker()
	h.w.loadCache()
	h.now = soon.Add(time.Second)
	res := h.sync()
	if res.Err != nil || res.FromAPI || res.Reported || h.items("v4") != "8.8.4.4/32" {
		t.Fatalf("offline: %+v %q", res, h.items("v4"))
	}
	if h.api.reportCount() != reports {
		t.Fatal("reported while the API was down")
	}
	// With neither the API nor a cache, nothing is touched.
	h.cfg.DataDir = t.TempDir()
	h.w = h.newWorker()
	if res := h.sync(); res.Err == nil || !strings.Contains(res.Err.Error(), "no desired state") {
		t.Fatalf("no state: %+v", res)
	}
}

func TestControllerFailureIsReported(t *testing.T) {
	h := newHarness(t, "realm=home family=ipv4 ipv4_list=v4")
	h.ctl.Add("v4", unifi.TypeIPv4, unifi.Item{Type: "IP_ADDRESS", Value: "192.0.2.1"})
	h.api.set(4, e("8.8.8.8/32", "home", "ann", "g", nil))
	h.ctl.FailPuts(10)
	res := h.sync()
	if res.Err == nil || !res.Reported {
		t.Fatalf("%+v", res)
	}
	if rep := h.api.lastReport(t); rep.Error == "" || rep.GeneratedAt != "" || !strings.Contains(rep.Error, "500") {
		t.Fatalf("report %+v", rep)
	}
	h.ctl.FailPuts(0)
	if res := h.sync(); res.Err != nil || h.items("v4") != "8.8.8.8/32" || h.api.lastReport(t).Error != "" {
		t.Fatalf("recovery: %+v", res)
	}
}

func TestListChecks(t *testing.T) {
	// A list named by an id that does not exist is an error, never created.
	h := newHarness(t, "realm=home family=ipv4 ipv4_list=00000000-1111-4222-8333-444444444444")
	h.api.set(1)
	if res := h.sync(); res.Err == nil || !strings.Contains(res.Err.Error(), "does not exist") {
		t.Fatalf("missing id: %+v", res)
	}
	// With list creation off, a missing name is an error too.
	h = newHarness(t, "realm=home family=ipv4 ipv4_list=v4")
	h.cfg.CreateLists = false
	h.w = h.newWorker()
	if res := h.sync(); res.Err == nil || h.ctl.Has("v4") {
		t.Fatalf("creation off: %+v", res)
	}
	// A list of the wrong family is not touched.
	h = newHarness(t, "realm=home family=ipv4 ipv4_list=v6list")
	h.ctl.Add("v6list", unifi.TypeIPv6, unifi.Item{Type: "IP_ADDRESS", Value: "100::1"})
	if res := h.sync(); res.Err == nil || !strings.Contains(res.Err.Error(), "IPV6_ADDRESSES") {
		t.Fatalf("wrong family: %+v", res)
	}
	// Lists found by id, and a collection that leaves out items.
	h = newHarness(t)
	id := h.ctl.Add("named", unifi.TypeIPv4, unifi.Item{Type: "SUBNET", Value: "203.0.113.0/24"})
	r, _ := rules.Parse("X", "realm=home family=ipv4 ipv4_list="+id)
	h.cfg.Rules = []rules.Rule{r}
	h.w = h.newWorker()
	h.ctl.OmitItems = true
	h.api.set(2, e("8.8.0.0/24", "home", "u", "g", nil))
	if res := h.sync(); res.Err != nil || h.items("named") != "8.8.0.0/24" {
		t.Fatalf("by id: %+v %q", res, h.items("named"))
	}
	// One list may not take both families.
	if _, err := New(Options{Config: config.Config{Rules: []rules.Rule{
		{Name: "A", Realm: "r", User: "*", Group: "*", Family: "ipv4", Addresses: "public", IPv4List: "x"},
		{Name: "B", Realm: "r", User: "*", Group: "*", Family: "ipv6", Addresses: "public", IPv6List: "x"},
	}}}); err == nil {
		t.Fatal("one list for both families accepted")
	}
}

func TestTooManyRejections(t *testing.T) {
	h := newHarness(t, "realm=home family=ipv4 ipv4_list=v4")
	var entries []ipvalet.Entry
	for i := 0; i < 201; i++ {
		entries = append(entries, e(fmt.Sprintf("8.8.%d.%d/32", i/250, i%250+1), "other", "u", "g", nil))
	}
	h.api.set(9, entries...)
	res := h.sync()
	if res.Err != nil || res.Rejected != 201 {
		t.Fatalf("%+v", res)
	}
	if rep := h.api.lastReport(t); rep.Error == "" || !strings.Contains(rep.Error, "201 prefixes rejected") {
		t.Fatalf("report %+v", rep)
	}
}

func TestCheckChangesNothing(t *testing.T) {
	h := newHarness(t, "realm=home family=ipv4 ipv4_list=v4")
	h.api.set(5, e("8.8.8.8/32", "home", "ann", "g", nil), e("9.9.9.9/32", "x", "y", "z", nil))
	var out strings.Builder
	if err := h.w.Check(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"UniFi Network 10.6.106", "revision 5", `List "v4" (IPV4_ADDRESSES): would be created with 1 items`,
		"Rejections: 1 no_matching_rule"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("check output lacks %q:\n%s", want, out.String())
		}
	}
	if h.ctl.Has("v4") || h.api.reportCount() != 0 {
		t.Fatal("check changed something")
	}
}

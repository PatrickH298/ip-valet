// Package worker runs the UniFi worker: it fetches desired state from the
// ip-valet API, places each entry into UniFi traffic matching lists by the
// configured rules, replaces each list's contents when they differ, and
// reports what it applied.
//
// It always reconciles from full desired state, so a missed signal, a
// restart or a hand edit in the UniFi UI is corrected on the next pass. The
// lists named in rules belong to the worker: their contents are replaced
// wholesale. Desired state is cached on disk, so expired entries leave the
// lists on time even while the API cannot be reached, across restarts too.
package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/PatrickH298/ip-valet/workers/unifi/internal/config"
	"github.com/PatrickH298/ip-valet/workers/unifi/internal/ipvalet"
	"github.com/PatrickH298/ip-valet/workers/unifi/internal/rules"
	"github.com/PatrickH298/ip-valet/workers/unifi/internal/unifi"
)

// Sentinels keep a list valid when nothing else belongs in it: UniFi refuses
// an empty list, and a refused update would leave expired addresses in place.
// Both are unroutable (TEST-NET-1 and the IPv6 discard prefix).
var sentinels = map[string]netip.Prefix{
	unifi.TypeIPv4: netip.MustParsePrefix("192.0.2.1/32"),
	unifi.TypeIPv6: netip.MustParsePrefix("100::1/128"),
}

// Options configure a Worker.
type Options struct {
	Config  config.Config
	API     *ipvalet.Client
	UniFi   *unifi.Client
	Log     *slog.Logger
	Version string
	Now     func() time.Time
}

// Worker is one UniFi worker.
type Worker struct {
	Options
	refs   map[string]string // list id or name -> list type
	siteID string

	etag        string
	state       *ipvalet.DesiredState
	revision    int64
	generatedAt string
	cacheBroken bool
	refused     map[netip.Prefix]string // the last sync's rejections, code and detail
}

// New checks the rules' lists and returns a worker.
func New(o Options) (*Worker, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	w := &Worker{Options: o, refs: map[string]string{}}
	add := func(ref, typ, rule string) error {
		if old, ok := w.refs[ref]; ok && old != typ {
			return fmt.Errorf("rule %s: list %q is used for both IPv4 and IPv6; a UniFi list holds one family", rule, ref)
		}
		w.refs[ref] = typ
		return nil
	}
	for _, r := range o.Config.Rules {
		if r.IPv4List != "" {
			if err := add(r.IPv4List, unifi.TypeIPv4, r.Name); err != nil {
				return nil, err
			}
		}
		if r.IPv6List != "" {
			if err := add(r.IPv6List, unifi.TypeIPv6, r.Name); err != nil {
				return nil, err
			}
		}
	}
	return w, nil
}

// Result is what one pass did.
type Result struct {
	FromAPI    bool     // desired state came from the API (not the cache)
	Changed    []string // lists whose contents were replaced or created
	Rejected   int
	Reported   bool
	NextExpiry *time.Time
	Err        error
}

// Run reconciles on every change signal, at the next expiry and every
// sync interval, until ctx ends.
func (w *Worker) Run(ctx context.Context) error {
	w.loadCache()
	trigger := make(chan struct{}, 1)
	go w.listen(ctx, trigger)
	tick := time.NewTicker(w.Config.SyncInterval)
	defer tick.Stop()
	expiry := time.NewTimer(time.Hour)
	expiry.Stop()
	for {
		res := w.Sync(ctx)
		if res.Err != nil && ctx.Err() == nil {
			w.Log.Error("sync failed", "error", res.Err.Error())
		}
		expiry.Stop()
		if res.NextExpiry != nil {
			expiry.Reset(max(time.Until(*res.NextExpiry)+time.Second, time.Second))
		}
		select {
		case <-ctx.Done():
			return nil
		case <-trigger:
		case <-tick.C:
		case <-expiry.C:
		}
	}
}

// listen holds the API's change-signal stream open, reconnecting with backoff.
func (w *Worker) listen(ctx context.Context, trigger chan<- struct{}) {
	backoff := time.Second
	for ctx.Err() == nil {
		connected := time.Now()
		err := w.API.Events(ctx, func(int64) {
			select {
			case trigger <- struct{}{}:
			default:
			}
		})
		if ctx.Err() != nil {
			return
		}
		if time.Since(connected) > time.Minute {
			backoff = time.Second
		}
		var se *ipvalet.StatusError
		if errors.As(err, &se) && se.Permanent() {
			w.Log.Error("the API refused the event stream; check IPVALET_UNIFI_API_KEY", "error", err.Error())
		} else if err != nil && !errors.Is(err, io.EOF) {
			w.Log.Warn("event stream lost; reconnecting", "error", err.Error(), "in", backoff.String())
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

// Sync runs one pass: fetch desired state (or use the cache), apply it to
// the lists, and report to the API when it answered.
func (w *Worker) Sync(ctx context.Context) Result {
	var res Result
	f, err := w.API.Desired(ctx, w.etag)
	switch {
	case err == nil && f.NotModified && w.state != nil:
		res.FromAPI = true
		w.revision, w.generatedAt = f.Revision, f.GeneratedAt
	case err == nil && f.State != nil:
		res.FromAPI = true
		w.etag, w.state, w.revision, w.generatedAt = f.ETag, f.State, f.Revision, f.GeneratedAt
		w.saveCache()
	case err == nil:
		// 304 without a cached state (the cache was lost): fetch in full.
		w.etag = ""
		return w.Sync(ctx)
	default:
		var se *ipvalet.StatusError
		if errors.As(err, &se) && se.Permanent() {
			w.Log.Error("the API refused the worker key; check IPVALET_UNIFI_API_KEY", "error", err.Error())
		} else {
			w.Log.Warn("desired state unavailable; working from the cached copy", "error", err.Error())
		}
	}
	if w.state == nil {
		res.Err = fmt.Errorf("no desired state yet: %w", err)
		return res
	}
	plan := rules.Build(w.entries(), w.Config.Rules, w.Config.Floor, w.Now())
	res.NextExpiry, res.Rejected = plan.NextExpiry, len(plan.Rejections)
	w.logRejections(plan.Rejections)
	res.Changed, res.Err = w.apply(ctx, plan)
	if res.FromAPI {
		if err := w.report(ctx, plan, res.Err); err != nil {
			w.Log.Warn("status report failed", "error", err.Error())
		} else {
			res.Reported = true
		}
	}
	if res.Err == nil {
		w.Log.Debug("in sync", "revision", w.revision, "changed", res.Changed, "rejected", res.Rejected,
			"from_api", res.FromAPI)
	}
	return res
}

func (w *Worker) entries() []rules.Entry {
	out := make([]rules.Entry, 0, len(w.state.Entries))
	for _, e := range w.state.Entries {
		p, err := netip.ParsePrefix(e.Prefix)
		if err != nil {
			w.Log.Warn("ignoring an entry with an unreadable prefix", "prefix", e.Prefix)
			continue
		}
		out = append(out, rules.Entry{Prefix: p, ExpiresAt: e.ExpiresAt, Realm: e.Realm, User: e.User, Group: e.Group})
	}
	return out
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// lists finds the configured lists among the site's, by id or name.
func (w *Worker) lists(ctx context.Context) (map[string]*unifi.List, error) {
	if w.siteID == "" {
		site, err := w.UniFi.ResolveSite(ctx, w.Config.Site)
		if err != nil {
			return nil, err
		}
		w.siteID = site.ID
		w.Log.Info("using UniFi site", "name", site.Name, "id", site.ID)
	}
	all, err := w.UniFi.Lists(ctx, w.siteID)
	if err != nil {
		return nil, err
	}
	found := map[string]*unifi.List{}
	for ref := range w.refs {
		for i := range all {
			l := &all[i]
			if l.ID != ref && (uuidPattern.MatchString(ref) || l.Name != ref) {
				continue
			}
			if found[ref] != nil {
				return nil, fmt.Errorf("more than one UniFi list is named %q; use its id instead", ref)
			}
			found[ref] = l
		}
	}
	return found, nil
}

func wantItems(ps []netip.Prefix, typ string) []unifi.Item {
	if len(ps) == 0 {
		return []unifi.Item{unifi.ItemFor(sentinels[typ])}
	}
	out := make([]unifi.Item, len(ps))
	for i, p := range ps {
		out[i] = unifi.ItemFor(p)
	}
	return out
}

func keys(items []unifi.Item) map[string]bool {
	m := map[string]bool{}
	for _, it := range items {
		m[it.Key()] = true
	}
	return m
}

// diff counts items to add and remove.
func diff(have, want []unifi.Item) (added, removed []string) {
	h, wnt := keys(have), keys(want)
	for k := range wnt {
		if !h[k] {
			added = append(added, k)
		}
	}
	for k := range h {
		if !wnt[k] {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// apply brings every configured list in line with the plan. Each list is
// handled on its own, so one failing list does not hold up the others; any
// failure fails the pass.
func (w *Worker) apply(ctx context.Context, plan rules.Plan) ([]string, error) {
	found, err := w.lists(ctx)
	if err != nil {
		return nil, err
	}
	refs := make([]string, 0, len(w.refs))
	for ref := range w.refs {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	var changed []string
	var errs []error
	for _, ref := range refs {
		typ := w.refs[ref]
		want := wantItems(plan.Lists[ref], typ)
		l := found[ref]
		if l == nil {
			if uuidPattern.MatchString(ref) || !w.Config.CreateLists {
				errs = append(errs, fmt.Errorf("UniFi list %q does not exist", ref))
				continue
			}
			created, err := w.UniFi.CreateList(ctx, w.siteID, ref, typ, want)
			if err != nil {
				errs = append(errs, fmt.Errorf("creating UniFi list %q: %w", ref, err))
				continue
			}
			w.Log.Info("created UniFi list", "list", ref, "id", created.ID, "type", typ, "items", len(want))
			changed = append(changed, ref)
			continue
		}
		if l.Type != typ {
			errs = append(errs, fmt.Errorf("UniFi list %q holds %s, but rules send it %s", ref, l.Type, typ))
			continue
		}
		cur := *l
		if cur.Items == nil {
			if cur, err = w.UniFi.GetList(ctx, w.siteID, l.ID); err != nil {
				errs = append(errs, err)
				continue
			}
		}
		added, removed := diff(cur.Items, want)
		if len(added) == 0 && len(removed) == 0 {
			continue
		}
		if err := w.UniFi.PutList(ctx, w.siteID, cur, want); err != nil {
			errs = append(errs, fmt.Errorf("updating UniFi list %q: %w", ref, err))
			continue
		}
		w.Log.Info("updated UniFi list", "list", ref, "items", len(want), "added", added, "removed", removed)
		changed = append(changed, ref)
	}
	return changed, errors.Join(errs...)
}

// report tells the API what was applied: success with the rejections, or the
// error. More rejections than a report holds is reported as an error, as the
// protocol asks.
func (w *Worker) report(ctx context.Context, plan rules.Plan, applyErr error) error {
	r := ipvalet.Report{Instance: w.Config.Instance, Version: w.Version, Revision: w.revision}
	switch {
	case applyErr != nil:
		r.Error = truncate(applyErr.Error(), 2000)
	case len(plan.Rejections) > ipvalet.MaxRejections:
		r.Error = fmt.Sprintf("%d prefixes rejected, more than the %d a status report holds; first: %s %s",
			len(plan.Rejections), ipvalet.MaxRejections, plan.Rejections[0].Prefix, plan.Rejections[0].Code)
	default:
		r.GeneratedAt = w.generatedAt
		r.Rejected = make([]ipvalet.Rejection, 0, len(plan.Rejections))
		for _, rj := range plan.Rejections {
			r.Rejected = append(r.Rejected, ipvalet.Rejection{Prefix: rj.Prefix.String(), Code: rj.Code, Detail: rj.Detail})
		}
	}
	return w.API.Report(ctx, r)
}

// logRejections logs each rejection that is new, or whose reason changed,
// once: every sync rejects the same prefixes again.
func (w *Worker) logRejections(rs []rules.Rejection) {
	now := make(map[netip.Prefix]string, len(rs))
	for _, r := range rs {
		why := r.Code + ": " + r.Detail
		now[r.Prefix] = why
		if w.refused[r.Prefix] != why {
			w.Log.Info("address refused", "prefix", r.Prefix.String(), "code", r.Code, "detail", r.Detail)
		}
	}
	w.refused = now
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}

// --- cache

type cached struct {
	ETag        string                `json:"etag"`
	Revision    int64                 `json:"revision"`
	GeneratedAt string                `json:"generated_at"`
	State       *ipvalet.DesiredState `json:"state"`
}

func (w *Worker) cachePath() string {
	if w.Config.DataDir == "" {
		return ""
	}
	return filepath.Join(w.Config.DataDir, "desired-state.json")
}

func (w *Worker) loadCache() {
	path := w.cachePath()
	if path == "" {
		return
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	var c cached
	if err == nil {
		err = json.Unmarshal(b, &c)
	}
	if err != nil || c.State == nil {
		w.Log.Warn("ignoring an unreadable desired-state cache", "path", path, "error", fmt.Sprint(err),
			"uid", os.Getuid(), "gid", os.Getgid())
		return
	}
	w.etag, w.state, w.revision, w.generatedAt = c.ETag, c.State, c.Revision, c.GeneratedAt
	w.Log.Info("loaded cached desired state", "revision", c.Revision, "entries", len(c.State.Entries))
}

func (w *Worker) saveCache() {
	path := w.cachePath()
	if path == "" || w.cacheBroken {
		return
	}
	err := func() error {
		b, err := json.Marshal(cached{ETag: w.etag, Revision: w.revision, GeneratedAt: w.generatedAt, State: w.state})
		if err != nil {
			return err
		}
		tmp, err := os.CreateTemp(filepath.Dir(path), ".desired-state-*")
		if err != nil {
			return err
		}
		defer os.Remove(tmp.Name())
		if _, err := tmp.Write(b); err != nil {
			tmp.Close()
			return err
		}
		if err := tmp.Close(); err != nil {
			return err
		}
		return os.Rename(tmp.Name(), path)
	}()
	if err != nil {
		w.cacheBroken = true
		w.Log.Warn("cannot write the desired-state cache; expiry while the API is down will not survive a restart",
			"path", path, "error", err.Error(), "uid", os.Getuid(), "gid", os.Getgid())
	}
}

// --- check

// Check prints what a pass would do, changing nothing: the site, each
// list's state and the changes it would get, and the rejections by code.
func (w *Worker) Check(ctx context.Context, out io.Writer) error {
	version, err := w.UniFi.Info(ctx)
	if err != nil {
		return fmt.Errorf("UniFi: %w", err)
	}
	fmt.Fprintf(out, "UniFi Network %s\n", version)
	found, err := w.lists(ctx)
	if err != nil {
		return err
	}
	f, err := w.API.Desired(ctx, "")
	if err != nil {
		return fmt.Errorf("ip-valet API: %w", err)
	}
	fmt.Fprintf(out, "Desired state: revision %d, %d entries\n", f.Revision, len(f.State.Entries))
	w.state = f.State
	plan := rules.Build(w.entries(), w.Config.Rules, w.Config.Floor, w.Now())
	refs := make([]string, 0, len(w.refs))
	for ref := range w.refs {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	for _, ref := range refs {
		typ := w.refs[ref]
		want := wantItems(plan.Lists[ref], typ)
		l := found[ref]
		switch {
		case l == nil && (uuidPattern.MatchString(ref) || !w.Config.CreateLists):
			fmt.Fprintf(out, "List %q (%s): MISSING\n", ref, typ)
		case l == nil:
			fmt.Fprintf(out, "List %q (%s): would be created with %d items\n", ref, typ, len(want))
		case l.Type != typ:
			fmt.Fprintf(out, "List %q: holds %s, but rules send it %s\n", ref, l.Type, typ)
		default:
			cur := *l
			if cur.Items == nil {
				if cur, err = w.UniFi.GetList(ctx, w.siteID, l.ID); err != nil {
					return err
				}
			}
			added, removed := diff(cur.Items, want)
			fmt.Fprintf(out, "List %q (%s, id %s): %d items now, %d wanted; +%d -%d %s\n", ref, typ, l.ID,
				len(cur.Items), len(want), len(added), len(removed), strings.Join(append(prefixed("+", added),
					prefixed("-", removed)...), " "))
		}
	}
	codes := map[string]int{}
	for _, r := range plan.Rejections {
		codes[r.Code]++
	}
	if len(codes) == 0 {
		fmt.Fprintln(out, "Rejections: none")
	}
	for c, n := range codes {
		fmt.Fprintf(out, "Rejections: %d %s\n", n, c)
	}
	return nil
}

func prefixed(p string, ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = p + s
	}
	return out
}

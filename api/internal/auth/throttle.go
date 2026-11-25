package auth

import (
	"container/list"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// FailureThrottle limits failed authentications per client network. Each
// network may fail perMinute times in a burst, refilling one attempt every
// 60/perMinute seconds. Once its budget is spent, the network's requests are
// refused before the key is even parsed. Successful requests never spend the
// budget.
//
// Bad keys are already refused from memory (see KeyIndex), so the throttle
// does not protect the database; it slows scanning from any one network and
// makes it visible. Its memory is bounded: past maxNetworks, the network that
// failed longest ago is forgotten. An attacker with more networks than that
// only regains attempts that cost the server almost nothing.
// State is in memory, per API instance.
type FailureThrottle struct {
	perMinute   int
	maxNetworks int
	mu          sync.Mutex
	buckets     map[netip.Prefix]*list.Element // value: *failBucket
	order       *list.List                     // front: most recent failure
}

type failBucket struct {
	network netip.Prefix
	lim     *rate.Limiter
	last    time.Time
}

const (
	// idleAfter is how long a network's state is kept after its last failure.
	idleAfter = 10 * time.Minute
	// defaultMaxNetworks bounds the throttle's memory (roughly 20 MB at most).
	defaultMaxNetworks = 100_000
)

// NewFailureThrottle returns a throttle; perMinute <= 0 disables it.
func NewFailureThrottle(perMinute int) *FailureThrottle {
	return newFailureThrottle(perMinute, defaultMaxNetworks)
}

func newFailureThrottle(perMinute, maxNetworks int) *FailureThrottle {
	return &FailureThrottle{perMinute: perMinute, maxNetworks: maxNetworks,
		buckets: map[netip.Prefix]*list.Element{}, order: list.New()}
}

// NetworkOf is the unit the throttle counts: an IPv4 address, or the /64
// holding an IPv6 address, since one IPv6 host can use a whole /64.
func NetworkOf(ip netip.Addr) netip.Prefix {
	ip = ip.Unmap()
	bits := 32
	if ip.Is6() {
		bits = 64
	}
	p, err := ip.Prefix(bits)
	if err != nil {
		return netip.Prefix{}
	}
	return p
}

// Blocked reports whether ip's network has spent its budget, and how long
// until it may try again.
func (t *FailureThrottle) Blocked(ip netip.Addr) (time.Duration, bool) {
	if t.perMinute <= 0 || !ip.IsValid() {
		return 0, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.buckets[NetworkOf(ip)]
	if e == nil {
		return 0, false
	}
	b := e.Value.(*failBucket)
	if tokens := b.lim.TokensAt(time.Now()); tokens < 1 {
		return time.Duration((1 - tokens) / float64(b.lim.Limit()) * float64(time.Second)), true
	}
	return 0, false
}

// Fail spends one attempt from ip's network. It reports true when this
// failure used up the budget, so the caller can log the transition.
func (t *FailureThrottle) Fail(ip netip.Addr) bool {
	if t.perMinute <= 0 || !ip.IsValid() {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	n := NetworkOf(ip)
	var b *failBucket
	if e := t.buckets[n]; e != nil {
		b = e.Value.(*failBucket)
		t.order.MoveToFront(e)
	} else {
		for t.order.Len() >= t.maxNetworks {
			oldest := t.order.Back()
			delete(t.buckets, oldest.Value.(*failBucket).network)
			t.order.Remove(oldest)
		}
		b = &failBucket{network: n, lim: rate.NewLimiter(rate.Limit(float64(t.perMinute)/60), t.perMinute)}
		t.buckets[n] = t.order.PushFront(b)
	}
	b.last = now
	b.lim.AllowN(now, 1)
	return b.lim.TokensAt(now) < 1
}

// Evict drops networks that have not failed for a while.
func (t *FailureThrottle) Evict(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for e := t.order.Back(); e != nil; e = t.order.Back() {
		b := e.Value.(*failBucket)
		if now.Sub(b.last) <= idleAfter {
			return
		}
		delete(t.buckets, b.network)
		t.order.Remove(e)
	}
}

// Len is the number of networks tracked.
func (t *FailureThrottle) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.order.Len()
}

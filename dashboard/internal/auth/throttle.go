package auth

import (
	"container/list"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Throttle limits failed sign-ins per client network, as the API server
// limits failed authentications. Each network may fail perMinute times in a
// burst, refilling one attempt every 60/perMinute seconds; once its budget is
// spent, its sign-in attempts are refused unchecked. Failures are not counted
// per user name, which would let anyone lock out a known user. Memory is
// bounded: past maxNetworks, the network that failed longest ago is forgotten.
type Throttle struct {
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
	throttleIdleAfter   = 10 * time.Minute
	throttleMaxNetworks = 100_000
)

// NewThrottle returns a throttle; perMinute <= 0 disables it.
func NewThrottle(perMinute int) *Throttle {
	return &Throttle{perMinute: perMinute, maxNetworks: throttleMaxNetworks,
		buckets: map[netip.Prefix]*list.Element{}, order: list.New()}
}

// NetworkOf is the unit the throttle counts: an IPv4 address, or the /64
// holding an IPv6 address.
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
func (t *Throttle) Blocked(ip netip.Addr) (time.Duration, bool) {
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

// Fail spends one attempt from ip's network, and reports true when this
// failure used up the budget.
func (t *Throttle) Fail(ip netip.Addr) bool {
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
func (t *Throttle) Evict(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for e := t.order.Back(); e != nil; e = t.order.Back() {
		b := e.Value.(*failBucket)
		if now.Sub(b.last) <= throttleIdleAfter {
			return
		}
		delete(t.buckets, b.network)
		t.order.Remove(e)
	}
}

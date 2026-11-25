package auth

import (
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// FailureThrottle limits failed authentications per client network. Each
// network may fail perMinute times in a burst, refilling one attempt every
// 60/perMinute seconds. Once its budget is spent, the network's requests are
// refused before any key is looked up, so a flood of guesses costs no
// database work. Successful requests never spend the budget.
//
// The secrets are 256-bit, so guessing one is not feasible at any rate; the
// throttle exists to keep floods of bad keys off the database and to make
// scanning slow and visible. State is in memory, per API instance.
type FailureThrottle struct {
	perMinute int
	mu        sync.Mutex
	buckets   map[netip.Prefix]*failBucket
}

type failBucket struct {
	lim  *rate.Limiter
	last time.Time
}

// idleAfter is how long a network's state is kept after its last failure.
const idleAfter = 10 * time.Minute

// NewFailureThrottle returns a throttle; perMinute <= 0 disables it.
func NewFailureThrottle(perMinute int) *FailureThrottle {
	return &FailureThrottle{perMinute: perMinute, buckets: map[netip.Prefix]*failBucket{}}
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
	b := t.buckets[NetworkOf(ip)]
	if b == nil {
		return 0, false
	}
	now := time.Now()
	if tokens := b.lim.TokensAt(now); tokens < 1 {
		wait := time.Duration((1 - tokens) / float64(b.lim.Limit()) * float64(time.Second))
		return wait, true
	}
	return 0, false
}

// Fail spends one attempt from ip's network. It reports true when this
// failure used up the budget, so the caller can log the transition once.
func (t *FailureThrottle) Fail(ip netip.Addr) bool {
	if t.perMinute <= 0 || !ip.IsValid() {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	n := NetworkOf(ip)
	b := t.buckets[n]
	if b == nil {
		b = &failBucket{lim: rate.NewLimiter(rate.Limit(float64(t.perMinute)/60), t.perMinute)}
		t.buckets[n] = b
	}
	b.last = now
	b.lim.AllowN(now, 1)
	return b.lim.TokensAt(now) < 1
}

// Evict drops networks that have not failed for a while.
func (t *FailureThrottle) Evict(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for n, b := range t.buckets {
		if now.Sub(b.last) > idleAfter {
			delete(t.buckets, n)
		}
	}
}

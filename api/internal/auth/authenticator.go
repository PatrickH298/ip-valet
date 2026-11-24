package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/time/rate"
)

// Principal is the authenticated caller, passed to handlers.
type Principal struct {
	Actor string // key id, or admin:env
	Kind  string
	KeyID string

	// Client keys.
	ClientID  string
	Realms    []string
	RateLimit *int // nil = IPVALET_DEFAULT_RATE_LIMIT

	// Worker keys.
	TargetID string
}

// HasRealm reports whether a client principal is bound to realm.
func (p *Principal) HasRealm(realm string) bool {
	for _, r := range p.Realms {
		if r == realm {
			return true
		}
	}
	return false
}

// Error is an authentication or authorisation failure.
type Error struct {
	Status     int
	Code       string
	Message    string
	RetryAfter int // seconds, for 429
}

func (e *Error) Error() string { return e.Message }

var (
	errUnauthenticated = &Error{Status: http.StatusUnauthorized, Code: "unauthenticated", Message: "a valid API key is required"}
	errForbidden       = &Error{Status: http.StatusForbidden, Code: "forbidden", Message: "this key cannot use this route"}
	errNoRealms        = &Error{Status: http.StatusForbidden, Code: "realm_not_allowed", Message: "this client is not bound to any realm"}
)

// Authenticator verifies bearer keys against the database and the
// environment admin key, and applies per-key rate limits to client keys.
type Authenticator struct {
	pool             *pgxpool.Pool
	envKeyID         string
	envKeyHash       []byte
	defaultRateLimit int
	log              *slog.Logger

	touchMu sync.Mutex
	touched map[string]time.Time
	touchCh chan string

	limits *limiters
}

// NewAuthenticator builds an authenticator. envKeyID may be empty.
func NewAuthenticator(pool *pgxpool.Pool, envKeyID string, envKeyHash []byte, defaultRateLimit int, log *slog.Logger) *Authenticator {
	return &Authenticator{
		pool:             pool,
		envKeyID:         envKeyID,
		envKeyHash:       envKeyHash,
		defaultRateLimit: defaultRateLimit,
		log:              log,
		touched:          map[string]time.Time{},
		touchCh:          make(chan string, 256),
		limits:           &limiters{m: map[string]*bucket{}},
	}
}

// EnvKeyID returns the environment admin key's id, or "".
func (a *Authenticator) EnvKeyID() string { return a.envKeyID }

// Authenticate verifies the Authorization header and that the key's kind is
// the one the route requires. A non-*Error error means the database failed.
func (a *Authenticator) Authenticate(ctx context.Context, header, requiredKind string) (*Principal, error) {
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return nil, errUnauthenticated
	}
	key, err := ParseKey(strings.TrimSpace(token))
	if err != nil {
		return nil, errUnauthenticated
	}

	if a.envKeyID != "" && key.ID == a.envKeyID {
		if subtle.ConstantTimeCompare(key.Hash(), a.envKeyHash) != 1 {
			return nil, errUnauthenticated
		}
		if requiredKind != KindAdmin {
			return nil, errForbidden
		}
		return &Principal{Actor: EnvAdminActor, Kind: KindAdmin, KeyID: key.ID}, nil
	}

	var (
		p                  = &Principal{Actor: key.ID, KeyID: key.ID}
		hash               []byte
		clientID, targetID *string
		active             bool
		rateLimit          *int32
		realms             []string
	)
	err = a.pool.QueryRow(ctx, `
		SELECT k.kind, k.secret_hash, k.client_id::text, k.target_id::text,
		       (k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > now())),
		       c.rate_limit_per_minute,
		       ARRAY(SELECT cr.realm::text FROM client_realms cr
		             WHERE cr.client_id = k.client_id ORDER BY cr.realm)
		FROM api_keys k LEFT JOIN clients c ON c.id = k.client_id
		WHERE k.id = $1`, key.ID).
		Scan(&p.Kind, &hash, &clientID, &targetID, &active, &rateLimit, &realms)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errUnauthenticated
	}
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(key.Hash(), hash) != 1 {
		return nil, errUnauthenticated
	}
	if !active {
		return nil, errUnauthenticated
	}
	if p.Kind != requiredKind {
		return nil, errForbidden
	}
	a.touch(key.ID)
	switch p.Kind {
	case KindClient:
		p.ClientID = *clientID
		p.Realms = realms
		if rateLimit != nil {
			n := int(*rateLimit)
			p.RateLimit = &n
		}
		if len(p.Realms) == 0 {
			return nil, errNoRealms
		}
		if err := a.rateLimit(p); err != nil {
			return nil, err
		}
	case KindWorker:
		p.TargetID = *targetID
	}
	return p, nil
}

// StillValid re-checks that a key used by a long-lived stream is still active.
func (a *Authenticator) StillValid(ctx context.Context, p *Principal) (bool, error) {
	if p.Actor == EnvAdminActor {
		return true, nil
	}
	var ok bool
	err := a.pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM api_keys WHERE id = $1
		  AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now()))`, p.KeyID).Scan(&ok)
	return ok, err
}

func (a *Authenticator) rateLimit(p *Principal) error {
	n := a.defaultRateLimit
	if p.RateLimit != nil {
		n = *p.RateLimit
	}
	if n <= 0 {
		return nil
	}
	ok, wait := a.limits.allow(p.KeyID, n, time.Now())
	if ok {
		return nil
	}
	secs := int(math.Ceil(wait.Seconds()))
	if secs < 1 {
		secs = 1
	}
	return &Error{Status: http.StatusTooManyRequests, Code: "rate_limited",
		Message: "rate limit exceeded", RetryAfter: secs}
}

// touch queues a last_used_at update at most once a minute per key.
func (a *Authenticator) touch(id string) {
	now := time.Now()
	a.touchMu.Lock()
	last, seen := a.touched[id]
	if seen && now.Sub(last) < time.Minute {
		a.touchMu.Unlock()
		return
	}
	a.touched[id] = now
	a.touchMu.Unlock()
	select {
	case a.touchCh <- id:
	default: // drop; the next request after a minute retries
	}
}

// Run writes last_used_at updates and evicts idle rate limiters until ctx ends.
func (a *Authenticator) Run(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-a.touchCh:
			uctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_, err := a.pool.Exec(uctx, `UPDATE api_keys SET last_used_at = now() WHERE id = $1`, id)
			cancel()
			if err != nil && ctx.Err() == nil {
				a.log.Warn("recording last_used_at failed", "key_id", id, "error", err.Error())
			}
		case now := <-tick.C:
			a.limits.evict(now, 10*time.Minute)
			a.touchMu.Lock()
			for id, t := range a.touched {
				if now.Sub(t) > time.Minute {
					delete(a.touched, id)
				}
			}
			a.touchMu.Unlock()
		}
	}
}

type bucket struct {
	lim  *rate.Limiter
	n    int
	last time.Time
}

type limiters struct {
	mu sync.Mutex
	m  map[string]*bucket
}

// allow takes one token from key's bucket (n per minute, burst n).
func (l *limiters) allow(key string, n int, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.m[key]
	if b == nil || b.n != n {
		b = &bucket{lim: rate.NewLimiter(rate.Limit(float64(n)/60), n), n: n}
		l.m[key] = b
	}
	b.last = now
	r := b.lim.ReserveN(now, 1)
	if !r.OK() {
		return false, time.Minute
	}
	if d := r.DelayFrom(now); d > 0 {
		r.CancelAt(now)
		return false, d
	}
	return true, 0
}

func (l *limiters) evict(now time.Time, idle time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, b := range l.m {
		if now.Sub(b.last) > idle {
			delete(l.m, k)
		}
	}
}

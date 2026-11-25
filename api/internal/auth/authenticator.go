package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Principal is the authenticated caller, passed to handlers.
type Principal struct {
	Actor string // key id, or admin:env
	Kind  string
	KeyID string

	// Client keys.
	ClientID string
	Realms   []string

	// Worker keys.
	WorkerID string
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

// Reasons a request failed authentication, for metrics.
const (
	FailMalformed   = "malformed"    // no bearer key, or not in the key format
	FailUnknownKey  = "unknown_key"  // no key with that id
	FailWrongSecret = "wrong_secret" // the key id exists, the secret does not match
	FailInactive    = "inactive"     // revoked or expired
	FailThrottled   = "throttled"    // refused unchecked: too many recent failures from this network
)

// Authenticator verifies bearer keys against the database and the
// environment admin key, and throttles networks that keep failing.
type Authenticator struct {
	pool       *pgxpool.Pool
	envKeyID   string
	envKeyHash []byte
	log        *slog.Logger
	throttle   *FailureThrottle
	keys       *KeyIndex

	// OnFailure, if set, is called with a Fail* reason for every refused request.
	OnFailure func(reason string)

	touchMu sync.Mutex
	touched map[string]time.Time
	touchCh chan string
}

// NewAuthenticator builds an authenticator. envKeyID may be empty.
// failuresPerMinute is the failed-authentication budget per client network
// (0 disables the throttle).
func NewAuthenticator(pool *pgxpool.Pool, envKeyID string, envKeyHash []byte, failuresPerMinute int, log *slog.Logger) *Authenticator {
	return &Authenticator{
		pool:       pool,
		envKeyID:   envKeyID,
		envKeyHash: envKeyHash,
		log:        log,
		throttle:   NewFailureThrottle(failuresPerMinute),
		keys:       NewKeyIndex(pool),
		touched:    map[string]time.Time{},
		touchCh:    make(chan string, 256),
	}
}

// LoadKeys fills the key index from the database; call it before serving.
func (a *Authenticator) LoadKeys(ctx context.Context) error { return a.keys.LoadAll(ctx) }

// RememberKey adds a key this instance just created to the index.
func (a *Authenticator) RememberKey(id string, hash []byte) { a.keys.Add(id, hash) }

// KeyCreated handles an ipvalet_keys notification: another instance (or the
// create-admin-key command) stored a key.
func (a *Authenticator) KeyCreated(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.keys.LoadOne(ctx, id); err != nil {
		a.log.Warn("loading a new key into the index failed; the periodic reload will pick it up",
			"key_id", id, "error", err.Error())
	}
}

// ReloadKeys reloads the whole index, for example after the LISTEN
// connection reconnects and notifications may have been missed.
func (a *Authenticator) ReloadKeys() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := a.keys.LoadAll(ctx); err != nil {
		a.log.Warn("reloading the key index failed", "error", err.Error())
	}
}

// EnvKeyID returns the environment admin key's id, or "".
func (a *Authenticator) EnvKeyID() string { return a.envKeyID }

func (a *Authenticator) fail(clientIP netip.Addr, reason string, keyID string) error {
	if a.OnFailure != nil {
		a.OnFailure(reason)
	}
	if reason == FailWrongSecret {
		// Key ids are not secret, but a wrong secret for a real key id is worth seeing.
		a.log.Warn("authentication failed: wrong secret for an existing key", "key_id", keyID, "client_ip", clientIP.String())
	}
	if a.throttle.Fail(clientIP) {
		a.log.Warn("throttling a network after repeated authentication failures",
			"network", NetworkOf(clientIP).String(), "client_ip", clientIP.String())
	}
	return errUnauthenticated
}

// Authenticate verifies the Authorization header and that the key's kind is
// the one the route requires. clientIP is the caller's address, used to
// throttle networks that fail authentication repeatedly: once a network's
// budget is spent, its requests are refused before any key is looked up.
// A non-*Error error means the database failed.
func (a *Authenticator) Authenticate(ctx context.Context, header, requiredKind string, clientIP netip.Addr) (*Principal, error) {
	if wait, blocked := a.throttle.Blocked(clientIP); blocked {
		if a.OnFailure != nil {
			a.OnFailure(FailThrottled)
		}
		return nil, &Error{Status: http.StatusTooManyRequests, Code: "too_many_attempts",
			Message:    "too many failed authentication attempts from this network; retry later",
			RetryAfter: max(1, int(math.Ceil(wait.Seconds())))}
	}
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return nil, a.fail(clientIP, FailMalformed, "")
	}
	key, err := ParseKey(strings.TrimSpace(token))
	if err != nil {
		return nil, a.fail(clientIP, FailMalformed, "")
	}

	if a.envKeyID != "" && key.ID == a.envKeyID {
		if subtle.ConstantTimeCompare(key.Hash(), a.envKeyHash) != 1 {
			return nil, a.fail(clientIP, FailWrongSecret, key.ID)
		}
		if requiredKind != KindAdmin {
			return nil, errForbidden
		}
		return &Principal{Actor: EnvAdminActor, Kind: KindAdmin, KeyID: key.ID}, nil
	}

	// Unknown ids and wrong secrets are refused from memory: a flood of bad
	// keys costs no database work.
	hash, known := a.keys.Lookup(key.ID)
	if !known {
		return nil, a.fail(clientIP, FailUnknownKey, key.ID)
	}
	if subtle.ConstantTimeCompare(key.Hash(), hash) != 1 {
		return nil, a.fail(clientIP, FailWrongSecret, key.ID)
	}

	var (
		p                  = &Principal{Actor: key.ID, KeyID: key.ID}
		clientID, workerID *string
		active             bool
		realms             []string
	)
	err = a.pool.QueryRow(ctx, `
		SELECT k.kind, k.client_id::text, k.worker_id::text,
		       (k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > now())),
		       ARRAY(SELECT cr.realm::text FROM client_realms cr
		             WHERE cr.client_id = k.client_id ORDER BY cr.realm)
		FROM api_keys k
		WHERE k.id = $1`, key.ID).
		Scan(&p.Kind, &clientID, &workerID, &active, &realms)
	if errors.Is(err, pgx.ErrNoRows) {
		a.keys.Remove(key.ID) // deleted with its client or worker
		return nil, a.fail(clientIP, FailUnknownKey, key.ID)
	}
	if err != nil {
		return nil, err
	}
	if !active {
		return nil, a.fail(clientIP, FailInactive, key.ID)
	}
	if p.Kind != requiredKind {
		return nil, errForbidden
	}
	a.touch(key.ID)
	switch p.Kind {
	case KindClient:
		p.ClientID = *clientID
		p.Realms = realms
		if len(p.Realms) == 0 {
			return nil, errNoRealms
		}
	case KindWorker:
		p.WorkerID = *workerID
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

// keyReloadEvery is the backstop full reload of the key index.
const keyReloadEvery = 5 * time.Minute

// Run writes last_used_at updates, evicts idle throttle state and reloads the
// key index until ctx ends.
func (a *Authenticator) Run(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	reload := time.NewTicker(keyReloadEvery)
	defer reload.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-reload.C:
			a.ReloadKeys()
		case id := <-a.touchCh:
			uctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_, err := a.pool.Exec(uctx, `UPDATE api_keys SET last_used_at = now() WHERE id = $1`, id)
			cancel()
			if err != nil && ctx.Err() == nil {
				a.log.Warn("recording last_used_at failed", "key_id", id, "error", err.Error())
			}
		case now := <-tick.C:
			a.throttle.Evict(now)
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

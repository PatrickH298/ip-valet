package auth

import (
	"context"
	"errors"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// KeyIndex holds every stored key's id and secret hash in memory, so a
// request with an unknown key id or a wrong secret is refused without a
// database query. A key's id and hash never change after it is created;
// whether it is still active (revoked, expired) is always read from the
// database, so revocation still takes effect on the next request.
//
// It is filled at startup, told about new keys through NOTIFY ipvalet_keys,
// reloaded whenever the LISTEN connection reconnects, and reloaded every few
// minutes as a backstop.
type KeyIndex struct {
	pool *pgxpool.Pool
	mu   sync.RWMutex
	m    map[string][]byte
}

// NewKeyIndex returns an empty index reading from pool.
func NewKeyIndex(pool *pgxpool.Pool) *KeyIndex {
	return &KeyIndex{pool: pool, m: map[string][]byte{}}
}

// LoadAll replaces the index with every key in the database.
func (x *KeyIndex) LoadAll(ctx context.Context) error {
	rows, err := x.pool.Query(ctx, `SELECT id, secret_hash FROM api_keys`)
	if err != nil {
		return err
	}
	defer rows.Close()
	m := map[string][]byte{}
	for rows.Next() {
		var (
			id   string
			hash []byte
		)
		if err := rows.Scan(&id, &hash); err != nil {
			return err
		}
		m[id] = hash
	}
	if err := rows.Err(); err != nil {
		return err
	}
	x.mu.Lock()
	x.m = m
	x.mu.Unlock()
	return nil
}

// LoadOne reads one key, adding it to the index (or dropping it if it is gone).
func (x *KeyIndex) LoadOne(ctx context.Context, id string) error {
	var hash []byte
	err := x.pool.QueryRow(ctx, `SELECT secret_hash FROM api_keys WHERE id = $1`, id).Scan(&hash)
	x.mu.Lock()
	defer x.mu.Unlock()
	switch {
	case err == nil:
		x.m[id] = hash
		return nil
	case errors.Is(err, pgx.ErrNoRows):
		delete(x.m, id)
		return nil
	}
	return err
}

// Add records a key created by this instance.
func (x *KeyIndex) Add(id string, hash []byte) {
	x.mu.Lock()
	x.m[id] = hash
	x.mu.Unlock()
}

// Remove drops a key that no longer exists.
func (x *KeyIndex) Remove(id string) {
	x.mu.Lock()
	delete(x.m, id)
	x.mu.Unlock()
}

// Lookup returns a key's secret hash.
func (x *KeyIndex) Lookup(id string) ([]byte, bool) {
	x.mu.RLock()
	defer x.mu.RUnlock()
	h, ok := x.m[id]
	return h, ok
}

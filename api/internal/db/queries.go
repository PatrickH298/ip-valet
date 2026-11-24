package db

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"

	"github.com/jackc/pgx/v5"

	"github.com/PatrickH298/ip-valet/api/internal/rules"
	"github.com/PatrickH298/ip-valet/api/internal/state"
)

// EntryCols selects an entry in ScanEntry's order; the table alias is e.
const EntryCols = `e.id::text, e.submission_id::text, e.realm::text, e.username::text, e.grp::text,
	e.prefix, e.expires_at, e.revision, e.client_id::text, e.key_id, e.created_at, e.updated_at,
	e.deleted_at, e.deleted_by, e.deleted_revision`

// ScanEntry scans a row selected with EntryCols.
func ScanEntry(row pgx.Row) (state.Entry, error) {
	var e state.Entry
	err := row.Scan(&e.ID, &e.SubmissionID, &e.Realm, &e.User, &e.Group, &e.Prefix, &e.ExpiresAt,
		&e.Revision, &e.ClientID, &e.KeyID, &e.CreatedAt, &e.UpdatedAt, &e.DeletedAt, &e.DeletedBy,
		&e.DeletedRevision)
	return e, err
}

// QueryEntries runs a query selecting EntryCols.
func QueryEntries(ctx context.Context, q Querier, sql string, args ...any) ([]state.Entry, error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []state.Entry
	for rows.Next() {
		e, err := ScanEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// GetEntry loads one entry, or nil. forUpdate locks the row.
func GetEntry(ctx context.Context, q Querier, id string, forUpdate bool) (*state.Entry, error) {
	sql := `SELECT ` + EntryCols + ` FROM entries e WHERE e.id = $1`
	if forUpdate {
		sql += ` FOR UPDATE`
	}
	e, err := ScanEntry(q.QueryRow(ctx, sql, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// TargetMatchesEntry is true when target t applies entry e: t holds e's
// address family and has a subscription matching e's realm, user and group.
const TargetMatchesEntry = `((family(e.prefix) = 4 AND t.ipv4) OR (family(e.prefix) = 6 AND t.ipv6))
	AND EXISTS (SELECT 1 FROM subscriptions s WHERE s.target_id = t.id
	    AND (s.realm    IS NULL OR s.realm    = e.realm)
	    AND (s.username IS NULL OR s.username = e.username)
	    AND (s.grp      IS NULL OR s.grp      = e.grp))`

// recordRemovals upserts entry_removals rows, keeping the later revision.
const recordRemovals = `ON CONFLICT (entry_id, target_id)
	DO UPDATE SET revision = GREATEST(entry_removals.revision, EXCLUDED.revision)`

// SoftDeleteEntries marks entries deleted at revision rev. First it records,
// for every target that matches each entry now, that the target must reach
// rev to confirm the removal. Call it before any change in the same
// transaction that stops targets matching these entries.
func SoftDeleteEntries(ctx context.Context, q Querier, ids []string, actor string, rev int64) error {
	if len(ids) == 0 {
		return nil
	}
	if _, err := q.Exec(ctx, `
		INSERT INTO entry_removals (entry_id, target_id, revision)
		SELECT e.id, t.id, $2 FROM entries e JOIN targets t ON `+TargetMatchesEntry+`
		WHERE e.id = ANY($1::uuid[]) AND e.deleted_at IS NULL
		`+recordRemovals, ids, rev); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `
		UPDATE entries SET deleted_at = now(), deleted_by = $2, deleted_revision = $3, updated_at = now()
		WHERE id = ANY($1::uuid[]) AND deleted_at IS NULL`, ids, actor, rev)
	return err
}

// EntriesHeldBy returns the entries a target matches that are not deleted,
// expired ones included (its worker may not have removed them yet).
func EntriesHeldBy(ctx context.Context, q Querier, targetID string) ([]state.Entry, error) {
	return QueryEntries(ctx, q, `SELECT `+EntryCols+` FROM entries e JOIN targets t ON t.id = $1
		WHERE e.deleted_at IS NULL AND `+TargetMatchesEntry+`
		ORDER BY e.created_at, e.id`, targetID)
}

// RecordStoppedMatching records, for each of ids that the target no longer
// matches, that the target must reach rev to confirm removing it. It returns
// how many entries stopped matching. A deleted target records nothing.
func RecordStoppedMatching(ctx context.Context, q Querier, targetID string, ids []string, rev func() (int64, error)) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	rows, err := q.Query(ctx, `SELECT e.id::text FROM entries e JOIN targets t ON t.id = $1
		WHERE e.id = ANY($2::uuid[]) AND NOT (`+TargetMatchesEntry+`)`, targetID, ids)
	if err != nil {
		return 0, err
	}
	stopped, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || len(stopped) == 0 {
		return 0, err
	}
	r, err := rev()
	if err != nil {
		return 0, err
	}
	_, err = q.Exec(ctx, `INSERT INTO entry_removals (entry_id, target_id, revision)
		SELECT unnest($1::uuid[]), $2, $3 `+recordRemovals, stopped, targetID, r)
	return len(stopped), err
}

// LoadRemovals loads the entry_removals rows for the given entries.
func LoadRemovals(ctx context.Context, q Querier, entryIDs []string) (state.Removals, error) {
	rem := state.Removals{}
	if len(entryIDs) == 0 {
		return rem, nil
	}
	rows, err := q.Query(ctx, `SELECT entry_id::text, target_id::text, revision FROM entry_removals
		WHERE entry_id = ANY($1::uuid[])`, entryIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			e, t string
			rev  int64
		)
		if err := rows.Scan(&e, &t, &rev); err != nil {
			return nil, err
		}
		rem.Add(e, t, rev)
	}
	return rem, rows.Err()
}

// LoadTargets loads every target with its subscriptions, sorted by label then id.
func LoadTargets(ctx context.Context, q Querier) ([]state.Target, error) {
	rows, err := q.Query(ctx, `
		SELECT id::text, name, label, ipv4, ipv6, applied_revision, applied_generated_at,
		       subscriptions_revision, last_seen_at
		FROM targets`)
	if err != nil {
		return nil, err
	}
	var ts []state.Target
	idx := map[string]int{}
	for rows.Next() {
		var t state.Target
		if err := rows.Scan(&t.ID, &t.Name, &t.Label, &t.IPv4, &t.IPv6, &t.AppliedRevision,
			&t.AppliedGeneratedAt, &t.SubscriptionsRevision, &t.LastSeenAt); err != nil {
			rows.Close()
			return nil, err
		}
		ts = append(ts, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	state.SortTargets(ts)
	for i := range ts {
		idx[ts[i].ID] = i
	}
	subs, err := LoadSubscriptions(ctx, q, "")
	if err != nil {
		return nil, err
	}
	for _, s := range subs {
		if i, ok := idx[s.TargetID]; ok {
			ts[i].Subs = append(ts[i].Subs, s)
		}
	}
	return ts, nil
}

// LoadSubscriptions loads subscriptions, all or for one target.
func LoadSubscriptions(ctx context.Context, q Querier, targetID string) ([]state.Subscription, error) {
	sql := `SELECT id::text, target_id::text, realm::text, username::text, grp::text FROM subscriptions`
	var args []any
	if targetID != "" {
		sql += ` WHERE target_id = $1`
		args = append(args, targetID)
	}
	sql += ` ORDER BY created_at, id`
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []state.Subscription
	for rows.Next() {
		var s state.Subscription
		if err := rows.Scan(&s.ID, &s.TargetID, &s.Realm, &s.User, &s.Group); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// LoadRejections loads target_rejections for the given prefixes (all when nil).
func LoadRejections(ctx context.Context, q Querier, prefixes []netip.Prefix) (state.Rejections, error) {
	rej := state.Rejections{}
	var (
		rows pgx.Rows
		err  error
	)
	if prefixes == nil {
		rows, err = q.Query(ctx, `SELECT target_id::text, prefix, code FROM target_rejections`)
	} else {
		if len(prefixes) == 0 {
			return rej, nil
		}
		rows, err = q.Query(ctx, `SELECT target_id::text, prefix, code FROM target_rejections
			WHERE prefix = ANY($1::cidr[])`, prefixes)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			t    string
			p    netip.Prefix
			code string
		)
		if err := rows.Scan(&t, &p, &code); err != nil {
			return nil, err
		}
		rej.Add(t, p, code)
	}
	return rej, rows.Err()
}

const baseRuleCols = `id::text, realm::text, username::text, grp::text, position, description, created_at, updated_at`

func scanBase(b *rules.Base) []any {
	return []any{&b.ID, &b.Realm, &b.User, &b.Group, &b.Position, &b.Description, &b.CreatedAt, &b.UpdatedAt}
}

// LoadRules loads a realm's four rule lists, each ordered by position.
func LoadRules(ctx context.Context, q Querier, realm string) (rules.Set, error) {
	var s rules.Set
	var err error
	if s.IP, err = LoadIPRules(ctx, q, realm); err != nil {
		return s, err
	}
	if s.Prefix, err = LoadPrefixRules(ctx, q, realm); err != nil {
		return s, err
	}
	if s.TTL, err = LoadTTLRules(ctx, q, realm); err != nil {
		return s, err
	}
	s.Cap, err = LoadCapRules(ctx, q, realm)
	return s, err
}

func loadList[T any](ctx context.Context, q Querier, sql, realm string, scan func(*T) []any) ([]T, error) {
	rows, err := q.Query(ctx, sql, realm)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []T
	for rows.Next() {
		var r T
		if err := rows.Scan(scan(&r)...); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// LoadIPRules loads a realm's IP rules in order.
func LoadIPRules(ctx context.Context, q Querier, realm string) ([]rules.IPRule, error) {
	return loadList(ctx, q, `SELECT `+baseRuleCols+`, prefix, action FROM ip_rules WHERE realm = $1 ORDER BY position`,
		realm, func(r *rules.IPRule) []any { return append(scanBase(&r.Base), &r.Prefix, &r.Action) })
}

// LoadPrefixRules loads a realm's prefix rules in order.
func LoadPrefixRules(ctx context.Context, q Querier, realm string) ([]rules.PrefixRule, error) {
	return loadList(ctx, q, `SELECT `+baseRuleCols+`, min_len_v4::int, min_len_v6::int FROM prefix_rules WHERE realm = $1 ORDER BY position`,
		realm, func(r *rules.PrefixRule) []any { return append(scanBase(&r.Base), &r.MinLenV4, &r.MinLenV6) })
}

// LoadTTLRules loads a realm's TTL rules in order.
func LoadTTLRules(ctx context.Context, q Querier, realm string) ([]rules.TTLRule, error) {
	return loadList(ctx, q, `SELECT `+baseRuleCols+`, max_ttl_seconds FROM ttl_rules WHERE realm = $1 ORDER BY position`,
		realm, func(r *rules.TTLRule) []any { return append(scanBase(&r.Base), &r.MaxTTLSeconds) })
}

// LoadCapRules loads a realm's cap rules in order.
func LoadCapRules(ctx context.Context, q Querier, realm string) ([]rules.CapRule, error) {
	return loadList(ctx, q, `SELECT `+baseRuleCols+`, max_prefixes FROM cap_rules WHERE realm = $1 ORDER BY position`,
		realm, func(r *rules.CapRule) []any { return append(scanBase(&r.Base), &r.MaxPrefixes) })
}

// InsertSeed writes a realm's seeded rules.
func InsertSeed(ctx context.Context, q Querier, s rules.Set) error {
	b := &pgx.Batch{}
	for _, r := range s.IP {
		b.Queue(`INSERT INTO ip_rules (realm, username, grp, position, description, prefix, action)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`, r.Realm, r.User, r.Group, r.Position, r.Description, r.Prefix, r.Action)
	}
	for _, r := range s.Prefix {
		b.Queue(`INSERT INTO prefix_rules (realm, username, grp, position, description, min_len_v4, min_len_v6)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`, r.Realm, r.User, r.Group, r.Position, r.Description, r.MinLenV4, r.MinLenV6)
	}
	for _, r := range s.TTL {
		b.Queue(`INSERT INTO ttl_rules (realm, username, grp, position, description, max_ttl_seconds)
			VALUES ($1, $2, $3, $4, $5, $6)`, r.Realm, r.User, r.Group, r.Position, r.Description, r.MaxTTLSeconds)
	}
	for _, r := range s.Cap {
		b.Queue(`INSERT INTO cap_rules (realm, username, grp, position, description, max_prefixes)
			VALUES ($1, $2, $3, $4, $5, $6)`, r.Realm, r.User, r.Group, r.Position, r.Description, r.MaxPrefixes)
	}
	return q.(interface {
		SendBatch(context.Context, *pgx.Batch) pgx.BatchResults
	}).SendBatch(ctx, b).Close()
}

// Audit is one audit_log row.
type Audit struct {
	Actor      string
	ClientID   *string
	Action     string
	ObjectType string
	ObjectID   string
	Realm      *string
	User       *string
	Group      *string
	Prefix     *netip.Prefix
	Details    map[string]any
}

// InsertAudit writes an audit row.
func InsertAudit(ctx context.Context, q Querier, a Audit) error {
	details := a.Details
	if details == nil {
		details = map[string]any{}
	}
	js, err := json.Marshal(details)
	if err != nil {
		return err
	}
	var objID *string
	if a.ObjectID != "" {
		objID = &a.ObjectID
	}
	_, err = q.Exec(ctx, `
		INSERT INTO audit_log (actor, client_id, action, object_type, object_id, realm, username, grp, prefix, details)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		a.Actor, a.ClientID, a.Action, a.ObjectType, objID, a.Realm, a.User, a.Group, a.Prefix, js)
	return err
}

// Notify sends a notification inside the current transaction.
func Notify(ctx context.Context, q Querier, channel, payload string) error {
	_, err := q.Exec(ctx, `SELECT pg_notify($1, $2)`, channel, payload)
	return err
}

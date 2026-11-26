package api

import (
	"context"
	"net/http"
	"net/url"
)

// --- realms

func (c *Admin) Realms(ctx context.Context) ([]Realm, error) {
	return listAll[Realm](ctx, c, "/v1/admin/realms", nil)
}

func (c *Admin) Realm(ctx context.Context, name string) (Realm, error) {
	var r Realm
	err := c.do(ctx, http.MethodGet, "/v1/admin/realms/"+pathEscape(name), nil, nil, &r)
	return r, err
}

func (c *Admin) CreateRealm(ctx context.Context, name string) (Realm, Extras, error) {
	var out struct {
		Realm
		Extras
	}
	err := c.do(ctx, http.MethodPost, "/v1/admin/realms", nil, map[string]any{"name": name}, &out)
	return out.Realm, out.Extras, err
}

func (c *Admin) DeleteRealm(ctx context.Context, name string) (RealmDeleteResult, error) {
	var out RealmDeleteResult
	err := c.do(ctx, http.MethodDelete, "/v1/admin/realms/"+pathEscape(name), nil, nil, &out)
	return out, err
}

// --- rules

func rulesPath(realm, list string) string {
	return "/v1/admin/realms/" + pathEscape(realm) + "/rules/" + pathEscape(list)
}

func (c *Admin) Rules(ctx context.Context, realm, list string) ([]Rule, error) {
	return listAll[Rule](ctx, c, rulesPath(realm, list), nil)
}

// CreateRule adds a rule; body holds the list's fields.
func (c *Admin) CreateRule(ctx context.Context, realm, list string, body map[string]any, mode Impact) (RuleMutation, error) {
	var out RuleMutation
	err := c.do(ctx, http.MethodPost, rulesPath(realm, list), mode.query(), body, &out)
	return out, err
}

// UpdateRule changes the fields present in body.
func (c *Admin) UpdateRule(ctx context.Context, realm, list, id string, body map[string]any, mode Impact) (RuleMutation, error) {
	var out RuleMutation
	err := c.do(ctx, http.MethodPatch, rulesPath(realm, list)+"/"+pathEscape(id), mode.query(), body, &out)
	return out, err
}

func (c *Admin) DeleteRule(ctx context.Context, realm, list, id string, mode Impact) (RuleMutation, error) {
	var out RuleMutation
	err := c.do(ctx, http.MethodDelete, rulesPath(realm, list)+"/"+pathEscape(id), mode.query(), nil, &out)
	return out, err
}

// --- clients

func (c *Admin) Clients(ctx context.Context) ([]Client, error) {
	return listAll[Client](ctx, c, "/v1/admin/clients", nil)
}

func (c *Admin) Client(ctx context.Context, id string) (Client, error) {
	var out Client
	err := c.do(ctx, http.MethodGet, "/v1/admin/clients/"+pathEscape(id), nil, nil, &out)
	return out, err
}

func (c *Admin) CreateClient(ctx context.Context, name string, realms []string) (Client, Extras, error) {
	var out struct {
		Client
		Extras
	}
	err := c.do(ctx, http.MethodPost, "/v1/admin/clients", nil, map[string]any{"name": name, "realms": realms}, &out)
	return out.Client, out.Extras, err
}

func (c *Admin) UpdateClient(ctx context.Context, id string, body map[string]any) (Client, Extras, error) {
	var out struct {
		Client
		Extras
	}
	err := c.do(ctx, http.MethodPatch, "/v1/admin/clients/"+pathEscape(id), nil, body, &out)
	return out.Client, out.Extras, err
}

func (c *Admin) DeleteClient(ctx context.Context, id string) (Client, error) {
	var out Client
	err := c.do(ctx, http.MethodDelete, "/v1/admin/clients/"+pathEscape(id), nil, nil, &out)
	return out, err
}

// --- workers and subscriptions

func (c *Admin) Workers(ctx context.Context) ([]Worker, error) {
	return listAll[Worker](ctx, c, "/v1/admin/workers", nil)
}

func (c *Admin) Worker(ctx context.Context, id string) (Worker, error) {
	var out Worker
	err := c.do(ctx, http.MethodGet, "/v1/admin/workers/"+pathEscape(id), nil, nil, &out)
	return out, err
}

func (c *Admin) CreateWorker(ctx context.Context, name, label string, ipv4, ipv6 bool) (WorkerMutation, error) {
	var out WorkerMutation
	err := c.do(ctx, http.MethodPost, "/v1/admin/workers", nil,
		map[string]any{"name": name, "label": label, "ipv4": ipv4, "ipv6": ipv6}, &out)
	return out, err
}

func (c *Admin) UpdateWorker(ctx context.Context, id string, body map[string]any, mode Impact) (WorkerMutation, error) {
	var out WorkerMutation
	err := c.do(ctx, http.MethodPatch, "/v1/admin/workers/"+pathEscape(id), mode.query(), body, &out)
	return out, err
}

func (c *Admin) DeleteWorker(ctx context.Context, id string, mode Impact) (WorkerMutation, error) {
	var out WorkerMutation
	err := c.do(ctx, http.MethodDelete, "/v1/admin/workers/"+pathEscape(id), mode.query(), nil, &out)
	return out, err
}

func (c *Admin) Subscriptions(ctx context.Context, workerID string) ([]Subscription, error) {
	return listAll[Subscription](ctx, c, "/v1/admin/workers/"+pathEscape(workerID)+"/subscriptions", nil)
}

func (c *Admin) CreateSubscription(ctx context.Context, workerID, realm, user, group string) (SubscriptionMutation, error) {
	var out SubscriptionMutation
	err := c.do(ctx, http.MethodPost, "/v1/admin/workers/"+pathEscape(workerID)+"/subscriptions", nil,
		map[string]any{"realm": realm, "user": user, "group": group}, &out)
	return out, err
}

func (c *Admin) DeleteSubscription(ctx context.Context, id string, mode Impact) (SubscriptionMutation, error) {
	var out SubscriptionMutation
	err := c.do(ctx, http.MethodDelete, "/v1/admin/subscriptions/"+pathEscape(id), mode.query(), nil, &out)
	return out, err
}

// --- health

func (c *Admin) Health(ctx context.Context) (Health, error) {
	var out Health
	err := c.do(ctx, http.MethodGet, "/v1/admin/health", nil, nil, &out)
	return out, err
}

func (c *Admin) WorkerHealth(ctx context.Context, id string) (WorkerHealth, error) {
	var out WorkerHealth
	err := c.do(ctx, http.MethodGet, "/v1/admin/workers/"+pathEscape(id)+"/health", nil, nil, &out)
	return out, err
}

// --- keys

// KeyFilter narrows the key list.
type KeyFilter struct {
	Kind, ClientID, WorkerID string
}

func (c *Admin) Keys(ctx context.Context, f KeyFilter, page PageQuery) (Page[Key], error) {
	q := url.Values{}
	setIf(q, "kind", f.Kind)
	setIf(q, "client_id", f.ClientID)
	setIf(q, "worker_id", f.WorkerID)
	var out Page[Key]
	err := c.do(ctx, http.MethodGet, "/v1/admin/keys", page.apply(q), nil, &out)
	return out, err
}

// AllKeys returns every key matching f.
func (c *Admin) AllKeys(ctx context.Context, f KeyFilter) ([]Key, error) {
	q := url.Values{}
	setIf(q, "kind", f.Kind)
	setIf(q, "client_id", f.ClientID)
	setIf(q, "worker_id", f.WorkerID)
	return listAll[Key](ctx, c, "/v1/admin/keys", q)
}

func (c *Admin) Key(ctx context.Context, id string) (Key, error) {
	var out Key
	err := c.do(ctx, http.MethodGet, "/v1/admin/keys/"+pathEscape(id), nil, nil, &out)
	return out, err
}

// CreateKey creates a key; body holds kind, name and the optional
// client_id, worker_id and expires_at.
func (c *Admin) CreateKey(ctx context.Context, body map[string]any) (CreatedKey, error) {
	var out CreatedKey
	err := c.do(ctx, http.MethodPost, "/v1/admin/keys", nil, body, &out)
	return out, err
}

func (c *Admin) RevokeKey(ctx context.Context, id string) (Key, error) {
	var out Key
	err := c.do(ctx, http.MethodPost, "/v1/admin/keys/"+pathEscape(id)+"/revoke", nil, nil, &out)
	return out, err
}

// --- entries

// EntryFilter narrows the entry list.
type EntryFilter struct {
	Realm, User, Group, Prefix, State, ClientID, WorkerID string
	IncludeEnded                                          bool
}

func (f EntryFilter) query() url.Values {
	q := url.Values{}
	setIf(q, "realm", f.Realm)
	setIf(q, "user", f.User)
	setIf(q, "group", f.Group)
	setIf(q, "prefix", f.Prefix)
	setIf(q, "state", f.State)
	setIf(q, "client_id", f.ClientID)
	setIf(q, "worker_id", f.WorkerID)
	if f.IncludeEnded {
		q.Set("include_ended", "true")
	}
	return q
}

// Submit adds or replaces entries for user in each group, in any realm,
// through the realm's rules (POST /v1/admin/submissions).
func (c *Admin) Submit(ctx context.Context, realm, user string, groups []string, prefix, ttl string) (Submission, error) {
	var out Submission
	err := c.do(ctx, http.MethodPost, "/v1/admin/submissions", nil,
		map[string]any{"realm": realm, "user": user, "groups": groups, "prefix": prefix, "ttl": ttl}, &out)
	return out, err
}

func (c *Admin) Entries(ctx context.Context, f EntryFilter, page PageQuery) (Page[Entry], error) {
	var out Page[Entry]
	err := c.do(ctx, http.MethodGet, "/v1/admin/entries", page.apply(f.query()), nil, &out)
	return out, err
}

func (c *Admin) Entry(ctx context.Context, id string) (Entry, error) {
	var out Entry
	err := c.do(ctx, http.MethodGet, "/v1/admin/entries/"+pathEscape(id), nil, nil, &out)
	return out, err
}

func (c *Admin) DeleteEntry(ctx context.Context, id string) (Entry, error) {
	var out Entry
	err := c.do(ctx, http.MethodDelete, "/v1/admin/entries/"+pathEscape(id), nil, nil, &out)
	return out, err
}

// --- audit

// AuditFilter narrows the audit log. Since and Until are RFC 3339.
type AuditFilter struct {
	Since, Until, Actor, OnBehalfOf, Realm, Action string
}

func (c *Admin) Audit(ctx context.Context, f AuditFilter, page PageQuery) (Page[AuditEntry], error) {
	q := url.Values{}
	setIf(q, "since", f.Since)
	setIf(q, "until", f.Until)
	setIf(q, "actor", f.Actor)
	setIf(q, "on_behalf_of", f.OnBehalfOf)
	setIf(q, "realm", f.Realm)
	setIf(q, "action", f.Action)
	var out Page[AuditEntry]
	err := c.do(ctx, http.MethodGet, "/v1/admin/audit", page.apply(q), nil, &out)
	return out, err
}

func setIf(q url.Values, k, v string) {
	if v != "" {
		q.Set(k, v)
	}
}

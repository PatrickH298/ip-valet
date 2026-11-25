package api

import "time"

// Warning is a non-fatal note on an admin change.
type Warning struct {
	Code           string `json:"code"`
	Message        string `json:"message"`
	RuleID         string `json:"rule_id,omitempty"`
	ShadowedBy     string `json:"shadowed_by,omitempty"`
	SubscriptionID string `json:"subscription_id,omitempty"`
}

// ImpactItem is an entry a change affects and what happens to it.
type ImpactItem struct {
	EntryID string `json:"entry_id"`
	Realm   string `json:"realm"`
	User    string `json:"user"`
	Group   string `json:"group"`
	Prefix  string `json:"prefix"`
	Effect  string `json:"effect"`
	Action  string `json:"action"`
}

// Extras are the fields every admin mutation response adds.
type Extras struct {
	Warnings []Warning    `json:"warnings"`
	Impact   []ImpactItem `json:"impact"`
	Enforced *struct {
		Shortened int `json:"shortened"`
		Removed   int `json:"removed"`
	} `json:"enforced"`
	DryRun bool `json:"dry_run"`
}

// Realm is a realm.
type Realm struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// RealmDeleteResult says what deleting a realm removed.
type RealmDeleteResult struct {
	Name                 string `json:"name"`
	EntriesRemoved       int    `json:"entries_removed"`
	RulesDeleted         int    `json:"rules_deleted"`
	SubscriptionsDeleted int    `json:"subscriptions_deleted"`
	ClientsUnbound       int    `json:"clients_unbound"`
	Revision             *int64 `json:"revision"`
	Extras
}

// Rule lists.
const (
	ListIP     = "ip"
	ListPrefix = "prefix"
	ListTTL    = "ttl"
	ListCap    = "cap"
)

// RuleLists are the four lists in the order they are checked.
var RuleLists = []string{ListIP, ListPrefix, ListTTL, ListCap}

// Rule is a rule of any list; the fields of other lists are empty.
type Rule struct {
	ID          string    `json:"id"`
	Realm       string    `json:"realm"`
	List        string    `json:"list"`
	Position    int       `json:"position"`
	User        string    `json:"user"`
	Group       string    `json:"group"`
	Description *string   `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`

	Prefix      string `json:"prefix,omitempty"`  // ip
	Action      string `json:"action,omitempty"`  // ip: accept or deny
	MinLenV4    *int   `json:"min_len_v4"`        // prefix
	MinLenV6    *int   `json:"min_len_v6"`        // prefix
	MaxTTL      string `json:"max_ttl,omitempty"` // ttl
	MaxPrefixes *int   `json:"max_prefixes"`      // cap
}

// RuleMutation is a rule change's response.
type RuleMutation struct {
	Rule
	Extras
}

// Client is a client.
type Client struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Realms    []string  `json:"realms"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Worker is a worker.
type Worker struct {
	ID                    string     `json:"id"`
	Name                  string     `json:"name"`
	Label                 string     `json:"label"`
	IPv4                  bool       `json:"ipv4"`
	IPv6                  bool       `json:"ipv6"`
	AppliedRevision       int64      `json:"applied_revision"`
	AppliedGeneratedAt    *time.Time `json:"applied_generated_at"`
	SubscriptionsRevision int64      `json:"subscriptions_revision"`
	LastSeenAt            *time.Time `json:"last_seen_at"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
}

// WorkerMutation is a worker change's response.
type WorkerMutation struct {
	Worker
	Extras
}

// Subscription routes a (realm, user, group) selector to a worker.
type Subscription struct {
	ID        string    `json:"id"`
	WorkerID  string    `json:"worker_id"`
	Realm     string    `json:"realm"`
	User      string    `json:"user"`
	Group     string    `json:"group"`
	CreatedAt time.Time `json:"created_at"`
}

// SubscriptionMutation is a subscription change's response.
type SubscriptionMutation struct {
	Subscription
	Extras
}

// Key is a key record; it never holds the secret.
type Key struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind"`
	ClientID   *string    `json:"client_id"`
	WorkerID   *string    `json:"worker_id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

// CreatedKey is a new key, with the full key shown this once.
type CreatedKey struct {
	Key
	Secret string `json:"key"`
	Extras
}

// KeySummary is a key in the health report.
type KeySummary struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

// WorkerState is an entry's state on one worker.
type WorkerState struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Label      string     `json:"label"`
	State      string     `json:"state"`
	Code       string     `json:"code,omitempty"`
	LastSeenAt *time.Time `json:"last_seen_at"`
}

// Entry is an entry as admins see it.
type Entry struct {
	ID           string        `json:"id"`
	SubmissionID string        `json:"submission_id"`
	Realm        string        `json:"realm"`
	User         string        `json:"user"`
	Group        string        `json:"group"`
	Prefix       string        `json:"prefix"`
	ExpiresAt    *time.Time    `json:"expires_at"`
	CreatedAt    time.Time     `json:"created_at"`
	UpdatedAt    time.Time     `json:"updated_at"`
	DeletedAt    *time.Time    `json:"deleted_at"`
	State        string        `json:"state"`
	Workers      []WorkerState `json:"workers"`
	ClientID     *string       `json:"client_id"`
	KeyID        *string       `json:"key_id"`
	Revision     int64         `json:"revision"`
	DeletedBy    *string       `json:"deleted_by"`
}

// Rejection is a prefix a worker refused.
type Rejection struct {
	Prefix   string  `json:"prefix"`
	Code     string  `json:"code"`
	Detail   *string `json:"detail"`
	Revision int64   `json:"revision"`
}

// WorkerHealth is one worker's health.
type WorkerHealth struct {
	WorkerID           string      `json:"worker_id"`
	Name               string      `json:"name"`
	Label              string      `json:"label"`
	AppliedRevision    int64       `json:"applied_revision"`
	Revision           int64       `json:"revision"`
	Lag                int64       `json:"lag"`
	AppliedGeneratedAt *time.Time  `json:"applied_generated_at"`
	LastSeenAt         *time.Time  `json:"last_seen_at"`
	LastError          *string     `json:"last_error"`
	LastErrorAt        *time.Time  `json:"last_error_at"`
	LastInstance       *string     `json:"last_instance"`
	LastVersion        *string     `json:"last_version"`
	WorkerStreams      int         `json:"worker_streams"`
	Rejections         []Rejection `json:"rejections"`
}

// Health is every worker's health and the keys that need attention.
type Health struct {
	Revision int64          `json:"revision"`
	Workers  []WorkerHealth `json:"workers"`
	Keys     struct {
		ExpiringSoon []KeySummary `json:"expiring_soon"`
		Unused       []KeySummary `json:"unused"`
	} `json:"keys"`
}

// AuditEntry is an audit log row.
type AuditEntry struct {
	ID         int64          `json:"id"`
	At         time.Time      `json:"at"`
	Actor      string         `json:"actor"`
	OnBehalfOf *string        `json:"on_behalf_of"`
	ClientID   *string        `json:"client_id"`
	Action     string         `json:"action"`
	ObjectType string         `json:"object_type"`
	ObjectID   *string        `json:"object_id"`
	Realm      *string        `json:"realm"`
	User       *string        `json:"user"`
	Group      *string        `json:"group"`
	Prefix     *string        `json:"prefix"`
	Details    map[string]any `json:"details"`
	ClientIP   *string        `json:"client_ip"`
}

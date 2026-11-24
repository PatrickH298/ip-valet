// Package state computes applied state (per entry, per target) and the
// desired-state ETag. It is pure: callers load the rows.
package state

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/PatrickH298/ip-valet/api/internal/rules"
)

// Overall and per-target states.
const (
	Active   = "active"
	Pending  = "pending"
	Partial  = "partial"
	Rejected = "rejected"
	Unrouted = "unrouted"
	Removing = "removing"
	Removed  = "removed"
	Expired  = "expired"
)

// AllStates lists every overall state.
var AllStates = []string{Active, Pending, Partial, Rejected, Unrouted, Removing, Removed, Expired}

// Worker rejection codes accepted in status reports.
var WorkerCodes = []string{"prefix_too_broad", "address_not_allowed", "family_unsupported", "target_full", "invalid"}

// Entry is one entries row.
type Entry struct {
	ID              string
	SubmissionID    string
	Realm           string
	User            string
	Group           string
	Prefix          netip.Prefix
	ExpiresAt       *time.Time
	Revision        int64
	ClientID        *string
	KeyID           *string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	DeletedAt       *time.Time
	DeletedBy       *string
	DeletedRevision *int64
}

// Ended reports whether the entry is deleted or expired at now.
func (e *Entry) Ended(now time.Time) bool {
	return e.DeletedRevision != nil || (e.ExpiresAt != nil && !now.Before(*e.ExpiresAt))
}

// Subscription is one subscriptions row.
type Subscription struct {
	ID       string
	TargetID string
	Realm    *string
	User     *string
	Group    *string
}

// Matches reports whether the subscription's selector matches.
func (s *Subscription) Matches(realm, user, group string) bool {
	return rules.Matches(s.Realm, s.User, s.Group, realm, user, group)
}

// Target is one targets row with its subscriptions.
type Target struct {
	ID                    string
	Name                  string
	Label                 string
	IPv4                  bool
	IPv6                  bool
	AppliedRevision       int64
	AppliedGeneratedAt    *time.Time
	SubscriptionsRevision int64
	LastSeenAt            *time.Time
	Subs                  []Subscription
}

// FamilyOK reports whether the target holds p's address family.
func (t *Target) FamilyOK(p netip.Prefix) bool {
	if p.Addr().Is4() {
		return t.IPv4
	}
	return t.IPv6
}

// Routes reports whether the target applies an entry with these fields.
func (t *Target) Routes(realm, user, group string, p netip.Prefix) bool {
	if !t.FamilyOK(p) {
		return false
	}
	for i := range t.Subs {
		if t.Subs[i].Matches(realm, user, group) {
			return true
		}
	}
	return false
}

// SortTargets orders targets by label, then id, for stable output.
func SortTargets(ts []Target) {
	sort.SliceStable(ts, func(i, j int) bool {
		if ts[i].Label != ts[j].Label {
			return ts[i].Label < ts[j].Label
		}
		return ts[i].ID < ts[j].ID
	})
}

// Routed reports whether any target applies the entry.
func Routed(targets []Target, realm, user, group string, p netip.Prefix) bool {
	for i := range targets {
		if targets[i].Routes(realm, user, group, p) {
			return true
		}
	}
	return false
}

type rejKey struct {
	target string
	prefix netip.Prefix
}

// Rejections holds target_rejections rows.
type Rejections map[rejKey]string

// Add records a rejection.
func (r Rejections) Add(targetID string, p netip.Prefix, code string) {
	r[rejKey{targetID, p}] = code
}

// Code returns the rejection code for (target, prefix), if any.
func (r Rejections) Code(targetID string, p netip.Prefix) (string, bool) {
	c, ok := r[rejKey{targetID, p}]
	return c, ok
}

// TargetState is an entry's state on one target.
type TargetState struct {
	Target *Target
	State  string
	Code   string // rejection code when State is rejected
}

// Removals holds entry_removals rows: entry id → target id → the revision
// from which that target no longer holds the entry.
type Removals map[string]map[string]int64

// Add records a removal row.
func (r Removals) Add(entryID, targetID string, rev int64) {
	m := r[entryID]
	if m == nil {
		m = map[string]int64{}
		r[entryID] = m
	}
	m[targetID] = rev
}

// confirmedGone reports whether target t has removed entry e, given the
// revision from which t no longer holds it. An expired entry also leaves a
// target once the target has applied a desired state generated after the
// expiry, since expiry bumps no revision.
func confirmedGone(e *Entry, t *Target, rev int64) bool {
	if t.AppliedRevision >= rev {
		return true
	}
	return e.ExpiresAt != nil && t.AppliedGeneratedAt != nil && !t.AppliedGeneratedAt.Before(*e.ExpiresAt)
}

// EntryState computes an entry's overall state and its per-target states.
// targets must already be sorted with SortTargets.
//
// A live entry is judged by the targets that match it now. An ended entry is
// judged by every target that held it: for a deleted entry, the targets on
// record in rem (written when it was deleted, or earlier when a target
// stopped matching it); for an expired entry, the targets that match it now
// plus those on record. A target that stopped matching a live entry is listed
// as removing until it confirms, without affecting the overall state.
func EntryState(e *Entry, targets []Target, rej Rejections, rem Removals, now time.Time) (string, []TargetState) {
	rows := rem[e.ID]

	if e.Ended(now) {
		final := Removed
		if e.DeletedRevision == nil {
			final = Expired
		}
		overall := final
		var per []TargetState
		for i := range targets {
			t := &targets[i]
			rev, onRecord := rows[t.ID]
			var gone bool
			switch {
			case e.DeletedRevision != nil:
				if !onRecord {
					continue
				}
				gone = confirmedGone(e, t, rev)
			case t.Routes(e.Realm, e.User, e.Group, e.Prefix):
				gone = t.AppliedGeneratedAt != nil && !t.AppliedGeneratedAt.Before(*e.ExpiresAt)
			case onRecord:
				gone = confirmedGone(e, t, rev)
			default:
				continue
			}
			s := final
			if !gone {
				s = Removing
				overall = Removing
			}
			per = append(per, TargetState{Target: t, State: s})
		}
		return overall, per
	}

	var (
		per                           []TargetState
		nMatched, nPending, nRejected int
	)
	for i := range targets {
		t := &targets[i]
		if !t.Routes(e.Realm, e.User, e.Group, e.Prefix) {
			if rev, onRecord := rows[t.ID]; onRecord && !confirmedGone(e, t, rev) {
				per = append(per, TargetState{Target: t, State: Removing})
			}
			continue
		}
		nMatched++
		need := max(e.Revision, t.SubscriptionsRevision)
		switch code, rejected := rej.Code(t.ID, e.Prefix); {
		case t.AppliedRevision < need:
			per = append(per, TargetState{Target: t, State: Pending})
			nPending++
		case rejected:
			per = append(per, TargetState{Target: t, State: Rejected, Code: code})
			nRejected++
		default:
			per = append(per, TargetState{Target: t, State: Active})
		}
	}
	switch {
	case nMatched == 0:
		return Unrouted, per
	case nPending > 0:
		return Pending, per
	case nRejected == nMatched:
		return Rejected, per
	case nRejected > 0:
		return Partial, per
	default:
		return Active, per
	}
}

// DesiredItem is one prefix in a target's desired state.
type DesiredItem struct {
	Prefix    netip.Prefix
	ExpiresAt *time.Time
}

// FormatTime renders a timestamp as RFC 3339 UTC, keeping sub-second digits when present.
func FormatTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// FormatMicro renders a timestamp as RFC 3339 UTC with exactly six fractional digits.
func FormatMicro(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000000Z07:00") }

// Families returns the target's families as API strings.
func Families(ipv4, ipv6 bool) []string {
	out := []string{}
	if ipv4 {
		out = append(out, "ipv4")
	}
	if ipv6 {
		out = append(out, "ipv6")
	}
	return out
}

// ETag is a quoted hex SHA-256 over the families line and one "prefix expires_at"
// line per item ("-" for no expiry). It excludes revision and generated_at.
func ETag(families []string, items []DesiredItem) string {
	var b strings.Builder
	b.WriteString(strings.Join(families, ","))
	b.WriteByte('\n')
	for _, it := range items {
		b.WriteString(it.Prefix.String())
		b.WriteByte(' ')
		if it.ExpiresAt == nil {
			b.WriteByte('-')
		} else {
			b.WriteString(FormatTime(*it.ExpiresAt))
		}
		b.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

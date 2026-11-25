package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/PatrickH298/ip-valet/api/internal/auth"
	"github.com/PatrickH298/ip-valet/api/internal/db"
	"github.com/PatrickH298/ip-valet/api/internal/rules"
	"github.com/PatrickH298/ip-valet/api/internal/state"
)

type desiredEntry struct {
	Prefix    string  `json:"prefix"`
	ExpiresAt *string `json:"expires_at"`
}

type desiredStateResponse struct {
	Revision     int64          `json:"revision"`
	GeneratedAt  string         `json:"generated_at"`
	NextChangeAt *string        `json:"next_change_at"`
	Families     []string       `json:"families"`
	Entries      []desiredEntry `json:"entries"`
}

func (s *Server) desiredState(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	if err := checkQuery(r); err != nil {
		return err
	}
	ctx := r.Context()
	var (
		rev         int64
		generatedAt time.Time
		ipv4, ipv6  bool
		items       []state.DesiredItem
	)
	err := db.InTx(ctx, s.Pool, db.SnapshotRead, func(tx pgx.Tx) error {
		var err error
		if rev, err = db.CurrentRevision(ctx, tx); err != nil {
			return err
		}
		if generatedAt, err = db.Now(ctx, tx); err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `SELECT ipv4, ipv6 FROM workers WHERE id = $1`, p.WorkerID).Scan(&ipv4, &ipv6)
		if errors.Is(err, pgx.ErrNoRows) {
			return errNotFound
		}
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `
			SELECT e.prefix,
			       CASE WHEN bool_or(e.expires_at IS NULL) THEN NULL
			            ELSE max(e.expires_at) END AS expires_at
			FROM entries e
			WHERE e.deleted_at IS NULL
			  AND (e.expires_at IS NULL OR e.expires_at > now())
			  AND ((family(e.prefix) = 4 AND $2) OR (family(e.prefix) = 6 AND $3))
			  AND EXISTS (
			    SELECT 1 FROM subscriptions s
			    WHERE s.worker_id = $1
			      AND (s.realm    IS NULL OR s.realm    = e.realm)
			      AND (s.username IS NULL OR s.username = e.username)
			      AND (s.grp      IS NULL OR s.grp      = e.grp))
			GROUP BY e.prefix
			ORDER BY e.prefix`, p.WorkerID, ipv4, ipv6)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var it state.DesiredItem
			if err := rows.Scan(&it.Prefix, &it.ExpiresAt); err != nil {
				return err
			}
			items = append(items, it)
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}

	families := state.Families(ipv4, ipv6)
	etag := state.ETag(families, items)
	gen := state.FormatMicro(generatedAt)
	h := w.Header()
	h.Set("IPValet-Revision", fmt.Sprint(rev))
	h.Set("IPValet-Generated-At", gen)
	h.Set("ETag", etag)
	h.Set("Cache-Control", "no-store")
	if etagMatches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return nil
	}
	resp := desiredStateResponse{Revision: rev, GeneratedAt: gen, Families: families, Entries: make([]desiredEntry, 0, len(items))}
	var next *time.Time
	for _, it := range items {
		resp.Entries = append(resp.Entries, desiredEntry{Prefix: it.Prefix.String(), ExpiresAt: tsPtr(it.ExpiresAt)})
		if it.ExpiresAt != nil && (next == nil || it.ExpiresAt.Before(*next)) {
			next = it.ExpiresAt
		}
	}
	resp.NextChangeAt = tsPtr(next)
	writeJSON(w, http.StatusOK, resp)
	return nil
}

func etagMatches(header, etag string) bool {
	if header == "" {
		return false
	}
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimPrefix(strings.TrimSpace(part), "W/")
		if part == "*" || part == etag {
			return true
		}
	}
	return false
}

type rejectedItem struct {
	Prefix *string `json:"prefix"`
	Code   *string `json:"code"`
	Detail *string `json:"detail"`
}

type statusRequest struct {
	Instance    *string        `json:"instance"`
	Version     *string        `json:"version"`
	Revision    *int64         `json:"revision"`
	GeneratedAt *string        `json:"generated_at"`
	Error       *string        `json:"error"`
	Rejected    []rejectedItem `json:"rejected"`
}

type statusResponse struct {
	AppliedRevision int64 `json:"applied_revision"`
}

// Status report limits. A report at these limits, with the longest prefixes
// and codes and ASCII details, is about 59 KB, so it fits in the default
// 64 KiB body limit; MaxStatusReportBytes is the body limit it needs.
const (
	maxRejected          = 200
	maxDetailChars       = 200
	MaxStatusReportBytes = 60 * 1024
)

func (s *Server) workerStatus(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	var req statusRequest
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	fe := fieldErrors{}
	if req.Instance == nil {
		fe.add("instance", "required")
	} else if n := utf8.RuneCountInString(*req.Instance); n < 1 || n > 128 {
		fe.add("instance", "must be 1 to 128 characters")
	}
	if req.Version != nil && utf8.RuneCountInString(*req.Version) > 64 {
		fe.add("version", "must be at most 64 characters")
	}
	if req.Revision == nil {
		fe.add("revision", "required")
	} else if *req.Revision < 0 {
		fe.add("revision", "must not be negative")
	}
	var generatedAt time.Time
	switch {
	case (req.Error == nil) == (req.GeneratedAt == nil):
		fe.add("generated_at", "exactly one of error or generated_at is required")
	case req.Error != nil:
		if n := utf8.RuneCountInString(*req.Error); n < 1 || n > 2000 {
			fe.add("error", "must be 1 to 2000 characters")
		}
		if req.Rejected != nil {
			fe.add("rejected", "only allowed with generated_at")
		}
	default:
		t, err := time.Parse(time.RFC3339Nano, *req.GeneratedAt)
		if err != nil {
			fe.add("generated_at", "must be an RFC 3339 timestamp")
		}
		generatedAt = t
	}
	if len(req.Rejected) > maxRejected {
		fe.add("rejected", fmt.Sprintf("at most %d items", maxRejected))
	}
	var (
		rejPrefixes []netip.Prefix
		rejCodes    []string
		rejDetails  []*string
		seen        = map[netip.Prefix]bool{}
	)
	for i, it := range req.Rejected {
		if i >= maxRejected {
			break
		}
		field := fmt.Sprintf("rejected[%d]", i)
		if it.Prefix == nil {
			fe.add(field+".prefix", "required")
			continue
		}
		pfx, err := rules.NormalizePrefix(*it.Prefix)
		if err != nil {
			fe.add(field+".prefix", "invalid prefix")
			continue
		}
		if it.Code == nil || !slices.Contains(state.WorkerCodes, *it.Code) {
			fe.add(field+".code", "must be one of "+strings.Join(state.WorkerCodes, ", "))
			continue
		}
		if it.Detail != nil && utf8.RuneCountInString(*it.Detail) > maxDetailChars {
			fe.add(field+".detail", fmt.Sprintf("must be at most %d characters", maxDetailChars))
			continue
		}
		if seen[pfx] {
			continue // first report for a prefix wins
		}
		seen[pfx] = true
		rejPrefixes = append(rejPrefixes, pfx)
		rejCodes = append(rejCodes, *it.Code)
		rejDetails = append(rejDetails, it.Detail)
	}
	if err := fe.err(); err != nil {
		return err
	}

	ctx := r.Context()
	var applied int64
	err := db.InTx(ctx, s.Pool, db.ReadCommitted, func(tx pgx.Tx) error {
		cur, err := db.CurrentRevision(ctx, tx)
		if err != nil {
			return err
		}
		if *req.Revision > cur {
			return invalid("revision", "is newer than the current revision")
		}
		if req.GeneratedAt != nil {
			var future bool
			if err := tx.QueryRow(ctx, `SELECT $1::timestamptz > clock_timestamp()`, generatedAt).Scan(&future); err != nil {
				return err
			}
			if future {
				return invalid("generated_at", "is in the future")
			}
		}
		var appliedRev int64
		err = tx.QueryRow(ctx, `SELECT applied_revision FROM workers WHERE id = $1 FOR UPDATE`, p.WorkerID).Scan(&appliedRev)
		if errors.Is(err, pgx.ErrNoRows) {
			return errNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE workers SET last_seen_at = now(), last_instance = $2, last_version = $3
			WHERE id = $1`, p.WorkerID, *req.Instance, req.Version); err != nil {
			return err
		}
		applied = appliedRev
		switch {
		case req.Error != nil:
			if _, err := tx.Exec(ctx, `UPDATE workers SET last_error = $2, last_error_at = now() WHERE id = $1`,
				p.WorkerID, *req.Error); err != nil {
				return err
			}
		case *req.Revision >= appliedRev:
			if _, err := tx.Exec(ctx, `UPDATE workers SET applied_revision = $2,
				applied_generated_at = greatest(applied_generated_at, $3) WHERE id = $1`,
				p.WorkerID, *req.Revision, generatedAt); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `DELETE FROM worker_rejections WHERE worker_id = $1`, p.WorkerID); err != nil {
				return err
			}
			if len(rejPrefixes) > 0 {
				if _, err := tx.Exec(ctx, `
					INSERT INTO worker_rejections (worker_id, prefix, code, detail, revision)
					SELECT $1, u.p, u.c, u.d, $5 FROM unnest($2::cidr[], $3::text[], $4::text[]) AS u(p, c, d)`,
					p.WorkerID, rejPrefixes, rejCodes, rejDetails, *req.Revision); err != nil {
					return err
				}
			}
			applied = *req.Revision
		}
		return db.Notify(ctx, tx, db.ChannelStatus, p.WorkerID)
	})
	if err != nil {
		return err
	}
	kind := "success"
	if req.Error != nil {
		kind = "error"
	}
	s.Log.Debug("status report", "worker_id", p.WorkerID, "instance", *req.Instance, "revision", *req.Revision,
		"kind", kind, "rejected", len(rejPrefixes), "applied_revision", applied)
	writeJSON(w, http.StatusOK, statusResponse{AppliedRevision: applied})
	return nil
}

package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/PatrickH298/ip-valet/api/internal/auth"
	"github.com/PatrickH298/ip-valet/api/internal/db"
	"github.com/PatrickH298/ip-valet/api/internal/rules"
)

var ruleTables = map[string]string{
	rules.ListIP: "ip_rules", rules.ListPrefix: "prefix_rules", rules.ListTTL: "ttl_rules", rules.ListCap: "cap_rules",
}

var ruleFields = map[string][]string{
	rules.ListIP:     {"prefix", "action"},
	rules.ListPrefix: {"min_len_v4", "min_len_v6"},
	rules.ListTTL:    {"max_ttl"},
	rules.ListCap:    {"max_prefixes"},
}

// ruleRow is one rule of any list.
type ruleRow struct {
	rules.Base
	list        string
	prefix      netip.Prefix
	action      string
	minV4       *int
	minV6       *int
	maxTTL      *int64
	maxPrefixes int
}

func (rr *ruleRow) item() rules.Item {
	it := rules.Item{ID: rr.ID, User: rr.User, Group: rr.Group}
	if rr.list == rules.ListIP {
		p := rr.prefix
		it.Prefix = &p
	}
	return it
}

func (rr *ruleRow) view() map[string]any {
	v := map[string]any{
		"id": rr.ID, "realm": rr.Realm, "list": rr.list, "position": rr.Position,
		"user": rules.SelectorString(rr.User), "group": rules.SelectorString(rr.Group),
		"description": rr.Description, "created_at": ts(rr.CreatedAt), "updated_at": ts(rr.UpdatedAt),
	}
	switch rr.list {
	case rules.ListIP:
		v["prefix"], v["action"] = rr.prefix.String(), rr.action
	case rules.ListPrefix:
		v["min_len_v4"], v["min_len_v6"] = rr.minV4, rr.minV6
	case rules.ListTTL:
		v["max_ttl"] = rules.FormatMaxTTL(rr.maxTTL)
	case rules.ListCap:
		v["max_prefixes"] = rr.maxPrefixes
	}
	return v
}

func loadRuleRows(ctx context.Context, q db.Querier, list, realm string) ([]ruleRow, error) {
	extra := map[string]string{
		rules.ListIP: "prefix, action", rules.ListPrefix: "min_len_v4::int, min_len_v6::int",
		rules.ListTTL: "max_ttl_seconds", rules.ListCap: "max_prefixes",
	}[list]
	rows, err := q.Query(ctx, `SELECT id::text, realm::text, username::text, grp::text, position, description,
		created_at, updated_at, `+extra+` FROM `+ruleTables[list]+` WHERE realm = $1 ORDER BY position`, realm)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ruleRow
	for rows.Next() {
		rr := ruleRow{list: list}
		dest := []any{&rr.ID, &rr.Realm, &rr.User, &rr.Group, &rr.Position, &rr.Description, &rr.CreatedAt, &rr.UpdatedAt}
		switch list {
		case rules.ListIP:
			dest = append(dest, &rr.prefix, &rr.action)
		case rules.ListPrefix:
			dest = append(dest, &rr.minV4, &rr.minV6)
		case rules.ListTTL:
			dest = append(dest, &rr.maxTTL)
		case rules.ListCap:
			dest = append(dest, &rr.maxPrefixes)
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		out = append(out, rr)
	}
	return out, rows.Err()
}

func shadowWarnings(rows []ruleRow) []rules.Warning {
	items := make([]rules.Item, len(rows))
	for i := range rows {
		items[i] = rows[i].item()
	}
	return rules.ShadowWarnings(items)
}

// ruleTarget validates the {realm} and {list} path values.
func ruleTarget(ctx context.Context, q db.Querier, r *http.Request) (realm, list string, err error) {
	realm, list = r.PathValue("realm"), r.PathValue("list")
	if _, ok := ruleTables[list]; !ok {
		return "", "", errNotFound
	}
	if _, err := getRealmView(ctx, q, realm); err != nil {
		return "", "", err
	}
	return realm, list, nil
}

func (s *Server) listRules(w http.ResponseWriter, r *http.Request, _ *auth.Principal) error {
	if err := checkQuery(r, "limit", "cursor"); err != nil {
		return err
	}
	ctx := r.Context()
	realm, list, err := ruleTarget(ctx, s.Pool, r)
	if err != nil {
		return err
	}
	page, err := parsePage(r)
	if err != nil {
		return err
	}
	var c struct {
		P int `json:"p"`
	}
	if _, err := page.cursorInto(&c); err != nil {
		return err
	}
	rows, err := loadRuleRows(ctx, s.Pool, list, realm)
	if err != nil {
		return err
	}
	resp := listResponse[map[string]any]{Items: []map[string]any{}}
	for i := range rows {
		if rows[i].Position <= c.P {
			continue
		}
		if len(resp.Items) == page.limit {
			resp.NextCursor = encodeCursor(map[string]int{"p": rows[i-1].Position})
			break
		}
		resp.Items = append(resp.Items, rows[i].view())
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

// parseRuleFields applies body fields to rr. On create, required fields must be present.
func parseRuleFields(r *http.Request, list string, rr *ruleRow, create bool) (position *int, err error) {
	allowed := append([]string{"user", "group", "position", "description"}, ruleFields[list]...)
	m, err := decodeObject(r, allowed...)
	if err != nil {
		return nil, err
	}
	fe := fieldErrors{}
	if v, ok := rawSelector(fe, m, "user", create); ok {
		rr.User = v
	}
	if v, ok := rawSelector(fe, m, "group", create); ok {
		rr.Group = v
	}
	if raw, ok := m["position"]; ok {
		var n int
		if err := json.Unmarshal(raw, &n); err != nil || n < 1 {
			fe.add("position", "must be a positive integer")
		} else {
			position = &n
		}
	}
	if raw, ok := m["description"]; ok {
		if isNull(raw) {
			rr.Description = nil
		} else {
			var d string
			if err := json.Unmarshal(raw, &d); err != nil || utf8.RuneCountInString(d) > 1000 {
				fe.add("description", "must be null or a string of at most 1000 characters")
			} else {
				rr.Description = &d
			}
		}
	}
	required := func(key string) bool {
		if _, ok := m[key]; !ok {
			if create {
				fe.add(key, "required")
			}
			return false
		}
		return true
	}
	switch list {
	case rules.ListIP:
		if required("prefix") {
			if v, ok := rawString(fe, m, "prefix"); ok {
				p, err := rules.NormalizePrefix(v)
				if err != nil {
					fe.add("prefix", "invalid prefix")
				}
				rr.prefix = p
			}
		}
		if required("action") {
			if v, ok := rawString(fe, m, "action"); ok {
				if v != rules.ActionAccept && v != rules.ActionDeny {
					fe.add("action", "must be accept or deny")
				}
				rr.action = v
			}
		}
	case rules.ListPrefix:
		for _, f := range []struct {
			key string
			max int
			dst **int
		}{{"min_len_v4", 32, &rr.minV4}, {"min_len_v6", 128, &rr.minV6}} {
			raw, ok := m[f.key]
			if !ok {
				continue
			}
			if isNull(raw) {
				*f.dst = nil
				continue
			}
			var n int
			if err := json.Unmarshal(raw, &n); err != nil || n < 0 || n > f.max {
				fe.add(f.key, fmt.Sprintf("must be null or an integer from 0 to %d", f.max))
				continue
			}
			*f.dst = &n
		}
	case rules.ListTTL:
		if required("max_ttl") {
			if v, ok := rawString(fe, m, "max_ttl"); ok {
				t, err := rules.ParseTTL(v)
				if err != nil {
					fe.add("max_ttl", err.Error())
				} else if t.Unlimited {
					rr.maxTTL = nil
				} else {
					rr.maxTTL = &t.Seconds
				}
			}
		}
	case rules.ListCap:
		if required("max_prefixes") {
			var n int
			if err := json.Unmarshal(m["max_prefixes"], &n); err != nil || n < 0 || n > 1<<30 {
				fe.add("max_prefixes", "must be a non-negative integer")
			}
			rr.maxPrefixes = n
		}
	}
	return position, fe.err()
}

func insertRule(ctx context.Context, tx pgx.Tx, rr *ruleRow) (string, error) {
	var (
		cols string
		args = []any{rr.Realm, rr.User, rr.Group, rr.Position, rr.Description}
	)
	switch rr.list {
	case rules.ListIP:
		cols, args = "prefix, action", append(args, rr.prefix, rr.action)
	case rules.ListPrefix:
		cols, args = "min_len_v4, min_len_v6", append(args, rr.minV4, rr.minV6)
	case rules.ListTTL:
		cols, args = "max_ttl_seconds", append(args, rr.maxTTL)
	case rules.ListCap:
		cols, args = "max_prefixes", append(args, rr.maxPrefixes)
	}
	ph := ""
	for i := 6; i <= len(args); i++ {
		ph += fmt.Sprintf(", $%d", i)
	}
	var id string
	err := tx.QueryRow(ctx, `INSERT INTO `+ruleTables[rr.list]+` (realm, username, grp, position, description, `+cols+`)
		VALUES ($1, $2, $3, $4, $5`+ph+`) RETURNING id::text`, args...).Scan(&id)
	return id, err
}

func updateRule(ctx context.Context, tx pgx.Tx, rr *ruleRow) error {
	var (
		set  string
		args = []any{rr.ID, rr.User, rr.Group, rr.Description}
	)
	switch rr.list {
	case rules.ListIP:
		set, args = "prefix = $5, action = $6", append(args, rr.prefix, rr.action)
	case rules.ListPrefix:
		set, args = "min_len_v4 = $5, min_len_v6 = $6", append(args, rr.minV4, rr.minV6)
	case rules.ListTTL:
		set, args = "max_ttl_seconds = $5", append(args, rr.maxTTL)
	case rules.ListCap:
		set, args = "max_prefixes = $5", append(args, rr.maxPrefixes)
	}
	_, err := tx.Exec(ctx, `UPDATE `+ruleTables[rr.list]+` SET username = $2, grp = $3, description = $4, `+set+`,
		updated_at = now() WHERE id = $1`, args...)
	return err
}

// writeOrder sets positions 1..n in the given id order; the deferred unique
// constraint allows the intermediate duplicates.
func writeOrder(ctx context.Context, tx pgx.Tx, list string, rows []ruleRow, order []string) error {
	cur := map[string]int{}
	for _, r := range rows {
		cur[r.ID] = r.Position
	}
	for i, id := range order {
		if cur[id] == i+1 {
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE `+ruleTables[list]+` SET position = $2, updated_at = now() WHERE id = $1`,
			id, i+1); err != nil {
			return err
		}
	}
	return nil
}

func findRule(rows []ruleRow, id string) int {
	for i := range rows {
		if rows[i].ID == id {
			return i
		}
	}
	return -1
}

func ids(rows []ruleRow) []string {
	out := make([]string, len(rows))
	for i := range rows {
		out[i] = rows[i].ID
	}
	return out
}

func (s *Server) auditRule(ctx context.Context, tx pgx.Tx, p *auth.Principal, action string, rr *ruleRow, details map[string]any) error {
	if details == nil {
		details = map[string]any{}
	}
	details["list"] = rr.list
	return db.InsertAudit(ctx, tx, db.Audit{Actor: p.Actor, Action: action, ObjectType: "rule", ObjectID: rr.ID,
		Realm: &rr.Realm, User: rr.User, Group: rr.Group, Details: details})
}

func (s *Server) createRule(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	ctx := r.Context()
	realm, list, err := ruleTarget(ctx, s.Pool, r)
	if err != nil {
		return err
	}
	rr := ruleRow{list: list, Base: rules.Base{Realm: realm}}
	pos, err := parseRuleFields(r, list, &rr, true)
	if err != nil {
		return err
	}
	return s.withImpact(w, r, p, impactScope{realm: realm}, func(ctx context.Context, tx pgx.Tx, _ *db.Revision) (*mutation, error) {
		rows, err := loadRuleRows(ctx, tx, list, realm)
		if err != nil {
			return nil, err
		}
		items := make([]rules.Item, len(rows))
		for i := range rows {
			items[i] = rows[i].item()
		}
		rr.Position = rules.DefaultInsertPosition(items)
		if pos != nil {
			if *pos > len(rows)+1 {
				return nil, invalid("position", fmt.Sprintf("must be from 1 to %d", len(rows)+1))
			}
			rr.Position = *pos
		}
		if _, err := tx.Exec(ctx, `UPDATE `+ruleTables[list]+` SET position = position + 1
			WHERE realm = $1 AND position >= $2`, realm, rr.Position); err != nil {
			return nil, err
		}
		id, err := insertRule(ctx, tx, &rr)
		if db.IsForeignKeyViolation(err) {
			return nil, errNotFound
		}
		if err != nil {
			return nil, err
		}
		rows, err = loadRuleRows(ctx, tx, list, realm)
		if err != nil {
			return nil, err
		}
		created := rows[findRule(rows, id)]
		if err := s.auditRule(ctx, tx, p, "rule.create", &created, map[string]any{"rule": created.view()}); err != nil {
			return nil, err
		}
		return &mutation{status: http.StatusCreated, object: created.view(), warnings: shadowWarnings(rows)}, nil
	})
}

func (s *Server) patchRule(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	ctx := r.Context()
	realm, list, err := ruleTarget(ctx, s.Pool, r)
	if err != nil {
		return err
	}
	id := r.PathValue("id")
	if !validUUID(id) {
		return errNotFound
	}
	rows, err := loadRuleRows(ctx, s.Pool, list, realm)
	if err != nil {
		return err
	}
	i := findRule(rows, id)
	if i < 0 {
		return errNotFound
	}
	rr := rows[i]
	pos, err := parseRuleFields(r, list, &rr, false)
	if err != nil {
		return err
	}
	return s.withImpact(w, r, p, impactScope{realm: realm}, func(ctx context.Context, tx pgx.Tx, _ *db.Revision) (*mutation, error) {
		rows, err := loadRuleRows(ctx, tx, list, realm)
		if err != nil {
			return nil, err
		}
		i := findRule(rows, id)
		if i < 0 {
			return nil, errNotFound
		}
		before := rows[i].view()
		if err := updateRule(ctx, tx, &rr); err != nil {
			return nil, err
		}
		if pos != nil && *pos != rows[i].Position {
			if *pos > len(rows) {
				return nil, invalid("position", fmt.Sprintf("must be from 1 to %d", len(rows)))
			}
			order := ids(rows)
			order = slices.Delete(order, i, i+1)
			order = slices.Insert(order, *pos-1, id)
			if err := writeOrder(ctx, tx, list, rows, order); err != nil {
				return nil, err
			}
		}
		if rows, err = loadRuleRows(ctx, tx, list, realm); err != nil {
			return nil, err
		}
		updated := rows[findRule(rows, id)]
		if err := s.auditRule(ctx, tx, p, "rule.update", &updated, map[string]any{"before": before, "after": updated.view()}); err != nil {
			return nil, err
		}
		return &mutation{status: http.StatusOK, object: updated.view(), warnings: shadowWarnings(rows)}, nil
	})
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	ctx := r.Context()
	realm, list, err := ruleTarget(ctx, s.Pool, r)
	if err != nil {
		return err
	}
	id := r.PathValue("id")
	if !validUUID(id) {
		return errNotFound
	}
	return s.withImpact(w, r, p, impactScope{realm: realm}, func(ctx context.Context, tx pgx.Tx, _ *db.Revision) (*mutation, error) {
		rows, err := loadRuleRows(ctx, tx, list, realm)
		if err != nil {
			return nil, err
		}
		i := findRule(rows, id)
		if i < 0 {
			return nil, errNotFound
		}
		deleted := rows[i]
		if _, err := tx.Exec(ctx, `DELETE FROM `+ruleTables[list]+` WHERE id = $1`, id); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `UPDATE `+ruleTables[list]+` SET position = position - 1
			WHERE realm = $1 AND position > $2`, realm, deleted.Position); err != nil {
			return nil, err
		}
		if err := s.auditRule(ctx, tx, p, "rule.delete", &deleted, map[string]any{"rule": deleted.view()}); err != nil {
			return nil, err
		}
		rest, err := loadRuleRows(ctx, tx, list, realm)
		if err != nil {
			return nil, err
		}
		return &mutation{status: http.StatusOK, object: deleted.view(), warnings: shadowWarnings(rest)}, nil
	})
}

func (s *Server) reorderRules(w http.ResponseWriter, r *http.Request, p *auth.Principal) error {
	ctx := r.Context()
	realm, list, err := ruleTarget(ctx, s.Pool, r)
	if err != nil {
		return err
	}
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := decodeJSON(r, &req); err != nil {
		return err
	}
	if req.IDs == nil {
		return invalid("ids", "required")
	}
	return s.withImpact(w, r, p, impactScope{realm: realm}, func(ctx context.Context, tx pgx.Tx, _ *db.Revision) (*mutation, error) {
		rows, err := loadRuleRows(ctx, tx, list, realm)
		if err != nil {
			return nil, err
		}
		have := map[string]bool{}
		for _, r := range rows {
			have[r.ID] = true
		}
		seen := map[string]bool{}
		for _, id := range req.IDs {
			if !have[id] || seen[id] {
				return nil, invalid("ids", "must list every rule in the list exactly once")
			}
			seen[id] = true
		}
		if len(req.IDs) != len(rows) {
			return nil, invalid("ids", "must list every rule in the list exactly once")
		}
		if err := writeOrder(ctx, tx, list, rows, req.IDs); err != nil {
			return nil, err
		}
		after, err := loadRuleRows(ctx, tx, list, realm)
		if err != nil {
			return nil, err
		}
		items := make([]map[string]any, len(after))
		for i := range after {
			items[i] = after[i].view()
		}
		if err := db.InsertAudit(ctx, tx, db.Audit{Actor: p.Actor, Action: "rule.reorder", ObjectType: "rule_list",
			ObjectID: list, Realm: &realm, Details: map[string]any{"list": list, "before": ids(rows), "after": req.IDs}}); err != nil {
			return nil, err
		}
		return &mutation{status: http.StatusOK, object: map[string]any{"items": items}, warnings: shadowWarnings(after)}, nil
	})
}

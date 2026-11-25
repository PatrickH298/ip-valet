package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/PatrickH298/ip-valet/api/internal/auth"
	"github.com/PatrickH298/ip-valet/api/internal/rules"
)

// apiError is an error response.
type apiError struct {
	Status  int
	Code    string
	Message string
	Fields  map[string]string
	Results []groupResult
	Impact  []impactItem
}

func (e *apiError) Error() string { return e.Message }

var (
	errNotFound = &apiError{Status: http.StatusNotFound, Code: "not_found", Message: "not found"}
	errConflict = &apiError{Status: http.StatusConflict, Code: "conflict", Message: "a resource with that name already exists"}
)

// invalid returns a 400 for one field.
func invalid(field, msg string) *apiError {
	return &apiError{Status: http.StatusBadRequest, Code: "invalid_request",
		Message: field + ": " + msg, Fields: map[string]string{field: msg}}
}

// fieldErrors collects per-field validation errors.
type fieldErrors map[string]string

func (f fieldErrors) add(field, msg string) {
	if _, ok := f[field]; !ok {
		f[field] = msg
	}
}

func (f fieldErrors) err() error {
	if len(f) == 0 {
		return nil
	}
	keys := make([]string, 0, len(f))
	for k := range f {
		keys = append(keys, k)
	}
	// Deterministic message: first field alphabetically.
	first := keys[0]
	for _, k := range keys {
		if k < first {
			first = k
		}
	}
	return &apiError{Status: http.StatusBadRequest, Code: "invalid_request",
		Message: first + ": " + f[first], Fields: map[string]string(f)}
}

type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Fields  map[string]string `json:"fields,omitempty"`
	Results []groupResult     `json:"results,omitempty"`
	Impact  []impactItem      `json:"impact,omitempty"`
}

// isUnavailable reports errors that mean the database cannot be reached.
func isUnavailable(err error) bool {
	var ce *pgconn.ConnectError
	var ne net.Error
	if errors.As(err, &ce) || errors.As(err, &ne) || pgconn.Timeout(err) ||
		errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	// Postgres's own reports that it cannot serve us right now: a pooled
	// connection it terminated (57P01 admin_shutdown and the rest of class 57),
	// a lost connection (class 08), too many clients or no resources (class
	// 53), or the database no longer existing (3D000).
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		switch {
		case strings.HasPrefix(pe.Code, "57"), strings.HasPrefix(pe.Code, "08"),
			strings.HasPrefix(pe.Code, "53"), pe.Code == "3D000":
			return true
		}
	}
	return false
}

func (s *Server) writeErr(w http.ResponseWriter, r *http.Request, err error) {
	var (
		ae  *apiError
		au  *auth.Error
		mbe *http.MaxBytesError
	)
	switch {
	case errors.As(err, &ae):
	case errors.As(err, &au):
		ae = &apiError{Status: au.Status, Code: au.Code, Message: au.Message}
		if au.Status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", "Bearer")
		}
		if au.RetryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(au.RetryAfter))
		}
	case errors.As(err, &mbe):
		ae = &apiError{Status: http.StatusRequestEntityTooLarge, Code: "body_too_large",
			Message: fmt.Sprintf("request body exceeds %d bytes", s.Config.MaxBodyBytes)}
	case r.Context().Err() != nil && errors.Is(err, r.Context().Err()):
		// Client went away; nothing useful to send.
		return
	case isUnavailable(err):
		id := ""
		if info := reqInfoFrom(r.Context()); info != nil {
			id = info.id
		}
		s.Log.Error("database unavailable", "request_id", id, "error", err.Error())
		ae = &apiError{Status: http.StatusServiceUnavailable, Code: "unavailable", Message: "the database is unavailable"}
	default:
		id := ""
		if info := reqInfoFrom(r.Context()); info != nil {
			id = info.id
		}
		s.Log.Error("internal error", "request_id", id, "method", r.Method, "route", r.Pattern, "error", err.Error())
		ae = &apiError{Status: http.StatusInternalServerError, Code: "internal", Message: "internal error"}
	}
	writeJSON(w, ae.Status, errorBody{Error: errorDetail{Code: ae.Code, Message: ae.Message,
		Fields: ae.Fields, Results: ae.Results, Impact: ae.Impact}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		http.Error(w, `{"error":{"code":"internal","message":"internal error"}}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// decodeJSON decodes exactly one JSON object, rejecting unknown fields.
func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return jsonError(err)
	}
	if _, err := dec.Token(); err != io.EOF {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return err
		}
		return &apiError{Status: http.StatusBadRequest, Code: "invalid_request", Message: "body must hold a single JSON object"}
	}
	return nil
}

func jsonError(err error) error {
	var (
		mbe *http.MaxBytesError
		ute *json.UnmarshalTypeError
		se  *json.SyntaxError
	)
	switch {
	case errors.As(err, &mbe):
		return err
	case errors.Is(err, io.EOF):
		return &apiError{Status: http.StatusBadRequest, Code: "invalid_request", Message: "a JSON body is required"}
	case errors.As(err, &ute):
		field := ute.Field
		if field == "" {
			return &apiError{Status: http.StatusBadRequest, Code: "invalid_request", Message: "body must be a JSON object"}
		}
		return invalid(field, "has the wrong type")
	case errors.As(err, &se):
		return &apiError{Status: http.StatusBadRequest, Code: "invalid_request", Message: "malformed JSON"}
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		name := strings.Trim(strings.TrimPrefix(err.Error(), "json: unknown field "), `"`)
		return invalid(name, "unknown field")
	}
	return &apiError{Status: http.StatusBadRequest, Code: "invalid_request", Message: "malformed JSON"}
}

// decodeObject decodes a JSON object into raw fields, for PATCH bodies and
// bodies whose shape depends on a path parameter. Keys not in allowed → 400.
func decodeObject(r *http.Request, allowed ...string) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&m); err != nil {
		return nil, jsonError(err)
	}
	if _, err := dec.Token(); err != io.EOF {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, err
		}
		return nil, &apiError{Status: http.StatusBadRequest, Code: "invalid_request", Message: "body must hold a single JSON object"}
	}
	if m == nil {
		return nil, &apiError{Status: http.StatusBadRequest, Code: "invalid_request", Message: "body must be a JSON object"}
	}
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	for k := range m {
		if !ok[k] {
			return nil, invalid(k, "unknown field")
		}
	}
	return m, nil
}

func isNull(raw json.RawMessage) bool { return string(bytes.TrimSpace(raw)) == "null" }

// --- field parsers for raw objects ---

func rawString(fe fieldErrors, m map[string]json.RawMessage, key string) (string, bool) {
	raw, ok := m[key]
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		fe.add(key, "must be a string")
		return "", false
	}
	return s, true
}

func rawSelector(fe fieldErrors, m map[string]json.RawMessage, key string, required bool) (*string, bool) {
	s, ok := rawString(fe, m, key)
	if !ok {
		if _, present := m[key]; !present && required {
			fe.add(key, `required ("*" or a name)`)
		}
		return nil, false
	}
	v, err := rules.ParseIdentSelector(s)
	if err != nil {
		fe.add(key, err.Error())
		return nil, false
	}
	return v, true
}

// --- uuids, timestamps, pagination ---

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func validUUID(s string) bool { return uuidPattern.MatchString(s) }

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func tsPtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := ts(*t)
	return &s
}

type listResponse[T any] struct {
	Items      []T     `json:"items"`
	NextCursor *string `json:"next_cursor"`
}

type pageParams struct {
	limit  int
	cursor json.RawMessage // decoded cursor, nil on the first page
}

func parsePage(r *http.Request) (pageParams, error) {
	p := pageParams{limit: 100}
	q := r.URL.Query()
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			return p, invalid("limit", "must be an integer from 1 to 1000")
		}
		p.limit = n
	}
	if v := q.Get("cursor"); v != "" {
		b, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil || !json.Valid(b) {
			return p, invalid("cursor", "invalid cursor")
		}
		p.cursor = b
	}
	return p, nil
}

// cursorInto decodes the page cursor into v; false on the first page.
func (p pageParams) cursorInto(v any) (bool, error) {
	if p.cursor == nil {
		return false, nil
	}
	if err := json.Unmarshal(p.cursor, v); err != nil {
		return false, invalid("cursor", "invalid cursor")
	}
	return true, nil
}

func encodeCursor(v any) *string {
	b, _ := json.Marshal(v)
	s := base64.RawURLEncoding.EncodeToString(b)
	return &s
}

func queryBool(r *http.Request, name string) (bool, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, invalid(name, "must be true or false")
	}
	return b, nil
}

func queryTime(r *http.Request, name string) (*time.Time, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return nil, invalid(name, "must be an RFC 3339 timestamp")
	}
	return &t, nil
}

// checkQuery rejects unknown query parameters.
func checkQuery(r *http.Request, allowed ...string) error {
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	for k := range r.URL.Query() {
		if !ok[k] {
			return invalid(k, "unknown query parameter")
		}
	}
	return nil
}

// Package api is a client for the ip-valet admin API (spec/openapi.yaml).
// Every call carries the dashboard's admin key and, when ctx names one, the
// person it acts for in IPValet-On-Behalf-Of.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Admin calls one API server's admin listener.
type Admin struct {
	base *url.URL
	key  string
	http *http.Client
}

// New returns a client for the admin listener at base, authenticating with key.
func New(base *url.URL, key string, timeout time.Duration) *Admin {
	return &Admin{base: base, key: key, http: &http.Client{
		Timeout: timeout,
		// The admin API never redirects; refuse to follow one with the key.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

type ctxKey struct{}

// OnBehalfOf returns ctx carrying the person API calls act for.
func OnBehalfOf(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, ctxKey{}, name)
}

// Error is an error response from the API server, or a failure to reach it.
type Error struct {
	Status    int // 0 when the server could not be reached
	Code      string
	Message   string
	Fields    map[string]string
	Impact    []ImpactItem
	Results   []GroupResult // with submission_rejected: one per group
	RequestID string
	Err       error // the transport error, when Status is 0
}

func (e *Error) Error() string {
	if e.Status == 0 {
		return "the API server could not be reached: " + e.Err.Error()
	}
	return fmt.Sprintf("API %d %s: %s", e.Status, e.Code, e.Message)
}

func (e *Error) Unwrap() error { return e.Err }

// IsCode reports whether err is an API error with the given code.
func IsCode(err error, code string) bool {
	var ae *Error
	return errors.As(err, &ae) && ae.Code == code
}

// IsNotFound reports whether err is a 404.
func IsNotFound(err error) bool {
	var ae *Error
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

type errorBody struct {
	Error struct {
		Code    string            `json:"code"`
		Message string            `json:"message"`
		Fields  map[string]string `json:"fields"`
		Impact  []ImpactItem      `json:"impact"`
		Results []GroupResult     `json:"results"`
	} `json:"error"`
}

// maxResponse bounds how much of a response is read: the largest admin page
// (1000 entries with their workers) is well under this.
const maxResponse = 32 << 20

// do sends one request. body, when not nil, is sent as JSON; out, when not
// nil, receives the JSON response.
func (c *Admin) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	u := *c.base
	u.Path = strings.TrimSuffix(c.base.Path, "/") + path
	u.RawQuery = query.Encode()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if name, ok := ctx.Value(ctxKey{}).(string); ok && name != "" {
		req.Header.Set("IPValet-On-Behalf-Of", name)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return &Error{Err: err}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return &Error{Err: err}
	}
	if resp.StatusCode >= 300 {
		e := &Error{Status: resp.StatusCode, RequestID: resp.Header.Get("X-Request-Id")}
		var eb errorBody
		if json.Unmarshal(raw, &eb) == nil && eb.Error.Code != "" {
			e.Code, e.Message, e.Fields, e.Impact = eb.Error.Code, eb.Error.Message, eb.Error.Fields, eb.Error.Impact
			e.Results = eb.Error.Results
		} else {
			e.Code, e.Message = "unexpected_response", http.StatusText(resp.StatusCode)
		}
		return e
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decoding %s %s: %w", method, path, err)
	}
	return nil
}

// Ready reports whether the API server is ready (GET /readyz).
func (c *Admin) Ready(ctx context.Context) error {
	u := *c.base
	u.Path = strings.TrimSuffix(c.base.Path, "/") + "/readyz"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return &Error{Err: err}
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &Error{Status: resp.StatusCode, Code: "not_ready", Message: "the API server is not ready"}
	}
	return nil
}

// Page is one page of a list.
type Page[T any] struct {
	Items      []T     `json:"items"`
	NextCursor *string `json:"next_cursor"`
}

// listAll follows cursors to collect a whole list, for lists that are small
// by nature (realms, rules, workers, clients, subscriptions). It stops after
// maxPages pages of 1000.
func listAll[T any](ctx context.Context, c *Admin, path string, query url.Values) ([]T, error) {
	const maxPages = 20
	if query == nil {
		query = url.Values{}
	}
	query.Set("limit", "1000")
	var all []T
	for range maxPages {
		var p Page[T]
		if err := c.do(ctx, http.MethodGet, path, query, nil, &p); err != nil {
			return nil, err
		}
		all = append(all, p.Items...)
		if p.NextCursor == nil {
			return all, nil
		}
		query.Set("cursor", *p.NextCursor)
	}
	return all, nil
}

// pathEscape escapes one path segment.
func pathEscape(s string) string { return url.PathEscape(s) }

// Impact selects how an impact-checked change is sent.
type Impact int

const (
	// Plain sends the change; one that affects entries is 409
	// confirmation_required with the impact in the error.
	Plain Impact = iota
	// DryRun applies and rolls back the change, returning its impact.
	DryRun
	// Confirm saves the change and its action on every affected entry.
	Confirm
)

func (i Impact) query() url.Values {
	q := url.Values{}
	switch i {
	case DryRun:
		q.Set("dry_run", "true")
	case Confirm:
		q.Set("confirm", "true")
	}
	return q
}

// PageQuery is a page request: limit and the previous page's cursor.
type PageQuery struct {
	Limit  int
	Cursor string
}

func (p PageQuery) apply(q url.Values) url.Values {
	if p.Limit > 0 {
		q.Set("limit", strconv.Itoa(p.Limit))
	}
	if p.Cursor != "" {
		q.Set("cursor", p.Cursor)
	}
	return q
}

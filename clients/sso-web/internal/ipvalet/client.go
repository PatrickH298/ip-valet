// Package ipvalet is a client for the ip-valet API's client endpoints
// (spec/openapi.yaml): submissions, a user's entries and deleting them.
// Every call carries the site's client key.
package ipvalet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client calls one API server's main listener.
type Client struct {
	base *url.URL
	key  string
	http *http.Client
}

// New returns a client for the API at base, authenticating with key.
func New(base *url.URL, key string, timeout time.Duration) *Client {
	return &Client{base: base, key: key, http: &http.Client{
		Timeout: timeout,
		// The API never redirects; refuse to follow one with the key.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// Limit is the limit a rejected group ran into.
type Limit struct {
	MaxTTL       string `json:"max_ttl,omitempty"`
	MinPrefixLen *int   `json:"min_prefix_len,omitempty"`
	MaxPrefixes  *int   `json:"max_prefixes,omitempty"`
}

// GroupResult is one group's outcome in a rejected submission.
type GroupResult struct {
	Group string `json:"group"`
	OK    bool   `json:"ok"`
	Code  string `json:"code,omitempty"`
	Limit *Limit `json:"limit,omitempty"`
}

// Error is an error response from the API server, or a failure to reach it.
type Error struct {
	Status    int // 0 when the server could not be reached
	Code      string
	Message   string
	Fields    map[string]string
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

// AsError returns err as an API error, if it is one.
func AsError(err error) (*Error, bool) {
	var ae *Error
	ok := errors.As(err, &ae)
	return ae, ok
}

type errorBody struct {
	Error struct {
		Code    string            `json:"code"`
		Message string            `json:"message"`
		Fields  map[string]string `json:"fields"`
		Results []GroupResult     `json:"results"`
	} `json:"error"`
}

const maxResponse = 16 << 20

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
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
			e.Code, e.Message, e.Fields, e.Results = eb.Error.Code, eb.Error.Message, eb.Error.Fields, eb.Error.Results
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
func (c *Client) Ready(ctx context.Context) error {
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

// Submission asks for one prefix for one user in groups of a realm.
type Submission struct {
	Realm  string   `json:"realm"`
	User   string   `json:"user"`
	Groups []string `json:"groups"`
	Prefix string   `json:"prefix"`
	TTL    string   `json:"ttl"`
}

// WorkerState is an entry's state on one worker, as clients see it.
type WorkerState struct {
	Label string `json:"label"`
	State string `json:"state"`
	Code  string `json:"code,omitempty"`
}

// Entry is an entry as clients see it.
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
	Replaced     bool          `json:"replaced"`
}

// Submitted is a successful submission.
type Submitted struct {
	SubmissionID string  `json:"submission_id"`
	Prefix       string  `json:"prefix"`
	Entries      []Entry `json:"entries"`
}

// Submit sends a submission (POST /v1/submissions).
func (c *Client) Submit(ctx context.Context, s Submission) (Submitted, error) {
	var out Submitted
	err := c.do(ctx, http.MethodPost, "/v1/submissions", nil, s, &out)
	return out, err
}

type page struct {
	Items      []Entry `json:"items"`
	NextCursor *string `json:"next_cursor"`
}

// maxPages bounds how many pages of 1000 entries are read for one user.
const maxPages = 5

// Entries lists a user's live entries in a realm (GET /v1/entries), or
// only those for prefix when it is not empty.
func (c *Client) Entries(ctx context.Context, realm, user, prefix string) ([]Entry, error) {
	q := url.Values{"realm": {realm}, "user": {user}, "limit": {"1000"}}
	if prefix != "" {
		q.Set("prefix", prefix)
	}
	var all []Entry
	for range maxPages {
		var p page
		if err := c.do(ctx, http.MethodGet, "/v1/entries", q, nil, &p); err != nil {
			return nil, err
		}
		all = append(all, p.Items...)
		if p.NextCursor == nil {
			break
		}
		q.Set("cursor", *p.NextCursor)
	}
	return all, nil
}

// DeleteEntry deletes an entry (DELETE /v1/entries/{id}).
func (c *Client) DeleteEntry(ctx context.Context, id string) (Entry, error) {
	var out Entry
	err := c.do(ctx, http.MethodDelete, "/v1/entries/"+url.PathEscape(id), nil, nil, &out)
	return out, err
}

// CheckRealm reports whether the key may list entries in realm: nil, or an
// *Error such as 403 realm_not_allowed or 401 for a refused key.
func (c *Client) CheckRealm(ctx context.Context, realm string) error {
	return c.do(ctx, http.MethodGet, "/v1/entries", url.Values{"realm": {realm}, "limit": {"1"}}, nil, &page{})
}

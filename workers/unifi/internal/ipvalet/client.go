// Package ipvalet is a client for the ip-valet worker API: desired state,
// the change-signal stream and status reports.
package ipvalet

import (
	"bufio"
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

// Client calls one API server with one worker key.
type Client struct {
	base   *url.URL
	key    string
	http   *http.Client // bounded requests
	stream *http.Client // the event stream: no overall timeout
}

// New returns a client for the API's main listener at base.
func New(base *url.URL, key string, timeout time.Duration) *Client {
	noRedirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{base: base, key: key,
		http:   &http.Client{Timeout: timeout, CheckRedirect: noRedirect},
		stream: &http.Client{CheckRedirect: noRedirect}}
}

// Entry is one desired-state entry.
type Entry struct {
	Prefix    string     `json:"prefix"`
	ExpiresAt *time.Time `json:"expires_at"`
	Realm     string     `json:"realm"`
	User      string     `json:"user"`
	Group     string     `json:"group"`
}

// DesiredState is the worker's desired state.
type DesiredState struct {
	Revision     int64      `json:"revision"`
	GeneratedAt  string     `json:"generated_at"`
	NextChangeAt *time.Time `json:"next_change_at"`
	Families     []string   `json:"families"`
	Entries      []Entry    `json:"entries"`
}

// Fetched is the result of a desired-state request.
type Fetched struct {
	State       *DesiredState // nil when NotModified
	NotModified bool
	ETag        string
	Revision    int64  // from IPValet-Revision
	GeneratedAt string // from IPValet-Generated-At
}

// StatusError is an HTTP error from the API.
type StatusError struct {
	Status int
	Body   string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("the API answered %d: %s", e.Status, e.Body)
}

// Permanent reports whether retrying cannot help without a configuration
// change: the key was refused, or the worker is gone.
func (e *StatusError) Permanent() bool {
	return e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden || e.Status == http.StatusNotFound
}

func (c *Client) url(path string) string {
	u := *c.base
	u.Path = strings.TrimSuffix(c.base.Path, "/") + path
	return u.String()
}

func (c *Client) request(ctx context.Context, method, path string, body any) (*http.Request, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.url(path), rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func statusError(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return &StatusError{Status: resp.StatusCode, Body: strings.TrimSpace(string(b))}
}

// Desired fetches desired state; etag, when set, asks for 304 if unchanged.
func (c *Client) Desired(ctx context.Context, etag string) (Fetched, error) {
	req, err := c.request(ctx, http.MethodGet, "/v1/worker/desired-state", nil)
	if err != nil {
		return Fetched{}, err
	}
	req.Header.Set("Accept", "application/json")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Fetched{}, err
	}
	defer resp.Body.Close()
	f := Fetched{ETag: resp.Header.Get("ETag"), GeneratedAt: resp.Header.Get("IPValet-Generated-At")}
	f.Revision, _ = strconv.ParseInt(resp.Header.Get("IPValet-Revision"), 10, 64)
	switch resp.StatusCode {
	case http.StatusNotModified:
		f.NotModified = true
		if f.ETag == "" {
			f.ETag = etag
		}
		return f, nil
	case http.StatusOK:
	default:
		return f, statusError(resp)
	}
	var ds DesiredState
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&ds); err != nil {
		return f, fmt.Errorf("decoding desired state: %w", err)
	}
	f.State = &ds
	f.Revision, f.GeneratedAt = ds.Revision, ds.GeneratedAt
	return f, nil
}

// Rejection is a prefix the worker did not apply.
type Rejection struct {
	Prefix string `json:"prefix"`
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
}

// Report is a status report: GeneratedAt on success, Error on failure.
type Report struct {
	Instance    string      `json:"instance"`
	Version     string      `json:"version,omitempty"`
	Revision    int64       `json:"revision"`
	GeneratedAt string      `json:"generated_at,omitempty"`
	Rejected    []Rejection `json:"rejected,omitempty"`
	Error       string      `json:"error,omitempty"`
}

// MaxRejections is the most rejections one report may carry.
const MaxRejections = 200

// Report sends a status report.
func (c *Client) Report(ctx context.Context, r Report) error {
	req, err := c.request(ctx, http.MethodPost, "/v1/worker/status", r)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return statusError(resp)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// Events holds the change-signal stream open and calls changed for every
// "changed" event (one arrives on every connect). It returns when the stream
// ends or ctx is done.
func (c *Client) Events(ctx context.Context, changed func(revision int64)) error {
	req, err := c.request(ctx, http.MethodGet, "/v1/worker/events", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := c.stream.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return statusError(resp)
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var event, id string
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if event == "changed" {
				rev, _ := strconv.ParseInt(id, 10, 64)
				changed(rev)
			}
			event, id = "", ""
		case strings.HasPrefix(line, ":"):
			// a keep-alive comment
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "id:"):
			id = strings.TrimSpace(strings.TrimPrefix(line, "id:"))
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return io.EOF
}

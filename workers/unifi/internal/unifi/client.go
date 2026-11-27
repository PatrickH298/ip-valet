// Package unifi is a minimal client for the UniFi Network integration API:
// sites and traffic matching lists. The same API is served locally
// (https://<console>/proxy/network/integration) and through the cloud
// connector (https://api.ui.com/v1/connector/consoles/<id>/proxy/network/integration);
// only the base URL differs. Requests authenticate with X-API-KEY.
//
// The API key reaches every endpoint of the Network API, not only lists, so
// it belongs to this worker alone.
package unifi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// List types.
const (
	TypeIPv4 = "IPV4_ADDRESSES"
	TypeIPv6 = "IPV6_ADDRESSES"
)

// Client calls one UniFi Network application.
type Client struct {
	base     *url.URL
	key      string
	http     *http.Client
	log      *slog.Logger
	attempts int
	sleep    func(context.Context, time.Duration) error
	// Backoff is the wait before retry attempt n (1-based), when the
	// controller gives no Retry-After. Tests shorten it.
	Backoff func(n int) time.Duration
}

func defaultBackoff(n int) time.Duration {
	return time.Duration(1<<n)*time.Second + time.Duration(rand.Int64N(int64(500*time.Millisecond)))
}

// New returns a client. verifyTLS false accepts a local console's
// self-signed certificate.
func New(base *url.URL, key string, verifyTLS bool, timeout time.Duration, log *slog.Logger) *Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if !verifyTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit, for a local console
	}
	return &Client{base: base, key: key, log: log, attempts: 4, sleep: sleepCtx, Backoff: defaultBackoff,
		http: &http.Client{Timeout: timeout, Transport: tr,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Error is a failed API call.
type Error struct {
	Method, Path string
	Status       int // 0 when the controller could not be reached
	Body         string
	Err          error
}

func (e *Error) Error() string {
	msg := "UniFi " + e.Method + " " + e.Path
	if e.Status != 0 {
		msg += fmt.Sprintf(": %d %s", e.Status, http.StatusText(e.Status))
		if e.Body != "" {
			msg += ": " + e.Body
		}
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *Error) Unwrap() error { return e.Err }

func retryable(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

// do sends a request, retrying connection failures, 429 and 5xx.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			return err
		}
	}
	u := *c.base
	u.Path = strings.TrimSuffix(c.base.Path, "/") + path
	u.RawQuery = query.Encode()
	var last error
	for attempt := 1; attempt <= c.attempts; attempt++ {
		var rdr io.Reader
		if raw != nil {
			rdr = bytes.NewReader(raw)
		}
		req, err := http.NewRequestWithContext(ctx, method, u.String(), rdr)
		if err != nil {
			return err
		}
		req.Header.Set("X-API-KEY", c.key)
		req.Header.Set("Accept", "application/json")
		if raw != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.http.Do(req)
		var wait time.Duration
		switch {
		case err != nil:
			last = &Error{Method: method, Path: path, Err: err}
		default:
			b, rerr := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
			resp.Body.Close()
			switch {
			case rerr != nil:
				last = &Error{Method: method, Path: path, Status: resp.StatusCode, Err: rerr}
			case retryable(resp.StatusCode):
				last = &Error{Method: method, Path: path, Status: resp.StatusCode, Body: truncate(string(b))}
				if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
					wait = min(time.Duration(s)*time.Second, time.Minute)
				}
			case resp.StatusCode >= 300:
				return &Error{Method: method, Path: path, Status: resp.StatusCode, Body: truncate(string(b))}
			default:
				if out == nil || len(bytes.TrimSpace(b)) == 0 {
					return nil
				}
				if err := json.Unmarshal(b, out); err != nil {
					return &Error{Method: method, Path: path, Status: resp.StatusCode,
						Err: fmt.Errorf("unexpected response: %w", err)}
				}
				return nil
			}
		}
		if attempt == c.attempts || ctx.Err() != nil {
			break
		}
		if wait == 0 {
			wait = c.Backoff(attempt)
		}
		c.log.Warn("UniFi request failed; retrying", "error", last.Error(), "attempt", attempt, "in", wait.String())
		if err := c.sleep(ctx, wait); err != nil {
			return err
		}
	}
	return last
}

type page[T any] struct {
	Offset     int `json:"offset"`
	Count      int `json:"count"`
	TotalCount int `json:"totalCount"`
	Data       []T `json:"data"`
}

// paginate reads a whole collection, 200 at a time.
func paginate[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	var all []T
	for offset := 0; ; {
		var p page[T]
		q := url.Values{"offset": {strconv.Itoa(offset)}, "limit": {"200"}}
		if err := c.do(ctx, http.MethodGet, path, q, nil, &p); err != nil {
			return nil, err
		}
		all = append(all, p.Data...)
		offset += len(p.Data)
		if len(p.Data) == 0 || offset >= p.TotalCount {
			return all, nil
		}
	}
}

// Info checks the key and returns the application's version.
func (c *Client) Info(ctx context.Context) (string, error) {
	var out struct {
		ApplicationVersion string `json:"applicationVersion"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/info", nil, nil, &out)
	return out.ApplicationVersion, err
}

// Site is a UniFi site.
type Site struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ResolveSite finds a site by id or name and returns its id.
func (c *Client) ResolveSite(ctx context.Context, idOrName string) (Site, error) {
	sites, err := paginate[Site](ctx, c, "/v1/sites")
	if err != nil {
		return Site{}, err
	}
	var names []string
	for _, s := range sites {
		if s.ID == idOrName || s.Name == idOrName {
			return s, nil
		}
		names = append(names, s.Name)
	}
	return Site{}, fmt.Errorf("no UniFi site has the id or name %q (sites: %s)", idOrName, strings.Join(names, ", "))
}

// Item is one traffic matching list item. The worker writes only address
// lists, whose values are strings, but reads every list on the site: port
// lists hold numbers (PORT_NUMBER value, PORT_NUMBER_RANGE start and stop),
// so reading takes a string, a number or any other JSON value as text.
type Item struct {
	Type  string `json:"type"`
	Value string `json:"value,omitempty"`
	Start string `json:"start,omitempty"` // IP_ADDRESS_RANGE, PORT_NUMBER_RANGE
	Stop  string `json:"stop,omitempty"`
}

// UnmarshalJSON implements json.Unmarshaler.
func (it *Item) UnmarshalJSON(b []byte) error {
	var raw struct {
		Type  string          `json:"type"`
		Value json.RawMessage `json:"value"`
		Start json.RawMessage `json:"start"`
		Stop  json.RawMessage `json:"stop"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*it = Item{Type: raw.Type, Value: text(raw.Value), Start: text(raw.Start), Stop: text(raw.Stop)}
	return nil
}

// text is a JSON string's value, or any other JSON value as written.
func text(r json.RawMessage) string {
	if len(r) == 0 || string(r) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(r, &s) == nil {
		return s
	}
	return string(bytes.TrimSpace(r))
}

// Key identifies an item for comparison; prefixes compare canonically.
func (it Item) Key() string {
	switch it.Type {
	case "IP_ADDRESS":
		if a, err := netip.ParseAddr(it.Value); err == nil {
			a = a.Unmap()
			return netip.PrefixFrom(a, a.BitLen()).String()
		}
	case "SUBNET":
		if p, err := netip.ParsePrefix(it.Value); err == nil {
			return p.Masked().String()
		}
	}
	return it.Type + ":" + it.Value + ":" + it.Start + "-" + it.Stop
}

// ItemFor turns a prefix into a list item. A single address must be sent as
// IP_ADDRESS with no prefix length; the API refuses 192.0.2.1/32 as a SUBNET.
func ItemFor(p netip.Prefix) Item {
	if p.IsSingleIP() {
		return Item{Type: "IP_ADDRESS", Value: p.Addr().String()}
	}
	return Item{Type: "SUBNET", Value: p.Masked().String()}
}

// List is a traffic matching list.
type List struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	Items []Item `json:"items"`
}

func listsPath(site string) string {
	return "/v1/sites/" + url.PathEscape(site) + "/traffic-matching-lists"
}

// Lists returns every traffic matching list of a site.
func (c *Client) Lists(ctx context.Context, site string) ([]List, error) {
	return paginate[List](ctx, c, listsPath(site))
}

// GetList returns one list with its items.
func (c *Client) GetList(ctx context.Context, site, id string) (List, error) {
	var l List
	err := c.do(ctx, http.MethodGet, listsPath(site)+"/"+url.PathEscape(id), nil, nil, &l)
	return l, err
}

type listBody struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Items []Item `json:"items"`
}

// CreateList creates a list; items must not be empty.
func (c *Client) CreateList(ctx context.Context, site, name, typ string, items []Item) (List, error) {
	if len(items) == 0 {
		return List{}, errors.New("a UniFi list needs at least one item")
	}
	var l List
	err := c.do(ctx, http.MethodPost, listsPath(site), nil, listBody{Type: typ, Name: name, Items: items}, &l)
	return l, err
}

// PutList replaces a list's items (and name) wholesale; items must not be
// empty, or the controller refuses the update and keeps the old contents.
func (c *Client) PutList(ctx context.Context, site string, l List, items []Item) error {
	if len(items) == 0 {
		return errors.New("a UniFi list needs at least one item")
	}
	return c.do(ctx, http.MethodPut, listsPath(site)+"/"+url.PathEscape(l.ID), nil,
		listBody{Type: l.Type, Name: l.Name, Items: items}, nil)
}

func truncate(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 500 {
		return s[:500] + "…"
	}
	return s
}

package unifi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The shapes the UniFi Network API (10.6.106) gives traffic matching list
// items: strings for addresses, numbers for ports.
const listsPage = `{"offset":0,"limit":200,"count":3,"totalCount":3,"data":[
 {"id":"a","name":"v4","type":"IPV4_ADDRESSES","items":[
  {"type":"IP_ADDRESS","value":"192.0.2.1"},{"type":"SUBNET","value":"198.51.100.0/24"},
  {"type":"IP_ADDRESS_RANGE","start":"203.0.113.1","stop":"203.0.113.9"}]},
 {"id":"b","name":"Web ports","type":"PORTS","items":[
  {"type":"PORT_NUMBER","value":443},{"type":"PORT_NUMBER_RANGE","start":8000,"stop":8080}]},
 {"id":"c","name":"future","type":"SOMETHING_NEW","items":[{"type":"X","value":{"a":1}},{"type":"Y","value":true}]}
]}`

func serve(t *testing.T, body string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	c := New(u, "key", true, 5*time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.Backoff = func(int) time.Duration { return time.Millisecond }
	return c
}

func TestListsReadsEveryKindOfList(t *testing.T) {
	lists, err := serve(t, listsPage).Lists(context.Background(), "site")
	if err != nil {
		t.Fatal(err)
	}
	if len(lists) != 3 {
		t.Fatalf("%+v", lists)
	}
	v4, ports, future := lists[0].Items, lists[1].Items, lists[2].Items
	if v4[0].Value != "192.0.2.1" || v4[1].Key() != "198.51.100.0/24" || v4[2].Start != "203.0.113.1" || v4[2].Stop != "203.0.113.9" {
		t.Fatalf("%+v", v4)
	}
	if ports[0].Value != "443" || ports[1].Start != "8000" || ports[1].Stop != "8080" {
		t.Fatalf("%+v", ports)
	}
	if future[0].Value != `{"a":1}` || future[1].Value != "true" {
		t.Fatalf("%+v", future)
	}
	// Address items are still written as strings.
	b, _ := json.Marshal(ItemFor(mustPrefix(t, "192.0.2.7/32")))
	if string(b) != `{"type":"IP_ADDRESS","value":"192.0.2.7"}` {
		t.Fatal(string(b))
	}
}

// A response the worker cannot read names the reason, not just the status.
func TestUnreadableResponseSaysWhy(t *testing.T) {
	_, err := serve(t, `{"offset":0,"count":1,"totalCount":1,"data":"not a list"}`).Lists(context.Background(), "site")
	var ue *Error
	if !errors.As(err, &ue) || ue.Status != 200 {
		t.Fatalf("%v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "200 OK: unexpected response: json: cannot unmarshal string") {
		t.Fatal(msg)
	}
}

func TestErrorText(t *testing.T) {
	cases := map[string]*Error{
		"UniFi GET /v1/sites: 404 Not Found: no such site": {Method: "GET", Path: "/v1/sites", Status: 404, Body: "no such site"},
		"UniFi GET /v1/sites: 502 Bad Gateway":             {Method: "GET", Path: "/v1/sites", Status: 502},
		"UniFi GET /v1/sites: connection refused":          {Method: "GET", Path: "/v1/sites", Err: errors.New("connection refused")},
		"UniFi GET /v1/sites: 200 OK: unexpected response: bad": {Method: "GET", Path: "/v1/sites", Status: 200,
			Err: errors.New("unexpected response: bad")},
	}
	for want, e := range cases {
		if got := e.Error(); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

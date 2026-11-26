// Package unifitest is a fake UniFi Network integration API for tests. It
// serves sites and traffic matching lists, and enforces what the real
// controller does: the API key, at least one item per list, and a single
// address sent without a prefix length.
package unifitest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/PatrickH298/ip-valet/workers/unifi/internal/unifi"
)

// SiteID is the fake's one site, named "Default".
const SiteID = "88f7af54-98f8-306a-a1c7-c9349722b1f6"

// Server is a running fake controller.
type Server struct {
	*httptest.Server
	Key string

	mu        sync.Mutex
	lists     map[string]*unifi.List
	nextID    int
	failPuts  int // fail this many PUTs with 500
	Puts      int
	OmitItems bool // list collection responses leave out items, as some versions do
}

// New starts a fake controller that accepts key.
func New(key string) *Server {
	s := &Server{Key: key, lists: map[string]*unifi.List{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/info", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"applicationVersion": "10.6.106"})
	})
	mux.HandleFunc("GET /v1/sites", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, page([]any{map[string]any{"id": SiteID, "name": "Default", "internalReference": "default"}}, r))
	})
	mux.HandleFunc("GET /v1/sites/{site}/traffic-matching-lists", s.listAll)
	mux.HandleFunc("POST /v1/sites/{site}/traffic-matching-lists", s.create)
	mux.HandleFunc("GET /v1/sites/{site}/traffic-matching-lists/{id}", s.get)
	mux.HandleFunc("PUT /v1/sites/{site}/traffic-matching-lists/{id}", s.put)
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-KEY") != s.Key {
			writeJSON(w, 401, map[string]any{"statusCode": 401, "message": "unauthorized"})
			return
		}
		mux.ServeHTTP(w, r)
	}))
	return s
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func page(items []any, r *http.Request) map[string]any {
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit == 0 {
		limit = 25
	}
	end := min(offset+limit, len(items))
	data := []any{}
	if offset < len(items) {
		data = items[offset:end]
	}
	return map[string]any{"offset": offset, "limit": limit, "count": len(data), "totalCount": len(items), "data": data}
}

func (s *Server) site(w http.ResponseWriter, r *http.Request) bool {
	if r.PathValue("site") != SiteID {
		writeJSON(w, 404, map[string]any{"message": "site not found"})
		return false
	}
	return true
}

func (s *Server) listAll(w http.ResponseWriter, r *http.Request) {
	if !s.site(w, r) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var items []any
	for i := 1; i <= s.nextID; i++ {
		l, ok := s.lists[fmt.Sprintf("%08d-0000-4000-8000-000000000000", i)]
		if !ok {
			continue
		}
		c := *l
		if s.OmitItems {
			c.Items = nil
		}
		items = append(items, c)
	}
	writeJSON(w, 200, page(items, r))
}

func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	if !s.site(w, r) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.lists[r.PathValue("id")]
	if !ok {
		writeJSON(w, 404, map[string]any{"message": "not found"})
		return
	}
	writeJSON(w, 200, l)
}

type body struct {
	Type  string       `json:"type"`
	Name  string       `json:"name"`
	Items []unifi.Item `json:"items"`
}

// validate refuses what the real controller refuses.
func validate(b body) string {
	if b.Name == "" {
		return "name is required"
	}
	if b.Type != unifi.TypeIPv4 && b.Type != unifi.TypeIPv6 {
		return "unsupported type " + b.Type
	}
	if len(b.Items) == 0 {
		return "items: size must be at least 1"
	}
	for _, it := range b.Items {
		switch it.Type {
		case "IP_ADDRESS":
			a, err := netip.ParseAddr(it.Value)
			if err != nil || strings.Contains(it.Value, "/") || a.Is6() != (b.Type == unifi.TypeIPv6) {
				return "invalid IP_ADDRESS " + it.Value
			}
		case "SUBNET":
			p, err := netip.ParsePrefix(it.Value)
			if err != nil || p.Addr().Is6() != (b.Type == unifi.TypeIPv6) {
				return "invalid SUBNET " + it.Value
			}
		default:
			return "unsupported item type " + it.Type
		}
	}
	return ""
}

func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	if !s.site(w, r) {
		return
	}
	var b body
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeJSON(w, 400, map[string]any{"message": err.Error()})
		return
	}
	if msg := validate(b); msg != "" {
		writeJSON(w, 400, map[string]any{"message": msg})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	l := &unifi.List{ID: fmt.Sprintf("%08d-0000-4000-8000-000000000000", s.nextID), Name: b.Name, Type: b.Type, Items: b.Items}
	s.lists[l.ID] = l
	writeJSON(w, 201, l)
}

func (s *Server) put(w http.ResponseWriter, r *http.Request) {
	if !s.site(w, r) {
		return
	}
	var b body
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeJSON(w, 400, map[string]any{"message": err.Error()})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Puts++
	if s.failPuts > 0 {
		s.failPuts--
		writeJSON(w, 500, map[string]any{"message": "controller busy"})
		return
	}
	l, ok := s.lists[r.PathValue("id")]
	if !ok {
		writeJSON(w, 404, map[string]any{"message": "not found"})
		return
	}
	if msg := validate(b); msg != "" {
		writeJSON(w, 400, map[string]any{"message": msg})
		return
	}
	if b.Type != l.Type {
		writeJSON(w, 400, map[string]any{"message": "type cannot change"})
		return
	}
	l.Name, l.Items = b.Name, b.Items
	writeJSON(w, 200, l)
}

// Add creates a list directly, as someone using the UniFi UI would.
func (s *Server) Add(name, typ string, items ...unifi.Item) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	id := fmt.Sprintf("%08d-0000-4000-8000-000000000000", s.nextID)
	s.lists[id] = &unifi.List{ID: id, Name: name, Type: typ, Items: items}
	return id
}

// Edit replaces a list's items directly, as a hand edit would.
func (s *Server) Edit(id string, items ...unifi.Item) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lists[id].Items = items
}

// FailPuts makes the next n updates fail with 500.
func (s *Server) FailPuts(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failPuts = n
}

// Items returns a list's item keys, by name.
func (s *Server) Items(name string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.lists {
		if l.Name == name {
			var out []string
			for _, it := range l.Items {
				out = append(out, it.Key())
			}
			sortStrings(out)
			return out
		}
	}
	return nil
}

// Has reports whether a list with this name exists.
func (s *Server) Has(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.lists {
		if l.Name == name {
			return true
		}
	}
	return false
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

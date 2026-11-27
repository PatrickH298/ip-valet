package web

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"time"

	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/httpx"
	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/rules"
)

// Address detection. The page knows the address its own connection came
// from. The other family's address needs a host reachable over that family
// only (IPVALET_SSO_DETECT_V4_URL, IPVALET_SSO_DETECT_V6_URL), served by
// this same program at /detect, or on its own port. The page's script asks
// that host, passing a token tied to the session; the host answers with the
// address it saw and a proof: that address, the session and an expiry,
// sealed. The register form sends the proof back, so the server registers
// only addresses it saw itself, never one the browser claims.

const (
	detectTokenTTL = time.Hour
	detectProofTTL = 30 * time.Minute
)

type detectToken struct {
	S string `json:"s"` // the session's tag
}

type detectProof struct {
	S string `json:"s"` // the session's tag
	A string `json:"a"` // the address seen
}

// sessionTag binds sealed values to a session without carrying its id.
func (s *Server) sessionTag(sess Session) string { return s.Sealer.Tag("session", sess.ID) }

// detectToken returns the token the page passes to the detection hosts.
func (s *Server) detectToken(sess Session) string {
	t, _ := s.Sealer.Seal("detect-token", detectTokenTTL, detectToken{S: s.sessionTag(sess)})
	return t
}

type detectAnswer struct {
	Address string `json:"address,omitempty"`
	Family  string `json:"family,omitempty"`
	Proof   string `json:"proof,omitempty"`
	Private bool   `json:"private,omitempty"`
	Error   string `json:"error,omitempty"`
}

// detect answers GET /detect?t=<token> with the caller's address and a proof.
func (s *Server) detect(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", s.PublicURL.Scheme+"://"+s.PublicURL.Host)
	h.Set("Vary", "Origin")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Type", "application/json")
	write := func(status int, a detectAnswer) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(a)
	}
	var tok detectToken
	if err := s.Sealer.Open("detect-token", r.URL.Query().Get("t"), &tok); err != nil {
		write(http.StatusForbidden, detectAnswer{Error: "reload the page to detect your address again"})
		return
	}
	ip := httpx.ClientIPFrom(r.Context())
	if !ip.IsValid() {
		write(http.StatusBadRequest, detectAnswer{Error: "no address"})
		return
	}
	proof, err := s.Sealer.Seal("detect-proof", detectProofTTL, detectProof{S: tok.S, A: ip.String()})
	if err != nil {
		write(http.StatusInternalServerError, detectAnswer{Error: "internal error"})
		return
	}
	write(http.StatusOK, detectAnswer{Address: ip.String(), Family: family(ip), Proof: proof,
		Private: rules.IsPrivate(netip.PrefixFrom(ip, ip.BitLen()))})
}

// detected returns the addresses a register form may use: the one its own
// connection came from, and those the detection hosts saw for this session.
// It reports whether a proof had expired or was not this session's.
func (s *Server) detected(r *http.Request, sess Session) (v4, v6 netip.Addr, stale bool) {
	set := func(a netip.Addr) {
		switch {
		case a.Is4() && !v4.IsValid():
			v4 = a
		case a.Is6() && !v6.IsValid():
			v6 = a
		}
	}
	set(httpx.ClientIPFrom(r.Context()))
	tag := s.sessionTag(sess)
	for _, raw := range r.PostForm["proof"] {
		var p detectProof
		if err := s.Sealer.Open("detect-proof", raw, &p); err != nil || p.S != tag {
			stale = true
			continue
		}
		if a, err := netip.ParseAddr(p.A); err == nil {
			set(a.Unmap())
		}
	}
	return v4, v6, stale
}

func family(a netip.Addr) string {
	if a.Is4() {
		return "ipv4"
	}
	return "ipv6"
}

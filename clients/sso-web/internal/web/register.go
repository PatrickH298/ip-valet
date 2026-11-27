package web

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/ipvalet"
	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/rules"
)

// Outcome is what happened to one prefix in one realm and group.
type Outcome struct {
	Realm, Group, Prefix string
	OK                   bool
	State                string     // the entry's state, when OK
	Expires              *time.Time // when OK; nil = never
	Note                 string     // when OK: the lifetime was shortened to a limit
	Code                 string     // the API's reason, when not OK
	Message              string     // for the person, when not OK
}

// ttlChoice picks the lifetime to ask for in a grant.
type ttlChoice func(rules.Grant) rules.TTL

// register submits every prefix to every grant, one submission per realm
// and group, so a limit in one never blocks another. With clamp (one-click
// registration, where the person chose no lifetime), a realm whose own
// rules allow less is asked again for its longest lifetime.
func (s *Server) register(ctx context.Context, user string, grants []rules.Grant, prefixes []netip.Prefix,
	ttl ttlChoice, clamp bool) []Outcome {
	var out []Outcome
	var down *Outcome // once the API is unreachable, the rest fail the same way
	for _, p := range prefixes {
		for _, g := range grants {
			o := Outcome{Realm: g.Realm, Group: g.Group, Prefix: p.String()}
			if down != nil {
				o.Code, o.Message = down.Code, down.Message
				out = append(out, o)
				continue
			}
			asked := ttl(g)
			sub := ipvalet.Submission{Realm: g.Realm, User: user, Groups: []string{g.Group}, Prefix: p.String(), TTL: asked.String()}
			res, err := s.API.Submit(ctx, sub)
			if limit, ok := ttlLimit(err); ok && clamp && rules.Longer(asked, limit) {
				sub.TTL = limit.String()
				res, err = s.API.Submit(ctx, sub)
				if err == nil {
					o.Note = fmt.Sprintf("for %s, the longest %s allows", limit.Human(), g.Realm)
				}
			}
			if err == nil {
				o.OK = true
				for _, e := range res.Entries {
					if e.Group == g.Group {
						o.State, o.Expires = e.State, e.ExpiresAt
					}
				}
				s.Log.Info("registered", "user", user, "realm", g.Realm, "group", g.Group, "prefix", p.String(),
					"ttl", sub.TTL, "state", o.State)
				out = append(out, o)
				continue
			}
			o.Code, o.Message = s.explain(err, g.Realm, p)
			s.Log.Info("registration refused", "user", user, "realm", g.Realm, "group", g.Group, "prefix", p.String(),
				"code", o.Code)
			if ae, ok := ipvalet.AsError(err); ok && (ae.Status == 0 || ae.Status >= 500 ||
				ae.Status == http.StatusUnauthorized) {
				down = &o
			}
			out = append(out, o)
		}
	}
	return out
}

// ttlLimit returns the realm's longest lifetime from a ttl_exceeded refusal.
func ttlLimit(err error) (rules.TTL, bool) {
	ae, ok := ipvalet.AsError(err)
	if !ok || ae.Code != "submission_rejected" || len(ae.Results) == 0 {
		return rules.TTL{}, false
	}
	for _, r := range ae.Results {
		if !r.OK && r.Code == "ttl_exceeded" && r.Limit != nil {
			t, err := rules.ParseTTL(r.Limit.MaxTTL)
			return t, err == nil
		}
	}
	return rules.TTL{}, false
}

// explain turns a refused submission into its code and a sentence for the
// person who asked.
func (s *Server) explain(err error, realm string, p netip.Prefix) (string, string) {
	ae, ok := ipvalet.AsError(err)
	if !ok {
		s.Log.Error("registration failed", "realm", realm, "error", err.Error())
		return "internal", "Something went wrong. Try again in a moment."
	}
	family := "IPv4"
	if p.Addr().Is6() {
		family = "IPv6"
	}
	switch {
	case ae.Status == 0 || ae.Status >= 500:
		s.Log.Error("API server unavailable", "status", ae.Status, "code", ae.Code, "error", ae.Error())
		return "unavailable", "The registration service is unavailable right now. Try again in a moment."
	case ae.Status == http.StatusUnauthorized:
		s.Log.Error("the API server refused the site's client key", "code", ae.Code, "request_id", ae.RequestID)
		return ae.Code, "This site cannot use the registration service right now. Tell your administrator."
	case ae.Code == "realm_not_allowed":
		s.Log.Error("the client key may not register in this realm; bind the client to it", "realm", realm)
		return ae.Code, fmt.Sprintf("This site may not register addresses in %s. Tell your administrator.", realm)
	case ae.Code == "submission_rejected" && len(ae.Results) > 0:
		for _, r := range ae.Results {
			if !r.OK {
				return r.Code, explainRule(r, realm, family)
			}
		}
	case ae.Code == "invalid_request":
		s.Log.Error("the API server refused a submission as invalid", "realm", realm, "message", ae.Message,
			"fields", fmt.Sprint(ae.Fields))
		return ae.Code, "The registration service refused the request as invalid. Tell your administrator."
	}
	s.Log.Warn("submission refused", "realm", realm, "status", ae.Status, "code", ae.Code, "message", ae.Message)
	return ae.Code, fmt.Sprintf("%s refused the address (%s).", realm, ae.Code)
}

func explainRule(r ipvalet.GroupResult, realm, family string) string {
	switch r.Code {
	case "cap_exceeded":
		if r.Limit != nil && r.Limit.MaxPrefixes != nil {
			return fmt.Sprintf("You already have the most addresses %s allows (%d). Revoke one below to register another.",
				realm, *r.Limit.MaxPrefixes)
		}
		return fmt.Sprintf("You already have the most addresses %s allows. Revoke one below to register another.", realm)
	case "ttl_exceeded":
		if r.Limit != nil {
			if t, err := rules.ParseTTL(r.Limit.MaxTTL); err == nil {
				return fmt.Sprintf("%s allows addresses for at most %s. Choose a shorter time.", realm, t.Human())
			}
		}
		return fmt.Sprintf("%s does not allow addresses for that long. Choose a shorter time.", realm)
	case "prefix_too_broad":
		if r.Limit != nil && r.Limit.MinPrefixLen != nil {
			return fmt.Sprintf("%s accepts %s subnets no wider than /%d. Choose /%d or narrower.",
				realm, family, *r.Limit.MinPrefixLen, *r.Limit.MinPrefixLen)
		}
		return fmt.Sprintf("%s does not accept a subnet that wide. Choose a narrower one.", realm)
	case "ip_denied":
		return fmt.Sprintf("%s does not accept this address.", realm)
	case "no_subscriber":
		return fmt.Sprintf("Nothing in %s uses %s addresses yet, so this one cannot go there. Tell your administrator if you need it.",
			realm, family)
	case "invalid_prefix":
		return "That address cannot be registered."
	case "realm_not_allowed":
		return fmt.Sprintf("This site may not register addresses in %s. Tell your administrator.", realm)
	}
	return fmt.Sprintf("%s refused the address (%s).", realm, r.Code)
}

// summarize turns outcomes into a flash: one line per prefix and realm.
func (s *Server) summarize(outcomes []Outcome, place func(realm, group string) string) *flash {
	f := &flash{Kind: "ok"}
	ok, failed := 0, 0
	for _, o := range outcomes {
		if o.OK {
			ok++
		} else {
			failed++
		}
	}
	switch {
	case ok == 0 && failed > 0:
		f.Kind = "error"
		f.Title = "Nothing was registered"
	case failed > 0:
		f.Kind = "warn"
		f.Title = "Some registrations failed"
	default:
		f.Title = "Registered"
	}
	sort.SliceStable(outcomes, func(i, j int) bool { return outcomes[i].Prefix < outcomes[j].Prefix })
	for _, o := range outcomes {
		var line string
		where := place(o.Realm, o.Group)
		if o.OK {
			line = o.Prefix + " in " + where
			switch {
			case o.Expires == nil:
				line += ", with no time limit"
			default:
				line += ", until " + s.when(*o.Expires)
			}
			if o.Note != "" {
				line += " (" + o.Note + ")"
			}
			line += "."
		} else {
			line = o.Prefix + " in " + where + ": " + o.Message
		}
		f.Lines = append(f.Lines, flashLine{OK: o.OK, Text: line})
	}
	return f
}

// when renders a time for people, in the configured zone.
func (s *Server) when(t time.Time) string {
	t = t.In(s.Location)
	now := time.Now().In(s.Location)
	layout := "Jan 2, 15:04"
	if t.Year() != now.Year() {
		layout = "Jan 2 2006, 15:04"
	}
	return t.Format(layout) + " " + zoneName(t)
}

func zoneName(t time.Time) string {
	name, _ := t.Zone()
	if strings.TrimLeft(name, "+-0123456789") == "" {
		return "UTC" + t.Format("-07:00")
	}
	return name
}

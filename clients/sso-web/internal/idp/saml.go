package idp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/config"
	"github.com/PatrickH298/ip-valet/clients/sso-web/internal/httpx"
)

// SAML signs people in with SAML 2.0 as a service provider: the
// SP-initiated web browser SSO profile, with responses posted to
// /saml/acs. The user name is an attribute or the subject's NameID; groups
// are an attribute's values.
type SAML struct {
	cfg  config.SAML
	env  Env
	key  crypto.Signer
	cert *x509.Certificate

	mu sync.Mutex
	sp *saml.ServiceProvider
}

// NewSAML returns a SAML provider. It reads the IdP's metadata when first
// needed, and again until that succeeds.
func NewSAML(cfg config.SAML, env Env) (*SAML, error) {
	s := &SAML{cfg: cfg, env: env}
	if cfg.KeyPEM != "" {
		var err error
		if s.key, s.cert, err = parseKeyPair(cfg.KeyPEM, cfg.CertPEM); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Name implements Provider.
func (s *SAML) Name() string { return "SAML" }

// CrossSitePosts implements Provider: the IdP posts responses from its site.
func (s *SAML) CrossSitePosts() []string { return []string{"POST /saml/acs"} }

// Routes implements Provider.
func (s *SAML) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /saml/acs", s.acs)
	mux.HandleFunc("GET /saml/metadata", s.metadata)
}

// Check implements Provider.
func (s *SAML) Check(ctx context.Context) error {
	_, err := s.load(ctx)
	return err
}

func (s *SAML) load(ctx context.Context) (*saml.ServiceProvider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sp != nil {
		return s.sp, nil
	}
	var md *saml.EntityDescriptor
	var err error
	if s.cfg.MetadataURL != nil {
		md, err = samlsp.FetchMetadata(ctx, s.env.client(), *s.cfg.MetadataURL)
		if err != nil {
			return nil, fmt.Errorf("fetching the IdP metadata from %s: %w", s.cfg.MetadataURL, err)
		}
	} else if md, err = samlsp.ParseMetadata(s.cfg.Metadata); err != nil {
		return nil, fmt.Errorf("reading the IdP metadata: %w", err)
	}
	base := s.env.PublicURL
	sp := &saml.ServiceProvider{
		EntityID:          s.cfg.EntityID,
		Key:               s.key,
		Certificate:       s.cert,
		MetadataURL:       *base.JoinPath("saml", "metadata"),
		AcsURL:            *base.JoinPath("saml", "acs"),
		IDPMetadata:       md,
		AuthnNameIDFormat: saml.UnspecifiedNameIDFormat,
		HTTPClient:        s.env.client(),
	}
	switch s.key.(type) {
	case *rsa.PrivateKey:
		sp.SignatureMethod = dsig.RSASHA256SignatureMethod
	case *ecdsa.PrivateKey:
		sp.SignatureMethod = dsig.ECDSASHA256SignatureMethod
	}
	if sp.GetSSOBindingLocation(saml.HTTPRedirectBinding) == "" && sp.GetSSOBindingLocation(saml.HTTPPostBinding) == "" {
		return nil, errors.New("the IdP metadata names no single sign-on service with the HTTP-Redirect or HTTP-POST binding")
	}
	s.sp = sp
	return sp, nil
}

type samlState struct {
	ID    string `json:"i"` // the AuthnRequest's ID
	Nonce string `json:"n"` // also in the browser's cookie
	Next  string `json:"x"`
}

const samlCookie = "saml"

// Begin implements Provider.
func (s *SAML) Begin(w http.ResponseWriter, r *http.Request, next string) {
	sp, err := s.load(r.Context())
	if err != nil {
		s.env.Log.Error("cannot use the SAML IdP", "error", err.Error())
		s.env.Fail(w, r, http.StatusBadGateway, "Sign-in unavailable",
			"The sign-in service could not be reached. Try again in a moment.")
		return
	}
	binding := saml.HTTPRedirectBinding
	loc := sp.GetSSOBindingLocation(binding)
	if loc == "" {
		binding, loc = saml.HTTPPostBinding, sp.GetSSOBindingLocation(saml.HTTPPostBinding)
	}
	req, err := sp.MakeAuthenticationRequest(loc, binding, saml.HTTPPostBinding)
	if err != nil {
		s.env.Log.Error("cannot make a SAML request", "error", err.Error())
		s.env.Fail(w, r, http.StatusInternalServerError, "Something went wrong", "Sign-in could not start.")
		return
	}
	st := samlState{ID: req.ID, Nonce: random(), Next: next}
	relay, err := s.env.Sealer.Seal("saml-login", loginTTL, st)
	if err != nil {
		s.env.Fail(w, r, http.StatusInternalServerError, "Something went wrong", "Sign-in could not start.")
		return
	}
	// The IdP posts the response from its own site, which carries only
	// SameSite=None cookies, and those must be Secure. Over plain HTTP
	// (development) the cookie is not sent back and is not required.
	secure := s.env.Cookies.Secure(r)
	sameSite := http.SameSiteLaxMode
	if secure {
		sameSite = http.SameSiteNoneMode
	}
	setStateCookie(w, secure, samlCookie, st.Nonce, sameSite)
	if binding == saml.HTTPRedirectBinding {
		u, err := req.Redirect(relay, sp)
		if err != nil {
			s.env.Fail(w, r, http.StatusInternalServerError, "Something went wrong", "Sign-in could not start.")
			return
		}
		http.Redirect(w, r, u.String(), http.StatusSeeOther)
		return
	}
	nonce := random()
	dest, _ := url.Parse(loc)
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; form-action "+
		dest.Scheme+"://"+dest.Host+"; frame-ancestors 'none'; base-uri 'none'")
	_, _ = w.Write(req.PostWithNonce(relay, nonce))
}

func (s *SAML) acs(w http.ResponseWriter, r *http.Request) {
	ip := httpx.ClientIPFrom(r.Context()).String()
	if err := r.ParseForm(); err != nil {
		s.env.Fail(w, r, http.StatusBadRequest, "Sign-in failed", "The sign-in response could not be read.")
		return
	}
	var st samlState
	if err := s.env.Sealer.Open("saml-login", r.PostForm.Get("RelayState"), &st); err != nil {
		s.env.Log.Warn("SAML response without a valid sign-in in progress", "client_ip", ip, "error", err.Error())
		s.env.Fail(w, r, http.StatusBadRequest, "Sign-in expired",
			"This sign-in was started too long ago, or did not start here. Sign in again.")
		return
	}
	cookie, secure := readStateCookie(r, samlCookie)
	clearStateCookie(w, secure, samlCookie, map[bool]http.SameSite{true: http.SameSiteNoneMode, false: http.SameSiteLaxMode}[secure])
	if s.env.Cookies.Secure(r) || cookie != "" {
		if subtle.ConstantTimeCompare([]byte(cookie), []byte(st.Nonce)) != 1 {
			s.env.Log.Warn("SAML response for a sign-in this browser did not start", "client_ip", ip)
			s.env.Fail(w, r, http.StatusBadRequest, "Sign-in failed",
				"The sign-in response did not match this browser's request. Sign in again.")
			return
		}
	}
	sp, err := s.load(r.Context())
	if err != nil {
		s.env.Log.Error("cannot use the SAML IdP", "error", err.Error())
		s.env.Fail(w, r, http.StatusBadGateway, "Sign-in unavailable", "The sign-in service could not be reached.")
		return
	}
	a, err := sp.ParseResponse(r, []string{st.ID})
	if err != nil {
		detail := err.Error()
		var ire *saml.InvalidResponseError
		if errors.As(err, &ire) && ire.PrivateErr != nil {
			detail = ire.PrivateErr.Error()
		}
		s.env.Log.Error("SAML response refused", "error", detail, "client_ip", ip)
		s.env.Fail(w, r, http.StatusForbidden, "Sign-in failed",
			"The sign-in service's answer could not be accepted. Try again; if it keeps happening, tell your administrator.")
		return
	}
	id, err := s.identity(a)
	if err != nil {
		s.env.Log.Error("SAML sign-in failed", "error", err.Error())
		s.env.Fail(w, r, http.StatusBadGateway, "Sign-in failed",
			"The sign-in service did not say who you are. Tell your administrator.")
		return
	}
	s.env.Done(w, r, id, st.Next)
}

func (s *SAML) identity(a *saml.Assertion) (Identity, error) {
	var id Identity
	values := func(name string) ([]string, bool) {
		var out []string
		found := false
		for _, st := range a.AttributeStatements {
			for _, at := range st.Attributes {
				if at.Name == name || at.FriendlyName == name {
					found = true
					for _, v := range at.Values {
						if v.Value != "" {
							out = append(out, v.Value)
						}
					}
				}
			}
		}
		return out, found
	}
	if s.cfg.UsernameAttribute != "" {
		v, _ := values(s.cfg.UsernameAttribute)
		if len(v) == 0 {
			return id, fmt.Errorf("the assertion has no %q attribute (IPVALET_SSO_SAML_USERNAME_ATTRIBUTE)", s.cfg.UsernameAttribute)
		}
		id.User = v[0]
	} else if a.Subject != nil && a.Subject.NameID != nil {
		id.User = strings.TrimSpace(a.Subject.NameID.Value)
	}
	if id.User == "" {
		return id, errors.New("the assertion has no subject NameID; set IPVALET_SSO_SAML_USERNAME_ATTRIBUTE")
	}
	groups, found := values(s.cfg.GroupsAttribute)
	if !found {
		s.env.Log.Info("the IdP sent no groups attribute; only user rules can match", "user", id.User,
			"attribute", s.cfg.GroupsAttribute)
	}
	id.Groups = groups
	return id, nil
}

func (s *SAML) metadata(w http.ResponseWriter, r *http.Request) {
	sp, err := s.load(r.Context())
	if err != nil {
		s.env.Log.Error("cannot use the SAML IdP", "error", err.Error())
		http.Error(w, "the IdP metadata is not available yet", http.StatusServiceUnavailable)
		return
	}
	b, err := xml.MarshalIndent(sp.Metadata(), "", "  ")
	if err != nil {
		http.Error(w, "cannot render metadata", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write(append([]byte(xml.Header), b...))
}

// parseKeyPair reads a PEM private key (PKCS #1, PKCS #8 or SEC 1) and its
// PEM certificate.
func parseKeyPair(keyPEM, certPEM string) (crypto.Signer, *x509.Certificate, error) {
	kb, _ := pem.Decode([]byte(keyPEM))
	if kb == nil {
		return nil, nil, errors.New("IPVALET_SSO_SAML_SP_KEY: no PEM block")
	}
	var key crypto.Signer
	if k, err := x509.ParsePKCS8PrivateKey(kb.Bytes); err == nil {
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, nil, errors.New("IPVALET_SSO_SAML_SP_KEY: unsupported key type")
		}
		key = s
	} else if k, err := x509.ParsePKCS1PrivateKey(kb.Bytes); err == nil {
		key = k
	} else if k, err := x509.ParseECPrivateKey(kb.Bytes); err == nil {
		key = k
	} else {
		return nil, nil, errors.New("IPVALET_SSO_SAML_SP_KEY: not a PKCS #1, PKCS #8 or EC private key")
	}
	switch key.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
	default:
		return nil, nil, errors.New("IPVALET_SSO_SAML_SP_KEY: must be an RSA or ECDSA key")
	}
	cb, _ := pem.Decode([]byte(certPEM))
	if cb == nil {
		return nil, nil, errors.New("IPVALET_SSO_SAML_SP_CERT: no PEM block")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("IPVALET_SSO_SAML_SP_CERT: %w", err)
	}
	return key, cert, nil
}

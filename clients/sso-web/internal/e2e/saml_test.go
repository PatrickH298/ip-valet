package e2e

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"encoding/xml"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
)

// fakeSAML is crewjam/saml's identity provider, signing in whoever the test
// names, with their groups in the eduPersonAffiliation attribute.
type fakeSAML struct {
	srv *httptest.Server
	idp *saml.IdentityProvider

	mu     sync.Mutex
	user   string
	groups []string
	spMeta string // where the service provider publishes its metadata
}

func selfSigned(t *testing.T, cn string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}

func newFakeSAML(t *testing.T) *fakeSAML {
	key, cert := selfSigned(t, "idp")
	f := &fakeSAML{}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	base, _ := url.Parse(f.srv.URL)
	f.idp = &saml.IdentityProvider{
		Key: key, Certificate: cert, Logger: logger.DefaultLogger,
		MetadataURL: *base.JoinPath("metadata"), SSOURL: *base.JoinPath("sso"),
		ServiceProviderProvider: f, SessionProvider: f,
	}
	mux.HandleFunc("GET /metadata", func(w http.ResponseWriter, _ *http.Request) {
		b, _ := xml.Marshal(f.idp.Metadata())
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/sso", f.idp.ServeSSO)
	return f
}

func (f *fakeSAML) signInAs(user string, groups ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.user, f.groups = user, groups
}

// GetServiceProvider implements saml.ServiceProviderProvider.
func (f *fakeSAML) GetServiceProvider(_ *http.Request, id string) (*saml.EntityDescriptor, error) {
	f.mu.Lock()
	meta := f.spMeta
	f.mu.Unlock()
	resp, err := http.Get(meta)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var ed saml.EntityDescriptor
	if err := xml.Unmarshal(b, &ed); err != nil {
		return nil, err
	}
	if ed.EntityID != id {
		return nil, os.ErrNotExist
	}
	return &ed, nil
}

// GetSession implements saml.SessionProvider.
func (f *fakeSAML) GetSession(_ http.ResponseWriter, _ *http.Request, _ *saml.IdpAuthnRequest) *saml.Session {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	return &saml.Session{ID: "session-" + f.user, Index: "1", CreateTime: now, ExpireTime: now.Add(time.Hour),
		NameID: f.user, Groups: f.groups}
}

var (
	formAction = regexp.MustCompile(`<form method="post" action="([^"]+)"`)
	formInput  = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)"`)
)

// postBack submits the IdP's auto-posting form, as the browser's script
// would: from the IdP's site.
func (b *browser) postBack(t *testing.T, p page, idpOrigin string) page {
	t.Helper()
	m := formAction.FindStringSubmatch(p.body)
	if m == nil {
		t.Fatalf("no form from the IdP (%d %s):\n%s", p.status, p.url, p.body)
	}
	form := url.Values{}
	for _, in := range formInput.FindAllStringSubmatch(p.body, -1) {
		form.Set(html.UnescapeString(in[1]), html.UnescapeString(in[2]))
	}
	req, _ := http.NewRequest("POST", html.UnescapeString(m[1]), stringsReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", idpOrigin)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	return b.do(req)
}

func TestSAML(t *testing.T) {
	if env.skip != "" {
		t.Skip(env.skip)
	}
	for _, signed := range []bool{false, true} {
		name := map[bool]string{false: "without an SP key", true: "with an SP key"}[signed]
		t.Run(name, func(t *testing.T) {
			f := newFakeSAML(t)
			vars := rulesEnv(map[string]string{
				"IPVALET_SSO_PROVIDER":              "saml",
				"IPVALET_SSO_SAML_IDP_METADATA_URL": f.srv.URL + "/metadata",
				"IPVALET_SSO_SAML_GROUPS_ATTRIBUTE": "eduPersonAffiliation",
			})
			if signed {
				key, cert := selfSigned(t, "sp")
				vars["IPVALET_SSO_SAML_SP_KEY"] = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY",
					Bytes: x509.MarshalPKCS1PrivateKey(key)}))
				vars["IPVALET_SSO_SAML_SP_CERT"] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
			}
			s := startSite(t, vars)
			f.mu.Lock()
			f.spMeta = s.base + "/saml/metadata"
			f.mu.Unlock()
			user := map[bool]string{false: "sam", true: "sue"}[signed]
			f.signInAs(user, "staff", "other")
			b := newBrowser(t, "8.8.8.8")
			// The site sends the browser to the IdP, which answers with a form
			// that posts the assertion back to /saml/acs.
			p := b.postBack(t, b.get(s.base+"/"), f.srv.URL)
			if p.status != 200 {
				t.Fatalf("%d %s:\n%s", p.status, p.url, text(p.body))
			}
			mustContain(t, p, "Your addresses", user, "office for 7 days")
			mustNotContain(t, p, "vpn")
			p = b.post(s.base+"/register", s.base, url.Values{})
			mustContain(t, p, "8.8.8.8/32 in office, until")
			// A response that carries no sign-in this site started is refused.
			b2 := newBrowser(t, "8.8.8.8")
			p = b2.post(s.base+"/saml/acs", f.srv.URL, url.Values{"SAMLResponse": {"bm90IHNhbWw="}, "RelayState": {"x"}})
			if p.status != http.StatusBadRequest {
				t.Fatalf("forged response: %d", p.status)
			}
		})
	}
}

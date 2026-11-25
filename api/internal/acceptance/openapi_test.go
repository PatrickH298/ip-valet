package acceptance

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/pb33f/libopenapi"
	validator "github.com/pb33f/libopenapi-validator"
	"github.com/pb33f/libopenapi-validator/config"

	"github.com/PatrickH298/ip-valet/api/internal/testutil"
)

const specPath = "../../../spec/openapi.yaml"

// TestMain checks every request and response the acceptance tests make
// against spec/openapi.yaml: responses always, and requests the server
// accepted (tests send invalid requests on purpose).
func TestMain(m *testing.M) {
	raw, err := os.ReadFile(specPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reading the OpenAPI document:", err)
		os.Exit(1)
	}
	doc, err := libopenapi.NewDocument(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "parsing the OpenAPI document:", err)
		os.Exit(1)
	}
	v, errs := validator.NewValidator(doc, config.WithFormatAssertions())
	if len(errs) > 0 {
		fmt.Fprintln(os.Stderr, "building the validator:", errs)
		os.Exit(1)
	}
	if ok, verrs := v.ValidateDocument(); !ok {
		for _, e := range verrs {
			fmt.Fprintln(os.Stderr, "OpenAPI document:", e.Message, e.Reason)
		}
		os.Exit(1)
	}
	var mu sync.Mutex // the validator is not documented as safe for concurrent use
	testutil.Validator = func(t testing.TB, req *http.Request, reqBody []byte, resp *http.Response, respBody []byte) {
		t.Helper()
		// Unknown routes and methods are expected to be absent from the document.
		if resp.StatusCode == http.StatusNotFound && strings.HasPrefix(req.URL.Path, "/v1/nothing") ||
			resp.StatusCode == http.StatusMethodNotAllowed {
			return
		}
		r := req.Clone(req.Context())
		r.Body = io.NopCloser(bytes.NewReader(reqBody))
		rs := *resp
		rs.Body = io.NopCloser(bytes.NewReader(respBody))
		rs.Request = r

		mu.Lock()
		defer mu.Unlock()
		if resp.StatusCode < 400 {
			if ok, verrs := v.ValidateHttpRequest(r); !ok {
				for _, e := range verrs {
					t.Errorf("OpenAPI: request %s %s: %s: %s %v", req.Method, req.URL.RequestURI(), e.Message, e.Reason, schemaErrs(e.SchemaValidationErrors))
				}
			}
			r.Body = io.NopCloser(bytes.NewReader(reqBody))
		}
		if ok, verrs := v.ValidateHttpResponse(r, &rs); !ok {
			for _, e := range verrs {
				t.Errorf("OpenAPI: response %d to %s %s: %s: %s %v\nbody: %.400s", resp.StatusCode, req.Method,
					req.URL.RequestURI(), e.Message, e.Reason, schemaErrs(e.SchemaValidationErrors), respBody)
			}
		}
	}
	os.Exit(m.Run())
}

func schemaErrs[T any](errs []T) []string {
	var out []string
	for _, e := range errs {
		out = append(out, fmt.Sprintf("%+v", e))
	}
	return out
}

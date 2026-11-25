package httpapi

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/pb33f/libopenapi"
)

// TestEveryRouteIsDocumented checks that spec/openapi.yaml and the server's
// route table list exactly the same operations.
func TestEveryRouteIsDocumented(t *testing.T) {
	raw, err := os.ReadFile("../../../spec/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := libopenapi.NewDocument(raw)
	if err != nil {
		t.Fatal(err)
	}
	model, err := doc.BuildV3Model()
	if err != nil {
		t.Fatal(err)
	}
	documented := map[string]bool{}
	for path, item := range model.Model.Paths.PathItems.FromOldest() {
		for method := range item.GetOperations().FromOldest() {
			documented[strings.ToUpper(method)+" "+path] = true
		}
	}
	served := map[string]bool{}
	for _, r := range New(Deps{}).Routes() {
		served[r] = true
	}
	var missing, extra []string
	for r := range served {
		if !documented[r] {
			missing = append(missing, r)
		}
	}
	for r := range documented {
		if !served[r] {
			extra = append(extra, r)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("routes missing from spec/openapi.yaml:\n  %s", strings.Join(missing, "\n  "))
	}
	if len(extra) > 0 {
		t.Errorf("operations in spec/openapi.yaml the server does not serve:\n  %s", strings.Join(extra, "\n  "))
	}
	if len(served) < 40 {
		t.Errorf("only %d routes registered", len(served))
	}
}

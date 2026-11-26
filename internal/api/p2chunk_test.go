package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestD42LookupCrossesItsChunkBoundary: the lookup of the no-redirect list takes 500 names at a time (spec 3.6, D31). A create and
// an Import of 501 and of 1,000 patterns, with the Iranian one last (past the first chunk, and at the end of the second),
// are refused with iranian_name at that pointer, for a name under .ir and for an entry of the list. A loop that skipped
// every chunk after the first, or filled the answer for the first only, would accept them (p2-B8-r2-2).
func TestD42LookupCrossesItsChunkBoundary(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	p := f.fresh(A.Tenant, A.User).mustProfile("Chunks", "custom")
	base := "/profiles/" + p.ID.String()
	f.env.Exec(t, `INSERT INTO ctrlz.catalog_no_redirect_domain (pattern, scope) VALUES ('digikala.com', 'domain') ON CONFLICT (pattern) DO NOTHING`)
	host := map[string]any{"kind": "host", "host": "proxy.example.net"}
	var before int
	f.env.Scan(t, `SELECT count(*) FROM ctrlz.rules WHERE tenant_id = $1`, []any{A.Tenant}, &before)
	for _, size := range []int{501, 1000} {
		for _, iranian := range []string{"x.ir", "digikala.com"} {
			var pats []string
			var docRules []string
			for i := 0; i < size-1; i++ {
				pat := fmt.Sprintf("h%d.example.com", i)
				pats = append(pats, pat)
				docRules = append(docRules, fmt.Sprintf(`{"pattern":%q,"action":"redirect","target":{"kind":"host","host":"proxy.example.net"}}`, pat))
			}
			pats = append(pats, iranian)
			docRules = append(docRules, fmt.Sprintf(`{"pattern":%q,"action":"redirect","target":{"kind":"host","host":"proxy.example.net"}}`, iranian))
			last := size - 1

			var fl fieldList
			r := f.fresh(A.Tenant, A.User).post(base+"/rules", map[string]any{"patterns": pats, "action": "redirect", "target": host})
			if r.Code != 422 {
				t.Errorf("create of %d patterns, %s last: %d %s, want 422", size, iranian, r.Code, r.Body)
			} else if _ = json.Unmarshal(r.Body, &fl); !fl.has(fmt.Sprintf("/patterns/%d", last), "iranian_name") {
				t.Errorf("create of %d patterns, %s last: fields %+v, want iranian_name at /patterns/%d", size, iranian, fl.Fields, last)
			}

			doc := `{"format":"ctrlz-profile","version":1,"kind":"custom","name":"Chunk import","rules":[` + strings.Join(docRules, ",") + `]}`
			r = f.fresh(A.Tenant, A.User).do("POST", "/profiles:import", map[string]any{"document": b64(doc)}, idem(uuid.NewString()))
			fl = fieldList{}
			if r.Code != 422 {
				t.Errorf("import of %d rules, %s last: %d %s, want 422", size, iranian, r.Code, r.Body)
			} else if _ = json.Unmarshal(r.Body, &fl); !fl.has(fmt.Sprintf("/rules/%d/pattern", last), "iranian_name") {
				t.Errorf("import of %d rules, %s last: fields %+v, want iranian_name at /rules/%d/pattern", size, iranian, fl.Fields, last)
			}
		}
	}
	var after int
	f.env.Scan(t, `SELECT count(*) FROM ctrlz.rules WHERE tenant_id = $1`, []any{A.Tenant}, &after)
	var made int
	f.env.Scan(t, `SELECT count(*) FROM ctrlz.profiles WHERE tenant_id = $1 AND name = 'Chunk import'`, []any{A.Tenant}, &made)
	if after != before || made != 0 {
		t.Errorf("refused writes left %d rules (was %d) and %d imported profiles", after, before, made)
	}
}

package api

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestNoRedirectVectorsThroughEveryEditMoveCopyAndFolderRoute: spec 10.2 S4 for the operations that do not type a pattern. Each
// case of the no-redirect group, with the entries it names in the list, is put through the edit of an action, the group edit,
// the move of an inheriting rule into a Redirect folder (the single edit, the group edit, the move and the move into a new
// folder), the Folder Rule turned to Redirect, and Copy and Move of a Redirect row to another profile by both routes. A case
// that says iranian_name is refused at the pointer of its route and the tenant's rows and folders are as they were; a case
// that says allowed is accepted. A check that answered from the TLD alone and skipped the list would pass the .ir cases of
// TestD42ThroughEveryRouteThatEditsMovesOrCopies, and fails here at the first entry of the list (p2-B8-r2-4).
func TestNoRedirectVectorsThroughEveryEditMoveCopyAndFolderRoute(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	p := f.fresh(A.Tenant, A.User).mustProfile("D42 vectors", "custom")
	p2 := f.fresh(A.Tenant, A.User).mustProfile("D42 vectors two", "custom")
	base := "/profiles/" + p.ID.String()
	host := map[string]any{"kind": "host", "host": "proxy.example.net"}
	digest := func() string {
		var s string
		f.env.Scan(t, `SELECT (SELECT coalesce(md5(string_agg(x::text, '|' ORDER BY x::text)), '') FROM ctrlz.rules x WHERE tenant_id = $1) || '/' ||
			(SELECT coalesce(md5(string_agg(x::text, '|' ORDER BY x::text)), '') FROM ctrlz.rule_folders x WHERE tenant_id = $1) || '/' ||
			(SELECT count(*) FROM ctrlz.profiles WHERE tenant_id = $1)::text`, []any{A.Tenant}, &s)
		return s
	}
	call := func(method, path string, body any, extra ...map[string]string) *resp {
		return f.fresh(A.Tenant, A.User).do(method, path, body, extra...)
	}
	batch := func(body map[string]any) *resp {
		return call("POST", base+"/rules:batch", body, idem(uuid.NewString()))
	}
	folder := func(name, action string) string {
		body := map[string]any{"name": name, "kind": "standard", "action": action}
		if action == "redirect" {
			body["target"] = host
		}
		var out struct {
			ID uuid.UUID `json:"id"`
		}
		call("POST", base+"/folders", body).want(201, "").json(&out)
		return out.ID.String()
	}
	// rule creates the one rule of a scenario with an action that is never refused, and returns its id.
	rule := func(pattern, action, folderID string) string {
		body := map[string]any{"patterns": []string{pattern}, "action": action}
		if folderID != "" {
			body["folder_id"] = folderID
		}
		if r := call("POST", base+"/rules", body); r.Code != 201 {
			t.Fatalf("a %s rule for %q: %d %s", action, pattern, r.Code, r.Body)
		}
		var id string
		f.env.Scan(t, `SELECT id::text FROM ctrlz.rules WHERE profile_id = $1 ORDER BY created_at DESC LIMIT 1`, []any{p.ID}, &id)
		return id
	}
	// grandfathered turns the rule into a Redirect row the way a catalog update would have left it.
	grandfathered := func(id string) string {
		f.env.Exec(t, `UPDATE ctrlz.rules SET action = 'redirect', target_kind = 'host', target_host = 'proxy.example.net' WHERE id = $1`, id)
		return id
	}
	// A scenario builds its rows, then returns the one request that would put a Redirect on the pattern.
	type scenario struct {
		name, pointer string
		prepare       func(pattern string) func() *resp
	}
	scenarios := []scenario{
		{"edit of the action", "/pattern", func(pat string) func() *resp {
			id := rule(pat, "block", "")
			return func() *resp {
				return call("PATCH", base+"/rules/"+id, map[string]any{"action": "redirect", "target": host})
			}
		}},
		{"group edit of the action", "/ids/0", func(pat string) func() *resp {
			id := rule(pat, "block", "")
			return func() *resp {
				return batch(map[string]any{"op": "edit", "ids": []string{id}, "set": map[string]any{"action": "redirect", "target": host}})
			}
		}},
		{"edit of the folder of an inheriting rule", "/pattern", func(pat string) func() *resp {
			id := rule(pat, "inherit", folder("Bypass", "bypass"))
			rf := folder("Redirect", "redirect")
			return func() *resp { return call("PATCH", base+"/rules/"+id, map[string]any{"folder_id": rf}) }
		}},
		{"group edit of the folder of an inheriting rule", "/ids/0", func(pat string) func() *resp {
			id := rule(pat, "inherit", folder("Bypass", "bypass"))
			rf := folder("Redirect", "redirect")
			return func() *resp {
				return batch(map[string]any{"op": "edit", "ids": []string{id}, "set": map[string]any{"folder_id": rf}})
			}
		}},
		{"move of an inheriting rule into a Redirect folder", "/ids/0", func(pat string) func() *resp {
			id := rule(pat, "inherit", folder("Bypass", "bypass"))
			rf := folder("Redirect", "redirect")
			return func() *resp { return batch(map[string]any{"op": "move", "ids": []string{id}, "dest_folder_id": rf}) }
		}},
		{"move of an inheriting rule into a new Redirect folder", "/ids/0", func(pat string) func() *resp {
			id := rule(pat, "inherit", folder("Bypass", "bypass"))
			return func() *resp {
				return batch(map[string]any{"op": "move", "ids": []string{id},
					"new_folder": map[string]any{"name": "Made", "kind": "standard", "action": "redirect", "target": host}})
			}
		}},
		{"Folder Rule turned to Redirect over an inheriting rule", "/action", func(pat string) func() *resp {
			bf := folder("Bypass", "bypass")
			rule(pat, "inherit", bf)
			return func() *resp {
				return call("PATCH", base+"/folders/"+bf, map[string]any{"action": "redirect", "target": host})
			}
		}},
		{"copy of a Redirect row to another profile", "/ids/0", func(pat string) func() *resp {
			id := grandfathered(rule(pat, "block", ""))
			return func() *resp {
				return batch(map[string]any{"op": "copy", "ids": []string{id}, "dest_profile_id": p2.ID.String(), "dest_root": true})
			}
		}},
		{"move of a Redirect row to another profile", "/ids/0", func(pat string) func() *resp {
			id := grandfathered(rule(pat, "block", ""))
			return func() *resp {
				return batch(map[string]any{"op": "move", "ids": []string{id}, "dest_profile_id": p2.ID.String(), "dest_root": true})
			}
		}},
		{"transfer copy of a Redirect row", "/ids/0", func(pat string) func() *resp {
			id := grandfathered(rule(pat, "block", ""))
			return func() *resp {
				return call("POST", base+"/rules/"+id+":transfer", map[string]any{"op": "copy", "dest_profile_id": p2.ID.String(), "dest_root": true})
			}
		}},
		{"transfer move of a Redirect row", "/ids/0", func(pat string) func() *resp {
			id := grandfathered(rule(pat, "block", ""))
			return func() *resp {
				return call("POST", base+"/rules/"+id+":transfer", map[string]any{"op": "move", "dest_profile_id": p2.ID.String(), "dest_root": true})
			}
		}},
	}

	ran := 0
	for _, c := range vectorCases(t, "no-redirect") {
		if c.Error {
			continue // no rule can hold a pattern that is not one
		}
		f.env.Exec(t, `DELETE FROM ctrlz.catalog_no_redirect_domain WHERE pattern IN ('digikala.com', 'shop.example.com')`)
		for _, a := range c.Args {
			scope, name, _ := strings.Cut(a, ":")
			f.env.Exec(t, `INSERT INTO ctrlz.catalog_no_redirect_domain (pattern, scope) VALUES ($1, $2) ON CONFLICT (pattern) DO UPDATE SET scope = EXCLUDED.scope`, name, scope)
		}
		for _, s := range scenarios {
			// The tenant's bulk-write buckets: 36 cases of eleven writes each would meet them, so each scenario starts a quiet
			// ten minutes later.
			f.ck.add(10 * time.Minute)
			// Rules go before their folders.
			f.env.Exec(t, `DELETE FROM ctrlz.rules WHERE tenant_id = $1`, A.Tenant)
			f.env.Exec(t, `DELETE FROM ctrlz.rule_folders WHERE tenant_id = $1`, A.Tenant)
			attack := s.prepare(c.Input)
			before := digest()
			r := attack()
			switch c.Expect {
			case "iranian_name":
				var fl fieldList
				if r.Code != 422 || r.code() != "validation_failed" {
					t.Errorf("%s, %s (%q): %d %s, want 422 iranian_name at %s", c.ID, s.name, c.Input, r.Code, r.Body, s.pointer)
					break
				}
				r.json(&fl)
				if !fl.has(s.pointer, "iranian_name") {
					t.Errorf("%s, %s (%q): fields %+v, want iranian_name at %s", c.ID, s.name, c.Input, fl.Fields, s.pointer)
				}
				if after := digest(); after != before {
					t.Errorf("%s, %s (%q): a refused request changed the tenant's rows or folders", c.ID, s.name, c.Input)
				}
			default:
				if r.Code < 200 || r.Code > 299 {
					t.Errorf("%s, %s (%q): %d %s, want it allowed", c.ID, s.name, c.Input, r.Code, r.Body)
				}
			}
			ran++
		}
	}
	if ran < 10*len(scenarios) {
		t.Fatalf("only %d runs for %d scenarios", ran, len(scenarios))
	}
}

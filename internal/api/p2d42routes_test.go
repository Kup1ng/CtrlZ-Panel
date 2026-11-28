package api

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

// TestD42ThroughEveryRouteThatEditsMovesOrCopies: spec 10.2 S4 asks the no-redirect rule at every route that can put a Redirect
// on a name, not only where a pattern is typed. Each call below would leave an Iranian name under a Redirect (an edit of the
// action, of the pattern, of the folder an inheriting rule sits in, of a Folder Rule over such a rule, a group edit, and a
// Copy or Move through both routes with a folder of the profile, a new one, and another profile). Each is refused with
// iranian_name at the pointer the UI reads, and the tenant's rows and folders are as they were. The grandfathered row then
// shows what stays allowed: switching it off, a comment, an expiry, a move inside its profile, and a delete (spec 3.7).
func TestD42ThroughEveryRouteThatEditsMovesOrCopies(t *testing.T) {
	f := newFrig(t, frigOpts{})
	A := f.env.A
	p := f.fresh(A.Tenant, A.User).mustProfile("D42 edits", "custom")
	p2 := f.fresh(A.Tenant, A.User).mustProfile("D42 edits two", "custom")
	base := "/profiles/" + p.ID.String()
	host := map[string]any{"kind": "host", "host": "proxy.example.net"}
	newFolder := func(name, action string) string {
		body := map[string]any{"name": name, "kind": "standard", "action": action}
		if action == "redirect" {
			body["target"] = host
		}
		var out struct {
			ID uuid.UUID `json:"id"`
		}
		f.fresh(A.Tenant, A.User).post(base+"/folders", body).want(201, "").json(&out)
		return out.ID.String()
	}
	rf, bf := newFolder("Redirect", "redirect"), newFolder("Bypass", "bypass")
	mk := func(pattern, action, folder string, target any) {
		body := map[string]any{"patterns": []string{pattern}, "action": action}
		if folder != "" {
			body["folder_id"] = folder
		}
		if target != nil {
			body["target"] = target
		}
		f.fresh(A.Tenant, A.User).post(base+"/rules", body).want(201, "")
	}
	mk("shop.ir", "block", "", nil)
	mk("b.example", "block", "", nil)
	mk("r.example", "redirect", "", host)
	mk("inh.ir", "inherit", bf, nil)
	// A grandfathered Iranian Redirect, planted as a catalog update would have made it.
	f.env.Exec(t, `INSERT INTO ctrlz.rules (tenant_id, profile_id, rule_key, match_kind, action, target_kind, target_host) VALUES ($1, $2, 'gf.ir', 'domain', 'redirect', 'host', 'proxy.example.net')`, A.Tenant, p.ID)
	id := func(key string) string {
		var s string
		f.env.Scan(t, `SELECT id::text FROM ctrlz.rules WHERE profile_id = $1 AND rule_key = $2`, []any{p.ID, key}, &s)
		return s
	}
	ir, plain, redirectRule, inherit, gf := id("shop.ir"), id("b.example"), id("r.example"), id("inh.ir"), id("gf.ir")
	digest := func() string {
		var s string
		f.env.Scan(t, `SELECT (SELECT coalesce(md5(string_agg(x::text, '|' ORDER BY x::text)), '') FROM ctrlz.rules x WHERE tenant_id = $1) || '/' ||
			(SELECT coalesce(md5(string_agg(x::text, '|' ORDER BY x::text)), '') FROM ctrlz.rule_folders x WHERE tenant_id = $1) || '/' ||
			(SELECT count(*) FROM ctrlz.profiles WHERE tenant_id = $1)::text`, []any{A.Tenant}, &s)
		return s
	}
	batch := func(body map[string]any) *resp {
		return f.fresh(A.Tenant, A.User).do("POST", base+"/rules:batch", body, idem(uuid.NewString()))
	}
	newFolderBody := map[string]any{"name": "Made", "kind": "standard", "action": "redirect", "target": host}

	type refusal struct {
		name string
		send func() *resp
		at   string
	}
	for _, c := range []refusal{
		{"an Iranian Block rule edited to Redirect", func() *resp {
			return f.fresh(A.Tenant, A.User).do("PATCH", base+"/rules/"+ir, map[string]any{"action": "redirect", "target": host})
		}, "/pattern"},
		{"the pattern of a Redirect rule edited to an Iranian name", func() *resp {
			return f.fresh(A.Tenant, A.User).do("PATCH", base+"/rules/"+redirectRule, map[string]any{"pattern": "x.ir"})
		}, "/pattern"},
		{"an inheriting Iranian rule moved into a Redirect folder", func() *resp {
			return f.fresh(A.Tenant, A.User).do("PATCH", base+"/rules/"+inherit, map[string]any{"folder_id": rf})
		}, "/pattern"},
		{"a Folder Rule turned to Redirect over an inheriting Iranian rule", func() *resp {
			return f.fresh(A.Tenant, A.User).do("PATCH", base+"/folders/"+bf, map[string]any{"action": "redirect", "target": host})
		}, "/action"},
		{"a group edit of the action", func() *resp {
			return batch(map[string]any{"op": "edit", "ids": []string{plain, ir}, "set": map[string]any{"action": "redirect", "target": host}})
		}, "/ids/1"},
		{"a group edit moving an inheriting Iranian rule into a Redirect folder", func() *resp {
			return batch(map[string]any{"op": "edit", "ids": []string{inherit}, "set": map[string]any{"folder_id": rf}})
		}, "/ids/0"},
		{"a move into a Redirect folder of the profile", func() *resp {
			return batch(map[string]any{"op": "move", "ids": []string{inherit}, "dest_folder_id": rf})
		}, "/ids/0"},
		{"a move into a new Redirect folder", func() *resp {
			return batch(map[string]any{"op": "move", "ids": []string{inherit}, "new_folder": newFolderBody})
		}, "/ids/0"},
		{"a copy of the grandfathered row to another profile", func() *resp {
			return batch(map[string]any{"op": "copy", "ids": []string{gf}, "dest_profile_id": p2.ID.String(), "dest_root": true})
		}, "/ids/0"},
		{"a copy of the grandfathered row to a new folder of another profile", func() *resp {
			return batch(map[string]any{"op": "copy", "ids": []string{gf}, "dest_profile_id": p2.ID.String(), "new_folder": map[string]any{"name": "Made", "kind": "standard"}})
		}, "/ids/0"},
		{"a move of the grandfathered row to another profile", func() *resp {
			return batch(map[string]any{"op": "move", "ids": []string{gf}, "dest_profile_id": p2.ID.String(), "dest_root": true})
		}, "/ids/0"},
		{"a transfer of the grandfathered row to a new folder of another profile", func() *resp {
			return f.fresh(A.Tenant, A.User).do("POST", base+"/rules/"+gf+":transfer",
				map[string]any{"op": "move", "dest_profile_id": p2.ID.String(), "new_folder": map[string]any{"name": "Made", "kind": "standard"}})
		}, "/ids/0"},
	} {
		before := digest()
		r := c.send()
		var fl fieldList
		_ = json.Unmarshal(r.Body, &fl)
		if r.Code != 422 || r.code() != "validation_failed" || !fl.has(c.at, "iranian_name") {
			t.Errorf("%s: %d %s, want 422 iranian_name at %s", c.name, r.Code, r.Body, c.at)
		}
		if after := digest(); after != before {
			t.Errorf("%s: a refused request changed the tenant's rows or folders", c.name)
		}
	}

	// What stays allowed on the grandfathered row: nothing that leaves its checked values alone is refused.
	rule := base + "/rules/" + gf
	for _, c := range []struct {
		name string
		send func() *resp
	}{
		{"an expiry", func() *resp { return f.fresh(A.Tenant, A.User).do("PATCH", rule, map[string]any{"expires_in": "1d"}) }},
		{"a group switch off", func() *resp { return batch(map[string]any{"op": "disable", "ids": []string{gf}}) }},
		{"a group comment", func() *resp {
			return batch(map[string]any{"op": "edit", "ids": []string{gf}, "set": map[string]any{"comment": "kept"}})
		}},
		{"a move inside its profile", func() *resp {
			return batch(map[string]any{"op": "move", "ids": []string{gf}, "dest_folder_id": bf})
		}},
	} {
		if r := c.send(); r.Code != 200 {
			t.Errorf("%s on the grandfathered row: %d %s, want 200", c.name, r.Code, r.Body)
		}
	}
	var folder string
	var enabled bool
	f.env.Scan(t, `SELECT folder_id::text, enabled FROM ctrlz.rules WHERE id = $1`, []any{gf}, &folder, &enabled)
	if folder != bf || enabled {
		t.Errorf("the grandfathered row is in folder %s, enabled %v, want the bypass folder and off", folder, enabled)
	}
	if r := batch(map[string]any{"op": "delete", "ids": []string{gf}}); r.Code != 200 {
		t.Errorf("a group delete of the grandfathered row: %d %s, want 200", r.Code, r.Body)
	}
	var n int
	f.env.Scan(t, `SELECT count(*) FROM ctrlz.rules WHERE id = $1`, []any{gf}, &n)
	if n != 0 {
		t.Errorf("the grandfathered row is still there after its delete")
	}
}

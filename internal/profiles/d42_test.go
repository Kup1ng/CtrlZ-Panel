package profiles_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Shared/vectors"

	"github.com/Kup1ng/CtrlZ-Panel/internal/profiles"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// TestD42RefusesRedirectOnIranianNames walks every route of the write path that takes a pattern with Redirect on
// the cases of the no-redirect group: each is refused with iranian_name at its pointer and writes nothing, and the
// same names with Block or Bypass pass (spec 3.6, 10.2 S4).
func TestD42RefusesRedirectOnIranianNames(t *testing.T) {
	f := newFx(t)
	p := f.newProfile(t, f.A.Tenant, "d42")
	cases := []struct {
		pattern string
		bad     bool
	}{
		{"example.ir", true}, {"www.example.ir", true}, {"ir", true}, {"xn--mgba3a4f16a", true}, {"example.xn--mgba3a4f16a", true},
		{"digikala.com", true}, {"www.digikala.com", true}, {"*.digikala.com", true}, {"server-*.digikala.com", true},
		{"*.example.ir", true}, {"@IR", true},
		{"www.mofidonline.com", true},    // a host entry: its exact name
		{"a.www.mofidonline.com", false}, // a host entry does not cover the names under it
		{"example.com", false}, {"ir.example.com", false}, {"iran.com", false}, {"!@IR", false}, {"@DE", false}, {"#IR", false},
	}
	for _, c := range cases {
		t.Run(c.pattern, func(t *testing.T) {
			before := f.digest(t, p)
			err := f.in(f.A.Tenant, func(tx store.Tx) error {
				_, err := f.env.CreateRules(tx, p, profiles.RuleIn{Patterns: []string{c.pattern}, Act: redirectHost("proxy.example.net")})
				return err
			})
			if c.bad {
				e, ok := err.(*profiles.Error)
				if !ok || !hasField(e, "/patterns/0", "iranian_name") {
					t.Fatalf("a Redirect on %s was not refused as iranian_name: %v", c.pattern, err)
				}
				if f.digest(t, p) != before {
					t.Error("the refusal wrote something")
				}
			} else if err != nil {
				t.Fatalf("a Redirect on %s was refused: %v", c.pattern, err)
			}
			// Block and Bypass are never refused for these names.
			for _, act := range []string{"block", "bypass"} {
				if err := f.in(f.A.Tenant, func(tx store.Tx) error {
					_, err := f.env.CreateRules(tx, p, profiles.RuleIn{Patterns: []string{c.pattern}, Act: profiles.Act{Action: act}})
					return err
				}); err != nil && !hasField(err.(*profiles.Error), "/patterns/0", "exists") {
					t.Errorf("%s on %s: %v", act, c.pattern, err)
				}
				f.exec(t, `DELETE FROM ctrlz.rules WHERE profile_id = $1`, p)
			}
			f.exec(t, `DELETE FROM ctrlz.rules WHERE profile_id = $1`, p)
		})
	}
}

// TestD42FolderRules: a Folder Rule that is a Redirect over an inheriting Iranian rule, and an inheriting Iranian
// rule written into such a folder, are refused; a Redirect folder holding a Block rule of an Iranian name is fine.
func TestD42FolderRules(t *testing.T) {
	f := newFx(t)
	p := f.newProfile(t, f.A.Tenant, "folders")
	var redirectFolder, bypassFolder uuid.UUID
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		r, err := f.env.CreateFolder(tx, p, profiles.FolderIn{Name: "redirect", Kind: "standard", Act: redirectHost("proxy.example.net")})
		if err != nil {
			return err
		}
		redirectFolder = r.ID
		b, err := f.env.CreateFolder(tx, p, profiles.FolderIn{Name: "bypass", Kind: "standard", Act: profiles.Act{Action: "bypass"}})
		bypassFolder = b.ID
		return err
	})
	inherit := profiles.Act{Action: "inherit"}
	e := f.refusal(t, f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.CreateRules(tx, p, profiles.RuleIn{Patterns: []string{"example.ir"}, Act: inherit, FolderID: redirectFolder})
		return err
	})
	if !hasField(e, "/patterns/0", "iranian_name") {
		t.Errorf("an inheriting Iranian rule in a Redirect folder: %v", e)
	}
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.CreateRules(tx, p, profiles.RuleIn{Patterns: []string{"example.ir"}, Act: block(), FolderID: redirectFolder})
		return err
	})
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.CreateRules(tx, p, profiles.RuleIn{Patterns: []string{"other.ir"}, Act: inherit, FolderID: bypassFolder})
		return err
	})
	// The folder rule turns into a Redirect over an inheriting Iranian rule.
	e = f.refusal(t, f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.UpdateFolder(tx, p, bypassFolder, profiles.FolderPatch{Act: &profiles.Act{Action: "redirect", Target: profiles.Target{Kind: "host", Host: "proxy.example.net"}}})
		return err
	})
	if !hasField(e, "/action", "iranian_name") {
		t.Errorf("a Redirect Folder Rule over an inheriting Iranian rule: %v", e)
	}
	// Clearing a Folder Rule while a rule inherits it is refused.
	e = f.refusal(t, f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.UpdateFolder(tx, p, bypassFolder, profiles.FolderPatch{Clear: []string{"action"}})
		return err
	})
	if !hasField(e, "/action", "has_inheriting_rules") {
		t.Errorf("clearing a Folder Rule that rules inherit: %v", e)
	}
	// A rule moved into the Redirect folder inherits its action there.
	var other uuid.UUID
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		rs, err := f.env.CreateRules(tx, p, profiles.RuleIn{Patterns: []string{"moved.ir"}, Act: inherit, FolderID: bypassFolder})
		other = rs[0].ID
		return err
	})
	e = f.refusal(t, f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.RulesBatch(tx, p, profiles.BatchIn{Op: "move", IDs: []uuid.UUID{other}, DestFolder: redirectFolder})
		return err
	})
	if !hasField(e, "/ids/0", "iranian_name") {
		t.Errorf("moving an inheriting Iranian rule into a Redirect folder: %v", e)
	}
}

// TestD42GrandfatheredRows: a rule that a later list covers stays in place and can still be switched, commented,
// expired, moved and removed; carrying it into another profile (Copy, Move) is a new write and is refused (3.6, 3.7).
func TestD42GrandfatheredRows(t *testing.T) {
	f := newFx(t)
	p := f.newProfile(t, f.A.Tenant, "old")
	other := f.newProfile(t, f.A.Tenant, "other")
	f.exec(t, `INSERT INTO ctrlz.rules (tenant_id, profile_id, rule_key, match_kind, action, target_kind, target_host)
VALUES ($1, $2, 'later.ir', 'domain', 'redirect', 'host', 'proxy.example.net')`, f.A.Tenant, p)
	var id uuid.UUID
	if err := f.db.Scan(f.ctx, `SELECT id FROM ctrlz.rules WHERE profile_id = $1`, []any{p}, &id); err != nil {
		t.Fatal(err)
	}
	off := false
	comment := "kept"
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		if _, err := f.env.UpdateRule(tx, p, id, profiles.RulePatch{Enabled: &off, Comment: &comment, Expiry: &profiles.Expiry{In: "1d"}}); err != nil {
			return err
		}
		if _, err := f.env.RulesBatch(tx, p, profiles.BatchIn{Op: "enable", IDs: []uuid.UUID{id}}); err != nil {
			return err
		}
		// The same action and target sent again is not a set value.
		_, err := f.env.UpdateRule(tx, p, id, profiles.RulePatch{Act: &profiles.Act{Action: "redirect", Target: profiles.Target{Kind: "host", Host: "proxy.example.net"}}})
		return err
	})
	for _, op := range []string{"copy", "move"} {
		before, beforeOther := f.digest(t, p), f.digest(t, other)
		e := f.refusal(t, f.A.Tenant, func(tx store.Tx) error {
			_, err := f.env.RulesBatch(tx, p, profiles.BatchIn{Op: op, IDs: []uuid.UUID{id}, DestProfile: other, DestRoot: true})
			return err
		})
		if !hasField(e, "/ids/0", "iranian_name") {
			t.Errorf("%s of a grandfathered Iranian Redirect: %v", op, e)
		}
		if f.digest(t, p) != before || f.digest(t, other) != beforeOther {
			t.Errorf("%s: a refusal wrote something", op)
		}
	}
	// Setting it to Block fixes it, and then it carries.
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		if _, err := f.env.UpdateRule(tx, p, id, profiles.RulePatch{Act: &profiles.Act{Action: "block"}}); err != nil {
			return err
		}
		_, err := f.env.RulesBatch(tx, p, profiles.BatchIn{Op: "copy", IDs: []uuid.UUID{id}, DestProfile: other, DestRoot: true})
		return err
	})
	f.must(t, f.A.Tenant, func(tx store.Tx) error { return f.env.DeleteRule(tx, p, id) })
}

// TestD42Services: a service whose catalog row says redirect_allowed is false refuses a Redirect with iranian_name,
// on the single and the group call, and accepts Block and Bypass; a service that may be redirected accepts it.
func TestD42Services(t *testing.T) {
	f := newFx(t)
	p := f.newProfile(t, f.A.Tenant, "services")
	toHost := profiles.ServiceState{Enabled: true, Act: redirectHost("proxy.example.net")}
	for _, slugs := range [][]string{{"digikala"}, {"aparat", "youtube"}, {"youtube", "digikala"}} {
		before := f.digest(t, p)
		e := f.refusal(t, f.A.Tenant, func(tx store.Tx) error { _, err := f.env.SetServices(tx, p, slugs, toHost); return err })
		bad := -1
		for i, s := range slugs {
			if s == "digikala" || s == "aparat" {
				bad = i
			}
		}
		if !hasField(e, "/slugs/"+string(rune('0'+bad)), "iranian_name") {
			t.Errorf("%v: %v", slugs, e)
		}
		if f.digest(t, p) != before {
			t.Errorf("%v: a refusal wrote something", slugs)
		}
	}
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		for _, act := range []string{"block", "bypass"} {
			if _, err := f.env.SetServices(tx, p, []string{"digikala", "aparat"}, profiles.ServiceState{Enabled: true, Act: profiles.Act{Action: act}}); err != nil {
				return err
			}
		}
		_, err := f.env.SetServices(tx, p, []string{"youtube"}, toHost)
		return err
	})
	// A service state that a later redirect_allowed = false covers stays and can be switched off.
	f.exec(t, `INSERT INTO ctrlz.profile_services (tenant_id, profile_id, service_slug, action, target_kind, target_host)
VALUES ($1, $2, 'snapp', 'redirect', 'host', 'proxy.example.net')`, f.A.Tenant, p)
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.SetServices(tx, p, []string{"snapp"}, profiles.ServiceState{Enabled: false, Act: redirectHost("proxy.example.net")})
		return err
	})
}

// TestNoRedirectVectorsThroughTheWritePath runs every case of the no-redirect group of the golden vectors through
// the route that creates rules, and through the pattern change of an existing rule: the shared predicate and the
// write path must give the answer the case carries (spec 10.3, 10.2 S4). The entries a case names are put into the
// list for the length of the case.
func TestNoRedirectVectorsThroughTheWritePath(t *testing.T) {
	f := newFx(t)
	p := f.newProfile(t, f.A.Tenant, "vectors")
	g, err := vectors.ReadGroup("no-redirect")
	if err != nil {
		t.Fatal(err)
	}
	var cases []vectors.TextCase
	if err := json.Unmarshal(g.Cases, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			f.exec(t, `DELETE FROM ctrlz.catalog_no_redirect_domain WHERE pattern IN ('digikala.com', 'shop.example.com')`)
			for _, a := range c.Args {
				scope, name, _ := strings.Cut(a, ":")
				f.exec(t, `INSERT INTO ctrlz.catalog_no_redirect_domain (pattern, scope) VALUES ($1, $2) ON CONFLICT (pattern) DO UPDATE SET scope = EXCLUDED.scope`, name, scope)
			}
			f.exec(t, `DELETE FROM ctrlz.rules WHERE profile_id = $1`, p)
			err := f.in(f.A.Tenant, func(tx store.Tx) error {
				_, err := f.env.CreateRules(tx, p, profiles.RuleIn{Patterns: []string{c.Input}, Act: redirectHost("proxy.example.net")})
				return err
			})
			e, refused := err.(*profiles.Error)
			switch {
			case c.Error:
				if !refused || len(e.Fields) != 1 || !strings.HasPrefix(e.Fields[0].Code, "pattern_") {
					t.Errorf("want a pattern code, got %v", err)
				}
			case c.Expect == "iranian_name":
				if !refused || !hasField(e, "/patterns/0", "iranian_name") {
					t.Errorf("want iranian_name, got %v", err)
				}
			default:
				if err != nil {
					t.Errorf("want it allowed, got %v", err)
				}
			}
			if c.Error || err != nil {
				return
			}
			// The same pattern reached by editing another rule that is a Redirect.
			var id uuid.UUID
			f.exec(t, `INSERT INTO ctrlz.rules (tenant_id, profile_id, rule_key, match_kind, action, target_kind, target_host)
VALUES ($1, $2, 'seed.example.com', 'domain', 'redirect', 'host', 'proxy.example.net')`, f.A.Tenant, p)
			if err := f.db.Scan(f.ctx, `SELECT id FROM ctrlz.rules WHERE profile_id = $1 AND rule_key = 'seed.example.com'`, []any{p}, &id); err != nil {
				t.Fatal(err)
			}
			in := c.Input
			err = f.in(f.A.Tenant, func(tx store.Tx) error {
				_, err := f.env.UpdateRule(tx, p, id, profiles.RulePatch{Pattern: &in})
				return err
			})
			if c.Expect == "iranian_name" {
				if e, ok := err.(*profiles.Error); !ok || !hasField(e, "/pattern", "iranian_name") {
					t.Errorf("an edit to the same pattern: want iranian_name, got %v", err)
				}
			}
		})
	}
}

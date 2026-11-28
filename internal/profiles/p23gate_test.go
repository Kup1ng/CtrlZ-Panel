package profiles_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/profiles"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The gaps the gate of P2 and P3 found in the rows T-138, T-184, T-186, T-193 and T-205: every value of a closed set and
// each bound, through the service the routes call, over real Postgres.

// TestDisableEveryForValueAndTheBoundsOfUntil: for=5m, 1h and 1d end at the application time plus the duration; an until
// in the future is stored as sent; the bound is a year (366 days) and one second past it is /until invalid; both forms
// together, a time that is not after now, and neither form are each refused and write nothing; Enable clears every one
// (spec 10.4 Disable, T-138). Change 5m to 4m or 1d to 12h in DisableUntil and the table fails; drop the year bound and the
// 366-day-and-a-second case is stored.
func TestDisableEveryForValueAndTheBoundsOfUntil(t *testing.T) {
	f := newFx(t)
	p := f.newProfile(t, f.A.Tenant, "disable table")
	disable := func(forText string, until *time.Time) (store.Profile, error) {
		var got store.Profile
		err := f.in(f.A.Tenant, func(tx store.Tx) (e error) { got, e = f.env.Disable(tx, p, forText, until); return })
		return got, err
	}
	enable := func() {
		t.Helper()
		f.must(t, f.A.Tenant, func(tx store.Tx) error { _, err := f.env.Enable(tx, p); return err })
	}
	for _, c := range []struct {
		forText string
		d       time.Duration
	}{{"5m", 5 * time.Minute}, {"1h", time.Hour}, {"1d", 24 * time.Hour}} {
		got, err := disable(c.forText, nil)
		if err != nil || got.DisabledUntil == nil || !got.DisabledUntil.Equal(f.now.Add(c.d)) {
			t.Errorf("for=%s: disabled until %v (%v), want %v", c.forText, got.DisabledUntil, err, f.now.Add(c.d))
		}
		enable()
	}

	// A moment in the future is kept as it was sent, and Enable clears it.
	when := f.now.Add(40 * time.Hour).Add(17 * time.Minute)
	if got, err := disable("", &when); err != nil || got.DisabledUntil == nil || !got.DisabledUntil.Equal(when) {
		t.Errorf("until=%v: stored %v (%v)", when, got.DisabledUntil, err)
	}
	enable()
	var left *time.Time
	f.scan(t, `SELECT disabled_until FROM ctrlz.profiles WHERE id = $1`, []any{p}, &left)
	if left != nil {
		t.Errorf("Enable left disabled_until %v", left)
	}
	// The far end of the bound is allowed; a second beyond it is not.
	edge := f.now.Add(366 * 24 * time.Hour)
	if got, err := disable("", &edge); err != nil || got.DisabledUntil == nil || !got.DisabledUntil.Equal(edge) {
		t.Errorf("until at the bound: %v (%v)", got.DisabledUntil, err)
	}
	enable()

	before := f.digest(t, p)
	over := edge.Add(time.Second)
	now := f.now
	for _, c := range []struct {
		name    string
		forText string
		until   *time.Time
		field   string
		code    string
	}{
		{"a year and a second", "", &over, "/until", "invalid"},
		{"until is now", "", &now, "/until", "in_past"},
		{"both forms", "1h", &when, "/until", "invalid"},
		{"an unknown for", "30m", nil, "/for", "invalid"},
		{"neither form", "", nil, "/for", "required"},
	} {
		e := f.refusal(t, f.A.Tenant, func(tx store.Tx) error { _, err := f.env.Disable(tx, p, c.forText, c.until); return err })
		if !hasField(e, c.field, c.code) {
			t.Errorf("%s: got %v, want %s %s", c.name, e, c.field, c.code)
		}
	}
	if f.digest(t, p) != before {
		t.Error("a refused Disable wrote something")
	}
}

func (f *fx) scan(t *testing.T, sql string, args []any, dst ...any) {
	t.Helper()
	if err := f.db.Scan(f.ctx, sql, args, dst...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// TestRuleExpiryEveryFormOnTheApplicationClock: expires_in 1h, 1d, 1w and 1m resolve to now plus 1 hour, 1 day, 7 days and
// 30 days on the application clock, on create and on edit; expires_at beyond a year, expires_in together with expires_at,
// and an unknown expires_in are invalid at the member the request used, and a past expires_at is in_past; none of them
// writes (spec 3.7, 10.4, T-184). Make 1m a calendar month or drop the year bound and a row of the table fails.
func TestRuleExpiryEveryFormOnTheApplicationClock(t *testing.T) {
	f := newFx(t)
	p := f.newProfile(t, f.A.Tenant, "expiry")
	create := func(pattern string, x profiles.Expiry) (store.RuleRow, error) {
		var rows []store.RuleRow
		err := f.in(f.A.Tenant, func(tx store.Tx) (e error) {
			rows, e = f.env.CreateRules(tx, p, profiles.RuleIn{Patterns: []string{pattern}, Act: block(), Expiry: x})
			return
		})
		if len(rows) == 1 {
			return rows[0], err
		}
		return store.RuleRow{}, err
	}
	for _, c := range []struct {
		in string
		d  time.Duration
	}{{"1h", time.Hour}, {"1d", 24 * time.Hour}, {"1w", 7 * 24 * time.Hour}, {"1m", 30 * 24 * time.Hour}} {
		r, err := create("in-"+c.in+".example.com", profiles.Expiry{In: c.in})
		if err != nil || r.ExpiresAt == nil || !r.ExpiresAt.Equal(f.now.Add(c.d)) {
			t.Errorf("expires_in=%s: %v (%v), want %v", c.in, r.ExpiresAt, err, f.now.Add(c.d))
		}
	}
	// A moment of the request is kept as it was sent.
	at := f.now.Add(10 * 24 * time.Hour)
	if r, err := create("at.example.com", profiles.Expiry{At: at, HasAt: true}); err != nil || r.ExpiresAt == nil || !r.ExpiresAt.Equal(at) {
		t.Errorf("expires_at: %v (%v)", r.ExpiresAt, err)
	}
	// An edit resolves the shortcut on the same clock.
	var id uuid.UUID
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		rs, err := f.env.CreateRules(tx, p, profiles.RuleIn{Patterns: []string{"edit.example.com"}, Act: block()})
		id = rs[0].ID
		return err
	})
	var edited store.RuleRow
	f.must(t, f.A.Tenant, func(tx store.Tx) (err error) {
		edited, err = f.env.UpdateRule(tx, p, id, profiles.RulePatch{Expiry: &profiles.Expiry{In: "1m"}})
		return
	})
	if edited.ExpiresAt == nil || !edited.ExpiresAt.Equal(f.now.Add(30*24*time.Hour)) {
		t.Errorf("an edit with expires_in=1m: %v", edited.ExpiresAt)
	}

	before := f.digest(t, p)
	far := f.now.Add(366*24*time.Hour + time.Second)
	past := f.now.Add(-time.Minute)
	for _, c := range []struct {
		name  string
		x     profiles.Expiry
		field string
		code  string
	}{
		{"beyond a year", profiles.Expiry{At: far, HasAt: true}, "/expires_at", "invalid"},
		{"in the past", profiles.Expiry{At: past, HasAt: true}, "/expires_at", "in_past"},
		{"both forms", profiles.Expiry{In: "1h", At: at, HasAt: true}, "/expires_in", "invalid"},
		{"an unknown shortcut", profiles.Expiry{In: "2h"}, "/expires_in", "invalid"},
	} {
		_, err := create("refused.example.com", c.x)
		e, ok := err.(*profiles.Error)
		if !ok || !hasField(e, c.field, c.code) {
			t.Errorf("%s: got %v, want %s %s", c.name, err, c.field, c.code)
		}
	}
	if f.digest(t, p) != before {
		t.Error("a refused expiry wrote a rule")
	}
}

// TestMagicFolderRules: the Do Not Log folder (the Magic folder) has no action: a folder of kind bypass is not available
// (D8), a Do Not Log folder with block, bypass or redirect is invalid at /action, an inheriting rule cannot be created,
// edited or moved into one, and one that inherits can only move to a folder that has a Folder Rule (spec 3.7, SC 4, T-186).
// Another tenant's folder is not found for a move (spec 10.4).
func TestMagicFolderRules(t *testing.T) {
	f := newFx(t)
	p := f.newProfile(t, f.A.Tenant, "magic")
	mk := func(in profiles.FolderIn) (store.FolderRow, error) {
		var row store.FolderRow
		err := f.in(f.A.Tenant, func(tx store.Tx) (e error) { row, e = f.env.CreateFolder(tx, p, in); return })
		return row, err
	}
	before := f.digest(t, p)
	if _, err := mk(profiles.FolderIn{Name: "Bypass", Kind: "bypass"}); err == nil || !hasField(err.(*profiles.Error), "/kind", "not_available") {
		t.Errorf("a folder of kind bypass: %v", err)
	}
	for _, a := range []profiles.Act{block(), {Action: "bypass"}, redirectHost("proxy.example.net")} {
		if _, err := mk(profiles.FolderIn{Name: "Magic", Kind: "do_not_log", Act: a}); err == nil || !hasField(err.(*profiles.Error), "/action", "invalid") {
			t.Errorf("a Do Not Log folder with %s: %v", a.Action, err)
		}
	}
	if f.digest(t, p) != before {
		t.Error("a refused folder was written")
	}
	magic, err := mk(profiles.FolderIn{Name: "Magic", Kind: "do_not_log"})
	if err != nil {
		t.Fatal(err)
	}
	// A Folder Rule cannot be added to it afterwards either.
	e := f.refusal(t, f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.UpdateFolder(tx, p, magic.ID, profiles.FolderPatch{Act: &profiles.Act{Action: "block"}})
		return err
	})
	if !hasField(e, "/action", "invalid") {
		t.Errorf("a Folder Rule on a Do Not Log folder: %v", e)
	}
	std, err := mk(profiles.FolderIn{Name: "Standard", Kind: "standard", Act: block()})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := mk(profiles.FolderIn{Name: "No rule", Kind: "standard"})
	if err != nil {
		t.Fatal(err)
	}

	// Create: inherit into the Magic folder is invalid; into a folder with a Folder Rule it is accepted; a plain action in
	// the Magic folder is accepted.
	create := func(pattern string, act profiles.Act, folder uuid.UUID) ([]store.RuleRow, error) {
		var rs []store.RuleRow
		err := f.in(f.A.Tenant, func(tx store.Tx) (e error) {
			rs, e = f.env.CreateRules(tx, p, profiles.RuleIn{Patterns: []string{pattern}, Act: act, FolderID: folder})
			return
		})
		return rs, err
	}
	inherit := profiles.Act{Action: "inherit"}
	if _, err := create("in-magic.example.com", inherit, magic.ID); err == nil || !hasField(err.(*profiles.Error), "/action", "invalid") {
		t.Errorf("create inherit in the Magic folder: %v", err)
	}
	if _, err := create("in-plain.example.com", inherit, plain.ID); err == nil || !hasField(err.(*profiles.Error), "/action", "needs_folder_action") {
		t.Errorf("create inherit in a folder with no Folder Rule: %v", err)
	}
	mr, err := create("block-in-magic.example.com", block(), magic.ID)
	if err != nil {
		t.Fatalf("a block rule in the Magic folder: %v", err)
	}
	ir, err := create("inherits.example.com", inherit, std.ID)
	if err != nil {
		t.Fatalf("inherit in a folder with a Folder Rule: %v", err)
	}

	// Edit: a rule in the Magic folder cannot be set to inherit.
	e = f.refusal(t, f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.UpdateRule(tx, p, mr[0].ID, profiles.RulePatch{Act: &inherit})
		return err
	})
	if !hasField(e, "/action", "invalid") {
		t.Errorf("edit to inherit in the Magic folder: %v", e)
	}
	// Move: a rule that inherits cannot move to the Magic folder, to a folder with no Folder Rule, or to the top level.
	for name, to := range map[string]profiles.RulePatch{
		"magic": {FolderID: &magic.ID}, "no folder rule": {FolderID: &plain.ID}, "top level": {Clear: []string{"folder"}},
	} {
		wantCode := "needs_folder_action"
		if name == "magic" {
			wantCode = "invalid"
		}
		e = f.refusal(t, f.A.Tenant, func(tx store.Tx) error { _, err := f.env.UpdateRule(tx, p, ir[0].ID, to); return err })
		if !hasField(e, "/action", wantCode) {
			t.Errorf("move an inheriting rule to %s: %v, want /action %s", name, e, wantCode)
		}
	}
	// The same through the group move of a batch: the item is named by its place in the request.
	e = f.refusal(t, f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.RulesBatch(tx, p, profiles.BatchIn{Op: "move", IDs: []uuid.UUID{ir[0].ID}, DestProfile: p, DestFolder: magic.ID})
		return err
	})
	if !hasField(e, "/ids/0/action", "invalid") {
		t.Errorf("a group move of an inheriting rule to the Magic folder: %v", e)
	}
	var folderOf uuid.UUID
	f.scan(t, `SELECT folder_id FROM ctrlz.rules WHERE id = $1`, []any{ir[0].ID}, &folderOf)
	if folderOf != std.ID {
		t.Errorf("a refused move left the rule in folder %s, want %s", folderOf, std.ID)
	}
	// Another tenant's folder is not found.
	pb := f.newProfile(t, f.B.Tenant, "magic b")
	var bFolder store.FolderRow
	f.must(t, f.B.Tenant, func(tx store.Tx) (err error) {
		bFolder, err = f.env.CreateFolder(tx, pb, profiles.FolderIn{Name: "Magic", Kind: "do_not_log"})
		return
	})
	e = f.refusal(t, f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.UpdateRule(tx, p, ir[0].ID, profiles.RulePatch{FolderID: &bFolder.ID})
		return err
	})
	if e.Kind != profiles.KindNotFound {
		t.Errorf("a move into tenant B's folder: %v", e)
	}
}

// TestBlockResponseModes: zero, nxdomain and refused are each stored and read back with no address; a simple mode that
// carries v4 or v6 is invalid at /block_response; switching from custom to a simple mode clears both addresses in the row; an
// unknown mode is invalid at /block_response/mode; tenant B's row is not touched by A's (spec 3.7, 10.4 Options, T-205).
func TestBlockResponseModes(t *testing.T) {
	f := newFx(t)
	p := f.newProfile(t, f.A.Tenant, "block response")
	pb := f.newProfile(t, f.B.Tenant, "block response b")
	patch := func(profile uuid.UUID, tenant uuid.UUID, b profiles.BlockResponse) (store.OptionsRow, error) {
		var row store.OptionsRow
		err := f.in(tenant, func(tx store.Tx) (e error) {
			row, e = f.env.PatchOptions(tx, profile, profiles.OptionsPatch{BlockResponse: &b})
			return
		})
		return row, err
	}
	read := func(profile, tenant uuid.UUID) store.OptionsRow {
		t.Helper()
		var row store.OptionsRow
		f.must(t, tenant, func(tx store.Tx) error {
			var ok bool
			var err error
			row, ok, err = tx.Options(profile)
			if err == nil && !ok {
				err = fmt.Errorf("no options row")
			}
			return err
		})
		return row
	}
	if _, err := patch(pb, f.B.Tenant, profiles.BlockResponse{Mode: "custom", V4: "203.0.113.5", V6: "2001:db8::5"}); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"zero", "nxdomain", "refused"} {
		// Each simple mode replaces a custom answer, so the addresses of the one before must be gone.
		if _, err := patch(p, f.A.Tenant, profiles.BlockResponse{Mode: "custom", V4: "203.0.113.9", V6: "2001:db8::9"}); err != nil {
			t.Fatal(err)
		}
		got, err := patch(p, f.A.Tenant, profiles.BlockResponse{Mode: mode})
		if err != nil || got.BlockResponse != mode || got.BlockV4 != "" || got.BlockV6 != "" {
			t.Errorf("mode %s: %+v (%v)", mode, got, err)
		}
		if row := read(p, f.A.Tenant); row.BlockResponse != mode || row.BlockV4 != "" || row.BlockV6 != "" {
			t.Errorf("mode %s read back as %+v", mode, row)
		}
	}
	before := f.digest(t, p)
	for _, c := range []struct {
		name  string
		b     profiles.BlockResponse
		field string
		code  string
	}{
		{"zero with v4", profiles.BlockResponse{Mode: "zero", V4: "192.0.2.1"}, "/block_response", "invalid"},
		{"nxdomain with v6", profiles.BlockResponse{Mode: "nxdomain", V6: "2001:db8::1"}, "/block_response", "invalid"},
		{"refused with both", profiles.BlockResponse{Mode: "refused", V4: "192.0.2.1", V6: "2001:db8::1"}, "/block_response", "invalid"},
		{"an unknown mode", profiles.BlockResponse{Mode: "weird"}, "/block_response/mode", "invalid"},
		{"an empty mode", profiles.BlockResponse{}, "/block_response/mode", "invalid"},
	} {
		_, err := patch(p, f.A.Tenant, c.b)
		e, ok := err.(*profiles.Error)
		if !ok || !hasField(e, c.field, c.code) {
			t.Errorf("%s: got %v, want %s %s", c.name, err, c.field, c.code)
		}
	}
	if f.digest(t, p) != before {
		t.Error("a refused block response wrote something")
	}
	if row := read(pb, f.B.Tenant); row.BlockResponse != "custom" || row.BlockV4 != "203.0.113.5" || !strings.HasPrefix(row.BlockV6, "2001:db8:") {
		t.Errorf("tenant B's block response changed: %+v", row)
	}
}

// TestTransferRechecksTheDestination: a copy or a move into another profile counts the destination's own limits and location
// set again. A destination at max_rules_per_profile or max_wildcards_per_profile is refused with exceeded and nothing is written
// in either profile; a Redirect rule whose location the destination's pair lacks is refused with location_not_allowed at
// /ids/<i>/target/location, and a fixed host carries as it is; tenant B's own limits are its own (spec 8.3 batch semantics,
// 4.2, T-193). Remove the destination's d.target call in transfer and the location case writes the rule; remove the cap check
// of insertRules and the limit cases write past the cap.
func TestTransferRechecksTheDestination(t *testing.T) {
	f := newFx(t)
	frankfurt, ny := f.loc(t, "DE", "Frankfurt"), f.loc(t, "US", "New York")
	// The destination is the seeded profile of tenant A, used by A's seeded Endpoint, which sits on the pair of nodes 1 and 3;
	// node 3 has Frankfurt only, so the set of the destination is {Frankfurt} while the global pair's has New York too.
	f.exec(t, `INSERT INTO ctrlz.nodes (id, slot, name, status, dns_advertised_ip) VALUES ('00000000-0000-7000-8000-0000000000c3', 3, 'node-3', 'active', '192.0.2.3')`)
	f.exec(t, `INSERT INTO ctrlz.location_availability (node_id, location_id) VALUES ('00000000-0000-7000-8000-0000000000c3', $1)`, frankfurt)
	f.exec(t, `UPDATE ctrlz.endpoints SET pair_override_node_a = '00000000-0000-7000-8000-0000000000c1', pair_override_node_b = '00000000-0000-7000-8000-0000000000c3' WHERE id = $1`, f.A.Endpoint)
	dst := f.A.Profile

	rules := func(profile, tenant uuid.UUID, act profiles.Act, patterns ...string) []uuid.UUID {
		t.Helper()
		var ids []uuid.UUID
		f.must(t, tenant, func(tx store.Tx) error {
			rs, err := f.env.CreateRules(tx, profile, profiles.RuleIn{Patterns: patterns, Act: act})
			for _, r := range rs {
				ids = append(ids, r.ID)
			}
			return err
		})
		return ids
	}
	transfer := func(op string, src, dest uuid.UUID, ids []uuid.UUID) (profiles.BatchResult, error) {
		var res profiles.BatchResult
		err := f.in(f.A.Tenant, func(tx store.Tx) (e error) {
			res, e = f.env.RulesBatch(tx, src, profiles.BatchIn{Op: op, IDs: ids, DestProfile: dest, DestRoot: true})
			return
		})
		return res, err
	}

	for _, op := range []string{"copy", "move"} {
		src := f.newProfile(t, f.A.Tenant, "src "+op)
		toNY := rules(src, f.A.Tenant, redirectTo(ny), op+"-ny.example.com")
		toHost := rules(src, f.A.Tenant, redirectHost("proxy.example.net"), op+"-host.example.com")
		plain := rules(src, f.A.Tenant, block(), op+"-block.example.com")
		all := append(append(append([]uuid.UUID{}, toNY...), toHost...), plain...)

		// The location the destination's pair lacks refuses the whole request; the host and the Block do not.
		dBefore, sBefore := f.digest(t, dst), f.digest(t, src)
		_, err := transfer(op, src, dst, all)
		e, ok := err.(*profiles.Error)
		if !ok || !hasField(e, "/ids/0/target/location", "location_not_allowed") {
			t.Fatalf("%s of a Redirect to a location the destination lacks: %v", op, err)
		}
		for _, x := range e.Fields {
			if strings.HasPrefix(x.Name, "/ids/1") || strings.HasPrefix(x.Name, "/ids/2") {
				t.Errorf("%s: the host or the Block rule was refused too: %+v", op, x)
			}
		}
		if f.digest(t, dst) != dBefore || f.digest(t, src) != sBefore {
			t.Errorf("%s: a refused transfer wrote something", op)
		}
		// Without it the same request goes through, and the host target arrives as it was.
		res, err := transfer(op, src, dst, append(append([]uuid.UUID{}, toHost...), plain...))
		if err != nil || res.Created != 2 {
			t.Fatalf("%s of a host and a Block: %+v %v", op, res, err)
		}
		var arrived int
		f.scan(t, `SELECT count(*) FROM ctrlz.rules WHERE profile_id = $1 AND rule_key = $2 AND action = 'redirect' AND target_host = 'proxy.example.net'`,
			[]any{dst, op + "-host.example.com"}, &arrived)
		if arrived != 1 {
			t.Errorf("%s: the host Redirect did not arrive as it was", op)
		}
		left := f.count(t, `SELECT count(*) FROM ctrlz.rules WHERE profile_id = $1`, src)
		if want := map[string]int{"copy": 3, "move": 1}[op]; left != want {
			t.Errorf("%s: the source holds %d rules, want %d", op, left, want)
		}
	}

	// The limits of the destination. Tenant A's cap is 3 rules and 1 wildcard; tenant B has the defaults.
	f.exec(t, `UPDATE ctrlz.tenant_entitlements SET max_rules_per_profile = 3, max_wildcards_per_profile = 1 WHERE tenant_id = $1`, f.A.Tenant)
	full := f.newProfile(t, f.A.Tenant, "full")
	rules(full, f.A.Tenant, block(), "f1.example.com", "f2.example.com", "f3.example.com")
	wildFull := f.newProfile(t, f.A.Tenant, "wild full")
	rules(wildFull, f.A.Tenant, block(), "*.w1.example.com")
	for _, op := range []string{"copy", "move"} {
		src := f.newProfile(t, f.A.Tenant, "limits "+op)
		one := rules(src, f.A.Tenant, block(), "limit-"+op+".example.com")
		wild := rules(src, f.A.Tenant, block(), "*.limit-"+op+".example.com")
		for _, c := range []struct {
			name  string
			dest  uuid.UUID
			ids   []uuid.UUID
			field string
		}{
			{"rules", full, one, "max_rules_per_profile"},
			{"wildcards", wildFull, wild, "max_wildcards_per_profile"},
		} {
			dBefore, sBefore := f.digest(t, c.dest), f.digest(t, src)
			_, err := transfer(op, src, c.dest, c.ids)
			if e, ok := err.(*profiles.Error); !ok || !hasField(e, c.field, "exceeded") {
				t.Errorf("%s into a destination at %s: %v", op, c.field, err)
			}
			if f.digest(t, c.dest) != dBefore || f.digest(t, src) != sBefore {
				t.Errorf("%s into a destination at %s wrote something", op, c.field)
			}
		}
	}
	// Tenant B holds more rules than A's cap in one profile and still takes a copy: the cap is the tenant's own.
	bSrc, bDst := f.newProfile(t, f.B.Tenant, "b src"), f.newProfile(t, f.B.Tenant, "b dst")
	rules(bDst, f.B.Tenant, block(), "b1.example.com", "b2.example.com", "b3.example.com", "b4.example.com")
	moved := rules(bSrc, f.B.Tenant, block(), "bm.example.com")
	err := f.in(f.B.Tenant, func(tx store.Tx) error {
		res, err := f.env.RulesBatch(tx, bSrc, profiles.BatchIn{Op: "copy", IDs: moved, DestProfile: bDst, DestRoot: true})
		if err == nil && res.Created != 1 {
			err = fmt.Errorf("created %d", res.Created)
		}
		return err
	})
	if err != nil {
		t.Errorf("tenant B was held to tenant A's cap: %v", err)
	}
}

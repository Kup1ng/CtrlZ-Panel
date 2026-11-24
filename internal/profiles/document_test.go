package profiles_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/profiles"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Documents (docs/specs/p2-profiles.md 5, 6): the types, the canonical export, import and the strict reader.

func (f *fx) export(t *testing.T, tenant, profile uuid.UUID) profiles.Document {
	t.Helper()
	var d profiles.Document
	err := f.st.WithTenant(f.ctx, tenant, store.TxOpts{Isolation: store.RepeatableRead, ReadOnly: true}, func(tx store.Tx) (e error) {
		d, e = f.env.ReadDocument(tx, profile)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestEveryTypeIsAValidDocumentAndCreatesItself: the preset of each of the seven kinds passes the reader, creating from it
// exports that same document plus the user's name, and a type that needs a destination the install lacks is flagged
// (spec 5, 10.4).
func TestEveryTypeIsAValidDocumentAndCreatesItself(t *testing.T) {
	f := newFx(t)
	for _, kind := range profiles.Kinds() {
		var raw []byte
		f.must(t, f.A.Tenant, func(tx store.Tx) (e error) { raw, _, e = tx.PresetGet(kind); return e })
		want, err := profiles.DecodeDocument(raw, nil)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		var res profiles.ImportResult
		f.must(t, f.A.Tenant, func(tx store.Tx) (e error) { res, e = f.env.CreateFromType(tx, "type "+kind, kind); return e })
		if res.Flagged != 0 {
			t.Errorf("%s: %d destinations flagged on an install with locations", kind, res.Flagged)
		}
		got := f.export(t, f.A.Tenant, res.Profile.ID)
		want.Name = "type " + kind
		want.Canonical(nil)
		if !bytes.Equal(got.Encode(), want.Encode()) {
			t.Errorf("%s: the profile exports\n%s\nthe preset is\n%s", kind, got.Encode(), want.Encode())
		}
	}
	// vpn_replacement on an install with no location: the Default Rule is kept and flagged (spec 4.2).
	f.exec(t, `DELETE FROM ctrlz.location_availability`)
	var res profiles.ImportResult
	f.must(t, f.A.Tenant, func(tx store.Tx) (e error) {
		res, e = f.env.CreateFromType(tx, "no locations", "vpn_replacement")
		return e
	})
	if res.Flagged != 1 {
		t.Errorf("vpn_replacement with an empty location set flagged %d, want 1", res.Flagged)
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.profile_options WHERE profile_id = $1 AND default_location_unavailable`, res.Profile.ID); n != 1 {
		t.Errorf("the Default Rule is not marked unavailable (%d)", n)
	}
}

// fixtureProfile uses every member of the document, an expired rule and two folders of one name among them.
func (f *fx) fixtureProfile(t *testing.T) uuid.UUID {
	t.Helper()
	f.now = time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	var id uuid.UUID
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		p, err := f.env.CreateProfile(tx, "Golden", "custom")
		if err != nil {
			return err
		}
		id = p.ID
		if _, err := f.env.SetFilter(tx, id, "ads-trackers", true, "strict"); err != nil {
			return err
		}
		if _, err := f.env.SetFilter(tx, id, "phishing", true, ""); err != nil {
			return err
		}
		if _, err := f.env.SetFilter(tx, id, "malware", false, "balanced"); err != nil {
			return err
		}
		snap, err := f.env.Catalog.Snapshot(tx)
		if err != nil {
			return err
		}
		fra := profiles.Target{Kind: "location"}
		for _, r := range snap.Rows {
			if r.Key.Country == "DE" {
				fra.LocationID = r.ID
			}
		}
		if _, err := f.env.SetServices(tx, id, []string{"youtube"}, profiles.ServiceState{Enabled: true, Act: profiles.Act{Action: "redirect", Target: fra}}); err != nil {
			return err
		}
		if _, err := f.env.SetServices(tx, id, []string{"netflix"}, profiles.ServiceState{Enabled: false, Act: profiles.Act{Action: "block"}}); err != nil {
			return err
		}
		folder := func(name, action string) uuid.UUID {
			row, err := f.env.CreateFolder(tx, id, profiles.FolderIn{Name: name, Kind: "standard", Act: profiles.Act{Action: action}})
			if err != nil {
				t.Fatal(err)
			}
			return row.ID
		}
		second := folder("Work", "block")
		folder("Work", "")
		if _, err := f.env.CreateFolder(tx, id, profiles.FolderIn{Name: "Quiet", Kind: "do_not_log"}); err != nil {
			return err
		}
		host := profiles.Target{Kind: "host", Host: "proxy.example.net"}
		ip := profiles.Target{Kind: "ip", IPv4: "192.0.2.7", IPv6: "2001:db8::7"}
		for _, in := range []profiles.RuleIn{
			{Patterns: []string{"zeta.example"}, Act: profiles.Act{Action: "block"}},
			{Patterns: []string{"alpha.example", "*.beta.example"}, Act: profiles.Act{Action: "redirect", Target: host}, Comment: "via the proxy"},
			{Patterns: []string{"gamma.example"}, Act: profiles.Act{Action: "bypass"}, FolderID: second, Disabled: true},
			{Patterns: []string{"delta.example"}, Act: profiles.Act{Action: "redirect", Target: ip}},
			{Patterns: []string{"@IR"}, Act: profiles.Act{Action: "bypass"}},
		} {
			if _, err := f.env.CreateRules(tx, id, in); err != nil {
				return err
			}
		}
		t3 := 120
		on := true
		if _, err := f.env.PatchOptions(tx, id, profiles.OptionsPatch{
			DefaultRule: &profiles.DefaultRule{Act: profiles.Act{Action: "redirect", Target: fra}}, BlockExfiltration: &on, RebindProtection: &on,
			BlockTTL: &t3, RedirectTTL: &t3, BypassTTL: &t3, DNS64: &on, SafeSearch: &on, DisableDNSSEC: &on, CNAMEFlattening: &on, RestrictedYouTube: &on,
			BlockResponse: &profiles.BlockResponse{Mode: "custom", V4: "0.0.0.0", V6: "::"},
			ECS:           &profiles.ECS{Mode: "custom", V4: "192.0.2.0/24", V6: "2001:db8::/48"},
		}); err != nil {
			return err
		}
		return nil
	})
	// The expired rule comes in as a document write would bring it.
	f.exec(t, `INSERT INTO ctrlz.rules (tenant_id, profile_id, folder_id, rule_key, match_kind, action, expires_at, comment)
SELECT $1, $2, f.id, 'epsilon.example', 'domain', 'block', $3, 'long gone' FROM ctrlz.rule_folders f WHERE f.profile_id = $2 AND f.name = 'Work' AND f.action = 'block'`,
		f.A.Tenant, id, f.now.Add(-time.Hour))
	return id
}

// TestTheExportIsCanonicalAndImportsAgain: the same profile gives the same bytes, an import of the export exports the same
// bytes under another name, and the bytes are the checked-in golden file (spec 6.1, 10.3).
func TestTheExportIsCanonicalAndImportsAgain(t *testing.T) {
	f := newFx(t)
	id := f.fixtureProfile(t)
	first := f.export(t, f.A.Tenant, id)
	second := f.export(t, f.A.Tenant, id)
	if !bytes.Equal(first.Encode(), second.Encode()) {
		t.Fatal("two exports of one profile differ")
	}
	golden := filepath.Join("testdata", "export.golden.json")
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, first.Encode(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Encode(), bytes.TrimRight(want, "\r\n")) {
		t.Fatalf("the export differs from %s:\n%s", golden, first.Encode())
	}
	// Folders of one name are told apart by the id they had, and refs are f1 to fN in that order.
	if !strings.Contains(string(first.Encode()), `"ref":"f1","name":"Quiet"`) || !strings.Contains(string(first.Encode()), `"name":"Work"`) {
		t.Errorf("folders are not in canonical order: %s", first.Encode())
	}
	raw := first.Encode()
	d, err := profiles.DecodeDocument(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	var res profiles.ImportResult
	f.must(t, f.A.Tenant, func(tx store.Tx) (e error) { res, e = f.env.ImportDocument(tx, d, "Golden copy"); return e })
	again := f.export(t, f.A.Tenant, res.Profile.ID)
	again.Name = "Golden"
	if !bytes.Equal(again.Encode(), raw) {
		t.Fatalf("import then export changed the document:\n%s\n%s", raw, again.Encode())
	}
	// Tenant B sees none of it: an id of A is not found.
	var nf *profiles.Error
	err = f.in(f.B.Tenant, func(tx store.Tx) error { _, e := f.env.ReadDocument(tx, id); return e })
	if !asRefusal(err, &nf) || nf.Kind != profiles.KindNotFound {
		t.Fatalf("B reads A's profile: %v", err)
	}
}

func asRefusal(err error, out **profiles.Error) bool {
	for err != nil {
		if e, ok := err.(*profiles.Error); ok {
			*out = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// TestTheReaderRefusesWhatItMustBeforeAnyTreeIsBuilt: invalid UTF-8, a duplicate key, a nesting depth beyond 8 and a
// file of too many values, each as json_syntax at the parent, and nothing of the file in the pointer (spec 6.2).
func TestTheReaderRefusesWhatItMustBeforeAnyTreeIsBuilt(t *testing.T) {
	for name, c := range map[string]struct {
		in      string
		pointer string
		bad     bool
	}{
		"valid":          {`{"a":[1,{"b":2}],"c":"d"}`, "", false},
		"invalid utf-8":  {"{\"a\":\"\xff\"}", "", true},
		"duplicate key":  {`{"rules":[{"a":1,"a":2}]}`, "/rules/0", true},
		"depth 8":        {strings.Repeat("[", 8) + strings.Repeat("]", 8), "", false},
		"depth 9":        {strings.Repeat("[", 9) + strings.Repeat("]", 9), "/0/0/0/0/0/0/0", true},
		"truncated":      {`{"a":`, "", true},
		"unknown member": {`{"zz\u0001":1,"zz\u0001":2}`, "", true},
	} {
		f := profiles.ScanJSON([]byte(c.in))
		switch {
		case c.bad && (f == nil || f.Code != profiles.CodeJSONSyntax):
			t.Errorf("%s: not refused (%v)", name, f)
		case c.bad && f.Name != c.pointer:
			t.Errorf("%s: pointer %q, want %q", name, f.Name, c.pointer)
		case !c.bad && f != nil:
			t.Errorf("%s: refused: %+v", name, *f)
		}
	}
	// A key the schema does not have is never echoed, however well-formed it looks; a member of the schema is
	// (finding p2-B3-r2-8).
	deep := strings.Repeat("[", 8) + "0" + strings.Repeat("]", 8)
	if f := profiles.ScanJSON([]byte(`{"anyname":` + deep + `}`)); f == nil || strings.Contains(f.Name, "anyname") {
		t.Errorf("an unknown member was echoed: %v", f)
	}
	if f := profiles.ScanJSON([]byte(`{"rules":` + deep + `}`)); f == nil || !strings.HasPrefix(f.Name, "/rules/0") {
		t.Errorf("a member of the schema is not named: %v", f)
	}
	// More values than the schema can hold.
	big := `[` + strings.Repeat("1,", profiles.DocValues) + `1]`
	if f := profiles.ScanJSON([]byte(big)); f == nil {
		t.Error("a file of more values than the cap was read")
	}
}

// TestADocumentKeepsAPastExpiryAndFlagsWhatTheInstallLacks: an export with expired rules imports again, a location this
// install has but the profile may not use is kept and flagged, one it does not have is refused (spec 4.2, 3.7).
func TestADocumentKeepsAPastExpiryAndFlagsWhatTheInstallLacks(t *testing.T) {
	f := newFx(t)
	doc := `{"format":"ctrlz-profile","version":1,"kind":"custom","rules":[
	  {"pattern":"old.example","action":"redirect","target":{"kind":"location","location":{"country":"US","city":"Los Angeles"}},"expires_at":"2020-01-01T00:00:00Z"}]}`
	d, err := profiles.DecodeDocument([]byte(doc), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Los Angeles is on the first node only, so the global pair does not share it: kept, and flagged.
	var res profiles.ImportResult
	f.must(t, f.A.Tenant, func(tx store.Tx) (e error) { res, e = f.env.ImportDocument(tx, d, "Flagged"); return e })
	if res.Flagged != 1 {
		t.Fatalf("flagged = %d, want 1", res.Flagged)
	}
	if n := f.count(t, `SELECT count(*) FROM ctrlz.rules WHERE profile_id = $1 AND location_unavailable AND expires_at < now()`, res.Profile.ID); n != 1 {
		t.Fatalf("the flagged expired rule is not stored (%d)", n)
	}
	d.Rules[0].Target.Location = &profiles.DocLoc{Country: "ZZ"}
	e := f.refusal(t, f.A.Tenant, func(tx store.Tx) error { _, e := f.env.ImportDocument(tx, d, "Unknown"); return e })
	if !hasField(e, "/rules/0/target/location", profiles.CodeUnknown) {
		t.Fatalf("an unknown location: %+v", e.Fields)
	}
}

// TestEveryMemberOfTheDocumentTypesIsNamedInAPointer pins the member list of the reader to the struct tags: a member of
// a fully populated document, put where the reader refuses it, is named in the pointer (finding p2-B3-r2-8).
func TestEveryMemberOfTheDocumentTypesIsNamedInAPointer(t *testing.T) {
	yes := true
	n := 5
	tg := &profiles.DocTarget{Kind: "location", Location: &profiles.DocLoc{Country: "DE", City: "x", Label: "y"}, IPv4: "1.1.1.1", IPv6: "::1", Host: "h"}
	d := profiles.Document{
		Format: "f", Version: 1, Name: "n", Kind: "custom",
		Filters:  []profiles.DocFilter{{ID: "a", Enabled: &yes, Mode: "m"}},
		Services: []profiles.DocService{{Slug: "s", Enabled: &yes, Action: "block", Target: tg}},
		Folders:  []profiles.DocFolder{{Ref: "f1", Name: "n", Kind: "standard", Action: "block", Target: tg}},
		Rules:    []profiles.DocRule{{Pattern: "p", Folder: "f1", Action: "block", Target: tg, Enabled: &yes, ExpiresAt: "t", Comment: "c"}},
		Options: profiles.DocOptions{DefaultRule: &profiles.DocDefaultRule{Action: "block", Target: tg}, BlockExfiltration: &yes, RebindProtection: &yes,
			DisableDNSSEC: &yes, BlockTTL: &n, RedirectTTL: &n, BypassTTL: &n, BlockResponse: &profiles.DocBlockResponse{Mode: "m", V4: "a", V6: "b"},
			ECS: &profiles.DocECS{Mode: "m", V4: "a", V6: "b"}, DNS64: &yes, CNAMEFlattening: &yes, SafeSearch: &yes, RestrictedYouTube: &yes},
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var tree any
	if err := json.Unmarshal(raw, &tree); err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, c := range x {
				names[k] = true
				walk(c)
			}
		case []any:
			for _, c := range x {
				walk(c)
			}
		}
	}
	walk(tree)
	deep := strings.Repeat("[", 8) + "0" + strings.Repeat("]", 8)
	for name := range names {
		if f := profiles.ScanJSON([]byte(`{"` + name + `":` + deep + `}`)); f == nil || !strings.HasPrefix(f.Name, "/"+name) {
			t.Errorf("member %q is not named in a pointer: %v", name, f)
		}
	}
	if len(names) < 40 {
		t.Errorf("only %d members found: the document the test fills is not whole", len(names))
	}
}

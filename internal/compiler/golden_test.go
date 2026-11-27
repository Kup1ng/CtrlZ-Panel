package compiler

import (
	"bytes"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	"github.com/Kup1ng/CtrlZ-Shared/policy"
	"github.com/Kup1ng/CtrlZ-Shared/rules"
	"github.com/Kup1ng/CtrlZ-Shared/vectors"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The golden judge of the column-to-blob step (P2 10.3, SC 15): every profile of the shared fixtures is written as the P2
// rows it would be stored as, compiled here, and must give the very bytes shared/vectors builds from the fixture's own
// description. The node's evaluator vectors run on those bytes, so a column the compiler reads differently shows as a
// different hash.

func locUUID(w uint16) uuid.UUID { return uuid.UUID{0: 0xB0, 14: byte(w >> 8), 15: byte(w)} }

func rowTarget(t *vectors.TargetJSON) (store.Target, bool) {
	if t == nil {
		return store.Target{}, true
	}
	switch t.Kind {
	case "location":
		return store.Target{Kind: "location", LocationID: locUUID(t.Location)}, true
	case "auto", "random":
		return store.Target{Kind: t.Kind}, len(t.Set) == 0
	case "ip":
		return store.Target{Kind: "ip", IPv4: t.V4, IPv6: t.V6}, true
	case "host":
		return store.Target{Kind: "host", Host: t.Host}, true
	}
	return store.Target{}, false
}

func ecsText(addr string, bits uint8, family int) string {
	if addr == "" {
		return ""
	}
	p, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", addr, bits))
	if err != nil {
		return ""
	}
	return p.String()
}

// rowsOf converts a fixture profile to the rows of a compile, and says whether the conversion is exact: a feature the
// rows cannot hold (a service with Do Not Log, an Auto set, a custom ECS under another mode) is a profile this test skips.
func rowsOf(name string, pj *vectors.ProfileJSON, f *vectors.FixtureFile, maps *store.CompilerMaps) (*ProfileData, bool, error) {
	pd := &ProfileData{ID: uuid.New(), Folders: map[uuid.UUID]store.FolderRow{}}
	if pj.DisabledUntil != "" {
		t, err := time.Parse(time.RFC3339, pj.DisabledUntil)
		if err != nil {
			return nil, false, err
		}
		pd.DisabledUntil = t.Unix()
	}
	exact := true
	o := &store.OptionsRow{BlockExfiltration: pj.Options.Exfiltration, RebindProtection: pj.Options.Rebind, DisableDNSSEC: pj.Options.DisableDNSSEC,
		DNS64: pj.Options.DNS64, CNAMEFlattening: pj.Options.Flatten, SafeSearch: pj.Options.SafeSearch, RestrictedYouTube: pj.Options.RestrictedYouTube}
	ttl := func(v *uint32) *int32 {
		if v == nil {
			return nil
		}
		x := int32(*v)
		return &x
	}
	o.BlockTTL, o.RedirectTTL, o.BypassTTL = ttl(pj.Options.BlockTTL), ttl(pj.Options.RedirectTTL), ttl(pj.Options.BypassTTL)
	if b := pj.Options.BlockResponse; b != nil {
		o.BlockResponse, o.BlockV4, o.BlockV6 = b.Mode, b.V4, b.V6
		if b.Mode != "custom" && (b.V4 != "" || b.V6 != "") {
			exact = false
		}
	}
	if e := pj.Options.ECS; e != nil {
		o.ECSMode = e.Mode
		if e.Mode == "custom" {
			o.ECSV4, o.ECSV6 = ecsText(e.V4, e.V4Bits, 4), ecsText(e.V6, e.V6Bits, 6)
		} else if e.V4 != "" || e.V6 != "" || e.V4Bits != 0 || e.V6Bits != 0 {
			exact = false
		}
	}
	o.DefaultAction = pj.Default
	if pj.Default == "null" {
		o.DefaultAction = ""
	}
	if pj.DefaultTarget != nil {
		var ok bool
		if o.DefaultTarget, ok = rowTarget(pj.DefaultTarget); !ok {
			exact = false
		}
	}
	pd.Options = o
	var folder uuid.UUID
	for _, r := range pj.Rules {
		pat, err := rules.Parse(r.Token)
		if err != nil {
			return nil, false, err
		}
		tg, ok := rowTarget(r.Target)
		exact = exact && ok
		row := store.RuleRow{ID: vectors.RuleID(r.Name), Key: pat.Key(), MatchKind: pat.Kind.String(), Negated: pat.Negated, Action: r.Action, Target: tg,
			Enabled: true, LocationUnavailable: r.LocUnavailable}
		if r.Expires != "" {
			t, err := time.Parse(time.RFC3339, r.Expires)
			if err != nil {
				return nil, false, err
			}
			row.ExpiresAt = &t
		}
		if r.DoNotLog {
			if folder == uuid.Nil {
				folder = uuid.New()
				pd.Folders[folder] = store.FolderRow{ID: folder, Name: "dnl", Kind: "do_not_log"}
			}
			row.FolderID = folder
		}
		pd.Rules = append(pd.Rules, row)
	}
	for _, s := range pj.Services {
		tg, ok := rowTarget(s.Target)
		exact = exact && ok && !s.DoNotLog
		pd.Services = append(pd.Services, store.ServiceRow{Slug: s.Name, Enabled: true, Action: s.Action, Target: tg, LocationUnavailable: s.LocUnavailable})
	}
	for _, n := range pj.Filters {
		pd.Filters = append(pd.Filters, store.FilterRow{FilterID: n, Enabled: true})
	}
	return pd, exact, nil
}

func TestProfilesGiveTheBytesOfTheSharedFixtures(t *testing.T) {
	compared := 0
	for _, name := range []string{"base", "iranian"} {
		fx, err := vectors.LoadFixture(name)
		if err != nil {
			t.Fatal(err)
		}
		maps := &store.CompilerMaps{Services: map[string]uint32{}, Filters: map[string]uint16{}, Modes: map[string]map[string]uint16{}, Locations: map[uuid.UUID]uint16{}}
		for _, s := range fx.File.Catalog.Services {
			maps.Services[s.Name] = s.Wire
		}
		for _, fl := range fx.File.Catalog.Filters {
			maps.Filters[fl.Name] = fl.ID
			maps.Modes[fl.Name] = map[string]uint16{"m": fl.Mode}
		}
		for w := 0; w < 64; w++ {
			maps.Locations[locUUID(uint16(w))] = uint16(w)
		}
		for pname, pj := range fx.File.Profiles {
			pd, exact, err := rowsOf(pname, &pj, fx.File, maps)
			if err != nil {
				t.Fatalf("%s/%s: %v", name, pname, err)
			}
			if !exact {
				continue
			}
			for i := range pd.Filters {
				pd.Filters[i].Mode = "" // one mode: the compiler finds it
			}
			p, err := CompileProfile(pd, maps)
			if err != nil {
				t.Fatalf("%s/%s: %v", name, pname, err)
			}
			if !bytes.Equal(p.Bytes, fx.ProfileBytes[pname]) {
				t.Errorf("%s/%s: the compiled blob is not the fixture's (%d and %d bytes)", name, pname, len(p.Bytes), len(fx.ProfileBytes[pname]))
			}
			compared++
		}
	}
	if compared < 10 {
		t.Fatalf("only %d profiles were compared", compared)
	}
	t.Logf("%d profiles compared", compared)
}

// A StackRecord carries what policy.NewStack folds over its slots: the three facts and the merged options.
func TestStackRecordsAreWhatTheNodeFoldsItself(t *testing.T) {
	checked := 0
	for _, name := range []string{"base", "iranian"} {
		fx, err := vectors.LoadFixture(name)
		if err != nil {
			t.Fatal(err)
		}
		maps := &store.CompilerMaps{Services: map[string]uint32{}, Filters: map[string]uint16{}, Modes: map[string]map[string]uint16{}, Locations: map[uuid.UUID]uint16{}}
		for _, s := range fx.File.Catalog.Services {
			maps.Services[s.Name] = s.Wire
		}
		for _, fl := range fx.File.Catalog.Filters {
			maps.Filters[fl.Name] = fl.ID
			maps.Modes[fl.Name] = map[string]uint16{"m": fl.Mode}
		}
		for w := 0; w < 64; w++ {
			maps.Locations[locUUID(uint16(w))] = uint16(w)
		}
		compiled := map[string]*Profile{}
		for pname, pj := range fx.File.Profiles {
			pd, exact, err := rowsOf(pname, &pj, fx.File, maps)
			if err != nil || !exact {
				continue
			}
			if compiled[pname], err = CompileProfile(pd, maps); err != nil {
				t.Fatal(err)
			}
		}
		for ename, ej := range fx.File.Endpoints {
			p1, p2 := compiled[ej.Profile1], compiled[ej.Profile2]
			if p1 == nil || (ej.Profile2 != "" && p2 == nil) {
				continue
			}
			var second *blob.Profile
			if ej.Profile2 != "" {
				second = fx.Profiles[ej.Profile2]
			}
			want := policy.NewStack(fx.Profiles[ej.Profile1], second, nil)
			got := Stack(p1, p2)
			if uint8(got.MaxDepth) != want.MaxDepth || got.HasDestGeo != want.HasDestGeo || got.Explicit != want.Explicit {
				t.Errorf("%s/%s: facts %d %v %v, want %d %v %v", name, ename, got.MaxDepth, got.HasDestGeo, got.Explicit, want.MaxDepth, want.HasDestGeo, want.Explicit)
			}
			mo := want.Merged.Marshal()
			if !bytes.Equal(got.MergedOptions, mo[:]) {
				t.Errorf("%s/%s: merged options differ", name, ename)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no stack was checked")
	}
}

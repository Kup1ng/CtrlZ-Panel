package endpoints

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Every zone the catalog lists loads from the embedded database, and the list is sorted (ValidZone searches it).
func TestEveryListedZoneLoads(t *testing.T) {
	zs := Zones()
	if len(zs) < 300 {
		t.Fatalf("only %d zones", len(zs))
	}
	if !slices.IsSorted(zs) {
		t.Error("the zone list is not sorted")
	}
	for _, z := range zs {
		if _, err := time.LoadLocation(z); err != nil {
			t.Errorf("%s: %v", z, err)
		}
	}
	for _, want := range []string{"Asia/Tehran", "UTC", "America/New_York"} {
		if !ValidZone(want) {
			t.Errorf("%s is not valid", want)
		}
	}
	for _, bad := range []string{"", "tehran", "Asia/Nowhere", "../etc/passwd", "US/Eastern", "asia/tehran"} {
		if ValidZone(bad) {
			t.Errorf("%q is valid", bad)
		}
	}
}

func TestClientLabel(t *testing.T) {
	cases := []struct {
		label, alias, want, code string
	}{
		{"kid-phone", "", "kid-phone", ""},
		{"", "Kid's Phone", "kid-s-phone", ""},
		{"", "گوشی", "", CodeRequired}, // Persian only: nothing is left after the slug
		{"", "", "", CodeRequired},
		{"Kid", "", "", CodeInvalid},
		{"-kid", "", "", CodeInvalid},
		{"kid-", "", "", CodeInvalid},
		{strings.Repeat("a", 37), "", "", CodeInvalid},
		{"default", "", "", CodeReserved},
		{"", "Default", "", CodeReserved},
	}
	for _, c := range cases {
		got, f := ClientLabel(c.label, c.alias)
		switch {
		case c.code == "" && (f != nil || got != c.want):
			t.Errorf("%q/%q: %q %+v, want %q", c.label, c.alias, got, f, c.want)
		case c.code != "" && (f == nil || f.Code != c.code):
			t.Errorf("%q/%q: %+v, want code %s", c.label, c.alias, f, c.code)
		}
	}
}

func TestCheckWindows(t *testing.T) {
	p := uuid.MustParse("00000000-0000-7000-8000-00000000000a")
	w := func(s, e int) WindowIn { return WindowIn{Start: s, End: e, ProfileID: p} }
	ok := [][]WindowIn{nil, {w(0, 30)}, {w(0, 10080)}, {w(60, 120), w(120, 180)}, {w(9990, 10080), w(0, 30)}}
	for _, c := range ok {
		if fs := checkWindows(c); fs != nil {
			t.Errorf("%v: %v", c, fs)
		}
	}
	bad := []struct {
		name string
		ws   []WindowIn
		code string
	}{
		{"not a multiple of 30 at the start", []WindowIn{w(10, 60)}, CodeGrid},
		{"not a multiple of 30 at the end", []WindowIn{w(0, 45)}, CodeGrid},
		{"shorter than 30 minutes", []WindowIn{w(60, 60)}, CodeGrid},
		{"backwards", []WindowIn{w(120, 60)}, CodeGrid},
		{"past the week", []WindowIn{w(10050, 10110)}, CodeGrid},
		{"negative", []WindowIn{w(-30, 30)}, CodeGrid},
		{"overlap", []WindowIn{w(0, 120), w(60, 180)}, CodeOverlap},
		{"same window twice", []WindowIn{w(0, 60), w(0, 60)}, CodeOverlap},
		{"same id twice, disjoint minutes", []WindowIn{{ID: uuid.MustParse("00000000-0000-7000-8000-0000000000aa"), Start: 0, End: 60, ProfileID: p}, {ID: uuid.MustParse("00000000-0000-7000-8000-0000000000aa"), Start: 120, End: 180, ProfileID: p}}, CodeDuplicate},
		{"no profile", []WindowIn{{Start: 0, End: 30}}, CodeRequired},
		{"profile 2 equals profile", []WindowIn{{Start: 0, End: 30, ProfileID: p, Profile2ID: p}}, CodeSameProfile},
		{"too many", make([]WindowIn, MaxWindowsPerEndpoint+1), CodeExceeded},
	}
	for _, c := range bad {
		fs := checkWindows(c.ws)
		if len(fs) == 0 || fs[0].Code != c.code {
			t.Errorf("%s: %v, want %s", c.name, fs, c.code)
		}
	}
	// The overlap is named at the window that starts inside the earlier one, by its place in the request.
	fs := checkWindows([]WindowIn{w(600, 660), w(0, 120), w(60, 90)})
	if len(fs) != 1 || fs[0].Name != "/windows/2/start" {
		t.Errorf("overlap field: %v", fs)
	}
}

// E2: a change of a column marks the endpoint_set exactly when the column is in the compile map of spec 3.2, one case per
// column. The columns that are not compiled are the ones of Patch that EndpointCols does not carry.
func TestCompiledColumns(t *testing.T) {
	pa := uuid.MustParse("00000000-0000-7000-8000-00000000000a")
	pb := uuid.MustParse("00000000-0000-7000-8000-00000000000b")
	base := EndpointCols{ProfileID: pa, AdminState: "enabled", AnalyticsLevel: "full", ScheduleTimezone: "Asia/Tehran"}
	compiled := map[string]func(c *EndpointCols){
		"profile_id":             func(c *EndpointCols) { c.ProfileID = pb },
		"profile2_id":            func(c *EndpointCols) { c.Profile2ID = pb },
		"admin_state":            func(c *EndpointCols) { c.AdminState = "soft_disabled" },
		"legacy_dns":             func(c *EndpointCols) { c.LegacyDNS = true },
		"require_authorized_ips": func(c *EndpointCols) { c.RequireAuthorizedIPs = true },
		"expose_ip":              func(c *EndpointCols) { c.ExposeIP = true },
		"authorize_secure_dns":   func(c *EndpointCols) { c.AuthorizeSecureDNS = true },
		"analytics_level":        func(c *EndpointCols) { c.AnalyticsLevel = "none" },
		"schedule_timezone":      func(c *EndpointCols) { c.ScheduleTimezone = "UTC" },
	}
	for name, change := range compiled {
		c := base
		change(&c)
		if !compiledChanged(base, c) {
			t.Errorf("a change of %s marks nothing", name)
		}
	}
	if compiledChanged(base, base) {
		t.Error("no change marks")
	}
	// The not-compiled members never reach the comparison: name, type, group, comment, authorize_ddns, prevent_deactivation.
	row := func() store.EndpointRow {
		return store.EndpointRow{ProfileID: pa, AdminState: "enabled", AnalyticsLevel: "full", ScheduleTimezone: "Asia/Tehran"}
	}
	yes := true
	name, typ, comment := "x", "phone", "c"
	g := uuid.New()
	p := Patch{Name: &name, Type: &typ, GroupID: &g, Comment: &comment, AuthorizeDDNS: &yes, PreventDeactivation: &yes}
	r := row()
	if fs := p.apply(&r, ""); fs != nil {
		t.Fatal(fs)
	}
	if compiledChanged(cols(row()), cols(r)) {
		t.Error("a change of a column that is not compiled marks the endpoint_set")
	}
	if r.Name != "x" || r.Type != "phone" || r.GroupID != g || r.Comment == nil || *r.Comment != "c" || !r.AuthorizeDDNS || !r.PreventDeactivation {
		t.Errorf("apply: %+v", r)
	}
}

func TestPatchApply(t *testing.T) {
	pa := uuid.MustParse("00000000-0000-7000-8000-00000000000a")
	pb := uuid.MustParse("00000000-0000-7000-8000-00000000000b")
	row := func() store.EndpointRow {
		return store.EndpointRow{ProfileID: pa, Profile2ID: pb, AdminState: "enabled", AnalyticsLevel: "full", ScheduleTimezone: "Asia/Tehran"}
	}
	t.Run("profile 2 equal to the enforced profile", func(t *testing.T) {
		r := row()
		fs := Patch{Profile2ID: &pa}.apply(&r, "")
		if len(fs) != 1 || fs[0] != (Field{"/profile2_id", CodeSameProfile}) {
			t.Errorf("%v", fs)
		}
	})
	t.Run("the enforced profile moves onto profile 2", func(t *testing.T) {
		r := row()
		fs := Patch{ProfileID: &pb}.apply(&r, "/set")
		if len(fs) != 1 || fs[0] != (Field{"/set/profile_id", CodeSameProfile}) {
			t.Errorf("%v", fs)
		}
	})
	t.Run("clearing profile 2 then setting the enforced profile", func(t *testing.T) {
		r := row()
		if fs := (Patch{ProfileID: &pb, ClearProfile2: true}).apply(&r, ""); fs != nil || r.ProfileID != pb || r.Profile2ID != uuid.Nil {
			t.Errorf("%v %+v", fs, r)
		}
	})
	t.Run("require authorized ips needs a row", func(t *testing.T) {
		r := row()
		yes := true
		fs := Patch{RequireAuthorizedIPs: &yes}.apply(&r, "")
		if len(fs) != 1 || fs[0] != (Field{"/require_authorized_ips", CodeNeedsAuthorizedIP}) {
			t.Errorf("%v", fs)
		}
		r = row()
		r.AuthorizedIPs = 1
		if fs := (Patch{RequireAuthorizedIPs: &yes}).apply(&r, ""); fs != nil || !r.RequireAuthorizedIPs {
			t.Errorf("%v %+v", fs, r)
		}
		// Already on: switching it on again is no new decision, with or without rows.
		r = row()
		r.RequireAuthorizedIPs = true
		if fs := (Patch{RequireAuthorizedIPs: &yes}).apply(&r, ""); fs != nil {
			t.Errorf("%v", fs)
		}
	})
	t.Run("the values", func(t *testing.T) {
		long := strings.Repeat("x", CommentLimit+1)
		bad := "loud"
		zone := "Mars/Base"
		p := Patch{Name: new(string), Comment: &long, AnalyticsLevel: &bad, AdminState: &bad, ScheduleTimezone: &zone}
		fs := p.pre("", true)
		want := []Field{{"/name", CodeRequired}, {"/comment", CodeTooLong}, {"/analytics_level", CodeInvalid}, {"/admin_state", CodeInvalid}, {"/schedule_timezone", CodeUnknown}}
		if !slices.Equal(fs, want) {
			t.Errorf("%v", fs)
		}
		if fs := (Patch{Type: new(string)}).pre("", false); len(fs) != 1 || fs[0] != (Field{"/type", CodeUnknown}) {
			t.Errorf("type: %v", fs)
		}
	})
}

func TestAwayOf(t *testing.T) {
	row := func(state string, require bool) store.EndpointRow {
		return store.EndpointRow{AdminState: state, RequireAuthorizedIPs: require}
	}
	cases := []struct {
		old, now store.EndpointRow
		want     Away
	}{
		{row("enabled", false), row("enabled", false), AwayNone},
		{row("enabled", false), row("soft_disabled", false), AwayAll},
		{row("enabled", false), row("hard_disabled", false), AwayAll},
		{row("hard_disabled", false), row("soft_disabled", false), AwayAll}, // hard to soft turns a dead Endpoint into unfiltered DNS
		{row("soft_disabled", false), row("enabled", false), AwayNone},
		{row("soft_disabled", false), row("soft_disabled", false), AwayNone},
		{row("enabled", false), row("enabled", true), AwayAll},
		{row("enabled", true), row("enabled", false), AwayNone},
	}
	for i, c := range cases {
		if got := awayOf(c.old, c.now); got != c.want {
			t.Errorf("case %d: %v, want %v", i, got, c.want)
		}
	}
}

func TestCheckIDs(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	if err := checkIDs([]uuid.UUID{a, b}); err != nil {
		t.Error(err)
	}
	for name, ids := range map[string][]uuid.UUID{"none": nil, "duplicate": {a, b, a}} {
		if checkIDs(ids) == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	many := make([]uuid.UUID, MaxIDsPerBatch+1)
	for i := range many {
		many[i] = uuid.New()
	}
	if err := checkIDs(many); err == nil || err.Fields[0].Code != CodeExceeded {
		t.Errorf("501 ids: %v", err)
	}
}

func TestCreateCheck(t *testing.T) {
	p := uuid.New()
	ok := CreateIn{Type: "phone", Names: []string{"a"}, ProfileID: p}
	if err := ok.check(true); err != nil {
		t.Fatal(err)
	}
	cases := map[string]CreateIn{
		"no names":     {Type: "phone", ProfileID: p},
		"empty name":   {Type: "phone", Names: []string{""}, ProfileID: p},
		"long name":    {Type: "phone", Names: []string{strings.Repeat("a", 65)}, ProfileID: p},
		"51 names":     {Type: "phone", Names: make([]string, 51), ProfileID: p},
		"no profile":   {Type: "phone", Names: []string{"a"}},
		"same profile": {Type: "phone", Names: []string{"a"}, ProfileID: p, Profile2ID: p},
		"analytics":    {Type: "phone", Names: []string{"a"}, ProfileID: p, AnalyticsLevel: "x"},
		"long comment": {Type: "phone", Names: []string{"a"}, ProfileID: p, Comment: strings.Repeat("c", 256)},
	}
	for name, in := range cases {
		if in.check(true) == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if ok.check(false) == nil {
		t.Error("an unknown type was accepted")
	}
	// 64 characters, counted as characters and not bytes.
	if err := (CreateIn{Type: "phone", Names: []string{strings.Repeat("ی", 64)}, ProfileID: p}).check(true); err != nil {
		t.Errorf("64 Persian letters: %v", err)
	}
}

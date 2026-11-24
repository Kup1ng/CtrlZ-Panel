package endpoints

import (
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"
	_ "time/tzdata" // the zone names of the schedule resolve the same on the api and in P4's compiler, with no system zoneinfo
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Shared/identity"
	"github.com/Kup1ng/CtrlZ-Shared/schedule"
)

// The bounds of spec 3.5 and 3.8. The two that name a count of rows a tenant shares between its requests are caps with their
// own race drivers (store.MaxGroupsPerTenant); these bound one request, and nothing is shared between requests that racing
// actors could spend.
const (
	// NameLimit is how long an Endpoint, group or token name may be, in characters.
	NameLimit = 64
	// CommentLimit is how long an Endpoint comment may be (T-221).
	CommentLimit = 255
	// AliasLimit is how long a client alias and a client group name may be.
	AliasLimit = 64
	// MaxNamesPerCreate is how many Endpoints one create makes: one per name.
	MaxNamesPerCreate = 50
	// MaxIDsPerBatch is how many ids one batch operation names.
	MaxIDsPerBatch = 500
	// MaxWindowsPerEndpoint is how many schedule windows an Endpoint has (the grid holds one byte per cell).
	MaxWindowsPerEndpoint = 64
	// DefaultTimezone is the zone of a new Endpoint (T-254).
	DefaultTimezone = "Asia/Tehran"
)

// Zones is the list of schedule time zones, as GET /catalog/timezones answers it.
func Zones() []string { return slices.Clone(zoneNames()) }

// ValidZone says the name is one of the listed zones and loads.
func ValidZone(name string) bool {
	if _, ok := slices.BinarySearch(zoneNames(), name); !ok {
		return false
	}
	_, err := time.LoadLocation(name)
	return err == nil
}

// checkName is the rule of an Endpoint, group and token name: 1 to NameLimit characters.
func checkName(s, field string) *Field {
	switch n := utf8.RuneCountInString(s); {
	case n == 0:
		return &Field{field, CodeRequired}
	case n > NameLimit:
		return &Field{field, CodeTooLong}
	}
	return nil
}

func tooLong(s string, limit int) bool { return utf8.RuneCountInString(s) > limit }

// CheckGroupName is the rule of a group's name.
func CheckGroupName(name string) *Error {
	if f := checkName(name, "/name"); f != nil {
		return invalid(*f)
	}
	return nil
}

// The enums of PS 4, as functions: a package-level slice would be state a caller could change.
func analyticsLevels() []string { return []string{"none", "some", "full"} }
func adminStates() []string     { return []string{"enabled", "soft_disabled", "hard_disabled"} }

// zoneNames is the sorted zone list, built once.
var zoneNames = sync.OnceValue(zoneNamesList)

// WindowIn is a window as a request names it: its id is optional, and an id the Endpoint already has keeps the window's
// identity across the replacement (the compiler's window_id is this id).
type WindowIn struct {
	ID         uuid.UUID
	Start, End int
	ProfileID  uuid.UUID
	Profile2ID uuid.UUID
}

// checkWindows applies the rules of spec 3.8 to a schedule PUT, with field names under /windows.
func checkWindows(ws []WindowIn) []Field {
	var fs []Field
	if len(ws) > MaxWindowsPerEndpoint {
		return []Field{{"/windows", CodeExceeded}}
	}
	for i, w := range ws {
		at := func(m string) string { return fmt.Sprintf("/windows/%d/%s", i, m) }
		switch {
		case w.Start%schedule.MinutesPerCell != 0 || w.End%schedule.MinutesPerCell != 0:
			fs = append(fs, Field{at("start"), CodeGrid})
		case w.Start < 0 || w.End > 7*24*60 || w.End-w.Start < schedule.MinutesPerCell:
			fs = append(fs, Field{at("end"), CodeGrid})
		}
		if w.ProfileID == uuid.Nil {
			fs = append(fs, Field{at("profile_id"), CodeRequired})
		} else if w.Profile2ID == w.ProfileID {
			fs = append(fs, Field{at("profile2_id"), CodeSameProfile})
		}
	}
	if fs != nil {
		return fs
	}
	order := make([]int, len(ws))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return ws[order[a]].Start < ws[order[b]].Start })
	for k := 1; k < len(order); k++ {
		if ws[order[k]].Start < ws[order[k-1]].End {
			fs = append(fs, Field{fmt.Sprintf("/windows/%d/start", order[k]), CodeOverlap})
		}
	}
	return fs
}

// ClientLabel resolves the label of a new client: the label given, checked against the grammar of SC 3.1, or the slug of the
// alias when none is given. "default" is the hub's own and is refused.
func ClientLabel(label, alias string) (string, *Field) {
	if label == "" {
		s, ok := identity.SlugClient(alias)
		if !ok {
			return "", &Field{"/label", CodeRequired}
		}
		label = s
	} else if !identity.ValidClient(label) {
		return "", &Field{"/label", CodeInvalid}
	}
	if label == "default" {
		return "", &Field{"/label", CodeReserved}
	}
	return label, nil
}

func inSet(v string, set []string) bool { return slices.Contains(set, v) }

// compiledChanged says whether a change of the row moves anything that compiles to a record (spec 3.2): the enforced and
// second profile, the admin state, Legacy DNS, Require Authorized IPs, Expose IP, Authorize by Secure DNS, the Analytics
// level and the zone of the schedule. A change of the name, the type, the group, the comment, Authorize by Dynamic DNS and
// Prevent Deactivation marks nothing. E2 tests it per column.
func compiledChanged(a, b EndpointCols) bool {
	return a.ProfileID != b.ProfileID || a.Profile2ID != b.Profile2ID || a.AdminState != b.AdminState || a.LegacyDNS != b.LegacyDNS ||
		a.RequireAuthorizedIPs != b.RequireAuthorizedIPs || a.ExposeIP != b.ExposeIP || a.AuthorizeSecureDNS != b.AuthorizeSecureDNS ||
		a.AnalyticsLevel != b.AnalyticsLevel || a.ScheduleTimezone != b.ScheduleTimezone
}

// EndpointCols are the writable columns of an Endpoint that the compile map names; the test of E2 builds them by column.
type EndpointCols struct {
	ProfileID, Profile2ID uuid.UUID
	AdminState            string
	LegacyDNS             bool
	RequireAuthorizedIPs  bool
	ExposeIP              bool
	AuthorizeSecureDNS    bool
	AnalyticsLevel        string
	ScheduleTimezone      string
}

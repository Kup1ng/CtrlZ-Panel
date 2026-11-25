package compiler

import (
	"slices"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	commonv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/common/v1"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/identity"
	"github.com/Kup1ng/CtrlZ-Shared/schedule"
	"github.com/Kup1ng/CtrlZ-Shared/wire"

	"github.com/Kup1ng/CtrlZ-Panel/internal/endpoints"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// grantCap is EndpointRecord.grant_cap of every record (SC 10.4). Grants themselves are P4b's.
const grantCap = 4096

// scheduleHorizon is how far past the compile the offset transitions of an Endpoint's zone are written (D31); the
// worker's daily horizon job marks the Endpoints whose last transition comes within 60 days of ending.
const scheduleHorizon = 400 * 24 * time.Hour

// TenantInput is one tenant as it is read in one REPEATABLE READ snapshot.
type TenantInput struct {
	Row       store.CompilerTenantRow
	Endpoints []store.CompilerEndpoint
	Windows   []store.WindowRow
	Clients   []store.CompilerClient
	// Authorized and Claims are by Endpoint and prefix.
	Authorized []store.CompilerPrefix
	Claims     []store.CompilerPrefix
	Profiles   []store.CompilerProfile
	// Rules is the rules of every profile, for a caller that has no database (a test). The compiler's own read leaves it
	// empty and sets RulesOf instead.
	Rules []store.ProfileRule
	// RulesOf reads the rules of one profile in the snapshot of the tenant, when set. The compile asks for one profile at a
	// time and drops its rows once the blob is built, so a tenant with 20 profiles of 10,000 rules holds one of them.
	RulesOf  func(profile uuid.UUID) ([]store.RuleRow, error)
	Folders  []store.ProfileFolder
	Services []store.ProfileService
	Filters  []store.ProfileFilter
	Options  []store.ProfileOptions
	Maps     store.CompilerMaps
}

// Output is what one tenant compiles to. Keys are the raw ids as strings, so no array travels by value.
type Output struct {
	Endpoints map[string]*policyv1.EndpointRecord
	Claims    map[string]*policyv1.ClaimRecord
	// Blobs holds every blob the records bind, by hash.
	Blobs map[string]*Profile
	// Kept names the Endpoints that could not be compiled and have no record in the log to fall back on: they get no
	// record, so no node serves them (6.2). An Endpoint that has a record is never kept: it is emitted with what the
	// database says now and, for the part that did not compile, the stack the log holds.
	Kept map[string]bool
	// Problems are what the pass found and an operator should hear of, each once per tenant and reason.
	Problems []Reason
	// readErr is the error of a RulesOf: the output is not to be used, and the caller treats it as the failed read of the tenant.
	readErr error
}

// CompileTenant compiles one tenant's Endpoints, claims and the profiles they bind (P3 3.2, SC 9.2). It is a pure
// function of its input and the time, which only the schedule horizon reads.
func CompileTenant(in *TenantInput, now time.Time) *Output { return CompileTenantWith(in, now, nil) }

// CompileTenantWith is CompileTenant with the record the log holds for an Endpoint, which a part that does not compile
// falls back to. A profile that fails to compile, or a zone the build does not know, says nothing about who may query the
// Endpoint, so the hold, the tokens, the authorized addresses and the claims always come from the rows; only the stacks
// and the schedule that failed stay as the log has them. An Endpoint with no record and a failing part is kept out.
func CompileTenantWith(in *TenantInput, now time.Time, prev func(key string) *policyv1.EndpointRecord) *Output {
	out := &Output{Endpoints: map[string]*policyv1.EndpointRecord{}, Claims: map[string]*policyv1.ClaimRecord{},
		Blobs: map[string]*Profile{}, Kept: map[string]bool{}}
	problem := func(r Reason) {
		if !slices.Contains(out.Problems, r) {
			out.Problems = append(out.Problems, r)
		}
	}

	// Which profiles are used at all: a profile nothing binds compiles to nothing.
	used := map[uuid.UUID]bool{}
	for i := range in.Endpoints {
		e := &in.Endpoints[i]
		used[e.ProfileID], used[e.Profile2ID] = true, true
	}
	for i := range in.Windows {
		used[in.Windows[i].ProfileID], used[in.Windows[i].Profile2ID] = true, true
	}
	for i := range in.Clients {
		used[in.Clients[i].ProfileID], used[in.Clients[i].Profile2ID] = true, true
	}
	delete(used, uuid.Nil)

	// The rules come from one place or the other, and are taken one profile at a time.
	var held map[uuid.UUID][]store.RuleRow
	rulesOf := in.RulesOf
	if rulesOf == nil {
		held = map[uuid.UUID][]store.RuleRow{}
		for i := range in.Rules {
			held[in.Rules[i].ProfileID] = append(held[in.Rules[i].ProfileID], in.Rules[i].RuleRow)
		}
		rulesOf = func(p uuid.UUID) ([]store.RuleRow, error) { return held[p], nil }
	}
	folders := map[uuid.UUID]map[uuid.UUID]store.FolderRow{}
	for i := range in.Folders {
		p := in.Folders[i].ProfileID
		if folders[p] == nil {
			folders[p] = map[uuid.UUID]store.FolderRow{}
		}
		folders[p][in.Folders[i].ID] = in.Folders[i].FolderRow
	}
	services := map[uuid.UUID][]store.ServiceRow{}
	for i := range in.Services {
		services[in.Services[i].ProfileID] = append(services[in.Services[i].ProfileID], in.Services[i].ServiceRow)
	}
	filters := map[uuid.UUID][]store.FilterRow{}
	for i := range in.Filters {
		filters[in.Filters[i].ProfileID] = append(filters[in.Filters[i].ProfileID], in.Filters[i].FilterRow)
	}
	options := map[uuid.UUID]*store.OptionsRow{}
	for i := range in.Options {
		options[in.Options[i].ProfileID] = &in.Options[i].OptionsRow
	}
	compiled := map[uuid.UUID]*Profile{}
	for i := range in.Profiles {
		p := &in.Profiles[i]
		if !used[p.ID] {
			continue
		}
		pd := &ProfileData{ID: p.ID, Folders: folders[p.ID], Services: services[p.ID], Filters: filters[p.ID], Options: options[p.ID]}
		if pd.Folders == nil {
			pd.Folders = map[uuid.UUID]store.FolderRow{}
		}
		if p.DisabledUntil != nil {
			pd.DisabledUntil = p.DisabledUntil.Unix()
		}
		rules, err := rulesOf(p.ID)
		if err != nil {
			out.readErr = err
			return out
		}
		pd.Rules = rules
		blob, err := CompileProfile(pd, &in.Maps)
		// The rows of this profile go before the next one is read.
		pd.Rules, rules = nil, nil
		delete(held, p.ID) // a no-op for the database read
		if err != nil {
			problem(ReasonProfile)
			continue
		}
		compiled[p.ID] = blob
	}

	byHash := map[string]*Profile{}
	for _, p := range compiled {
		byHash[string(p.Hash)] = p
	}
	windows := map[uuid.UUID][]store.WindowRow{}
	for _, w := range in.Windows {
		windows[w.EndpointID] = append(windows[w.EndpointID], w)
	}
	clients := map[uuid.UUID][]store.CompilerClient{}
	for _, c := range in.Clients {
		clients[c.EndpointID] = append(clients[c.EndpointID], c)
	}
	authorized := map[uuid.UUID][]store.CompilerPrefix{}
	for _, a := range in.Authorized {
		authorized[a.EndpointID] = append(authorized[a.EndpointID], a)
	}
	claims := map[uuid.UUID][]store.CompilerPrefix{}
	for _, c := range in.Claims {
		claims[c.EndpointID] = append(claims[c.EndpointID], c)
	}

	// The horizon starts at the day, not the instant, so the record of an Endpoint does not change on every
	// compile and is re-emitted only when a transition enters it or the start passes one.
	from := now.UTC().Truncate(24 * time.Hour).Unix()
	to := from + int64(scheduleHorizon/time.Second)

	for i := range in.Endpoints {
		e := &in.Endpoints[i]
		key := string(e.ID[:])
		var old *policyv1.EndpointRecord
		if prev != nil {
			old = prev(key)
		}
		rec, ok := compileEndpoint(e, in, compiled, windows[e.ID], clients[e.ID], authorized[e.ID], from, to, old, problem)
		if !ok {
			out.Kept[key] = true
			continue
		}
		out.Endpoints[key] = rec
		for _, h := range bindings(rec) {
			// A stack taken from the log names a blob that was not compiled now; the nodes hold it already.
			if p := byHash[string(h)]; p != nil {
				out.Blobs[string(h)] = p
			}
		}
		if e.LegacyDNS {
			for _, c := range claims[e.ID] {
				p, err := prefixWire(c.Prefix)
				if err != nil {
					problem(ReasonClaim)
					continue
				}
				out.Claims[string(c.ID[:])] = &policyv1.ClaimRecord{ClaimId: c.ID[:], EndpointId: e.ID[:], Prefix: p}
			}
		}
	}
	return out
}

// bindings lists every profile hash a record binds, base, windows and clients, each once.
func bindings(e *policyv1.EndpointRecord) [][]byte {
	seen := map[string]bool{}
	var out [][]byte
	add := func(s *policyv1.StackRecord) {
		if s == nil {
			return
		}
		for _, h := range [][]byte{s.Profile1Hash, s.Profile2Hash} {
			if len(h) != 0 && !seen[string(h)] {
				seen[string(h)] = true
				out = append(out, h)
			}
		}
	}
	add(e.Base)
	for _, w := range e.GetSchedule().GetWindows() {
		add(w.Stack)
	}
	for _, c := range e.Clients {
		add(c.Stack)
	}
	return out
}

func stackOf(compiled map[uuid.UUID]*Profile, p1, p2 uuid.UUID) (*policyv1.StackRecord, bool) {
	a := compiled[p1]
	if a == nil {
		return nil, false
	}
	var b *Profile
	if p2 != uuid.Nil {
		if b = compiled[p2]; b == nil {
			return nil, false
		}
	}
	return Stack(a, b), true
}

// compileEndpoint is the compile map of P3 3.2, field by field. A stack or a schedule that does not compile (a profile that
// failed, a zone the build does not know) is taken from old, the record the log holds, so the rest of the record still
// follows the rows; it reports false only when there is no old record to take it from, and the caller then gives the
// Endpoint no record.
func compileEndpoint(e *store.CompilerEndpoint, in *TenantInput, compiled map[uuid.UUID]*Profile, ws []store.WindowRow, cs []store.CompilerClient,
	auth []store.CompilerPrefix, from, to int64, old *policyv1.EndpointRecord, problem func(Reason)) (*policyv1.EndpointRecord, bool) {
	// A value the database constrains and the compiler does not know fails closed: an unknown state hard-disables, an
	// unknown analytics level records nothing.
	state, known := adminOf(e.AdminState)
	if !known {
		state = commonv1.AdminState_ADMIN_STATE_HARD_DISABLED
		problem(ReasonRecordInvalid)
	}
	// The hold of the Endpoint or of the tenant is a hard disable on every node (PS 4).
	if e.AdminHold || in.Row.AdminHold {
		state = commonv1.AdminState_ADMIN_STATE_HARD_DISABLED
	}
	level, known := analyticsOf(e.AnalyticsLevel)
	if !known {
		level = commonv1.AnalyticsLevel_ANALYTICS_LEVEL_NONE
		problem(ReasonRecordInvalid)
	}
	rid := identity.RIDHash(e.ResolverID)
	token := e.TokenHash
	if len(token) != 32 {
		// A row with no token hash matches no path token: 32 bytes that no SHA-256 of a token is.
		token = make([]byte, 32)
	}
	base, ok := stackOf(compiled, e.ProfileID, e.Profile2ID)
	if !ok {
		if old == nil || old.Base == nil {
			return nil, false
		}
		base = old.Base
	}
	rec := &policyv1.EndpointRecord{
		EndpointId: e.ID[:], RidHash: rid[:], DohTokenHash: token, AdminState: state,
		LegacyDns: e.LegacyDNS, RequireAuthorizedIps: e.RequireAuthorizedIPs, ExposeIp: e.ExposeIP,
		AuthorizeSecureDns: e.AuthorizeSecureDNS, AnalyticsLevel: level,
		// Every Endpoint carries the global pair (D30), which a zero id names: it is in no table, so the node
		// takes the global pair (SC 8a.2 step 2). wire.ValidateEndpoint wants 16 bytes, so the id is 16 zeros.
		PairId: make([]byte, 16), PairVersion: uint32(e.PairVersion),
		Base: base, ClientCap: uint32(in.Row.ClientCap), GrantCap: grantCap,
	}
	if len(ws) != 0 {
		sc, ok := scheduleOf(e, ws, compiled, from, to)
		if !ok {
			problem(ReasonSchedule)
			if old == nil {
				return nil, false
			}
			sc = old.Schedule
		}
		rec.Schedule = sc
	}
	oldStack := map[string]*policyv1.StackRecord{}
	for _, c := range old.GetClients() {
		oldStack[string(c.ClientId)] = c.Stack
	}
	seen := map[string]bool{}
	for _, c := range cs {
		h := identity.ClientHash(c.Label)
		if seen[string(h[:])] {
			continue
		}
		seen[string(h[:])] = true
		cr := &policyv1.ClientRecord{ClientId: c.ID[:], ClientHash: h[:]}
		if c.ProfileID != uuid.Nil {
			if cr.Stack, ok = stackOf(compiled, c.ProfileID, c.Profile2ID); !ok {
				if old == nil {
					return nil, false
				}
				// The stack the log had for this client, and with none (a new client) no record of the client: it is
				// served the Endpoint's base, as an unknown client is.
				if cr.Stack = oldStack[string(c.ID[:])]; cr.Stack == nil {
					continue
				}
			}
		}
		if c.Analytics != "" {
			cr.AnalyticsOverride, cr.HasAnalyticsOverride = analyticsOf(c.Analytics)
		}
		rec.Clients = append(rec.Clients, cr)
	}
	if len(rec.Clients) > wire.MaxClientsPerEP {
		rec.Clients = rec.Clients[:wire.MaxClientsPerEP]
		problem(ReasonClientsCut)
	}
	for _, a := range auth {
		p, err := prefixWire(a.Prefix)
		if err != nil {
			problem(ReasonPrefix)
			continue
		}
		rec.Authorized = append(rec.Authorized, p)
	}
	if len(rec.Authorized) > wire.MaxAuthorizedIPs {
		// The compiler holds no read of authorized_ips.source (migration 0037), so the cut keeps the first prefixes
		// in prefix order and not manual rows first as P4 6.2 would; only a manual entitlement above 800 gets here.
		rec.Authorized = rec.Authorized[:wire.MaxAuthorizedIPs]
		problem(ReasonAuthorizedCut)
	}
	return rec, true
}

// scheduleOf builds the ScheduleRecord of an Endpoint: its zone's offset transitions over the horizon, the grid from
// the one function of internal/endpoints, and one stack a window.
func scheduleOf(e *store.CompilerEndpoint, ws []store.WindowRow, compiled map[uuid.UUID]*Profile, from, to int64) (*policyv1.ScheduleRecord, bool) {
	loc, err := time.LoadLocation(e.ScheduleTimezone)
	if err != nil || e.ScheduleTimezone == "" {
		return nil, false
	}
	base, trs := schedule.BuildTransitions(loc, from, to)
	sc := &policyv1.ScheduleRecord{Zone: e.ScheduleTimezone, BaseOffset: base}
	for _, t := range trs {
		sc.Transitions = append(sc.Transitions, &policyv1.OffsetTransition{At: t.At, Offset: t.Offset})
	}
	in := make([]endpoints.Window, len(ws))
	for i, w := range ws {
		in[i] = endpoints.Window{ID: w.ID, Start: w.Start, End: w.End}
	}
	grid := endpoints.Grid(in)
	sc.Grid = grid[:]
	for _, w := range ws {
		st, ok := stackOf(compiled, w.ProfileID, w.Profile2ID)
		if !ok {
			return nil, false
		}
		sc.Windows = append(sc.Windows, &policyv1.WindowRecord{WindowId: w.ID[:], Stack: st})
	}
	return sc, true
}

// equalRecord is proto.Equal for two Endpoint records.
func equalRecord(a, b *policyv1.EndpointRecord) bool { return proto.Equal(a, b) }

func analyticsOf(s string) (commonv1.AnalyticsLevel, bool) {
	switch s {
	case "none":
		return commonv1.AnalyticsLevel_ANALYTICS_LEVEL_NONE, true
	case "some":
		return commonv1.AnalyticsLevel_ANALYTICS_LEVEL_SOME, true
	case "full":
		return commonv1.AnalyticsLevel_ANALYTICS_LEVEL_FULL, true
	}
	return 0, false
}

func adminOf(s string) (commonv1.AdminState, bool) {
	switch s {
	case "enabled":
		return commonv1.AdminState_ADMIN_STATE_ENABLED, true
	case "soft_disabled":
		return commonv1.AdminState_ADMIN_STATE_SOFT_DISABLED, true
	case "hard_disabled":
		return commonv1.AdminState_ADMIN_STATE_HARD_DISABLED, true
	}
	return 0, false
}

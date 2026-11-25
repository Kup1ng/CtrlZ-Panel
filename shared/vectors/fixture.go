package vectors

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	"github.com/Kup1ng/CtrlZ-Shared/gtable"
	"github.com/Kup1ng/CtrlZ-Shared/identity"
	"github.com/Kup1ng/CtrlZ-Shared/locations"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/policy"
	"github.com/Kup1ng/CtrlZ-Shared/rules"
	"github.com/Kup1ng/CtrlZ-Shared/schedule"
)

// FixtureFile is the plain-text description of a world the cases run in:
// catalog tables, geo data, locations, profiles and Endpoints. It is compiled
// with blob.Build and gtable.Builder at test time, so a fixture stays readable
// and the compilers are exercised by every run.
type FixtureFile struct {
	Format    int                     `json:"format"`
	Catalog   CatalogJSON             `json:"catalog"`
	Geo       GeoJSON                 `json:"geo"`
	Locations LocationsJSON           `json:"locations"`
	Self      SelfJSON                `json:"self"`
	Profiles  map[string]ProfileJSON  `json:"profiles"`
	Endpoints map[string]EndpointJSON `json:"endpoints"`
}

type CatalogJSON struct {
	KeyHex     string            `json:"key_hex"`
	Version    uint64            `json:"version"`
	Filters    []FilterJSON      `json:"filters"`
	Services   []ServiceJSON     `json:"services"`
	Categories []CategoryJSON    `json:"categories"`
	SafeSearch map[string]string `json:"safe_search"`
	YouTube    map[string]string `json:"youtube"`
}

type FilterJSON struct {
	Name    string   `json:"name"`
	ID      uint16   `json:"id"`
	Mode    uint16   `json:"mode"`
	Domains []string `json:"domains"` // "suffix:x", "full:x", or bare for suffix
}

type ServiceJSON struct {
	Name    string   `json:"name"`
	Wire    uint32   `json:"wire"`
	Domains []string `json:"domains"`
}

type CategoryJSON struct {
	Domain string `json:"domain"`
	Mask   uint32 `json:"mask"`
	SvcCat uint8  `json:"svc_cat"`
}

type GeoJSON struct {
	Country map[string]string `json:"country"`
	ASN     map[string]uint32 `json:"asn"`
}

// LocationsJSON: Healthy lists the wire ids this node has working configs for.
// Latency (milliseconds by wire id) feeds Auto; with none, Auto picks the
// lowest wire id, which keeps cases independent of any measurement.
type LocationsJSON struct {
	Healthy []uint16          `json:"healthy"`
	Latency map[string]uint32 `json:"latency"`
}

type SelfJSON struct {
	DNSIP          string   `json:"dns_ip"`
	ProxyIP        string   `json:"proxy_ip"`
	PeerProxyIP    string   `json:"peer_proxy_ip"`
	PeerUsable     bool     `json:"peer_usable"`
	PanelHostnames []string `json:"panel_hostnames"`
}

type ProfileJSON struct {
	DisabledUntil string       `json:"disabled_until"`
	Options       OptionsJSON  `json:"options"`
	Default       string       `json:"default"`
	DefaultTarget *TargetJSON  `json:"default_target"`
	Rules         []RuleJSON   `json:"rules"`
	Services      []ServiceUse `json:"services"`
	Filters       []string     `json:"filters"`
}

type OptionsJSON struct {
	Exfiltration      *bool          `json:"exfiltration"`
	Rebind            *bool          `json:"rebind"`
	DisableDNSSEC     *bool          `json:"disable_dnssec"`
	DNS64             *bool          `json:"dns64"`
	Flatten           *bool          `json:"flatten"`
	SafeSearch        *bool          `json:"safe_search"`
	RestrictedYouTube *bool          `json:"restricted_youtube"`
	BlockResponse     *BlockRespJSON `json:"block_response"`
	ECS               *ECSJSON       `json:"ecs"`
	BlockTTL          *uint32        `json:"block_ttl"`
	RedirectTTL       *uint32        `json:"redirect_ttl"`
	BypassTTL         *uint32        `json:"bypass_ttl"`
}

type BlockRespJSON struct {
	Mode string `json:"mode"` // zero, nxdomain, refused, custom, branded
	V4   string `json:"v4"`
	V6   string `json:"v6"`
}

type ECSJSON struct {
	Mode   string `json:"mode"` // none, auto, custom
	V4     string `json:"v4"`
	V4Bits uint8  `json:"v4_bits"`
	V6     string `json:"v6"`
	V6Bits uint8  `json:"v6_bits"`
}

type TargetJSON struct {
	Kind     string   `json:"kind"` // location, auto, random, ip, host
	Location uint16   `json:"location"`
	Set      []uint16 `json:"set"`
	V4       string   `json:"v4"`
	V6       string   `json:"v6"`
	Host     string   `json:"host"`
}

type RuleJSON struct {
	Name           string      `json:"name"`
	Token          string      `json:"token"`
	Action         string      `json:"action"`
	Target         *TargetJSON `json:"target"`
	Expires        string      `json:"expires"`
	DoNotLog       bool        `json:"do_not_log"`
	LocUnavailable bool        `json:"location_unavailable"`
}

type ServiceUse struct {
	Name           string      `json:"name"`
	Action         string      `json:"action"`
	Target         *TargetJSON `json:"target"`
	DoNotLog       bool        `json:"do_not_log"`
	LocUnavailable bool        `json:"location_unavailable"`
}

type EndpointJSON struct {
	Profile1 string                `json:"profile1"`
	Profile2 string                `json:"profile2"`
	PairLocs []uint16              `json:"pair_locs"`
	Schedule *ScheduleJSON         `json:"schedule"`
	Clients  map[string]ClientJSON `json:"clients"`
}

type ClientJSON struct {
	Profile1 string `json:"profile1"`
	Profile2 string `json:"profile2"`
}

type ScheduleJSON struct {
	BaseOffset  int32            `json:"base_offset"`
	Transitions []TransitionJSON `json:"transitions"`
	Windows     []WindowJSON     `json:"windows"`
	// Fill sets grid cells: window is 1-based; cells From..To inclusive.
	Fill []FillJSON `json:"fill"`
}

type TransitionJSON struct {
	At     string `json:"at"`
	Offset int32  `json:"offset"`
}

type WindowJSON struct {
	ID       string `json:"id"`
	Profile1 string `json:"profile1"`
	Profile2 string `json:"profile2"`
}

type FillJSON struct {
	From   int `json:"from"`
	To     int `json:"to"`
	Window int `json:"window"`
}

// Fixture is a compiled FixtureFile.
type Fixture struct {
	Name string
	File *FixtureFile

	// Compiled artifacts, exposed so another implementation (the node's glue
	// harness) can load them through its own code paths.
	ProfileBytes map[string][]byte
	Profiles     map[string]*blob.Profile
	TableBytes   map[uint32][]byte // by FilterWire; services and categories below
	ServiceTable []byte
	CatTable     []byte
	Catalog      *policy.Catalog
	Endpoints    map[string]*policy.EndpointView

	ruleLabel map[[16]byte]string
	svcLabel  map[uint32]string
}

// RuleID derives the stable 16-byte id of a rule label.
func RuleID(label string) [16]byte {
	h := sha256.Sum256([]byte("vector-rule:" + label))
	var id [16]byte
	copy(id[:], h[:16])
	return id
}

// EndpointID derives the stable id of an Endpoint label.
func EndpointID(label string) [16]byte {
	h := sha256.Sum256([]byte("vector-endpoint:" + label))
	var id [16]byte
	copy(id[:], h[:16])
	return id
}

func parseTime(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0, err
	}
	return t.Unix(), nil
}

func action(s string) (blob.Action, error) {
	switch s {
	case "block":
		return blob.ActBlock, nil
	case "bypass":
		return blob.ActBypass, nil
	case "redirect":
		return blob.ActRedirect, nil
	case "", "null":
		return blob.ActNone, nil
	}
	return 0, fmt.Errorf("unknown action %q", s)
}

func targetSpec(t *TargetJSON) (*blob.TargetSpec, error) {
	if t == nil {
		return nil, nil
	}
	ts := &blob.TargetSpec{Location: t.Location, Set: t.Set}
	switch t.Kind {
	case "location":
		ts.Kind = blob.TargetLocation
	case "auto":
		ts.Kind = blob.TargetAuto
	case "random":
		ts.Kind = blob.TargetRandom
	case "ip":
		ts.Kind = blob.TargetIP
		if t.V4 != "" {
			a, err := netip.ParseAddr(t.V4)
			if err != nil {
				return nil, err
			}
			ts.V4 = a
		}
		if t.V6 != "" {
			a, err := netip.ParseAddr(t.V6)
			if err != nil {
				return nil, err
			}
			ts.V6 = a
		}
	case "host":
		ts.Kind = blob.TargetHost
		n, err := names.FromString(t.Host)
		if err != nil {
			return nil, err
		}
		ts.Host = append([]byte(nil), n.Wire()...)
	default:
		return nil, fmt.Errorf("unknown target kind %q", t.Kind)
	}
	return ts, nil
}

func boolOpt(o *blob.Options, bit uint32, v *bool) {
	if v == nil {
		return
	}
	o.Present |= bit
	if *v {
		o.Bools |= uint8(bit)
	}
}

func (oj *OptionsJSON) build() (blob.Options, error) {
	var o blob.Options
	boolOpt(&o, blob.OptExfiltration, oj.Exfiltration)
	boolOpt(&o, blob.OptRebind, oj.Rebind)
	boolOpt(&o, blob.OptDisableDNSSEC, oj.DisableDNSSEC)
	boolOpt(&o, blob.OptDNS64, oj.DNS64)
	boolOpt(&o, blob.OptFlatten, oj.Flatten)
	boolOpt(&o, blob.OptSafeSearch, oj.SafeSearch)
	boolOpt(&o, blob.OptRestrictedYouTube, oj.RestrictedYouTube)
	if b := oj.BlockResponse; b != nil {
		o.Present |= blob.OptBlockResponse
		switch b.Mode {
		case "zero":
			o.BlockResponse = blob.BlockZero
		case "nxdomain":
			o.BlockResponse = blob.BlockNXDomain
		case "refused":
			o.BlockResponse = blob.BlockRefused
		case "custom":
			o.BlockResponse = blob.BlockCustom
		case "branded":
			o.BlockResponse = blob.BlockBranded
		default:
			return o, fmt.Errorf("block_response mode %q", b.Mode)
		}
		if b.V4 != "" {
			a, err := netip.ParseAddr(b.V4)
			if err != nil {
				return o, err
			}
			o.BlockV4 = a.As4()
		}
		if b.V6 != "" {
			a, err := netip.ParseAddr(b.V6)
			if err != nil {
				return o, err
			}
			o.BlockV6 = a.As16()
		}
	}
	if e := oj.ECS; e != nil {
		o.Present |= blob.OptECS
		switch e.Mode {
		case "none":
			o.ECSMode = blob.ECSNone
		case "auto":
			o.ECSMode = blob.ECSAuto
		case "custom":
			o.ECSMode = blob.ECSCustom
		default:
			return o, fmt.Errorf("ecs mode %q", e.Mode)
		}
		o.ECSV4Prefix, o.ECSV6Prefix = e.V4Bits, e.V6Bits
		if e.V4 != "" {
			a, err := netip.ParseAddr(e.V4)
			if err != nil {
				return o, err
			}
			o.ECSV4 = a.As4()
		}
		if e.V6 != "" {
			a, err := netip.ParseAddr(e.V6)
			if err != nil {
				return o, err
			}
			o.ECSV6 = a.As16()
		}
	}
	if oj.BlockTTL != nil {
		o.Present |= blob.OptBlockTTL
		o.BlockTTL = *oj.BlockTTL
	}
	if oj.RedirectTTL != nil {
		o.Present |= blob.OptRedirectTTL
		o.RedirectTTL = *oj.RedirectTTL
	}
	if oj.BypassTTL != nil {
		o.Present |= blob.OptBypassTTL
		o.BypassTTL = *oj.BypassTTL
	}
	return o, nil
}

func domainEntry(s string) (gtable.Entry, error) {
	exact := false
	if v, ok := strings.CutPrefix(s, "full:"); ok {
		exact, s = true, v
	} else if v, ok := strings.CutPrefix(s, "suffix:"); ok {
		s = v
	}
	n, err := names.FromString(s)
	if err != nil {
		return gtable.Entry{}, err
	}
	return gtable.Entry{Name: append([]byte(nil), n.Wire()...), Exact: exact}, nil
}

// Compile builds every artifact of f. name is the fixture's file name.
func Compile(name string, f *FixtureFile) (*Fixture, error) {
	fx := &Fixture{Name: name, File: f,
		ProfileBytes: map[string][]byte{}, Profiles: map[string]*blob.Profile{}, TableBytes: map[uint32][]byte{},
		Endpoints: map[string]*policy.EndpointView{}, ruleLabel: map[[16]byte]string{}, svcLabel: map[uint32]string{}}

	// Catalog.
	keyB, err := hex.DecodeString(f.Catalog.KeyHex)
	if err != nil || len(keyB) != 16 {
		return nil, fmt.Errorf("fixture %s: catalog.key_hex must be 32 hex characters", name)
	}
	var key [16]byte
	copy(key[:], keyB)
	byWire := map[uint32][]gtable.Entry{}
	filterByName := map[string]FilterJSON{}
	for _, fl := range f.Catalog.Filters {
		filterByName[fl.Name] = fl
		w := policy.FilterWire(fl.ID, fl.Mode)
		for _, d := range fl.Domains {
			e, err := domainEntry(d)
			if err != nil {
				return nil, fmt.Errorf("filter %s: %w", fl.Name, err)
			}
			byWire[w] = append(byWire[w], e)
		}
		if _, ok := byWire[w]; !ok {
			byWire[w] = nil
		}
	}
	filters := map[uint32]*gtable.Table{}
	for w, es := range byWire {
		data, err := (&gtable.Builder{Kind: gtable.KindFilter, CatalogVersion: f.Catalog.Version, Key: key, Entries: es}).Build()
		if err != nil {
			return nil, err
		}
		t, err := gtable.Open(data)
		if err != nil {
			return nil, err
		}
		fx.TableBytes[w] = data
		filters[w] = t
	}
	svcByName := map[string]ServiceJSON{}
	var svcEntries []gtable.Entry
	for _, s := range f.Catalog.Services {
		svcByName[s.Name] = s
		fx.svcLabel[s.Wire] = s.Name
		for _, d := range s.Domains {
			e, err := domainEntry(d)
			if err != nil {
				return nil, err
			}
			e.Wire = s.Wire
			svcEntries = append(svcEntries, e)
		}
	}
	var svcTbl, catTbl *gtable.Table
	if len(f.Catalog.Services) > 0 {
		fx.ServiceTable, err = (&gtable.Builder{Kind: gtable.KindService, CatalogVersion: f.Catalog.Version, Key: key, Entries: svcEntries}).Build()
		if err != nil {
			return nil, err
		}
		if svcTbl, err = gtable.Open(fx.ServiceTable); err != nil {
			return nil, err
		}
	}
	if len(f.Catalog.Categories) > 0 {
		var ces []gtable.Entry
		for _, c := range f.Catalog.Categories {
			e, err := domainEntry(c.Domain)
			if err != nil {
				return nil, err
			}
			e.Mask, e.SvcCat = c.Mask, c.SvcCat
			ces = append(ces, e)
		}
		fx.CatTable, err = (&gtable.Builder{Kind: gtable.KindCategory, CatalogVersion: f.Catalog.Version, Key: key, Entries: ces}).Build()
		if err != nil {
			return nil, err
		}
		if catTbl, err = gtable.Open(fx.CatTable); err != nil {
			return nil, err
		}
	}
	rw := policy.Rewrite{SafeSearch: map[string]names.Name{}, YouTube: map[string]names.Name{}}
	for _, p := range []struct {
		src map[string]string
		dst map[string]names.Name
	}{{f.Catalog.SafeSearch, rw.SafeSearch}, {f.Catalog.YouTube, rw.YouTube}} {
		for from, to := range p.src {
			a, err := names.FromString(from)
			if err != nil {
				return nil, err
			}
			b, err := names.FromString(to)
			if err != nil {
				return nil, err
			}
			p.dst[string(a.Wire())] = b
		}
	}
	fx.Catalog, err = policy.NewCatalog(svcTbl, filters, catTbl, rw)
	if err != nil {
		return nil, err
	}

	// Profiles.
	for pname, pj := range f.Profiles {
		spec := &blob.Spec{}
		if spec.DisabledUntil, err = parseTime(pj.DisabledUntil); err != nil {
			return nil, fmt.Errorf("profile %s: %w", pname, err)
		}
		if spec.Options, err = pj.Options.build(); err != nil {
			return nil, fmt.Errorf("profile %s: %w", pname, err)
		}
		if spec.Default, err = action(pj.Default); err != nil {
			return nil, err
		}
		if spec.DefaultTarget, err = targetSpec(pj.DefaultTarget); err != nil {
			return nil, err
		}
		for _, r := range pj.Rules {
			pat, err := rules.Parse(r.Token)
			if err != nil {
				return nil, fmt.Errorf("profile %s rule %s: %w", pname, r.Name, err)
			}
			a, err := action(r.Action)
			if err != nil {
				return nil, err
			}
			ts, err := targetSpec(r.Target)
			if err != nil {
				return nil, err
			}
			exp, err := parseTime(r.Expires)
			if err != nil {
				return nil, err
			}
			id := RuleID(r.Name)
			fx.ruleLabel[id] = r.Name
			spec.Rules = append(spec.Rules, blob.RuleSpec{ID: id, Pattern: pat, Action: a, Target: ts, ExpiresAt: exp, DoNotLog: r.DoNotLog, LocationUnavailable: r.LocUnavailable})
		}
		for _, s := range pj.Services {
			sv, ok := svcByName[s.Name]
			if !ok {
				return nil, fmt.Errorf("profile %s: unknown service %q", pname, s.Name)
			}
			a, err := action(s.Action)
			if err != nil {
				return nil, err
			}
			ts, err := targetSpec(s.Target)
			if err != nil {
				return nil, err
			}
			spec.Services = append(spec.Services, blob.ServiceSpec{Wire: sv.Wire, Action: a, Target: ts, DoNotLog: s.DoNotLog, LocationUnavailable: s.LocUnavailable})
		}
		for _, fname := range pj.Filters {
			fl, ok := filterByName[fname]
			if !ok {
				return nil, fmt.Errorf("profile %s: unknown filter %q", pname, fname)
			}
			spec.Filters = append(spec.Filters, blob.FilterSpec{FilterID: fl.ID, ModeWire: fl.Mode})
		}
		data, err := blob.Build(spec)
		if err != nil {
			return nil, fmt.Errorf("profile %s: %w", pname, err)
		}
		p, err := blob.Open(data)
		if err != nil {
			return nil, err
		}
		fx.ProfileBytes[pname], fx.Profiles[pname] = data, p
	}

	// Endpoints.
	prof := func(n string) (*blob.Profile, error) {
		if n == "" {
			return nil, nil
		}
		p, ok := fx.Profiles[n]
		if !ok {
			return nil, fmt.Errorf("unknown profile %q", n)
		}
		return p, nil
	}
	for ename, ej := range f.Endpoints {
		bm := make([]byte, 0)
		for _, l := range ej.PairLocs {
			for len(bm) <= int(l)/8 {
				bm = append(bm, 0)
			}
			bm[l/8] |= 1 << (l % 8)
		}
		pairLocs := locations.BitmapFromBytes(bm)
		stack := func(a, b string) (*policy.Stack, error) {
			p1, err := prof(a)
			if err != nil {
				return nil, err
			}
			p2, err := prof(b)
			if err != nil {
				return nil, err
			}
			return policy.NewStack(p1, p2, pairLocs), nil
		}
		ev := &policy.EndpointView{ID: EndpointID(ename), Clients: map[[16]byte]*policy.Stack{}}
		if ev.Base, err = stack(ej.Profile1, ej.Profile2); err != nil {
			return nil, fmt.Errorf("endpoint %s: %w", ename, err)
		}
		for cl, cj := range ej.Clients {
			s, err := stack(cj.Profile1, cj.Profile2)
			if err != nil {
				return nil, err
			}
			ev.Clients[identity.ClientHash(cl)] = s
		}
		if sj := ej.Schedule; sj != nil {
			var trs []schedule.Transition
			for _, t := range sj.Transitions {
				at, err := parseTime(t.At)
				if err != nil {
					return nil, err
				}
				trs = append(trs, schedule.Transition{At: at, Offset: t.Offset})
			}
			grid := make([]byte, schedule.Cells)
			for _, fl := range sj.Fill {
				for c := fl.From; c <= fl.To; c++ {
					grid[c] = byte(fl.Window)
				}
			}
			sc, err := schedule.New(sj.BaseOffset, trs, grid, len(sj.Windows))
			if err != nil {
				return nil, err
			}
			ev.Sched = sc
			for _, w := range sj.Windows {
				s, err := stack(w.Profile1, w.Profile2)
				if err != nil {
					return nil, err
				}
				ev.Windows = append(ev.Windows, s)
				var id [16]byte
				h := sha256.Sum256([]byte("vector-window:" + w.ID))
				copy(id[:], h[:16])
				ev.WindowIDs = append(ev.WindowIDs, id)
			}
		}
		fx.Endpoints[ename] = ev
	}
	return fx, nil
}

// RefText renders a Ref the way vector files write it: a rule label, "svc:name",
// "filter:<id>", "default", "exfiltration", "system" or "".
func (fx *Fixture) RefText(r policy.Ref) string {
	switch r.Kind {
	case policy.RefRule:
		if l, ok := fx.ruleLabel[r.ID]; ok {
			return l
		}
		return "rule:" + hex.EncodeToString(r.ID[:4])
	case policy.RefService:
		if l, ok := fx.svcLabel[r.Wire]; ok {
			return "svc:" + l
		}
		return fmt.Sprintf("svc:%d", r.Wire)
	case policy.RefFilter:
		return fmt.Sprintf("filter:%d", r.Wire)
	case policy.RefDefault:
		return "default"
	case policy.RefExfiltration:
		return "exfiltration"
	case policy.RefSystem:
		return "system"
	}
	return ""
}

// WindowName returns the window label for a window id, for diagnostics.
func (fx *Fixture) sortedEndpoints() []string {
	out := make([]string, 0, len(fx.Endpoints))
	for k := range fx.Endpoints {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

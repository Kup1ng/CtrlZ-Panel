package compiler

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Shared/blob"
	policyv1 "github.com/Kup1ng/CtrlZ-Shared/gen/ctrlz/policy/v1"
	"github.com/Kup1ng/CtrlZ-Shared/names"
	"github.com/Kup1ng/CtrlZ-Shared/rules"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// ProfileData is everything one profile compiles from, read in one snapshot of the tenant.
type ProfileData struct {
	ID            uuid.UUID
	DisabledUntil int64 // Unix seconds, 0 for none
	Options       *store.OptionsRow
	Folders       map[uuid.UUID]store.FolderRow
	Rules         []store.RuleRow
	Services      []store.ServiceRow
	Filters       []store.FilterRow
}

// Profile is a compiled profile: the CZPB bytes, their SHA-256 and what a StackRecord needs of the blob.
//
// Bytes is nil once the blob has been put in the artifact store as it was built (TenantInput.Sink): a tenant with 20 maxed
// profiles would otherwise hold 100 MiB of them while it compiles (W4-r4-4). Len says the size either way.
type Profile struct {
	Bytes []byte
	Hash  []byte
	// size is the length of Bytes once they are released.
	size int
	Opts *blob.Options
	// MaxLabels, HasDestGeo and Explicit are the header facts a stack folds over its two slots (policy.NewStack).
	MaxLabels  uint32
	HasDestGeo bool
	Explicit   bool
}

// Len is the size of the blob in bytes, whether or not the bytes are still held.
func (p *Profile) Len() int {
	if p.Bytes != nil {
		return len(p.Bytes)
	}
	return p.size
}

// release drops the bytes after they are in the store, and keeps the size.
func (p *Profile) release() {
	p.size, p.Bytes = len(p.Bytes), nil
}

// ErrProfile is wrapped by every failure to compile one profile. The tenant's other profiles still compile: an
// Endpoint that binds the failed one keeps the record it had (6.2).
var ErrProfile = errors.New("compiler: profile does not compile")

// CompileProfile builds the CZPB blob of one profile (SC 9.2) from the P2 tables.
//
// What it decides, because the blob holds only resolved facts (SC 4, "Folder semantics"):
//   - a rule with enabled = false is never compiled; one past its expires_at still is, because the node acts on
//     expiry at query time so that a lapse during a panel outage still ends on time (T-035);
//   - an `inherit` action takes the folder's action, target and location flag; a rule of a `do_not_log` folder gets
//     the flag and keeps its own action; a `bypass` folder (Magic Bypass, D8) is stored and not compiled in v1;
//   - a disabled service or filter is absent, which differs from Bypass.
func CompileProfile(p *ProfileData, m *store.CompilerMaps) (*Profile, error) {
	spec := &blob.Spec{DisabledUntil: p.DisabledUntil}
	var err error
	if p.Options != nil {
		if err = optionsOf(p.Options, &spec.Options); err != nil {
			return nil, fmt.Errorf("%w: options", ErrProfile)
		}
		if spec.Default, spec.DefaultTarget, err = actionOf(p.Options.DefaultAction, &p.Options.DefaultTarget, m); err != nil {
			return nil, fmt.Errorf("%w: default rule", ErrProfile)
		}
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		if !r.Enabled {
			continue
		}
		folder, inFolder := p.Folders[r.FolderID]
		if r.FolderID != uuid.Nil && !inFolder {
			return nil, fmt.Errorf("%w: rule of a missing folder", ErrProfile)
		}
		if inFolder && folder.Kind == "bypass" {
			continue
		}
		act, tgt, unavailable := r.Action, &r.Target, r.LocationUnavailable
		if act == "inherit" {
			if !inFolder || folder.Action == "" {
				return nil, fmt.Errorf("%w: inherit without a folder action", ErrProfile)
			}
			act, tgt, unavailable = folder.Action, &folder.Target, folder.LocationUnavailable
		}
		pat, err := rules.Parse(r.Key)
		if err != nil || pat.Kind.String() != r.MatchKind || pat.Negated != r.Negated {
			return nil, fmt.Errorf("%w: rule key", ErrProfile)
		}
		a, ts, err := actionOf(act, tgt, m)
		if err != nil || a == blob.ActNone {
			return nil, fmt.Errorf("%w: rule action", ErrProfile)
		}
		rs := blob.RuleSpec{ID: r.ID, Pattern: pat, Action: a, Target: ts, DoNotLog: inFolder && folder.Kind == "do_not_log",
			LocationUnavailable: unavailable}
		if r.ExpiresAt != nil {
			rs.ExpiresAt = r.ExpiresAt.Unix()
		}
		spec.Rules = append(spec.Rules, rs)
	}
	for i := range p.Services {
		s := &p.Services[i]
		if !s.Enabled {
			continue
		}
		w, ok := m.Services[s.Slug]
		if !ok {
			return nil, fmt.Errorf("%w: unknown service", ErrProfile)
		}
		a, ts, err := actionOf(s.Action, &s.Target, m)
		if err != nil || a == blob.ActNone {
			return nil, fmt.Errorf("%w: service action", ErrProfile)
		}
		spec.Services = append(spec.Services, blob.ServiceSpec{Wire: w, Action: a, Target: ts, LocationUnavailable: s.LocationUnavailable})
	}
	for i := range p.Filters {
		f := &p.Filters[i]
		if !f.Enabled {
			continue
		}
		fw, ok := m.Filters[f.FilterID]
		if !ok {
			return nil, fmt.Errorf("%w: unknown filter", ErrProfile)
		}
		mw, ok := filterMode(m.Modes[f.FilterID], f.Mode)
		if !ok {
			return nil, fmt.Errorf("%w: unknown filter mode", ErrProfile)
		}
		spec.Filters = append(spec.Filters, blob.FilterSpec{FilterID: fw, ModeWire: mw})
	}
	data, err := blob.Build(spec)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProfile, err)
	}
	opened, err := blob.Open(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProfile, err)
	}
	h := opened.Hash()
	hdr := opened.Header()
	// A copy: the pointer into the opened blob would keep it and the bytes it reads from alive as long as a stack names it.
	opts := *opened.Options()
	return &Profile{Bytes: data, Hash: h[:], Opts: &opts, MaxLabels: uint32(hdr.MaxLabels), HasDestGeo: hdr.HasDestGeo(), Explicit: hdr.Explicit()}, nil
}

// filterMode is the wire id of the mode a profile names. A filter with one mode stores none: that mode is it. A filter
// with several and no name cannot be written (the foreign key of profile_filters), so it reads as unknown.
func filterMode(modes map[string]uint16, mode string) (uint16, bool) {
	if mode != "" {
		w, ok := modes[mode]
		return w, ok
	}
	if len(modes) != 1 {
		return 0, false
	}
	for _, w := range modes {
		return w, true
	}
	return 0, false
}

// actionOf turns the action and target columns into a blob action and target. "" is the null Default Rule.
func actionOf(action string, t *store.Target, m *store.CompilerMaps) (blob.Action, *blob.TargetSpec, error) {
	switch action {
	case "":
		return blob.ActNone, nil, nil
	case "block":
		return blob.ActBlock, nil, nil
	case "bypass":
		return blob.ActBypass, nil, nil
	case "redirect":
		ts, err := targetOf(t, m)
		return blob.ActRedirect, ts, err
	}
	return 0, nil, errors.New("action")
}

func targetOf(t *store.Target, m *store.CompilerMaps) (*blob.TargetSpec, error) {
	switch t.Kind {
	case "location":
		w, ok := m.Locations[t.LocationID]
		if !ok {
			return nil, errors.New("location")
		}
		return &blob.TargetSpec{Kind: blob.TargetLocation, Location: w}, nil
	case "auto":
		// The effective set comes from the pair's locations, which P4b fills (P4 1.2): no location is available
		// until then, so every Auto and Random Redirect acts as Bypass with location_unavailable on the node.
		return &blob.TargetSpec{Kind: blob.TargetAuto}, nil
	case "random":
		return &blob.TargetSpec{Kind: blob.TargetRandom}, nil
	case "ip":
		ts := &blob.TargetSpec{Kind: blob.TargetIP}
		var err error
		if t.IPv4 != "" {
			if ts.V4, err = netip.ParseAddr(t.IPv4); err != nil {
				return nil, err
			}
		}
		if t.IPv6 != "" {
			if ts.V6, err = netip.ParseAddr(t.IPv6); err != nil {
				return nil, err
			}
		}
		return ts, nil
	case "host":
		n, err := names.FromString(t.Host)
		if err != nil {
			return nil, err
		}
		return &blob.TargetSpec{Kind: blob.TargetHost, Host: append([]byte(nil), n.Wire()...)}, nil
	}
	return nil, errors.New("target kind")
}

func setBool(o *blob.Options, bit uint32, v *bool) {
	if v == nil {
		return
	}
	o.Present |= bit
	if *v {
		o.Bools |= uint8(bit)
	}
}

// optionsOf is the OPTS record of a profile (SC 9.2): a NULL column is "not set", so the other slot of a stack or the
// default decides.
func optionsOf(r *store.OptionsRow, o *blob.Options) error {
	setBool(o, blob.OptExfiltration, r.BlockExfiltration)
	setBool(o, blob.OptRebind, r.RebindProtection)
	setBool(o, blob.OptDisableDNSSEC, r.DisableDNSSEC)
	setBool(o, blob.OptDNS64, r.DNS64)
	setBool(o, blob.OptFlatten, r.CNAMEFlattening)
	setBool(o, blob.OptSafeSearch, r.SafeSearch)
	setBool(o, blob.OptRestrictedYouTube, r.RestrictedYouTube)
	switch r.BlockResponse {
	case "":
	case "zero", "nxdomain", "refused", "custom", "branded":
		o.Present |= blob.OptBlockResponse
		o.BlockResponse = map[string]uint8{"zero": blob.BlockZero, "nxdomain": blob.BlockNXDomain, "refused": blob.BlockRefused,
			"custom": blob.BlockCustom, "branded": blob.BlockBranded}[r.BlockResponse]
		// The branded page's hash is P4b's: until it exists the field stays zero and the node serves the
		// Branded response as it serves a missing page (P4 1.2).
		if r.BlockResponse == "custom" {
			if r.BlockV4 != "" {
				b, err := ipBytes(r.BlockV4)
				if err != nil || len(b) != 4 {
					return errAddr
				}
				copy(o.BlockV4[:], b)
			}
			if r.BlockV6 != "" {
				b, err := ipBytes(r.BlockV6)
				if err != nil || len(b) != 16 {
					return errAddr
				}
				copy(o.BlockV6[:], b)
			}
		}
	default:
		return errors.New("block_response")
	}
	switch r.ECSMode {
	case "":
	case "none", "auto", "custom":
		o.Present |= blob.OptECS
		o.ECSMode = map[string]uint8{"none": blob.ECSNone, "auto": blob.ECSAuto, "custom": blob.ECSCustom}[r.ECSMode]
		if r.ECSMode == "custom" {
			if err := ecsOf(o, r.ECSV4, 4); err != nil {
				return err
			}
			if err := ecsOf(o, r.ECSV6, 16); err != nil {
				return err
			}
		}
	default:
		return errors.New("ecs_mode")
	}
	ttl := func(bit uint32, v *int32, dst *uint32) {
		if v != nil {
			o.Present |= bit
			*dst = uint32(*v)
		}
	}
	ttl(blob.OptBlockTTL, r.BlockTTL, &o.BlockTTL)
	ttl(blob.OptRedirectTTL, r.RedirectTTL, &o.RedirectTTL)
	ttl(blob.OptBypassTTL, r.BypassTTL, &o.BypassTTL)
	return nil
}

// ecsOf sets the custom ECS subnet of one family from its cidr text.
func ecsOf(o *blob.Options, cidr string, size int) error {
	if cidr == "" {
		return nil
	}
	p, err := cidrWire(cidr)
	if err != nil || len(p.Addr) != size {
		return errAddr
	}
	if size == 4 {
		copy(o.ECSV4[:], p.Addr)
		o.ECSV4Prefix = uint8(p.Bits)
	} else {
		copy(o.ECSV6[:], p.Addr)
		o.ECSV6Prefix = uint8(p.Bits)
	}
	return nil
}

// Stack is the StackRecord of one or two compiled profiles: the merged options are computed here once so the node's
// hot path never merges (R27), and the three facts are what policy.NewStack folds over its slots.
func Stack(p1, p2 *Profile) *policyv1.StackRecord {
	s := &policyv1.StackRecord{Profile1Hash: p1.Hash}
	var zero blob.Options
	second := &zero
	if p2 != nil {
		s.Profile2Hash = p2.Hash
		second = p2.Opts
	}
	merged := blob.Merge(p1.Opts, second)
	mo := merged.Marshal()
	s.MergedOptions = mo[:]
	s.MaxDepth, s.HasDestGeo, s.Explicit = p1.MaxLabels, p1.HasDestGeo, p1.Explicit
	if p2 != nil {
		s.MaxDepth = max(s.MaxDepth, p2.MaxLabels)
		s.HasDestGeo = s.HasDestGeo || p2.HasDestGeo
		s.Explicit = s.Explicit || p2.Explicit
	}
	return s
}

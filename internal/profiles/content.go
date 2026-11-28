package profiles

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"

	shared "github.com/Kup1ng/CtrlZ-Shared/locations"

	"github.com/Kup1ng/CtrlZ-Panel/internal/locations"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Services, filters and options (spec 3.7, 4.2, 8.2).

// ServiceState is what a service is set to.
type ServiceState struct {
	Enabled bool
	Act     Act // block, bypass or redirect
}

// BatchResult counts what a batch did (spec 3.5, 8.3).
type BatchResult struct {
	Created, Updated, Skipped, Conflict, Flagged int
	Items                                        []Outcome
}

// Outcome is the result for one item of a batch.
type Outcome struct {
	Index   int
	Outcome string // created, updated, skipped, conflict
	ID      uuid.UUID
}

func (r *BatchResult) add(index int, outcome string, id uuid.UUID) {
	switch outcome {
	case "created":
		r.Created++
	case "updated":
		r.Updated++
	case "skipped":
		r.Skipped++
	case "conflict":
		r.Conflict++
	}
	r.Items = append(r.Items, Outcome{Index: index, Outcome: outcome, ID: id})
}

// setForService is the set of locations a Redirect of the service may use: the profile's own, limited to the
// regions the service may be reached from.
func (w *wtx) setForService(c store.CatalogService) func() ([]shared.Key, error) {
	return func() ([]shared.Key, error) {
		a, err := w.allowed()
		if err != nil {
			return nil, err
		}
		return locations.ForService(a, c.AllowedRegions), nil
	}
}

// SetServices upserts each slug with the given state (Choose Service Add, the group actions, T-164): one
// transaction, all or none. A group action with a Redirect uses the intersection of the sets of its services
// (EffectiveSelection); a service whose catalog row says redirect_allowed is false refuses a Redirect with
// iranian_name (D42); a state equal to the stored one is not checked again (3.7).
func (e *Env) SetServices(tx store.Tx, profile uuid.UUID, slugs []string, st ServiceState) (BatchResult, error) {
	w, err := e.begin(tx, profile, 0)
	if err != nil {
		return BatchResult{}, err
	}
	if len(slugs) == 0 {
		return BatchResult{}, invalid(Field{"/slugs", CodeRequired})
	}
	cat, err := tx.CatalogServices(slugs)
	if err != nil {
		return BatchResult{}, err
	}
	byslug := map[string]store.CatalogService{}
	for _, c := range cat {
		byslug[c.Slug] = c
	}
	cur, err := tx.Services(profile)
	if err != nil {
		return BatchResult{}, err
	}
	have := map[string]store.ServiceRow{}
	for _, s := range cur {
		have[s.Slug] = s
	}
	var fs []Field
	seen := map[string]bool{}
	// The set of a group action: the locations every selected service can use.
	var sel []shared.Key
	if st.Act.Action == "redirect" {
		var sets [][]shared.Key
		for _, s := range slugs {
			if c, ok := byslug[s]; ok {
				a, err := w.allowed()
				if err != nil {
					return BatchResult{}, err
				}
				sets = append(sets, locations.ForService(a, c.AllowedRegions))
			}
		}
		sel = locations.ForSelection(sets...)
	}
	var res BatchResult
	type todo struct {
		i   int
		row store.ServiceRow
		out string
	}
	var work []todo
	for i, slug := range slugs {
		f := fmt.Sprintf("/slugs/%d", i)
		if seen[slug] {
			fs = append(fs, Field{f, CodeDuplicate})
			continue
		}
		seen[slug] = true
		c, ok := byslug[slug]
		if !ok {
			fs = append(fs, Field{f, CodeUnknown})
			continue
		}
		switch st.Act.Action {
		case "block", "bypass", "redirect":
		default:
			fs = append(fs, Field{"/action", CodeInvalid})
			continue
		}
		prev, exists := have[slug]
		row := store.ServiceRow{Slug: slug, Enabled: st.Enabled, Action: st.Act.Action}
		unchanged := exists && prev.Action == st.Act.Action && (st.Act.Action != "redirect" || sameTarget(st.Act.Target, prev.Target))
		if unchanged {
			row.Target, row.LocationUnavailable = prev.Target, prev.LocationUnavailable
		} else {
			if st.Act.Action == "redirect" && !c.RedirectAllowed {
				fs = append(fs, Field{f, CodeIranianName})
				continue
			}
			set := func() ([]shared.Key, error) { return sel, nil }
			if len(slugs) == 1 {
				set = w.setForService(c)
			}
			r, tfs, err := w.target(f, st.Act, false, set)
			if err != nil {
				return BatchResult{}, err
			}
			if tfs != nil {
				fs = append(fs, tfs...)
				continue
			}
			row.Target = r.t
		}
		out := "created"
		switch {
		case exists && prev.Enabled == row.Enabled && unchanged:
			out = "skipped"
		case exists:
			out = "updated"
		}
		work = append(work, todo{i, row, out})
	}
	if len(fs) > 0 {
		return BatchResult{}, invalid(fs...)
	}
	for _, t := range work {
		if t.out != "skipped" {
			if err := tx.ServiceUpsert(w.pw, t.row); err != nil {
				if errors.Is(err, store.ErrConstraint) {
					return BatchResult{}, invalid(Field{fmt.Sprintf("/slugs/%d", t.i), CodeUnknown})
				}
				return BatchResult{}, err
			}
		}
		res.add(t.i, t.out, uuid.Nil)
	}
	if err := w.mark(); err != nil {
		return BatchResult{}, err
	}
	return res, nil
}

// DeleteServices removes the services from the profile (remove all of a category, T-163). A slug the profile
// does not have is skipped.
func (e *Env) DeleteServices(tx store.Tx, profile uuid.UUID, slugs []string) (BatchResult, error) {
	w, err := e.begin(tx, profile, 0)
	if err != nil {
		return BatchResult{}, err
	}
	// The same key twice is refused as SetServices does, before anything is deleted (3.7).
	var dups []Field
	seenSlug := map[string]bool{}
	for i, s := range slugs {
		if seenSlug[s] {
			dups = append(dups, Field{fmt.Sprintf("/slugs/%d", i), CodeDuplicate})
		}
		seenSlug[s] = true
	}
	if len(dups) > 0 {
		return BatchResult{}, invalid(dups...)
	}
	var res BatchResult
	for i, s := range slugs {
		ok, err := tx.ServiceDelete(w.pw, s)
		if err != nil {
			return BatchResult{}, err
		}
		if ok {
			res.add(i, "updated", uuid.Nil)
		} else {
			res.add(i, "skipped", uuid.Nil)
		}
	}
	if err := w.mark(); err != nil {
		return BatchResult{}, err
	}
	return res, nil
}

// SetFilter turns a filter on or off and picks its mode (T-144 to T-146). A filter with one mode takes no mode;
// on first enable with no mode the default one (the lowest wire id) is used; an off filter keeps its mode.
func (e *Env) SetFilter(tx store.Tx, profile uuid.UUID, filter string, enabled bool, mode string) (store.FilterRow, error) {
	w, err := e.begin(tx, profile, 0)
	if err != nil {
		return store.FilterRow{}, err
	}
	cat, err := tx.CatalogFilters([]string{filter})
	if err != nil {
		return store.FilterRow{}, err
	}
	if len(cat) != 1 {
		return store.FilterRow{}, invalid(Field{"/filter_id", CodeUnknown})
	}
	modes := cat[0].Modes
	cur, err := tx.Filters(profile)
	if err != nil {
		return store.FilterRow{}, err
	}
	var prev *store.FilterRow
	for i := range cur {
		if cur[i].FilterID == filter {
			prev = &cur[i]
		}
	}
	row := store.FilterRow{FilterID: filter, Enabled: enabled}
	switch {
	case len(modes) <= 1:
		// A one-mode filter has no mode to choose; its single row is internal.
		if mode != "" {
			return store.FilterRow{}, invalid(Field{"/mode", CodeInvalid})
		}
	default:
		switch {
		case mode != "":
			if !has(modes, mode) {
				return store.FilterRow{}, invalid(Field{"/mode", CodeInvalid})
			}
			row.Mode = mode
		case prev != nil && prev.Mode != "":
			row.Mode = prev.Mode
		default:
			row.Mode = modes[0]
		}
	}
	if err := tx.FilterUpsert(w.pw, row); err != nil {
		if errors.Is(err, store.ErrConstraint) {
			return store.FilterRow{}, invalid(Field{"/mode", CodeInvalid})
		}
		return store.FilterRow{}, err
	}
	if err := w.mark(); err != nil {
		return store.FilterRow{}, err
	}
	return row, nil
}

// ---------------------------------------------------------------------------
// Options.

// DefaultRule is the Default Rule option: an action and, for a Redirect, a target.
type DefaultRule struct{ Act Act }

// BlockResponse is the Block Response option (SC 6).
type BlockResponse struct {
	Mode   string // zero, nxdomain, refused, custom, branded
	V4, V6 string
}

// ECS is the ECS option: a mode and, for custom, up to two subnets.
type ECS struct {
	Mode   string // none, auto, custom
	V4, V6 string
}

// OptionsPatch is the fields to set and the names to clear; "not set" is the default of every option (open
// question 3), so a switch turned off clears the option.
type OptionsPatch struct {
	DefaultRule       *DefaultRule
	BlockExfiltration *bool
	RebindProtection  *bool
	DisableDNSSEC     *bool
	BlockTTL          *int
	RedirectTTL       *int
	BypassTTL         *int
	BlockResponse     *BlockResponse
	ECS               *ECS
	DNS64             *bool
	CNAMEFlattening   *bool
	SafeSearch        *bool
	RestrictedYouTube *bool
	Clear             []string
}

// OptionNames are the names a patch may clear.
func OptionNames() []string {
	return []string{"default_rule", "block_exfiltration", "rebind_protection", "disable_dnssec", "block_ttl", "redirect_ttl",
		"bypass_ttl", "block_response", "ecs", "dns64", "cname_flattening", "safe_search", "restricted_youtube"}
}

func ttl(field string, v *int, dst **int32, fs *[]Field) {
	if v == nil {
		return
	}
	if *v < 1 || *v > 86400 {
		*fs = append(*fs, Field{field, CodeOutOfRange})
		return
	}
	x := int32(*v)
	*dst = &x
}

// cidrShape checks the text of a subnet: an address of the family, a slash and a prefix length in range. The
// host bits are the database's to judge (store.CIDRHostBits), since no address is taken apart in Go.
func cidrShape(s string, v4 bool) bool {
	addr, bits, ok := strings.Cut(s, "/")
	if !ok || !parseIP(addr, v4) {
		return false
	}
	n, err := strconv.Atoi(bits)
	if err != nil || bits != strconv.Itoa(n) {
		return false
	}
	if v4 {
		return n >= 0 && n <= 32
	}
	return n >= 0 && n <= 128
}

func (w *wtx) checkBlockResponse(b BlockResponse, row *store.OptionsRow, fs *[]Field) {
	switch b.Mode {
	case "zero", "nxdomain", "refused":
		if b.V4 != "" || b.V6 != "" {
			*fs = append(*fs, Field{"/block_response", CodeInvalid})
			return
		}
	case "custom":
		if b.V4 == "" && b.V6 == "" {
			*fs = append(*fs, Field{"/block_response/v4", CodeRequired})
			return
		}
		if b.V4 != "" && !parseIP(b.V4, true) {
			*fs = append(*fs, Field{"/block_response/v4", CodeInvalid})
			return
		}
		if b.V6 != "" && !parseIP(b.V6, false) {
			*fs = append(*fs, Field{"/block_response/v6", CodeInvalid})
			return
		}
	case "branded":
		*fs = append(*fs, Field{"/block_response/mode", CodeNotAvailable})
		return
	default:
		*fs = append(*fs, Field{"/block_response/mode", CodeInvalid})
		return
	}
	row.BlockResponse, row.BlockV4, row.BlockV6 = b.Mode, b.V4, b.V6
}

func (w *wtx) checkECS(x ECS, row *store.OptionsRow, fs *[]Field) error {
	switch x.Mode {
	case "none", "auto":
		if x.V4 != "" || x.V6 != "" {
			*fs = append(*fs, Field{"/ecs", CodeInvalid})
			return nil
		}
	case "custom":
		if x.V4 == "" && x.V6 == "" {
			*fs = append(*fs, Field{"/ecs/v4", CodeRequired})
			return nil
		}
		for _, c := range []struct {
			name, v string
			v4      bool
		}{{"/ecs/v4", x.V4, true}, {"/ecs/v6", x.V6, false}} {
			if c.v == "" {
				continue
			}
			if !cidrShape(c.v, c.v4) {
				*fs = append(*fs, Field{c.name, CodeInvalid})
				continue
			}
			dirty, err := w.tx.CIDRHostBits(c.v)
			if err != nil {
				return err
			}
			if dirty {
				*fs = append(*fs, Field{c.name, CodeInvalid})
			}
		}
		if len(*fs) > 0 {
			return nil
		}
	default:
		*fs = append(*fs, Field{"/ecs/mode", CodeInvalid})
		return nil
	}
	row.ECSMode, row.ECSV4, row.ECSV6 = x.Mode, x.V4, x.V6
	return nil
}

// PatchOptions merges a patch into the profile's options and writes the row (spec 3.7). The Default Rule is
// the declared exception of D42: a Redirect there is accepted and the node turns it into Bypass for Iranian
// names. Its location is checked against the set like any other item.
func (e *Env) PatchOptions(tx store.Tx, profile uuid.UUID, in OptionsPatch) (store.OptionsRow, error) {
	w, err := e.begin(tx, profile, 0)
	if err != nil {
		return store.OptionsRow{}, err
	}
	_, err = w.patchOptions(in, false)
	if err != nil {
		return store.OptionsRow{}, err
	}
	row, _, err := tx.Options(profile)
	return row, err
}

// patchOptions is PatchOptions inside a write that is already open. A document write (doc) keeps a location outside
// the set and flags it; it returns how many destinations it flagged.
func (w *wtx) patchOptions(in OptionsPatch, doc bool) (int, error) {
	tx, profile := w.tx, w.pw.ID()
	row, _, err := tx.Options(profile)
	if err != nil {
		return 0, err
	}
	var fs []Field
	for _, n := range in.Clear {
		switch n {
		case "default_rule":
			row.DefaultAction, row.DefaultTarget, row.DefaultLocationUnavailable = "", store.Target{}, false
		case "block_exfiltration":
			row.BlockExfiltration = nil
		case "rebind_protection":
			row.RebindProtection = nil
		case "disable_dnssec":
			row.DisableDNSSEC = nil
		case "block_ttl":
			row.BlockTTL = nil
		case "redirect_ttl":
			row.RedirectTTL = nil
		case "bypass_ttl":
			row.BypassTTL = nil
		case "block_response":
			row.BlockResponse, row.BlockV4, row.BlockV6 = "", "", ""
		case "ecs":
			row.ECSMode, row.ECSV4, row.ECSV6 = "", "", ""
		case "dns64":
			row.DNS64 = nil
		case "cname_flattening":
			row.CNAMEFlattening = nil
		case "safe_search":
			row.SafeSearch = nil
		case "restricted_youtube":
			row.RestrictedYouTube = nil
		default:
			fs = append(fs, Field{"/clear", CodeInvalid})
		}
	}
	if d := in.DefaultRule; d != nil {
		a := d.Act
		switch a.Action {
		case "block", "bypass", "redirect":
			unchanged := a.Action == row.DefaultAction && (a.Action != "redirect" || sameTarget(a.Target, row.DefaultTarget))
			if !unchanged {
				res, tfs, err := w.target("/default_rule", a, doc, w.allowed)
				if err != nil {
					return 0, err
				}
				fs = append(fs, tfs...)
				if tfs == nil {
					row.DefaultAction, row.DefaultTarget, row.DefaultLocationUnavailable = a.Action, res.t, res.flagged
				}
			}
		default:
			fs = append(fs, Field{"/default_rule/action", CodeInvalid})
		}
	}
	if in.BlockExfiltration != nil {
		row.BlockExfiltration = in.BlockExfiltration
	}
	if in.RebindProtection != nil {
		row.RebindProtection = in.RebindProtection
	}
	if in.DisableDNSSEC != nil {
		row.DisableDNSSEC = in.DisableDNSSEC
	}
	ttl("/block_ttl", in.BlockTTL, &row.BlockTTL, &fs)
	ttl("/redirect_ttl", in.RedirectTTL, &row.RedirectTTL, &fs)
	ttl("/bypass_ttl", in.BypassTTL, &row.BypassTTL, &fs)
	if in.BlockResponse != nil {
		w.checkBlockResponse(*in.BlockResponse, &row, &fs)
	}
	if in.ECS != nil {
		if err := w.checkECS(*in.ECS, &row, &fs); err != nil {
			return 0, err
		}
	}
	for _, s := range []struct {
		in  *bool
		dst **bool
	}{{in.DNS64, &row.DNS64}, {in.CNAMEFlattening, &row.CNAMEFlattening}, {in.SafeSearch, &row.SafeSearch}, {in.RestrictedYouTube, &row.RestrictedYouTube}} {
		if s.in != nil {
			*s.dst = s.in
		}
	}
	if len(fs) > 0 {
		return 0, invalid(fs...)
	}
	if err := tx.OptionsSet(w.pw, row); err != nil {
		if errors.Is(err, store.ErrConstraint) {
			return 0, invalid(Field{"/", CodeInvalid})
		}
		return 0, err
	}
	if err := w.mark(); err != nil {
		return 0, err
	}
	flagged := 0
	if row.DefaultLocationUnavailable {
		flagged = 1
	}
	return flagged, nil
}

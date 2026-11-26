package profiles

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	shared "github.com/Kup1ng/CtrlZ-Shared/locations"
	"github.com/Kup1ng/CtrlZ-Shared/rules"

	"github.com/Kup1ng/CtrlZ-Panel/internal/caps"
	"github.com/Kup1ng/CtrlZ-Panel/internal/locations"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Export, Import, Duplicate, types and Upload Folder (spec 5, 6). A document write is a write of a whole profile or
// folder, possibly from another install: a location this install has but the profile may not use is kept and flagged,
// and a rule or service that would be an Iranian Redirect is refused (spec 3.6, 4.2).

// snapshot reads the location catalog once for a read.
func (e *Env) snapshot(tx store.Tx) (locations.Snapshot, error) {
	if e.Catalog == nil {
		return locations.Snapshot{}.Index(), nil
	}
	return e.Catalog.Snapshot(tx)
}

func optBool(b bool) *bool { return &b }

func optInt(v *int32) *int {
	if v == nil {
		return nil
	}
	x := int(*v)
	return &x
}

// ReadDocument reads a profile as a document, in canonical form. The caller opens a read-only RepeatableRead
// transaction, so a concurrent move cannot give a rule whose folder is missing (spec 6.1). A locked profile can be
// read: Export and Duplicate work on it (spec 7.3).
func (e *Env) ReadDocument(tx store.Tx, id uuid.UUID) (Document, error) {
	p, ok, err := tx.ProfileGet(id)
	if err != nil {
		return Document{}, err
	}
	if !ok {
		return Document{}, notFound()
	}
	snap, err := e.snapshot(tx)
	if err != nil {
		return Document{}, err
	}
	key := func(id uuid.UUID) (shared.Key, bool) {
		r, ok := snap.ByID(id)
		return r.Key, ok
	}
	d := Document{Format: DocFormat, Version: DocVersion, Name: p.Name, Kind: p.Kind,
		Filters: []DocFilter{}, Services: []DocService{}, Folders: []DocFolder{}, Rules: []DocRule{}}
	fl, err := tx.Filters(id)
	if err != nil {
		return Document{}, err
	}
	for _, f := range fl {
		d.Filters = append(d.Filters, DocFilter{ID: f.FilterID, Enabled: optBool(f.Enabled), Mode: f.Mode})
	}
	sv, err := tx.Services(id)
	if err != nil {
		return Document{}, err
	}
	for _, s := range sv {
		d.Services = append(d.Services, DocService{Slug: s.Slug, Enabled: optBool(s.Enabled), Action: s.Action, Target: docTarget(s.Target, key)})
	}
	fo, err := tx.FoldersBare(id)
	if err != nil {
		return Document{}, err
	}
	for _, f := range fo {
		d.Folders = append(d.Folders, DocFolder{Ref: f.ID.String(), Name: f.Name, Kind: f.Kind, Action: f.Action, Target: docTarget(f.Target, key)})
	}
	rs, err := tx.RulesAll(id)
	if err != nil {
		return Document{}, err
	}
	for _, r := range rs {
		dr := DocRule{Pattern: r.Key, Action: r.Action, Target: docTarget(r.Target, key), Enabled: optBool(r.Enabled), Comment: r.Comment}
		if r.FolderID != uuid.Nil {
			dr.Folder = r.FolderID.String()
		}
		if r.ExpiresAt != nil {
			dr.ExpiresAt = formatExpiry(*r.ExpiresAt)
		}
		d.Rules = append(d.Rules, dr)
	}
	o, _, err := tx.Options(id)
	if err != nil {
		return Document{}, err
	}
	d.Options = docOptions(o, key)
	d.Canonical(func(ref string) uuid.UUID { u, _ := uuid.Parse(ref); return u })
	return d, nil
}

func docOptions(o store.OptionsRow, key func(uuid.UUID) (shared.Key, bool)) DocOptions {
	d := DocOptions{BlockExfiltration: o.BlockExfiltration, RebindProtection: o.RebindProtection, DisableDNSSEC: o.DisableDNSSEC,
		BlockTTL: optInt(o.BlockTTL), RedirectTTL: optInt(o.RedirectTTL), BypassTTL: optInt(o.BypassTTL),
		DNS64: o.DNS64, CNAMEFlattening: o.CNAMEFlattening, SafeSearch: o.SafeSearch, RestrictedYouTube: o.RestrictedYouTube}
	if o.DefaultAction != "" {
		d.DefaultRule = &DocDefaultRule{Action: o.DefaultAction, Target: docTarget(o.DefaultTarget, key)}
	}
	if o.BlockResponse != "" {
		d.BlockResponse = &DocBlockResponse{Mode: o.BlockResponse, V4: o.BlockV4, V6: o.BlockV6}
	}
	if o.ECSMode != "" {
		d.ECS = &DocECS{Mode: o.ECSMode, V4: o.ECSV4, V6: o.ECSV6}
	}
	return d
}

// ReadRulesDocument reads the rules of one folder as a document (Export Rules, T-188).
func (e *Env) ReadRulesDocument(tx store.Tx, profile, folder uuid.UUID) (RulesDocument, error) {
	if _, ok, err := tx.Folder(profile, folder); err != nil {
		return RulesDocument{}, err
	} else if !ok {
		return RulesDocument{}, notFound()
	}
	snap, err := e.snapshot(tx)
	if err != nil {
		return RulesDocument{}, err
	}
	key := func(id uuid.UUID) (shared.Key, bool) {
		r, ok := snap.ByID(id)
		return r.Key, ok
	}
	rs, err := tx.RulesInFolder(profile, folder)
	if err != nil {
		return RulesDocument{}, err
	}
	d := RulesDocument{Format: RulesFormat, Version: DocVersion, Rules: []DocRule{}}
	for _, r := range rs {
		dr := DocRule{Pattern: r.Key, Action: r.Action, Target: docTarget(r.Target, key), Enabled: optBool(r.Enabled), Comment: r.Comment}
		if r.ExpiresAt != nil {
			dr.ExpiresAt = formatExpiry(*r.ExpiresAt)
		}
		d.Rules = append(d.Rules, dr)
	}
	d.Canonical()
	return d, nil
}

// ---------------------------------------------------------------------------
// Writing a document.

func toTarget(t *DocTarget) Target {
	if t == nil {
		return Target{}
	}
	out := Target{Kind: t.Kind, IPv4: t.IPv4, IPv6: t.IPv6, Host: t.Host}
	if t.Location != nil {
		out.LocationKey = &LocKey{Country: t.Location.Country, City: t.Location.City, Label: t.Location.Label}
	}
	return out
}

func prefixed(prefix string, fs []Field) []Field {
	out := make([]Field, len(fs))
	for i, f := range fs {
		out[i] = Field{prefix + f.Name, f.Code}
	}
	return out
}

// ImportResult is what a document write made: the new profile and how many destinations it had to flag.
type ImportResult struct {
	Profile store.Profile
	Flagged int
}

// ImportDocument creates a new, unlocked profile from a document (Import, Duplicate, a type; spec 6.2, 6.4). The
// caller's transaction holds the tenant lock that decides max_profiles, and a refusal rolls all of it back.
func (e *Env) ImportDocument(tx store.Tx, d Document, name string) (ImportResult, error) {
	if err := e.CheckImport(tx, d, name); err != nil {
		return ImportResult{}, err
	}
	pw, won, err := tx.ProfileCreate(name, d.Kind)
	if err != nil {
		return ImportResult{}, err
	}
	if !won.Yes() {
		return ImportResult{}, invalid(Field{"max_profiles", CodeExceeded})
	}
	if e.gate != nil {
		if err := e.gate(tx); err != nil {
			return ImportResult{}, err
		}
	}
	w := &wtx{e: e, tx: tx, pw: pw}
	flagged, err := w.applyDocument(d)
	if err != nil {
		return ImportResult{}, err
	}
	if err := w.mark(); err != nil {
		return ImportResult{}, err
	}
	p, _, err := tx.ProfileGet(pw.ID())
	return ImportResult{Profile: p, Flagged: flagged}, err
}

// CheckImport is what an Import or a Duplicate is refused for before any row is written: the name, the kind and the
// limits on the size of the document. The handler runs it before it queues a job (spec 3.5).
func (e *Env) CheckImport(tx store.Tx, d Document, name string) error {
	var fs []Field
	if f := checkName(name, "/name", NameLimit); f != nil {
		fs = append(fs, *f)
	}
	if !validKind(d.Kind) {
		fs = append(fs, Field{"/kind", CodeInvalid})
	}
	lim, err := tx.Limits()
	if err != nil {
		return err
	}
	if len(d.Rules) > lim.MaxRulesPerRequest {
		fs = append(fs, Field{"max_rules_per_request", CodeExceeded})
	}
	if len(d.Folders) > caps.MaxFoldersPerProfile {
		fs = append(fs, Field{"max_folders_per_profile", CodeExceeded})
	}
	if fs != nil {
		return invalid(fs...)
	}
	return nil
}

// CreateFromType creates a profile from the document of its type (spec 5): Import of that document with the user's
// name and kind.
func (e *Env) CreateFromType(tx store.Tx, name, kind string) (ImportResult, error) {
	if !validKind(kind) {
		return ImportResult{}, invalid(Field{"/kind", CodeInvalid})
	}
	raw, ok, err := tx.PresetGet(kind)
	if err != nil {
		return ImportResult{}, err
	}
	if !ok {
		return ImportResult{}, invalid(Field{"/kind", CodeNotAvailable})
	}
	d, err := DecodeDocument(raw, nil)
	if err != nil {
		return ImportResult{}, err
	}
	d.Kind = kind
	return e.ImportDocument(tx, d, name)
}

// applyDocument checks every item of the document and writes it into the profile the write holds. Every problem is a
// field, in document order, and nothing is returned until all sections were checked, so one answer names them all
// (at most 100). It returns how many destinations were flagged.
func (w *wtx) applyDocument(d Document) (int, error) {
	var fs []Field
	flagged := 0

	// Filters.
	var filterRows []store.FilterRow
	{
		ids := make([]string, 0, len(d.Filters))
		for _, f := range d.Filters {
			ids = append(ids, f.ID)
		}
		cat := map[string]store.CatalogFilter{}
		if len(ids) > 0 {
			rows, err := w.tx.CatalogFilters(ids)
			if err != nil {
				return 0, err
			}
			for _, c := range rows {
				cat[c.ID] = c
			}
		}
		seen := map[string]bool{}
		for i, f := range d.Filters {
			if err := w.tx.Context().Err(); err != nil {
				return 0, err
			}
			p := fmt.Sprintf("/filters/%d", i)
			c, ok := cat[f.ID]
			switch {
			case seen[f.ID]:
				fs = append(fs, Field{p + "/id", CodeDuplicate})
				continue
			case !ok:
				fs = append(fs, Field{p + "/id", CodeUnknown})
				continue
			}
			seen[f.ID] = true
			row := store.FilterRow{FilterID: f.ID, Enabled: on(f.Enabled)}
			switch {
			case len(c.Modes) <= 1:
				if f.Mode != "" {
					fs = append(fs, Field{p + "/mode", CodeInvalid})
					continue
				}
			case f.Mode == "":
				row.Mode = c.Modes[0]
			case !has(c.Modes, f.Mode):
				fs = append(fs, Field{p + "/mode", CodeInvalid})
				continue
			default:
				row.Mode = f.Mode
			}
			filterRows = append(filterRows, row)
		}
	}

	// Folders: checked in memory, inserted in document order once everything is known.
	type plannedFolder struct {
		row store.FolderRow
		ref string
	}
	var folders []plannedFolder
	byRef := map[string]*store.FolderRow{}
	{
		seen := map[string]bool{}
		for i, f := range d.Folders {
			if err := w.tx.Context().Err(); err != nil {
				return 0, err
			}
			p := fmt.Sprintf("/folders/%d", i)
			if f.Ref == "" {
				fs = append(fs, Field{p + "/ref", CodeRequired})
				continue
			}
			if seen[f.Ref] {
				fs = append(fs, Field{p + "/ref", CodeDuplicate})
				continue
			}
			seen[f.Ref] = true
			row, ffs, err := w.checkFolder(FolderIn{Name: f.Name, Kind: f.Kind, Act: Act{Action: f.Action, Target: toTarget(f.Target)}}, true)
			if err != nil {
				return 0, err
			}
			if len(ffs) > 0 {
				fs = append(fs, prefixed(p, ffs)...)
				continue
			}
			if row.LocationUnavailable {
				flagged++
			}
			folders = append(folders, plannedFolder{row: row, ref: f.Ref})
		}
		for i := range folders {
			byRef[folders[i].ref] = &folders[i].row
		}
	}

	// Services.
	var serviceRows []store.ServiceRow
	{
		slugs := make([]string, 0, len(d.Services))
		for _, s := range d.Services {
			slugs = append(slugs, s.Slug)
		}
		cat := map[string]store.CatalogService{}
		if len(slugs) > 0 {
			rows, err := w.tx.CatalogServices(slugs)
			if err != nil {
				return 0, err
			}
			for _, c := range rows {
				cat[c.Slug] = c
			}
		}
		seen := map[string]bool{}
		for i, s := range d.Services {
			if err := w.tx.Context().Err(); err != nil {
				return 0, err
			}
			p := fmt.Sprintf("/services/%d", i)
			c, ok := cat[s.Slug]
			switch {
			case seen[s.Slug]:
				fs = append(fs, Field{p + "/slug", CodeDuplicate})
				continue
			case !ok:
				fs = append(fs, Field{p + "/slug", CodeUnknown})
				continue
			}
			seen[s.Slug] = true
			switch s.Action {
			case "block", "bypass", "redirect":
			default:
				fs = append(fs, Field{p + "/action", CodeInvalid})
				continue
			}
			if s.Action == "redirect" && !c.RedirectAllowed {
				fs = append(fs, Field{p + "/action", CodeIranianName})
				continue
			}
			res, tfs, err := w.target(p, Act{Action: s.Action, Target: toTarget(s.Target)}, true, w.setForService(c))
			if err != nil {
				return 0, err
			}
			if tfs != nil {
				fs = append(fs, tfs...)
				continue
			}
			if res.flagged {
				flagged++
			}
			serviceRows = append(serviceRows, store.ServiceRow{Slug: s.Slug, Enabled: on(s.Enabled), Action: s.Action, Target: res.t, LocationUnavailable: res.flagged})
		}
	}

	// Rules.
	type plannedRule struct {
		row    store.NewRule
		folder string
	}
	var planned []plannedRule
	{
		seen := map[string]bool{}
		var ps []rules.Pattern
		var at []int
		for i, r := range d.Rules {
			// The work has a deadline (6.5 property 5): the CPU part of an import looks at it between two items.
			if err := w.tx.Context().Err(); err != nil {
				return 0, err
			}
			p := fmt.Sprintf("/rules/%d", i)
			ruleFs := len(fs)
			pat, err := parse(r.Pattern)
			if err != nil {
				fs = append(fs, Field{p + "/pattern", PatternCode(err)})
			} else if seen[pat.key] {
				fs = append(fs, Field{p + "/pattern", CodeDuplicate})
			} else {
				seen[pat.key] = true
			}
			var folder *store.FolderRow
			if r.Folder != "" {
				if folder = byRef[r.Folder]; folder == nil {
					fs = append(fs, Field{p + "/folder", CodeUnknown})
				}
			}
			if tooLong(r.Comment, commentLimit) {
				fs = append(fs, Field{p + "/comment", CodeTooLong})
			}
			var exp *time.Time
			if r.ExpiresAt != "" {
				t, ok := parseExpiry(r.ExpiresAt)
				if !ok {
					fs = append(fs, Field{p + "/expires_at", CodeInvalid})
				} else if x, f := w.e.expiry(p+"/expires_at", Expiry{At: t, HasAt: true}, true); f != nil {
					fs = append(fs, *f)
				} else {
					exp = x
				}
			}
			res, afs, err := w.actFields(p, Act{Action: r.Action, Target: toTarget(r.Target)}, folder, true)
			if err != nil {
				return 0, err
			}
			fs = append(fs, afs...)
			if len(fs) > ruleFs {
				continue
			}
			nr := store.NewRule{Key: pat.key, MatchKind: pat.p.Kind.String(), Negated: pat.p.Negated, Action: r.Action, Target: res.t,
				Enabled: on(r.Enabled), ExpiresAt: exp, Comment: r.Comment, LocationUnavailable: res.flagged}
			if res.flagged {
				flagged++
			}
			planned = append(planned, plannedRule{row: nr, folder: r.Folder})
			if effRedirect(r.Action, folder) {
				ps, at = append(ps, pat.p), append(at, i)
			}
		}
		// D42, in chunks of the one lookup: a Redirect (the rule's own or its folder's) on an Iranian name is refused.
		if len(ps) > 0 {
			ir, err := w.iranian(ps)
			if err != nil {
				return 0, err
			}
			for j, bad := range ir {
				if bad {
					fs = append(fs, Field{fmt.Sprintf("/rules/%d/pattern", at[j]), CodeIranianName})
				}
			}
		}
	}

	// Options.
	var optPatch *OptionsPatch
	{
		patch := optionsPatch(d.Options)
		optPatch = &patch
	}

	if len(fs) > 0 {
		return 0, invalid(fs...)
	}

	// Nothing was refused: write.
	for _, f := range filterRows {
		if err := w.tx.FilterUpsert(w.pw, f); err != nil {
			return 0, err
		}
	}
	ids := map[string]uuid.UUID{}
	for _, f := range folders {
		id, err := w.insertFolder(f.row)
		if err != nil {
			return 0, err
		}
		ids[f.ref] = id
	}
	for _, s := range serviceRows {
		if err := w.tx.ServiceUpsert(w.pw, s); err != nil {
			return 0, err
		}
	}
	var rows []store.NewRule
	wild := 0
	for _, p := range planned {
		if p.folder != "" {
			p.row.FolderID = ids[p.folder]
		}
		if p.row.MatchKind == "subdomains" || p.row.MatchKind == "glob" {
			wild++
		}
		rows = append(rows, p.row)
	}
	if _, err := w.insertRules(ruleBatch{rows: rows, wild: wild}); err != nil {
		return 0, err
	}
	of, err := w.patchOptions(*optPatch, true)
	if err != nil {
		if ie, ok := err.(*Error); ok && ie.Kind == KindValidation {
			return 0, invalid(prefixed("/options", ie.Fields)...)
		}
		return 0, err
	}
	flagged += of
	return flagged, nil
}

// optionsPatch turns the options of a document into a patch that sets each one of them. Options that are not set are
// absent in both, so the new profile keeps their default.
func optionsPatch(o DocOptions) OptionsPatch {
	p := OptionsPatch{BlockExfiltration: o.BlockExfiltration, RebindProtection: o.RebindProtection, DisableDNSSEC: o.DisableDNSSEC,
		BlockTTL: o.BlockTTL, RedirectTTL: o.RedirectTTL, BypassTTL: o.BypassTTL,
		DNS64: o.DNS64, CNAMEFlattening: o.CNAMEFlattening, SafeSearch: o.SafeSearch, RestrictedYouTube: o.RestrictedYouTube}
	if o.DefaultRule != nil {
		p.DefaultRule = &DefaultRule{Act: Act{Action: o.DefaultRule.Action, Target: toTarget(o.DefaultRule.Target)}}
	}
	if o.BlockResponse != nil {
		p.BlockResponse = &BlockResponse{Mode: o.BlockResponse.Mode, V4: o.BlockResponse.V4, V6: o.BlockResponse.V6}
	}
	if o.ECS != nil {
		p.ECS = &ECS{Mode: o.ECS.Mode, V4: o.ECS.V4, V6: o.ECS.V6}
	}
	return p
}

// ---------------------------------------------------------------------------
// Upload Folder (spec 6.3, T-195).

// rulePayload is the canonical encoding of what Upload compares: action, target, enabled, expiry and comment (spec 6.3).
func rulePayload(action string, t store.Target, enabled bool, exp *time.Time, comment string) string {
	var b strings.Builder
	b.WriteString(action)
	b.WriteByte(0x1f)
	b.WriteString(t.Kind)
	b.WriteByte(0x1f)
	b.WriteString(t.LocationID.String())
	b.WriteByte(0x1f)
	b.WriteString(t.IPv4)
	b.WriteByte(0x1f)
	b.WriteString(t.IPv6)
	b.WriteByte(0x1f)
	b.WriteString(t.Host)
	b.WriteByte(0x1f)
	b.WriteString(strconv.FormatBool(enabled))
	b.WriteByte(0x1f)
	if exp != nil {
		b.WriteString(strconv.FormatInt(exp.UnixMicro(), 10))
	}
	b.WriteByte(0x1f)
	b.WriteString(comment)
	return b.String()
}

// uploadItemShape is what a rule of a rules document is refused for without any row work: its pattern, the length of its
// comment and its expiry. UploadRules runs it per item, and CheckUploadShape runs it before a job is queued.
func (e *Env) uploadItemShape(p string, r DocRule) (pat parsed, exp *time.Time, fs []Field) {
	pat, perr := parse(r.Pattern)
	if perr != nil {
		fs = append(fs, Field{p + "/pattern", PatternCode(perr)})
	}
	if tooLong(r.Comment, commentLimit) {
		fs = append(fs, Field{p + "/comment", CodeTooLong})
	}
	if r.ExpiresAt != "" {
		t, ok := parseExpiry(r.ExpiresAt)
		if !ok {
			fs = append(fs, Field{p + "/expires_at", CodeInvalid})
		} else if x, f := e.expiry(p+"/expires_at", Expiry{At: t, HasAt: true}, true); f != nil {
			fs = append(fs, *f)
		} else {
			exp = x
		}
	}
	return pat, exp, fs
}

// CheckUploadShape is UploadRules' check of what needs no row work: the mode, the size against the tenant's limit and the
// shape of every item. The handler runs it before it queues a job, so a malformed upload is the same 422 as inline and
// never holds the tenant's single job slot (spec 3.5).
func (e *Env) CheckUploadShape(tx store.Tx, d RulesDocument, mode string) error {
	if mode != "new_only" && mode != "upsert" {
		return invalid(Field{"/mode", CodeInvalid})
	}
	lim, err := tx.Limits()
	if err != nil {
		return err
	}
	if len(d.Rules) > lim.MaxRulesPerRequest {
		return invalid(Field{"max_rules_per_request", CodeExceeded})
	}
	var fs []Field
	for i, r := range d.Rules {
		if err := tx.Context().Err(); err != nil {
			return err
		}
		_, _, f := e.uploadItemShape(fmt.Sprintf("/rules/%d", i), r)
		fs = append(fs, f...)
	}
	if len(fs) > 0 {
		return invalid(fs...)
	}
	return nil
}

// UploadRules merges a rules document into a folder, never deleting (spec 6.3): mode "new_only" or "upsert". A key in
// another folder, or at the top level, is a conflict. It is a document write, so a location outside the set is
// flagged and an Iranian Redirect is refused.
func (e *Env) UploadRules(tx store.Tx, profile, folderID uuid.UUID, d RulesDocument, mode string) (BatchResult, error) {
	var um rules.UploadMode
	switch mode {
	case "new_only":
		um = rules.UploadNewOnly
	case "upsert":
		um = rules.UploadUpsert
	default:
		return BatchResult{}, invalid(Field{"/mode", CodeInvalid})
	}
	w, err := e.begin(tx, profile, len(d.Rules))
	if err != nil {
		return BatchResult{}, err
	}
	folder, err := w.folder(folderID)
	if err != nil {
		return BatchResult{}, err
	}
	if folder == nil {
		return BatchResult{}, notFound()
	}

	type incoming struct {
		row    store.NewRule
		parsed rules.Pattern
	}
	var fs []Field
	ins := make([]incoming, len(d.Rules))
	var items []rules.Item
	var redirects []rules.Pattern
	var redirectAt []int
	for i, r := range d.Rules {
		if err := w.tx.Context().Err(); err != nil {
			return BatchResult{}, err
		}
		p := fmt.Sprintf("/rules/%d", i)
		ruleFs := len(fs)
		pat, exp, shape := e.uploadItemShape(p, r)
		fs = append(fs, shape...)
		res, afs, err := w.actFields(p, Act{Action: r.Action, Target: toTarget(r.Target)}, folder, true)
		if err != nil {
			return BatchResult{}, err
		}
		fs = append(fs, afs...)
		if len(fs) > ruleFs {
			continue
		}
		nr := store.NewRule{FolderID: folderID, Key: pat.key, MatchKind: pat.p.Kind.String(), Negated: pat.p.Negated, Action: r.Action,
			Target: res.t, Enabled: on(r.Enabled), ExpiresAt: exp, Comment: r.Comment, LocationUnavailable: res.flagged}
		ins[i] = incoming{row: nr, parsed: pat.p}
		items = append(items, rules.Item{Key: nr.Key, Folder: folderID.String(), Payload: rulePayload(nr.Action, nr.Target, nr.Enabled, nr.ExpiresAt, nr.Comment)})
		if effRedirect(nr.Action, folder) {
			redirects, redirectAt = append(redirects, pat.p), append(redirectAt, i)
		}
	}
	if len(redirects) > 0 && len(fs) == 0 {
		ir, err := w.iranian(redirects)
		if err != nil {
			return BatchResult{}, err
		}
		for j, bad := range ir {
			if bad {
				fs = append(fs, Field{fmt.Sprintf("/rules/%d/pattern", redirectAt[j]), CodeIranianName})
			}
		}
	}
	if len(fs) > 0 {
		return BatchResult{}, invalid(fs...)
	}

	exist, err := tx.RulesAll(profile)
	if err != nil {
		return BatchResult{}, err
	}
	byKey := map[string]store.RuleRow{}
	existing := make([]rules.Item, 0, len(exist))
	for _, r := range exist {
		byKey[r.Key] = r
		f := ""
		if r.FolderID != uuid.Nil {
			f = r.FolderID.String()
		}
		existing = append(existing, rules.Item{Key: r.Key, Folder: f, Payload: rulePayload(r.Action, r.Target, r.Enabled, r.ExpiresAt, r.Comment)})
	}
	merged := rules.MergeUpload(existing, items, um)

	// The outcome of each incoming item, by the same rule MergeUpload applies, in order against the evolving state.
	state := map[string]rules.Item{}
	for _, it := range existing {
		state[it.Key] = it
	}
	var res BatchResult
	var create []store.NewRule
	createAt := map[string]int{}
	type upd struct {
		row store.RuleRow
		at  int
	}
	var updates []upd
	flagged := 0
	for i := range d.Rules {
		in := ins[i].row
		it := rules.Item{Key: in.Key, Folder: folderID.String(), Payload: rulePayload(in.Action, in.Target, in.Enabled, in.ExpiresAt, in.Comment)}
		cur, ok := state[it.Key]
		switch {
		case !ok:
			state[it.Key] = it
			createAt[it.Key] = len(create)
			create = append(create, in)
			res.add(i, "created", uuid.Nil)
			if in.LocationUnavailable {
				flagged++
			}
		case cur.Folder != it.Folder:
			res.add(i, "conflict", uuid.Nil)
		case um == rules.UploadUpsert && cur.Payload != it.Payload:
			state[it.Key] = it
			if at, fresh := createAt[it.Key]; fresh {
				// A key repeated inside the file after it was created by it: the later row wins.
				create[at] = in
			} else {
				old := byKey[it.Key]
				old.Action, old.Target, old.Enabled, old.ExpiresAt, old.Comment, old.LocationUnavailable = in.Action, in.Target, in.Enabled, in.ExpiresAt, in.Comment, in.LocationUnavailable
				updates = append(updates, upd{old, i})
			}
			res.add(i, "updated", byKey[it.Key].ID)
			if in.LocationUnavailable {
				flagged++
			}
		default:
			res.add(i, "skipped", uuid.Nil)
		}
	}
	if res.Created != merged.Created || res.Updated != merged.Updated || res.Skipped != merged.Skipped || res.Conflict != merged.Conflicts {
		// The shared merge and the per-item outcomes disagree: a defect, never a request that can be answered.
		return BatchResult{}, fmt.Errorf("profiles: upload outcomes differ from the shared merge")
	}

	wild := 0
	for _, c := range create {
		if c.MatchKind == "subdomains" || c.MatchKind == "glob" {
			wild++
		}
	}
	if _, err := w.insertRules(ruleBatch{rows: create, wild: wild}); err != nil {
		return BatchResult{}, err
	}
	// The insert returns its ids in key order, not in the order of the rows, so the created items are pointed at their
	// ids by key.
	if len(create) > 0 {
		keys := make([]string, len(create))
		for i, c := range create {
			keys[i] = c.Key
		}
		got, err := tx.RulesByKeys(profile, keys)
		if err != nil {
			return BatchResult{}, err
		}
		keyed := map[string]uuid.UUID{}
		for _, g := range got {
			keyed[g.Key] = g.ID
		}
		for i := range res.Items {
			if res.Items[i].Outcome == "created" {
				res.Items[i].ID = keyed[ins[res.Items[i].Index].row.Key]
			}
		}
	}
	for _, u := range updates {
		won, err := tx.RuleUpdate(w.pw, u.row)
		if err != nil {
			return BatchResult{}, err
		}
		if !won.Yes() {
			return BatchResult{}, &Error{Kind: KindConflict}
		}
	}
	if res.Created+res.Updated > 0 {
		if err := w.mark(); err != nil {
			return BatchResult{}, err
		}
	}
	res.Flagged = flagged
	return res, nil
}

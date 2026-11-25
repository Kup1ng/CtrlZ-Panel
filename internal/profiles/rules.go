package profiles

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Shared/rules"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Rules and folders (spec 3.7, 6.3, 8.2).

// RuleIn is a create: one action, target, folder, comment and expiry for every pattern of the request (a Geo
// Rule dialog with several rows is several requests of one pattern or one request each).
type RuleIn struct {
	Patterns []string
	Act      Act
	FolderID uuid.UUID
	Comment  string
	Expiry   Expiry
	Disabled bool // a new rule is enabled unless this says otherwise
}

func expiryField(x Expiry) string {
	if x.In != "" {
		return "/expires_in"
	}
	return "/expires_at"
}

// folder reads a folder of the profile under the guard; an id of another profile or tenant is not found.
func (w *wtx) folder(id uuid.UUID) (*store.FolderRow, error) {
	if id == uuid.Nil {
		return nil, nil
	}
	f, ok, err := w.tx.Folder(w.pw.ID(), id)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, notFound()
	}
	return &f, nil
}

// inheritFields: a rule that inherits needs a folder that has a Folder Rule, and a Do Not Log folder has none
// (SC 4).
func inheritFields(field string, f *store.FolderRow) []Field {
	switch {
	case f == nil:
		return []Field{{field + "/action", CodeNeedsFolderAction}}
	case f.Kind == "do_not_log":
		return []Field{{field + "/action", CodeInvalid}}
	case f.Action == "":
		return []Field{{field + "/action", CodeNeedsFolderAction}}
	}
	return nil
}

// effRedirect is whether the rule's effective action is Redirect: its own, or its folder's for inherit.
func effRedirect(action string, f *store.FolderRow) bool {
	return action == "redirect" || (action == "inherit" && f != nil && f.Action == "redirect")
}

// actFields checks an action and its target for a rule in a folder: the action is one of the four, inherit
// needs its folder, and a Redirect target passes the location set (items refuse, documents flag).
func (w *wtx) actFields(field string, a Act, f *store.FolderRow, doc bool) (resolved, []Field, error) {
	switch a.Action {
	case "block", "bypass", "redirect":
	case "inherit":
		if fs := inheritFields(field, f); fs != nil {
			return resolved{}, fs, nil
		}
	default:
		return resolved{}, []Field{{field + "/action", CodeInvalid}}, nil
	}
	return w.target(field, a, doc, w.allowed)
}

// ruleBatch is the checked result of a create: rows to insert.
type ruleBatch struct {
	rows []store.NewRule
	wild int
}

// buildRules checks every pattern of the request and makes the rows. Every problem is a field, named by the
// pointer of the request; nothing is written by it.
func (w *wtx) buildRules(in RuleIn, folder *store.FolderRow, doc bool) (ruleBatch, error) {
	var fs []Field
	if len(in.Patterns) == 0 {
		return ruleBatch{}, invalid(Field{"/patterns", CodeRequired})
	}
	if tooLong(in.Comment, commentLimit) {
		fs = append(fs, Field{"/comment", CodeTooLong})
	}
	exp, f := w.e.expiry(expiryField(in.Expiry), in.Expiry, doc)
	if f != nil {
		fs = append(fs, *f)
	}
	res, afs, err := w.actFields("", in.Act, folder, doc)
	if err != nil {
		return ruleBatch{}, err
	}
	fs = append(fs, afs...)

	var ps []rules.Pattern
	var keys []string
	var at []int
	seen := map[string]bool{}
	for i, text := range in.Patterns {
		p, err := parse(text)
		if err != nil {
			fs = append(fs, Field{fmt.Sprintf("/patterns/%d", i), PatternCode(err)})
			continue
		}
		if seen[p.key] {
			fs = append(fs, Field{fmt.Sprintf("/patterns/%d", i), CodeDuplicate})
			continue
		}
		seen[p.key] = true
		ps, keys, at = append(ps, p.p), append(keys, p.key), append(at, i)
	}
	if len(keys) > 0 {
		exist, err := w.tx.RulesByKeys(w.pw.ID(), keys)
		if err != nil {
			return ruleBatch{}, err
		}
		have := map[string]bool{}
		for _, r := range exist {
			have[r.Key] = true
		}
		for j, k := range keys {
			if have[k] {
				fs = append(fs, Field{fmt.Sprintf("/patterns/%d", at[j]), CodeExists})
			}
		}
		// D42: a Redirect on a name that is never proxied is refused, whether the rule's own or its folder's.
		if effRedirect(in.Act.Action, folder) && len(afs) == 0 {
			ir, err := w.iranian(ps)
			if err != nil {
				return ruleBatch{}, err
			}
			for j, bad := range ir {
				if bad {
					fs = append(fs, Field{fmt.Sprintf("/patterns/%d", at[j]), CodeIranianName})
				}
			}
		}
	}
	if len(fs) > 0 {
		return ruleBatch{}, invalid(fs...)
	}
	var out ruleBatch
	for j, k := range keys {
		nr := store.NewRule{Key: k, MatchKind: ps[j].Kind.String(), Negated: ps[j].Negated, Action: in.Act.Action, Target: res.t,
			Enabled: !in.Disabled, ExpiresAt: exp, Comment: in.Comment, LocationUnavailable: res.flagged}
		if folder != nil {
			nr.FolderID = folder.ID
		}
		if ps[j].Kind.IsWildcard() {
			out.wild++
		}
		out.rows = append(out.rows, nr)
	}
	return out, nil
}

// insertRules writes a checked batch; a loss is the rule cap or the wildcard cap of the profile.
func (w *wtx) insertRules(b ruleBatch) ([]uuid.UUID, error) {
	ids, won, err := w.tx.RulesInsert(w.pw, b.rows)
	if errors.Is(err, store.ErrConflict) {
		return nil, invalid(Field{"/patterns", CodeExists})
	}
	if err != nil {
		return nil, err
	}
	if !won.Yes() {
		over, overWild, err := w.tx.RulesCapReached(w.pw, len(b.rows), b.wild)
		if err != nil {
			return nil, err
		}
		switch {
		case over:
			return nil, invalid(Field{"max_rules_per_profile", CodeExceeded})
		case overWild:
			return nil, invalid(Field{"max_wildcards_per_profile", CodeExceeded})
		}
		return nil, &Error{Kind: KindConflict}
	}
	return ids, nil
}

// CreateRules adds rules to the profile in one transaction: all or none (spec 3.5).
func (e *Env) CreateRules(tx store.Tx, profile uuid.UUID, in RuleIn) ([]store.RuleRow, error) {
	w, err := e.begin(tx, profile, len(in.Patterns))
	if err != nil {
		return nil, err
	}
	folder, err := w.folder(in.FolderID)
	if err != nil {
		return nil, err
	}
	b, err := w.buildRules(in, folder, false)
	if err != nil {
		return nil, err
	}
	ids, err := w.insertRules(b)
	if err != nil {
		return nil, err
	}
	if err := w.mark(); err != nil {
		return nil, err
	}
	return tx.RulesGet(profile, ids)
}

// RulePatch is the one-rule edit: the fields to set, and the names to clear (comment, expires, folder).
type RulePatch struct {
	Pattern  *string
	Act      *Act
	FolderID *uuid.UUID
	Enabled  *bool
	Comment  *string
	Expiry   *Expiry
	Clear    []string
}

func has(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// UpdateRule edits one rule. The item checks run on the values the request sets; a value equal to the stored
// one is not set, so a flagged or grandfathered rule can still be switched, commented, expired or moved (3.7).
func (e *Env) UpdateRule(tx store.Tx, profile, id uuid.UUID, in RulePatch) (store.RuleRow, error) {
	w, err := e.begin(tx, profile, 0)
	if err != nil {
		return store.RuleRow{}, err
	}
	got, err := tx.RulesGet(profile, []uuid.UUID{id})
	if err != nil {
		return store.RuleRow{}, err
	}
	if len(got) != 1 {
		return store.RuleRow{}, notFound()
	}
	cur := got[0]
	nr := cur
	var fs []Field

	// Folder first: the action's checks need the folder the rule ends up in.
	folderID := cur.FolderID
	switch {
	case has(in.Clear, "folder"):
		folderID = uuid.Nil
	case in.FolderID != nil:
		folderID = *in.FolderID
	}
	folderSet := folderID != cur.FolderID
	folder, err := w.folder(folderID)
	if err != nil {
		return store.RuleRow{}, err
	}
	nr.FolderID = folderID

	patternSet := false
	var np *rules.Pattern
	if in.Pattern != nil {
		p, perr := parse(*in.Pattern)
		if perr != nil {
			fs = append(fs, Field{"/pattern", PatternCode(perr)})
		} else if p.key != cur.Key {
			patternSet = true
			nr.Key, nr.MatchKind, nr.Negated = p.key, p.p.Kind.String(), p.p.Negated
			np = &p.p
		}
	}
	actSet := false
	if in.Act != nil && (in.Act.Action != cur.Action || (in.Act.Action == "redirect" && !sameTarget(in.Act.Target, cur.Target))) {
		actSet = true
		nr.Action = in.Act.Action
	}
	if in.Enabled != nil {
		nr.Enabled = *in.Enabled
	}
	switch {
	case has(in.Clear, "comment"):
		nr.Comment = ""
	case in.Comment != nil:
		if tooLong(*in.Comment, commentLimit) {
			fs = append(fs, Field{"/comment", CodeTooLong})
		}
		nr.Comment = *in.Comment
	}
	switch {
	case has(in.Clear, "expires"):
		nr.ExpiresAt = nil
	case in.Expiry != nil:
		exp, f := e.expiry(expiryField(*in.Expiry), *in.Expiry, false)
		if f != nil {
			fs = append(fs, *f)
		}
		nr.ExpiresAt = exp
	}

	// The action and target checks, only for what the request sets; moving a rule that inherits into another
	// folder sets its effective action, so it is checked too (3.7).
	inheritMoved := folderSet && cur.Action == "inherit" && !actSet
	if actSet || inheritMoved {
		act := Act{Action: nr.Action}
		if in.Act != nil && actSet {
			act = *in.Act
		}
		res, afs, err := w.actFields("", act, folder, false)
		if err != nil {
			return store.RuleRow{}, err
		}
		fs = append(fs, afs...)
		if afs == nil {
			nr.Target, nr.LocationUnavailable = res.t, res.flagged
			if act.Action != "redirect" {
				nr.Target = store.Target{}
			}
		}
	}
	// D42 on what the request sets: a new pattern, a new action or target, or a new folder for an inheriting rule.
	if (patternSet || actSet || inheritMoved) && effRedirect(nr.Action, folder) && len(fs) == 0 {
		var p rules.Pattern
		if np != nil {
			p = *np
		} else {
			pp, perr := parse(nr.Key)
			if perr != nil {
				return store.RuleRow{}, perr // a stored key always parses; a defect if not
			}
			p = pp.p
		}
		ir, err := w.iranian([]rules.Pattern{p})
		if err != nil {
			return store.RuleRow{}, err
		}
		if ir[0] {
			fs = append(fs, Field{"/pattern", CodeIranianName})
		}
	}
	if patternSet && len(fs) == 0 {
		exist, err := tx.RulesByKeys(profile, []string{nr.Key})
		if err != nil {
			return store.RuleRow{}, err
		}
		if len(exist) > 0 {
			fs = append(fs, Field{"/pattern", CodeExists})
		}
	}
	if len(fs) > 0 {
		return store.RuleRow{}, invalid(fs...)
	}
	won, err := tx.RuleUpdate(w.pw, nr)
	switch {
	case errors.Is(err, store.ErrConflict):
		return store.RuleRow{}, invalid(Field{"/pattern", CodeExists})
	case err != nil:
		return store.RuleRow{}, err
	case !won.Yes():
		return store.RuleRow{}, invalid(Field{"max_wildcards_per_profile", CodeExceeded})
	}
	if err := w.mark(); err != nil {
		return store.RuleRow{}, err
	}
	out, err := tx.RulesGet(profile, []uuid.UUID{id})
	if err != nil || len(out) != 1 {
		return store.RuleRow{}, err
	}
	return out[0], nil
}

// DeleteRule removes one rule of the profile.
func (e *Env) DeleteRule(tx store.Tx, profile, id uuid.UUID) error {
	w, err := e.begin(tx, profile, 0)
	if err != nil {
		return err
	}
	n, err := tx.RulesDelete(w.pw, []uuid.UUID{id})
	if err != nil {
		return err
	}
	if n != 1 {
		return notFound()
	}
	return w.mark()
}

// ---------------------------------------------------------------------------
// Folders.

// FolderIn is a folder to create.
type FolderIn struct {
	Name string
	Kind string // standard or do_not_log; bypass is not available (D8)
	Act  Act    // a Folder Rule: block, bypass or redirect; empty for none
}

// checkFolder validates a folder's own fields. A Do Not Log folder has no action.
func (w *wtx) checkFolder(in FolderIn, doc bool) (store.FolderRow, []Field, error) {
	var fs []Field
	if f := checkName(in.Name, "/name", folderNameLimit); f != nil {
		fs = append(fs, *f)
	}
	switch in.Kind {
	case "standard", "do_not_log":
	default:
		fs = append(fs, Field{"/kind", CodeNotAvailable})
	}
	row := store.FolderRow{Name: in.Name, Kind: in.Kind}
	switch in.Act.Action {
	case "":
		if in.Act.Target.Kind != "" {
			fs = append(fs, Field{"/target", CodeInvalid})
		}
	case "block", "bypass", "redirect":
		if in.Kind == "do_not_log" {
			fs = append(fs, Field{"/action", CodeInvalid})
			break
		}
		res, afs, err := w.target("", in.Act, doc, w.allowed)
		if err != nil {
			return row, nil, err
		}
		fs = append(fs, afs...)
		row.Action, row.Target, row.LocationUnavailable = in.Act.Action, res.t, res.flagged
	default:
		fs = append(fs, Field{"/action", CodeInvalid})
	}
	return row, fs, nil
}

// insertFolder adds a checked folder, and answers the folder cap.
func (w *wtx) insertFolder(row store.FolderRow) (uuid.UUID, error) {
	id, won, err := w.tx.FolderInsert(w.pw, row)
	if err != nil {
		return uuid.Nil, err
	}
	if !won.Yes() {
		return uuid.Nil, invalid(Field{"max_folders_per_profile", CodeExceeded})
	}
	return id, nil
}

// CreateFolder adds a folder.
func (e *Env) CreateFolder(tx store.Tx, profile uuid.UUID, in FolderIn) (store.FolderRow, error) {
	w, err := e.begin(tx, profile, 0)
	if err != nil {
		return store.FolderRow{}, err
	}
	row, fs, err := w.checkFolder(in, false)
	if err != nil {
		return store.FolderRow{}, err
	}
	if len(fs) > 0 {
		return store.FolderRow{}, invalid(fs...)
	}
	id, err := w.insertFolder(row)
	if err != nil {
		return store.FolderRow{}, err
	}
	if err := w.mark(); err != nil {
		return store.FolderRow{}, err
	}
	f, _, err := tx.Folder(profile, id)
	return f, err
}

// FolderPatch is the folder edit: a name, a Folder Rule, or clearing the Folder Rule.
type FolderPatch struct {
	Name  *string
	Act   *Act
	Clear []string // "action"
}

// UpdateFolder edits a folder. Clearing a Folder Rule that rules inherit is refused (SC 4); setting a Redirect
// Folder Rule over an inheriting Iranian rule is refused (D42).
func (e *Env) UpdateFolder(tx store.Tx, profile, id uuid.UUID, in FolderPatch) (store.FolderRow, error) {
	w, err := e.begin(tx, profile, 0)
	if err != nil {
		return store.FolderRow{}, err
	}
	cur, err := w.folder(id)
	if err != nil {
		return store.FolderRow{}, err
	}
	if cur == nil {
		return store.FolderRow{}, notFound()
	}
	nf := *cur
	var fs []Field
	if in.Name != nil {
		if f := checkName(*in.Name, "/name", folderNameLimit); f != nil {
			fs = append(fs, *f)
		}
		nf.Name = *in.Name
	}
	inheriting, err := tx.FolderInheriting(profile, id)
	if err != nil {
		return store.FolderRow{}, err
	}
	switch {
	case has(in.Clear, "action"):
		if inheriting > 0 {
			fs = append(fs, Field{"/action", CodeHasInheritingRules})
		}
		nf.Action, nf.Target, nf.LocationUnavailable = "", store.Target{}, false
	case in.Act != nil && in.Act.Action != "" &&
		(in.Act.Action != cur.Action || (in.Act.Action == "redirect" && !sameTarget(in.Act.Target, cur.Target))):
		if cur.Kind == "do_not_log" {
			fs = append(fs, Field{"/action", CodeInvalid})
			break
		}
		// The closed set of a Folder Rule, as at create: any other value would reach the CHECK of the table and
		// come back as a constraint error instead of a 422.
		if a := in.Act.Action; a != "block" && a != "bypass" && a != "redirect" {
			fs = append(fs, Field{"/action", CodeInvalid})
			break
		}
		res, afs, err := w.target("", *in.Act, false, w.allowed)
		if err != nil {
			return store.FolderRow{}, err
		}
		fs = append(fs, afs...)
		if afs == nil {
			nf.Action, nf.Target, nf.LocationUnavailable = in.Act.Action, res.t, res.flagged
			if in.Act.Action == "redirect" && inheriting > 0 {
				if bad, err := w.inheritingIranian(id); err != nil {
					return store.FolderRow{}, err
				} else if bad {
					fs = append(fs, Field{"/action", CodeIranianName})
				}
			}
		}
	}
	if len(fs) > 0 {
		return store.FolderRow{}, invalid(fs...)
	}
	if ok, err := tx.FolderUpdate(w.pw, nf); err != nil {
		return store.FolderRow{}, err
	} else if !ok {
		return store.FolderRow{}, notFound()
	}
	if err := w.mark(); err != nil {
		return store.FolderRow{}, err
	}
	f, _, err := tx.Folder(profile, id)
	return f, err
}

// inheritingIranian says whether a rule that inherits the folder's action is Iranian.
func (w *wtx) inheritingIranian(folder uuid.UUID) (bool, error) {
	all, err := w.tx.RulesAll(w.pw.ID())
	if err != nil {
		return false, err
	}
	var ps []rules.Pattern
	for _, r := range all {
		if r.FolderID != folder || r.Action != "inherit" {
			continue
		}
		p, perr := parse(r.Key)
		if perr != nil {
			continue
		}
		ps = append(ps, p.p)
	}
	ir, err := w.iranian(ps)
	if err != nil {
		return false, err
	}
	for _, b := range ir {
		if b {
			return true, nil
		}
	}
	return false, nil
}

// DeleteFolder removes a folder and its rules (the confirm dialog says so).
func (e *Env) DeleteFolder(tx store.Tx, profile, id uuid.UUID) error {
	w, err := e.begin(tx, profile, 0)
	if err != nil {
		return err
	}
	ok, err := tx.FolderDelete(w.pw, id)
	if err != nil {
		return err
	}
	if !ok {
		return notFound()
	}
	return w.mark()
}

// timeNow keeps the clock in one place for the selector of a batch.
func (e *Env) timeNow() time.Time { return e.now() }

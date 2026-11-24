package profiles

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Shared/rules"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Batch operations on rules (spec 3.5, 8.3): one transaction, all or none. The same code runs inline for up to
// 1,000 items and as a job above that, where it runs again against the state at run time.

// Selector is the filter of "select all" over the rules list.
type Selector struct {
	Folder   string // "" any, "root" the top level, "folder" the one in FolderID
	FolderID uuid.UUID
	Q        string // the text typed, as SearchText converts it
	Status   string // "", enabled, disabled, expired
	Action   string
}

// EditSet is what a group Edit sets; Clear names what it removes (comment, expires, folder).
type EditSet struct {
	Act      *Act
	Comment  *string
	Expiry   *Expiry
	FolderID *uuid.UUID
}

// BatchIn is a RulesBatch request.
type BatchIn struct {
	Op          string // copy, move, edit, enable, disable, delete
	IDs         []uuid.UUID
	Selector    *Selector
	DestProfile uuid.UUID
	DestFolder  uuid.UUID
	DestRoot    bool
	NewFolder   *FolderIn
	Set         *EditSet
	Clear       []string
}

// JobThreshold is how many items turn a request into a job (D31): above it the request is validated for shape,
// queued, and run by the worker.
const JobThreshold = 1000

func idOrder(a, b uuid.UUID) bool { return bytes.Compare(a[:], b[:]) < 0 }

// CheckBatch is what a batch request is refused for before any row is read: the operation, exactly one of ids and
// selector, the limit of the tenant on the ids, a repeated id, the selector vocabulary and, for a copy, a destination
// other than the source. RulesBatch runs it first, and the handler runs it before it queues a job, so a malformed request
// above 1,000 items is the same 422 as inline and never holds the tenant's single job slot (spec 3.5).
func (e *Env) CheckBatch(tx store.Tx, profile uuid.UUID, in BatchIn) (store.Limits, error) {
	switch in.Op {
	case "copy", "move", "edit", "enable", "disable", "delete":
	default:
		return store.Limits{}, invalid(Field{"/op", CodeInvalid})
	}
	if (len(in.IDs) > 0) == (in.Selector != nil) {
		return store.Limits{}, invalid(Field{"/ids", CodeRequired})
	}
	lim, err := tx.Limits()
	if err != nil {
		return store.Limits{}, err
	}
	if len(in.IDs) > lim.MaxRulesPerRequest {
		return store.Limits{}, invalid(Field{"max_rules_per_request", CodeExceeded})
	}
	// The same id twice is refused, not folded into one item: the answer is keyed by the position in the request,
	// so a folded id would leave a gap in the client's mapping (spec 3.7).
	var dups []Field
	seen := make(map[uuid.UUID]bool, len(in.IDs))
	for i, id := range in.IDs {
		if seen[id] {
			dups = append(dups, Field{fmt.Sprintf("/ids/%d", i), CodeDuplicate})
		}
		seen[id] = true
	}
	if len(dups) > 0 {
		return store.Limits{}, invalid(dups...)
	}
	if in.Selector != nil {
		if fs := checkSelector(*in.Selector); len(fs) > 0 {
			return store.Limits{}, invalid(fs...)
		}
	}
	if in.Op == "copy" && (in.DestProfile == uuid.Nil || in.DestProfile == profile) {
		return store.Limits{}, invalid(Field{"/dest_profile_id", CodeInvalid})
	}
	return lim, nil
}

// RulesBatch runs a batch over the rules of a profile.
func (e *Env) RulesBatch(tx store.Tx, profile uuid.UUID, in BatchIn) (BatchResult, error) {
	lim, err := e.CheckBatch(tx, profile, in)
	if err != nil {
		return BatchResult{}, err
	}

	// The guard: the profile written, and for a transfer the destination. Copy guards only the destination and
	// reads the source under the path profile, so a locked source can be copied from. Move guards both in id order,
	// so two opposite moves cannot deadlock.
	var w, d *wtx
	cross := (in.Op == "copy" || in.Op == "move") && in.DestProfile != uuid.Nil && in.DestProfile != profile
	switch {
	case in.Op == "copy":
		if _, ok, err := tx.ProfileGet(profile); err != nil {
			return BatchResult{}, err
		} else if !ok {
			return BatchResult{}, notFound()
		}
		if d, err = e.begin(tx, in.DestProfile, 0); err != nil {
			return BatchResult{}, err
		}
	case cross: // move to another profile
		a, b := profile, in.DestProfile
		if !idOrder(a, b) {
			a, b = b, a
		}
		first, err := e.begin(tx, a, 0)
		if err != nil {
			return BatchResult{}, err
		}
		second, err := e.begin(tx, b, 0)
		if err != nil {
			return BatchResult{}, err
		}
		w, d = first, second
		if a != profile {
			w, d = second, first
		}
	default:
		if w, err = e.begin(tx, profile, 0); err != nil {
			return BatchResult{}, err
		}
		d = w
	}

	ids := in.IDs
	if in.Selector != nil {
		s := in.Selector
		if s.Folder == "folder" {
			// A folder of another profile or tenant is not found, as in every other route of the profile (spec 3.7).
			if _, ok, err := tx.Folder(profile, s.FolderID); err != nil {
				return BatchResult{}, err
			} else if !ok {
				return BatchResult{}, notFound()
			}
		}
		ids, err = tx.RuleIDsMatching(profile, store.RuleSelector{Folder: s.Folder, FolderID: s.FolderID, Q: SearchText(s.Q),
			Status: s.Status, Action: s.Action, Now: e.timeNow(), MaxResult: lim.MaxRulesPerRequest})
		if err != nil {
			return BatchResult{}, err
		}
		if len(ids) > lim.MaxRulesPerRequest {
			return BatchResult{}, invalid(Field{"max_rules_per_request", CodeExceeded})
		}
	}
	if len(ids) == 0 {
		return BatchResult{}, nil
	}
	rows, err := tx.RulesGet(profile, ids)
	if err != nil {
		return BatchResult{}, err
	}
	index := map[uuid.UUID]int{}
	for i, id := range ids {
		index[id] = i
	}
	if len(rows) != len(index) {
		// An id that is not a rule of this profile: another profile's, another tenant's, or none.
		return BatchResult{}, notFound()
	}
	sort.Slice(rows, func(i, j int) bool { return index[rows[i].ID] < index[rows[j].ID] })

	var res BatchResult
	switch in.Op {
	case "enable", "disable":
		want := in.Op == "enable"
		var change []uuid.UUID
		for _, r := range rows {
			if r.Enabled != want {
				change = append(change, r.ID)
			}
		}
		if len(change) > 0 {
			if _, err := tx.RulesSetEnabled(w.pw, change, want); err != nil {
				return BatchResult{}, err
			}
		}
		for _, r := range rows {
			out := "updated"
			if r.Enabled == want {
				out = "skipped"
			}
			res.add(index[r.ID], out, r.ID)
		}
	case "delete":
		if _, err := tx.RulesDelete(w.pw, ids); err != nil {
			return BatchResult{}, err
		}
		for _, r := range rows {
			res.add(index[r.ID], "updated", r.ID)
		}
	case "edit":
		if err := w.editRules(rows, in, index, &res); err != nil {
			return BatchResult{}, err
		}
	case "copy", "move":
		if err := transfer(w, d, rows, in, cross, index, &res); err != nil {
			return BatchResult{}, err
		}
	}
	if err := w.markBoth(d); err != nil {
		return BatchResult{}, err
	}
	return res, nil
}

// checkSelector refuses a selector outside the closed vocabularies, so a typo is a 422 and not a selection of
// nothing that reads as success.
func checkSelector(s Selector) []Field {
	var fs []Field
	switch s.Folder {
	case "", "root":
	case "folder":
		if s.FolderID == uuid.Nil {
			fs = append(fs, Field{"/selector/folder_id", CodeRequired})
		}
	default:
		fs = append(fs, Field{"/selector/folder", CodeInvalid})
	}
	switch s.Status {
	case "", "enabled", "disabled", "expired":
	default:
		fs = append(fs, Field{"/selector/status", CodeInvalid})
	}
	switch s.Action {
	case "", "block", "bypass", "redirect", "inherit":
	default:
		fs = append(fs, Field{"/selector/action", CodeInvalid})
	}
	return fs
}

// iranSet answers D42 for the rows of one batch: the first question reads the whole list of names in chunks of 500
// (spec 3.6), later ones are map reads. A lookup per row made a batch of N rules N round trips under the profile's
// row lock, which is the lock every other writer of the profile waits on.
type iranSet struct {
	w    *wtx
	rows []store.RuleRow
	m    map[string]bool
}

func (s *iranSet) has(key string) (bool, error) {
	if s.m == nil {
		var ps []rules.Pattern
		var ks []string
		seen := map[string]bool{}
		for _, r := range s.rows {
			if seen[r.Key] {
				continue
			}
			seen[r.Key] = true
			if p, err := parse(r.Key); err == nil { // a key that does not parse gets its error when it is asked about
				ps, ks = append(ps, p.p), append(ks, r.Key)
			}
		}
		ir, err := s.w.iranian(ps)
		if err != nil {
			return false, err
		}
		m := make(map[string]bool, len(ks))
		for i, k := range ks {
			m[k] = ir[i]
		}
		s.m = m
	}
	if v, ok := s.m[key]; ok {
		return v, nil
	}
	_, err := parse(key)
	return false, err
}

// markBoth marks the profiles a transfer wrote, both under the transaction's batch id so the compiler makes one
// entry of them (spec 3.2). For a copy only the destination changed.
func (w *wtx) markBoth(d *wtx) error {
	if w != nil {
		if err := w.mark(); err != nil {
			return err
		}
	}
	if d != nil && (w == nil || d.pw.ID() != w.pw.ID()) {
		return d.mark()
	}
	return nil
}

// editRules applies a group Edit: each rule gets the values the request sets, checked as an item write.
func (w *wtx) editRules(rows []store.RuleRow, in BatchIn, index map[uuid.UUID]int, res *BatchResult) error {
	set := in.Set
	if set == nil {
		set = &EditSet{}
	}
	var fs []Field
	var exp *timePtr
	if set.Expiry != nil {
		t, f := w.e.expiry("/set/expires_in", *set.Expiry, false)
		if f != nil {
			fs = append(fs, *f)
		}
		exp = &timePtr{t}
	}
	if set.Comment != nil && tooLong(*set.Comment, commentLimit) {
		fs = append(fs, Field{"/set/comment", CodeTooLong})
	}
	var newFolder *store.FolderRow
	if set.FolderID != nil {
		f, err := w.folder(*set.FolderID)
		if err != nil {
			return err
		}
		newFolder = f
	}
	type edit struct {
		row store.RuleRow
		out string
	}
	var work []edit
	// Each folder is read once for the whole call: a folder read counts its rules, and a group edit of a thousand
	// rules in one folder read it a thousand times under the profile's row lock.
	cache := map[uuid.UUID]*store.FolderRow{}
	if newFolder != nil {
		cache[newFolder.ID] = newFolder
	}
	getFolder := func(id uuid.UUID) (*store.FolderRow, error) {
		if f, ok := cache[id]; ok {
			return f, nil
		}
		f, err := w.folder(id)
		if err != nil {
			return nil, err
		}
		cache[id] = f
		return f, nil
	}
	iran := &iranSet{w: w, rows: rows}
	for _, r := range rows {
		nr := r
		f := fmt.Sprintf("/ids/%d", index[r.ID])
		folderID := r.FolderID
		switch {
		case has(in.Clear, "folder"):
			folderID = uuid.Nil
		case set.FolderID != nil:
			folderID = *set.FolderID
		}
		nr.FolderID = folderID
		actSet := set.Act != nil && (set.Act.Action != r.Action || (set.Act.Action == "redirect" && !sameTarget(set.Act.Target, r.Target)))
		inheritMoved := folderID != r.FolderID && r.Action == "inherit" && !actSet
		if actSet {
			nr.Action = set.Act.Action
		}
		if actSet || inheritMoved {
			// The folder the rule will sit in: only an edit that sets an action or moves an inheriting rule needs it.
			folder, err := getFolder(folderID)
			if err != nil {
				return err
			}
			act := Act{Action: nr.Action}
			if actSet {
				act = *set.Act
			}
			res, afs, err := w.actFields(f, act, folder, false)
			if err != nil {
				return err
			}
			if afs != nil {
				fs = append(fs, afs...)
				continue
			}
			nr.Target, nr.LocationUnavailable = res.t, res.flagged
			if act.Action != "redirect" {
				nr.Target = store.Target{}
			}
			if effRedirect(nr.Action, folder) {
				ir, err := iran.has(r.Key)
				if err != nil {
					return err
				}
				if ir {
					fs = append(fs, Field{f, CodeIranianName})
					continue
				}
			}
		}
		switch {
		case has(in.Clear, "comment"):
			nr.Comment = ""
		case set.Comment != nil:
			nr.Comment = *set.Comment
		}
		switch {
		case has(in.Clear, "expires"):
			nr.ExpiresAt = nil
		case exp != nil:
			nr.ExpiresAt = exp.t
		}
		out := "updated"
		if nr.FolderID == r.FolderID && nr.Action == r.Action && nr.Comment == r.Comment && sameTime(nr.ExpiresAt, r.ExpiresAt) &&
			nr.Target == r.Target && nr.LocationUnavailable == r.LocationUnavailable {
			out = "skipped"
		}
		work = append(work, edit{nr, out})
	}
	if len(fs) > 0 {
		return invalid(fs...)
	}
	for _, x := range work {
		if x.out == "updated" {
			won, err := w.tx.RuleUpdate(w.pw, x.row)
			if err != nil {
				return err
			}
			if !won.Yes() {
				return invalid(Field{"max_wildcards_per_profile", CodeExceeded})
			}
		}
		res.add(index[x.row.ID], x.out, x.row.ID)
	}
	return nil
}

// transfer copies or moves rules to a folder of this profile or of another one. The destination's lock, quotas and
// location set are checked again for what arrives (T-193); a rule that would be Iranian under a Redirect there is
// refused with iranian_name, including a grandfathered one carried out of its profile (3.6).
func transfer(w, d *wtx, rows []store.RuleRow, in BatchIn, cross bool, index map[uuid.UUID]int, res *BatchResult) error {
	// The destination folder: exactly one of an existing folder, the top level, or a new one.
	n := 0
	if in.DestFolder != uuid.Nil {
		n++
	}
	if in.DestRoot {
		n++
	}
	if in.NewFolder != nil {
		n++
	}
	if n != 1 {
		return invalid(Field{"/dest_folder_id", CodeRequired})
	}
	var dest *store.FolderRow
	switch {
	case in.DestFolder != uuid.Nil:
		f, err := d.folder(in.DestFolder)
		if err != nil {
			return err
		}
		dest = f
	case in.NewFolder != nil:
		row, fs, err := d.checkFolder(*in.NewFolder, false)
		if err != nil {
			return err
		}
		if len(fs) > 0 {
			return invalid(fs...)
		}
		id, err := d.insertFolder(row)
		if err != nil {
			return err
		}
		f, _, err := d.tx.Folder(d.pw.ID(), id)
		if err != nil {
			return err
		}
		dest = &f
	}
	destID := uuid.Nil
	if dest != nil {
		destID = dest.ID
	}

	var fs []Field
	var keys []string
	for _, r := range rows {
		keys = append(keys, r.Key)
	}
	have := map[string]store.RuleKeyRow{}
	if cross {
		exist, err := d.tx.RulesByKeys(d.pw.ID(), keys)
		if err != nil {
			return err
		}
		for _, x := range exist {
			have[x.Key] = x
		}
	}
	iran := &iranSet{w: d, rows: rows}
	var batch ruleBatch
	var moved []uuid.UUID
	var created []int
	for _, r := range rows {
		i := index[r.ID]
		f := fmt.Sprintf("/ids/%d", i)
		if cross {
			if _, clash := have[r.Key]; clash {
				res.add(i, "conflict", r.ID)
				continue
			}
		} else if r.FolderID == destID {
			res.add(i, "skipped", r.ID)
			continue
		}
		// What the rule becomes in the destination: its own action, or the destination folder's for inherit.
		nr := store.NewRule{FolderID: destID, Key: r.Key, MatchKind: r.MatchKind, Negated: r.Negated, Action: r.Action, Target: r.Target,
			Enabled: r.Enabled, ExpiresAt: r.ExpiresAt, Comment: r.Comment}
		if r.Action == "inherit" {
			if ifs := inheritFields(f, dest); ifs != nil {
				fs = append(fs, ifs...)
				continue
			}
		}
		if cross && r.Action == "redirect" {
			// The location a rule carries must be one the destination can use; a fixed IP or host carries as is.
			res2, tfs, err := d.target(f, Act{Action: "redirect", Target: storedTarget(r.Target)}, false, d.allowed)
			if err != nil {
				return err
			}
			if tfs != nil {
				fs = append(fs, tfs...)
				continue
			}
			nr.Target = res2.t
		}
		if effRedirect(r.Action, dest) && (cross || r.Action == "inherit") {
			ir, err := iran.has(r.Key)
			if err != nil {
				return err
			}
			if ir {
				fs = append(fs, Field{f, CodeIranianName})
				continue
			}
		}
		if cross {
			batch.rows = append(batch.rows, nr)
			if r.MatchKind == "subdomains" || r.MatchKind == "glob" {
				batch.wild++
			}
			created = append(created, i)
			moved = append(moved, r.ID)
			continue
		}
		// Within the profile a move is an edit of the folder.
		upd := r
		upd.FolderID = destID
		won, err := w.tx.RuleUpdate(w.pw, upd)
		if err != nil {
			return err
		}
		if !won.Yes() {
			return invalid(Field{"max_wildcards_per_profile", CodeExceeded})
		}
		res.add(i, "updated", r.ID)
	}
	if len(fs) > 0 {
		return invalid(fs...)
	}
	if cross && len(batch.rows) > 0 {
		ids, err := d.insertRules(batch)
		if err != nil {
			if k := (*Error)(nil); errors.As(err, &k) && k.Kind == KindValidation {
				return k
			}
			return err
		}
		_ = ids // the outcome items name the source index; the new ids are not part of the answer
		for _, i := range created {
			res.add(i, "created", uuid.Nil)
		}
		if in.Op == "move" {
			if _, err := w.tx.RulesDelete(w.pw, moved); err != nil {
				return err
			}
		}
	}
	return nil
}

// timePtr and sameTime keep the edit's expiry compare short.
type timePtr struct{ t *time.Time }

func sameTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

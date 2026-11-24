package store

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/caps"
)

// The content of a profile: rules, folders, services, filters and options (spec 3.1, 3.4, 4).
//
// Every method takes the ProfileWrite of the profile it writes and bounds each statement by its
// id, so an id of a rule, folder or filter of another profile (or another tenant) matches no row
// and the caller answers 404. Addresses travel as text: the profiles package has parsed them, the
// database casts them, and no netip value crosses this package (the network-cut rule).

// Target is where a Redirect goes, in the columns of the action-and-target set of PS 1. The zero
// Kind is "no target" (Block, Bypass, inherit).
type Target struct {
	Kind       string // "", location, auto, random, ip, host
	LocationID uuid.UUID
	IPv4, IPv6 string
	Host       string
}

// nullIf is the empty string as NULL.
func nullIf(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nullUUID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

// ---------------------------------------------------------------------------
// Rules.

// RuleRow is a rule as stored.
type RuleRow struct {
	ID                  uuid.UUID
	FolderID            uuid.UUID // Nil at the top level
	Key                 string
	MatchKind           string
	Negated             bool
	Action              string
	Target              Target
	Enabled             bool
	ExpiresAt           *time.Time
	Comment             string
	LocationUnavailable bool
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// ruleColumns reads the target addresses as text (host() drops the mask the inet type carries).
const ruleColumns = `id, folder_id, rule_key, match_kind, negated, action, target_kind, target_location_id,
  host(target_ipv4), host(target_ipv6), target_host, enabled, expires_at, comment, location_unavailable, created_at, updated_at`

func scanRule(r interface{ Scan(...any) error }) (RuleRow, error) {
	var x RuleRow
	var folder, loc *uuid.UUID
	var kind, v4, v6, host, comment *string
	err := r.Scan(&x.ID, &folder, &x.Key, &x.MatchKind, &x.Negated, &x.Action, &kind, &loc, &v4, &v6, &host, &x.Enabled,
		&x.ExpiresAt, &comment, &x.LocationUnavailable, &x.CreatedAt, &x.UpdatedAt)
	if err != nil {
		return x, err
	}
	if folder != nil {
		x.FolderID = *folder
	}
	x.Target = scanTarget(kind, loc, v4, v6, host)
	if comment != nil {
		x.Comment = *comment
	}
	return x, nil
}

func scanTarget(kind *string, loc *uuid.UUID, v4, v6, host *string) Target {
	var t Target
	if kind != nil {
		t.Kind = *kind
	}
	if loc != nil {
		t.LocationID = *loc
	}
	if v4 != nil {
		t.IPv4 = *v4
	}
	if v6 != nil {
		t.IPv6 = *v6
	}
	if host != nil {
		t.Host = *host
	}
	return t
}

// NewRule is a rule to insert.
type NewRule struct {
	FolderID            uuid.UUID
	Key                 string
	MatchKind           string
	Negated             bool
	Action              string
	Target              Target
	Enabled             bool
	ExpiresAt           *time.Time
	Comment             string
	LocationUnavailable bool
}

// ruleItem is NewRule as one item of the recordset the INSERT reads.
type ruleItem struct {
	FolderID            *uuid.UUID `json:"folder_id"`
	Key                 string     `json:"key"`
	MatchKind           string     `json:"match_kind"`
	Negated             bool       `json:"negated"`
	Action              string     `json:"action"`
	TargetKind          *string    `json:"target_kind"`
	TargetLocationID    *uuid.UUID `json:"target_location_id"`
	TargetIPv4          *string    `json:"target_ipv4"`
	TargetIPv6          *string    `json:"target_ipv6"`
	TargetHost          *string    `json:"target_host"`
	Enabled             bool       `json:"enabled"`
	ExpiresAt           *time.Time `json:"expires_at"`
	Comment             *string    `json:"comment"`
	LocationUnavailable bool       `json:"location_unavailable"`
}

func items(rs []NewRule) ([]byte, int) {
	out := make([]ruleItem, len(rs))
	wild := 0
	for i, r := range rs {
		out[i] = ruleItem{FolderID: nullUUID(r.FolderID), Key: r.Key, MatchKind: r.MatchKind, Negated: r.Negated, Action: r.Action,
			TargetKind: nullIf(r.Target.Kind), TargetLocationID: nullUUID(r.Target.LocationID), TargetIPv4: nullIf(r.Target.IPv4),
			TargetIPv6: nullIf(r.Target.IPv6), TargetHost: nullIf(r.Target.Host), Enabled: r.Enabled, ExpiresAt: r.ExpiresAt,
			Comment: nullIf(r.Comment), LocationUnavailable: r.LocationUnavailable}
		if r.MatchKind == "subdomains" || r.MatchKind == "glob" {
			wild++
		}
	}
	b, _ := json.Marshal(out) // a slice of plain structs cannot fail to marshal
	return b, wild
}

// qRulesInsert adds all the rules or none: the WHERE does not depend on the row, so the two
// per-profile caps (rules, and the wildcards among them) either let the whole batch in or stop it.
// "After the write" is count + n, so the compare is count + n - 1 against ctrlz.cap_reached's
// "spent >= cap". ORDER BY puts the rows in key order, so two batches that meet on a key wait for
// each other in one order.
const qRulesInsert = `INSERT INTO ctrlz.rules (tenant_id, profile_id, folder_id, rule_key, match_kind, negated, action, target_kind,
  target_location_id, target_ipv4, target_ipv6, target_host, enabled, expires_at, comment, location_unavailable)
SELECT $1::uuid, $2::uuid, x.folder_id, x.key, x.match_kind, x.negated, x.action, x.target_kind, x.target_location_id,
  x.target_ipv4::inet, x.target_ipv6::inet, x.target_host, x.enabled, x.expires_at, x.comment, x.location_unavailable
FROM jsonb_to_recordset($3::jsonb) AS x(folder_id uuid, key text, match_kind text, negated boolean, action text, target_kind text,
  target_location_id uuid, target_ipv4 text, target_ipv6 text, target_host text, enabled boolean, expires_at timestamptz,
  comment text, location_unavailable boolean)
WHERE NOT ctrlz.cap_reached((SELECT count(*) FROM ctrlz.rules r WHERE r.tenant_id = $1 AND r.profile_id = $2) + $4::int - 1,
    (SELECT COALESCE(te.max_rules_per_profile, d.max_rules_per_profile) FROM ctrlz.entitlement_defaults d LEFT JOIN ctrlz.tenant_entitlements te ON te.tenant_id = $1))
  AND ($5::int = 0 OR NOT ctrlz.cap_reached((SELECT count(*) FROM ctrlz.rules r WHERE r.tenant_id = $1 AND r.profile_id = $2
    AND r.match_kind IN ('subdomains', 'glob')) + $5::int - 1,
    (SELECT COALESCE(te.max_wildcards_per_profile, d.max_wildcards_per_profile) FROM ctrlz.entitlement_defaults d LEFT JOIN ctrlz.tenant_entitlements te ON te.tenant_id = $1)))
ORDER BY x.key
RETURNING id`

// RulesInsert adds rules to the profile. A loss is one of the per-profile caps, and RulesCapReached
// says which; nothing was written. A key that already exists in the profile is ErrConflict, which
// a caller that read the existing keys under the guard never meets.
func (t Tx) RulesInsert(w ProfileWrite, rs []NewRule) ([]uuid.UUID, Won, error) {
	if err := t.check(w); err != nil {
		return nil, Won{}, err
	}
	if len(rs) == 0 {
		return nil, won(true), nil
	}
	body, wild := items(rs)
	rows, err := t.tx.Query(t.ctx, qRulesInsert, t.tenant, w.id, body, int32(len(rs)), int32(wild))
	if err != nil {
		return nil, Won{}, sanitize(err)
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, Won{}, sanitize(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, Won{}, sanitize(err)
	}
	return ids, won(len(ids) == len(rs)), nil
}

// qRulesCapReached says which per-profile cap a batch of n rules with nw wildcards would pass. It is
// the explanation of a lost RulesInsert, asked in the same transaction under the same guard, and it
// uses the same comparison.
const qRulesCapReached = `SELECT ctrlz.cap_reached((SELECT count(*) FROM ctrlz.rules r WHERE r.tenant_id = $1 AND r.profile_id = $2) + $3::int - 1,
    (SELECT COALESCE(te.max_rules_per_profile, d.max_rules_per_profile) FROM ctrlz.entitlement_defaults d LEFT JOIN ctrlz.tenant_entitlements te ON te.tenant_id = $1)),
  $4::int > 0 AND ctrlz.cap_reached((SELECT count(*) FROM ctrlz.rules r WHERE r.tenant_id = $1 AND r.profile_id = $2
    AND r.match_kind IN ('subdomains', 'glob')) + $4::int - 1,
    (SELECT COALESCE(te.max_wildcards_per_profile, d.max_wildcards_per_profile) FROM ctrlz.entitlement_defaults d LEFT JOIN ctrlz.tenant_entitlements te ON te.tenant_id = $1))`

// RulesCapReached names the cap a batch of n rules, nw of them wildcards, would pass.
func (t Tx) RulesCapReached(w ProfileWrite, n, nw int) (rules, wildcards bool, err error) {
	if err := t.check(w); err != nil {
		return false, false, err
	}
	err = t.tx.QueryRow(t.ctx, qRulesCapReached, t.tenant, w.id, int32(n), int32(nw)).Scan(&rules, &wildcards)
	return rules, wildcards, sanitize(err)
}

// RuleCountsOf is how many rules and wildcards a profile holds.
const qRuleKeys = `SELECT id, rule_key, folder_id FROM ctrlz.rules WHERE tenant_id = $1 AND profile_id = $2 AND rule_key = ANY ($3::text[])`

// RuleKeyRow is the key, folder and id of an existing rule.
type RuleKeyRow struct {
	ID       uuid.UUID
	Key      string
	FolderID uuid.UUID
}

// RulesByKeys reads the rules of the profile that have one of the keys: what Create, Upload and the
// transfers need to tell a new key from an existing one. Called under the guard, the answer cannot
// change before the write.
func (t Tx) RulesByKeys(profile uuid.UUID, keys []string) ([]RuleKeyRow, error) {
	rows, err := t.tx.Query(t.ctx, qRuleKeys, t.tenant, profile, keys)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []RuleKeyRow
	for rows.Next() {
		var r RuleKeyRow
		var f *uuid.UUID
		if err := rows.Scan(&r.ID, &r.Key, &f); err != nil {
			return nil, sanitize(err)
		}
		if f != nil {
			r.FolderID = *f
		}
		out = append(out, r)
	}
	return out, sanitize(rows.Err())
}

const qRulesGet = `SELECT ` + ruleColumns + ` FROM ctrlz.rules WHERE tenant_id = $1 AND profile_id = $2 AND id = ANY ($3::uuid[]) ORDER BY id`

// RulesGet reads the rules of the profile with these ids. An id of another profile is simply not in the
// answer, so a caller that expected n rows and got fewer answers 404.
func (t Tx) RulesGet(profile uuid.UUID, ids []uuid.UUID) ([]RuleRow, error) {
	rows, err := t.tx.Query(t.ctx, qRulesGet, t.tenant, profile, ids)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []RuleRow
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, sanitize(err)
		}
		out = append(out, r)
	}
	return out, sanitize(rows.Err())
}

const qRulesAll = `SELECT ` + ruleColumns + ` FROM ctrlz.rules WHERE tenant_id = $1 AND profile_id = $2 ORDER BY rule_key, id`

// RulesAll reads every rule of the profile in key order: Export and Duplicate read through it.
func (t Tx) RulesAll(profile uuid.UUID) ([]RuleRow, error) {
	rows, err := t.tx.Query(t.ctx, qRulesAll, t.tenant, profile)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []RuleRow
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, sanitize(err)
		}
		out = append(out, r)
	}
	return out, sanitize(rows.Err())
}

// RuleSelector is the filter of a selection ("select all" of the rules list).
type RuleSelector struct {
	Folder    string // "" any, "root", or "folder"
	FolderID  uuid.UUID
	Q         string // already lowered and converted by the caller
	Status    string // "", enabled, disabled, expired
	Action    string
	Now       time.Time
	MaxResult int // returns at most MaxResult+1 ids, so the caller can tell it passed the bound
}

const qRuleIDsMatching = `SELECT id FROM ctrlz.rules WHERE tenant_id = $1 AND profile_id = $2
  AND ($3::text = '' OR ($3::text = 'root' AND folder_id IS NULL) OR ($3::text = 'folder' AND folder_id = $4::uuid))
  AND ($5::text = '' OR strpos(rule_key, $5::text) > 0)
  AND ($6::text = '' OR ($6::text = 'enabled' AND enabled AND (expires_at IS NULL OR expires_at > $8::timestamptz))
       OR ($6::text = 'disabled' AND NOT enabled) OR ($6::text = 'expired' AND expires_at IS NOT NULL AND expires_at <= $8::timestamptz))
  AND ($7::text = '' OR action = $7::text)
ORDER BY id LIMIT $9::int`

// RuleIDsMatching returns the ids of the rules a selector matches, in id order, at most MaxResult+1.
func (t Tx) RuleIDsMatching(profile uuid.UUID, s RuleSelector) ([]uuid.UUID, error) {
	var folder any = nil
	if s.FolderID != uuid.Nil {
		folder = s.FolderID
	}
	rows, err := t.tx.Query(t.ctx, qRuleIDsMatching, t.tenant, profile, s.Folder, folder, s.Q, s.Status, s.Action, s.Now, int32(s.MaxResult+1))
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, id)
	}
	return out, sanitize(rows.Err())
}

// qRuleUpdate replaces every editable column of one rule. A pattern that becomes a wildcard is a
// new wildcard of the profile, so the per-profile cap is in the WHERE (a rule that was one already
// adds none). The key is unique per profile: a key that exists is ErrConflict.
const qRuleUpdate = `UPDATE ctrlz.rules r SET folder_id = $4, rule_key = $5, match_kind = $6, negated = $7, action = $8, target_kind = $9,
  target_location_id = $10, target_ipv4 = $11::text::inet, target_ipv6 = $12::text::inet, target_host = $13, enabled = $14,
  expires_at = $15, comment = $16, location_unavailable = $17
WHERE r.tenant_id = $1 AND r.profile_id = $2 AND r.id = $3
  AND (NOT ($6::text IN ('subdomains', 'glob') AND r.match_kind NOT IN ('subdomains', 'glob'))
       OR NOT ctrlz.cap_reached((SELECT count(*) FROM ctrlz.rules w WHERE w.tenant_id = $1 AND w.profile_id = $2 AND w.match_kind IN ('subdomains', 'glob')),
         (SELECT COALESCE(te.max_wildcards_per_profile, d.max_wildcards_per_profile) FROM ctrlz.entitlement_defaults d LEFT JOIN ctrlz.tenant_entitlements te ON te.tenant_id = $1)))
RETURNING r.id`

// RuleUpdate rewrites one rule of the profile. A loss is either no such rule (the caller read it
// under the guard, so that is a defect) or the wildcard cap, which RulesCapReached(w, 0, 1) names.
func (t Tx) RuleUpdate(w ProfileWrite, r RuleRow) (Won, error) {
	if err := t.check(w); err != nil {
		return Won{}, err
	}
	var id uuid.UUID
	return wonOf(t.tx.QueryRow(t.ctx, qRuleUpdate, t.tenant, w.id, r.ID, nullUUID(r.FolderID), r.Key, r.MatchKind, r.Negated, r.Action,
		nullIf(r.Target.Kind), nullUUID(r.Target.LocationID), nullIf(r.Target.IPv4), nullIf(r.Target.IPv6), nullIf(r.Target.Host),
		r.Enabled, r.ExpiresAt, nullIf(r.Comment), r.LocationUnavailable).Scan(&id))
}

const qRulesSetEnabled = `UPDATE ctrlz.rules SET enabled = $4 WHERE tenant_id = $1 AND profile_id = $2 AND id = ANY (ARRAY(SELECT id FROM ctrlz.rules
  WHERE tenant_id = $1 AND profile_id = $2 AND id = ANY ($3::uuid[])` + keyOrder + ` LIMIT $5::int` + lockNoKeyUpdate + `))`

// RulesSetEnabled switches rules of the profile on or off and reports how many it changed.
func (t Tx) RulesSetEnabled(w ProfileWrite, ids []uuid.UUID, enabled bool) (int, error) {
	if err := t.check(w); err != nil {
		return 0, err
	}
	tag, err := t.tx.Exec(t.ctx, qRulesSetEnabled, t.tenant, w.id, ids, enabled, int32(len(ids)))
	return int(tag.RowsAffected()), sanitize(err)
}

const qRulesDelete = `DELETE FROM ctrlz.rules WHERE tenant_id = $1 AND profile_id = $2 AND id = ANY (ARRAY(SELECT id FROM ctrlz.rules
  WHERE tenant_id = $1 AND profile_id = $2 AND id = ANY ($3::uuid[])` + keyOrder + ` LIMIT $4::int` + lockUpdate + `))`

// RulesDelete removes rules of the profile and reports how many it removed.
func (t Tx) RulesDelete(w ProfileWrite, ids []uuid.UUID) (int, error) {
	if err := t.check(w); err != nil {
		return 0, err
	}
	tag, err := t.tx.Exec(t.ctx, qRulesDelete, t.tenant, w.id, ids, int32(len(ids)))
	return int(tag.RowsAffected()), sanitize(err)
}

// ---------------------------------------------------------------------------
// Folders.

// FolderRow is a rule folder.
type FolderRow struct {
	ID                  uuid.UUID
	Name                string
	Kind                string
	Action              string // "" is no Folder Rule
	Target              Target
	LocationUnavailable bool
	RuleCount           int
}

const folderColumns = `f.id, f.name, f.kind, f.action, f.target_kind, f.target_location_id, host(f.target_ipv4), host(f.target_ipv6), f.target_host,
  f.location_unavailable, (SELECT count(*) FROM ctrlz.rules r WHERE r.tenant_id = f.tenant_id AND r.folder_id = f.id)`

func scanFolder(r interface{ Scan(...any) error }) (FolderRow, error) {
	var f FolderRow
	var action, kind, v4, v6, host *string
	var loc *uuid.UUID
	err := r.Scan(&f.ID, &f.Name, &f.Kind, &action, &kind, &loc, &v4, &v6, &host, &f.LocationUnavailable, &f.RuleCount)
	if err != nil {
		return f, err
	}
	if action != nil {
		f.Action = *action
	}
	f.Target = scanTarget(kind, loc, v4, v6, host)
	return f, nil
}

const qFoldersList = `SELECT ` + folderColumns + ` FROM ctrlz.rule_folders f WHERE f.tenant_id = $1 AND f.profile_id = $2 ORDER BY f.name, f.id`

// Folders lists the folders of the profile, by name then id.
func (t Tx) Folders(profile uuid.UUID) ([]FolderRow, error) {
	rows, err := t.tx.Query(t.ctx, qFoldersList, t.tenant, profile)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []FolderRow
	for rows.Next() {
		f, err := scanFolder(rows)
		if err != nil {
			return nil, sanitize(err)
		}
		out = append(out, f)
	}
	return out, sanitize(rows.Err())
}

const qFolderGet = `SELECT ` + folderColumns + ` FROM ctrlz.rule_folders f WHERE f.tenant_id = $1 AND f.profile_id = $2 AND f.id = $3`

// Folder reads one folder of the profile; an id of another profile is not found.
func (t Tx) Folder(profile, id uuid.UUID) (FolderRow, bool, error) {
	f, err := scanFolder(t.tx.QueryRow(t.ctx, qFolderGet, t.tenant, profile, id))
	ok, err := notFound(err)
	return f, ok, err
}

// qFolderInsert adds a folder unless the profile holds caps.MaxFoldersPerProfile of them. The count
// is taken under the guard's row lock, which serialises every writer of the profile.
const qFolderInsert = `INSERT INTO ctrlz.rule_folders (tenant_id, profile_id, name, kind, action, target_kind, target_location_id, target_ipv4,
  target_ipv6, target_host, location_unavailable)
SELECT $1::uuid, $2::uuid, $3::text, $4::text, $5::text, $6::text, $7::uuid, $8::text::inet, $9::text::inet, $10::text, $11::boolean
WHERE NOT ctrlz.cap_reached((SELECT count(*) FROM ctrlz.rule_folders f WHERE f.tenant_id = $1 AND f.profile_id = $2), $12::int)
RETURNING id`

// FolderInsert adds a folder. A loss is the folder cap.
func (t Tx) FolderInsert(w ProfileWrite, f FolderRow) (uuid.UUID, Won, error) {
	if err := t.check(w); err != nil {
		return uuid.Nil, Won{}, err
	}
	var id uuid.UUID
	wn, err := wonRow(t.tx.QueryRow(t.ctx, qFolderInsert, t.tenant, w.id, f.Name, f.Kind, nullIf(f.Action), nullIf(f.Target.Kind),
		nullUUID(f.Target.LocationID), nullIf(f.Target.IPv4), nullIf(f.Target.IPv6), nullIf(f.Target.Host), f.LocationUnavailable,
		int32(caps.MaxFoldersPerProfile)).Scan(&id))
	if err != nil || !wn.Yes() {
		return uuid.Nil, Won{}, err
	}
	return id, wn, nil
}

const qFolderUpdate = `UPDATE ctrlz.rule_folders SET name = $4, action = $5, target_kind = $6, target_location_id = $7, target_ipv4 = $8::text::inet,
  target_ipv6 = $9::text::inet, target_host = $10, location_unavailable = $11
WHERE tenant_id = $1 AND profile_id = $2 AND id = $3`

// FolderUpdate rewrites the editable columns of a folder of the profile and reports whether it was there.
func (t Tx) FolderUpdate(w ProfileWrite, f FolderRow) (bool, error) {
	if err := t.check(w); err != nil {
		return false, err
	}
	tag, err := t.tx.Exec(t.ctx, qFolderUpdate, t.tenant, w.id, f.ID, f.Name, nullIf(f.Action), nullIf(f.Target.Kind), nullUUID(f.Target.LocationID),
		nullIf(f.Target.IPv4), nullIf(f.Target.IPv6), nullIf(f.Target.Host), f.LocationUnavailable)
	return tag.RowsAffected() == 1, sanitize(err)
}

const qFolderDelete = `DELETE FROM ctrlz.rule_folders WHERE tenant_id = $1 AND profile_id = $2 AND id = $3`

// FolderDelete removes a folder and, by the foreign key, its rules (the confirm dialog says so).
func (t Tx) FolderDelete(w ProfileWrite, id uuid.UUID) (bool, error) {
	if err := t.check(w); err != nil {
		return false, err
	}
	tag, err := t.tx.Exec(t.ctx, qFolderDelete, t.tenant, w.id, id)
	return tag.RowsAffected() == 1, sanitize(err)
}

const qFolderInheriting = `SELECT count(*) FROM ctrlz.rules WHERE tenant_id = $1 AND profile_id = $2 AND folder_id = $3 AND action = 'inherit'`

// FolderInheriting is how many rules of the folder inherit its Folder Rule.
func (t Tx) FolderInheriting(profile, folder uuid.UUID) (int, error) {
	var n int
	err := t.tx.QueryRow(t.ctx, qFolderInheriting, t.tenant, profile, folder).Scan(&n)
	return n, sanitize(err)
}

// qFolderInheritingKeys is one page of the keys of a folder's inheriting rules in key order. The unique index
// (tenant_id, profile_id, rule_key) gives the order, and the filter on the folder is applied to its rows, so no
// page costs memory beyond its own keys however large the profile is.
const qFolderInheritingKeys = `SELECT rule_key FROM ctrlz.rules WHERE tenant_id = $1 AND profile_id = $2 AND folder_id = $3
  AND action = 'inherit' AND rule_key > $4 ORDER BY rule_key LIMIT $5`

// FolderInheritingKeys returns at most limit keys of the rules that inherit the folder's action, in key order,
// starting after the key `after` ("" for the first page). The D42 check of a Folder Rule walks them page by page
// instead of reading the profile: an ordinary route must never hold more than a page of rules (6.5 (d)).
func (t Tx) FolderInheritingKeys(profile, folder uuid.UUID, after string, limit int) ([]string, error) {
	rows, err := t.tx.Query(t.ctx, qFolderInheritingKeys, t.tenant, profile, folder, after, int32(limit))
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, k)
	}
	return out, sanitize(rows.Err())
}

// ---------------------------------------------------------------------------
// Services.

// ServiceRow is a service state of a profile.
type ServiceRow struct {
	Slug                string
	Enabled             bool
	Action              string
	Target              Target
	LocationUnavailable bool
}

const qServicesList = `SELECT service_slug, enabled, action, target_kind, target_location_id, host(target_ipv4), host(target_ipv6), target_host, location_unavailable
FROM ctrlz.profile_services WHERE tenant_id = $1 AND profile_id = $2 ORDER BY service_slug`

// Services lists the service states of the profile, by slug.
func (t Tx) Services(profile uuid.UUID) ([]ServiceRow, error) {
	rows, err := t.tx.Query(t.ctx, qServicesList, t.tenant, profile)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []ServiceRow
	for rows.Next() {
		var s ServiceRow
		var kind, v4, v6, host *string
		var loc *uuid.UUID
		if err := rows.Scan(&s.Slug, &s.Enabled, &s.Action, &kind, &loc, &v4, &v6, &host, &s.LocationUnavailable); err != nil {
			return nil, sanitize(err)
		}
		s.Target = scanTarget(kind, loc, v4, v6, host)
		out = append(out, s)
	}
	return out, sanitize(rows.Err())
}

const qServiceUpsert = `INSERT INTO ctrlz.profile_services (tenant_id, profile_id, service_slug, enabled, action, target_kind, target_location_id,
  target_ipv4, target_ipv6, target_host, location_unavailable)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::text::inet, $9::text::inet, $10, $11)
ON CONFLICT (tenant_id, profile_id, service_slug) DO UPDATE SET enabled = EXCLUDED.enabled, action = EXCLUDED.action,
  target_kind = EXCLUDED.target_kind, target_location_id = EXCLUDED.target_location_id, target_ipv4 = EXCLUDED.target_ipv4,
  target_ipv6 = EXCLUDED.target_ipv6, target_host = EXCLUDED.target_host, location_unavailable = EXCLUDED.location_unavailable`

// ServiceUpsert sets the state of one service of the profile. An unknown slug is ErrConstraint (the
// foreign key to the catalog).
func (t Tx) ServiceUpsert(w ProfileWrite, s ServiceRow) error {
	if err := t.check(w); err != nil {
		return err
	}
	_, err := t.tx.Exec(t.ctx, qServiceUpsert, t.tenant, w.id, s.Slug, s.Enabled, s.Action, nullIf(s.Target.Kind), nullUUID(s.Target.LocationID),
		nullIf(s.Target.IPv4), nullIf(s.Target.IPv6), nullIf(s.Target.Host), s.LocationUnavailable)
	return sanitize(err)
}

const qServiceDelete = `DELETE FROM ctrlz.profile_services WHERE tenant_id = $1 AND profile_id = $2 AND service_slug = $3`

// ServiceDelete removes the service from the profile (it is then neither Bypass nor anything).
func (t Tx) ServiceDelete(w ProfileWrite, slug string) (bool, error) {
	if err := t.check(w); err != nil {
		return false, err
	}
	tag, err := t.tx.Exec(t.ctx, qServiceDelete, t.tenant, w.id, slug)
	return tag.RowsAffected() == 1, sanitize(err)
}

// ---------------------------------------------------------------------------
// Filters.

// FilterRow is the state of a filter in a profile. Mode is "" for a filter with one mode.
type FilterRow struct {
	FilterID string
	Enabled  bool
	Mode     string
}

const qFiltersList = `SELECT filter_id, enabled, mode FROM ctrlz.profile_filters WHERE tenant_id = $1 AND profile_id = $2 ORDER BY filter_id`

// Filters lists the filter states of the profile.
func (t Tx) Filters(profile uuid.UUID) ([]FilterRow, error) {
	rows, err := t.tx.Query(t.ctx, qFiltersList, t.tenant, profile)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []FilterRow
	for rows.Next() {
		var f FilterRow
		var mode *string
		if err := rows.Scan(&f.FilterID, &f.Enabled, &mode); err != nil {
			return nil, sanitize(err)
		}
		if mode != nil {
			f.Mode = *mode
		}
		out = append(out, f)
	}
	return out, sanitize(rows.Err())
}

const qFilterUpsert = `INSERT INTO ctrlz.profile_filters (tenant_id, profile_id, filter_id, mode, enabled) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (tenant_id, profile_id, filter_id) DO UPDATE SET mode = EXCLUDED.mode, enabled = EXCLUDED.enabled`

// FilterUpsert sets a filter of the profile. A filter or mode the catalog does not have is ErrConstraint.
func (t Tx) FilterUpsert(w ProfileWrite, f FilterRow) error {
	if err := t.check(w); err != nil {
		return err
	}
	_, err := t.tx.Exec(t.ctx, qFilterUpsert, t.tenant, w.id, f.FilterID, nullIf(f.Mode), f.Enabled)
	return sanitize(err)
}

// ---------------------------------------------------------------------------
// Options.

// OptionsRow is the profile_options row; every option is optional ("not set" is NULL, PS 4), and a
// string option is "" when it is not set.
type OptionsRow struct {
	DefaultAction              string
	DefaultTarget              Target
	DefaultLocationUnavailable bool
	BlockExfiltration          *bool
	RebindProtection           *bool
	DisableDNSSEC              *bool
	BlockTTL, RedirectTTL      *int32
	BypassTTL                  *int32
	BlockResponse              string
	BlockV4, BlockV6           string
	ECSMode                    string
	ECSV4, ECSV6               string
	DNS64                      *bool
	CNAMEFlattening            *bool
	SafeSearch                 *bool
	RestrictedYouTube          *bool
}

const qOptionsGet = `SELECT default_action, default_target_kind, default_target_location_id, host(default_target_ipv4), host(default_target_ipv6),
  default_target_host, default_location_unavailable, block_exfiltration, rebind_protection, disable_dnssec, block_ttl, redirect_ttl, bypass_ttl,
  block_response, host(block_custom_v4), host(block_custom_v6), ecs_mode, ecs_v4::text, ecs_v6::text, dns64, cname_flattening, safe_search, restricted_youtube
FROM ctrlz.profile_options WHERE tenant_id = $1 AND profile_id = $2`

// Options reads the options row of the profile; a profile with none has the zero value, found false.
func (t Tx) Options(profile uuid.UUID) (OptionsRow, bool, error) {
	var o OptionsRow
	var action, kind, v4, v6, host, resp, b4, b6, ecs, e4, e6 *string
	var loc *uuid.UUID
	err := t.tx.QueryRow(t.ctx, qOptionsGet, t.tenant, profile).Scan(&action, &kind, &loc, &v4, &v6, &host, &o.DefaultLocationUnavailable,
		&o.BlockExfiltration, &o.RebindProtection, &o.DisableDNSSEC, &o.BlockTTL, &o.RedirectTTL, &o.BypassTTL, &resp, &b4, &b6, &ecs, &e4, &e6,
		&o.DNS64, &o.CNAMEFlattening, &o.SafeSearch, &o.RestrictedYouTube)
	ok, err := notFound(err)
	if err != nil || !ok {
		return OptionsRow{}, ok, err
	}
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	o.DefaultAction = str(action)
	o.DefaultTarget = scanTarget(kind, loc, v4, v6, host)
	o.BlockResponse, o.BlockV4, o.BlockV6, o.ECSMode, o.ECSV4, o.ECSV6 = str(resp), str(b4), str(b6), str(ecs), str(e4), str(e6)
	return o, true, nil
}

const qOptionsSet = `INSERT INTO ctrlz.profile_options (tenant_id, profile_id, default_action, default_target_kind, default_target_location_id,
  default_target_ipv4, default_target_ipv6, default_target_host, default_location_unavailable, block_exfiltration, rebind_protection, disable_dnssec,
  block_ttl, redirect_ttl, bypass_ttl, block_response, block_custom_v4, block_custom_v6, ecs_mode, ecs_v4, ecs_v6, dns64, cname_flattening,
  safe_search, restricted_youtube)
VALUES ($1, $2, $3, $4, $5, $6::text::inet, $7::text::inet, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17::text::inet, $18::text::inet, $19,
  $20::text::cidr, $21::text::cidr, $22, $23, $24, $25)
ON CONFLICT (tenant_id, profile_id) DO UPDATE SET default_action = EXCLUDED.default_action, default_target_kind = EXCLUDED.default_target_kind,
  default_target_location_id = EXCLUDED.default_target_location_id, default_target_ipv4 = EXCLUDED.default_target_ipv4,
  default_target_ipv6 = EXCLUDED.default_target_ipv6, default_target_host = EXCLUDED.default_target_host,
  default_location_unavailable = EXCLUDED.default_location_unavailable, block_exfiltration = EXCLUDED.block_exfiltration,
  rebind_protection = EXCLUDED.rebind_protection, disable_dnssec = EXCLUDED.disable_dnssec, block_ttl = EXCLUDED.block_ttl,
  redirect_ttl = EXCLUDED.redirect_ttl, bypass_ttl = EXCLUDED.bypass_ttl, block_response = EXCLUDED.block_response,
  block_custom_v4 = EXCLUDED.block_custom_v4, block_custom_v6 = EXCLUDED.block_custom_v6, ecs_mode = EXCLUDED.ecs_mode,
  ecs_v4 = EXCLUDED.ecs_v4, ecs_v6 = EXCLUDED.ecs_v6, dns64 = EXCLUDED.dns64, cname_flattening = EXCLUDED.cname_flattening,
  safe_search = EXCLUDED.safe_search, restricted_youtube = EXCLUDED.restricted_youtube`

// OptionsSet writes the whole options row of the profile. The caller merges a patch into what Options
// read under the guard.
func (t Tx) OptionsSet(w ProfileWrite, o OptionsRow) error {
	if err := t.check(w); err != nil {
		return err
	}
	_, err := t.tx.Exec(t.ctx, qOptionsSet, t.tenant, w.id, nullIf(o.DefaultAction), nullIf(o.DefaultTarget.Kind), nullUUID(o.DefaultTarget.LocationID),
		nullIf(o.DefaultTarget.IPv4), nullIf(o.DefaultTarget.IPv6), nullIf(o.DefaultTarget.Host), o.DefaultLocationUnavailable,
		o.BlockExfiltration, o.RebindProtection, o.DisableDNSSEC, o.BlockTTL, o.RedirectTTL, o.BypassTTL, nullIf(o.BlockResponse),
		nullIf(o.BlockV4), nullIf(o.BlockV6), nullIf(o.ECSMode), nullIf(o.ECSV4), nullIf(o.ECSV6), o.DNS64, o.CNAMEFlattening, o.SafeSearch,
		o.RestrictedYouTube)
	return sanitize(err)
}

// ---------------------------------------------------------------------------
// Global catalog reads.

// CatalogService is what the write path needs of a catalog service.
type CatalogService struct {
	Slug            string
	RedirectAllowed bool
	AllowedRegions  []string // nil: no regional limit
	Deprecated      bool
}

const qCatalogServices = `SELECT slug, redirect_allowed, allowed_regions, state = 'deprecated' FROM ctrlz.catalog_service WHERE slug = ANY ($1::text[]) ORDER BY slug`

// CatalogServices reads the services with these slugs; a slug that is not in the answer is unknown.
func (t Tx) CatalogServices(slugs []string) ([]CatalogService, error) {
	rows, err := t.tx.Query(t.ctx, qCatalogServices, slugs)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []CatalogService
	for rows.Next() {
		var s CatalogService
		if err := rows.Scan(&s.Slug, &s.RedirectAllowed, &s.AllowedRegions, &s.Deprecated); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, s)
	}
	return out, sanitize(rows.Err())
}

// CatalogFilter is a filter and its modes, the default mode first (the lowest wire id, T-146).
type CatalogFilter struct {
	ID    string
	Modes []string
}

const qCatalogFilter = `SELECT f.id, COALESCE(array_agg(m.mode ORDER BY m.wire_id) FILTER (WHERE m.mode IS NOT NULL), '{}')
FROM ctrlz.catalog_filter f LEFT JOIN ctrlz.catalog_filter_mode m ON m.filter_id = f.id
WHERE f.id = ANY ($1::text[]) GROUP BY f.id ORDER BY f.id`

// CatalogFilters reads the filters with these ids and their modes in wire order.
func (t Tx) CatalogFilters(ids []string) ([]CatalogFilter, error) {
	rows, err := t.tx.Query(t.ctx, qCatalogFilter, ids)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []CatalogFilter
	for rows.Next() {
		var f CatalogFilter
		if err := rows.Scan(&f.ID, &f.Modes); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, f)
	}
	return out, sanitize(rows.Err())
}

// NoRedirectEntry is a row of catalog_no_redirect_domain.
type NoRedirectEntry struct {
	Pattern string
	Host    bool // scope host; false is scope domain
}

// qNoRedirect is the one lookup of the D42 list (spec 3.6, 10.2 S8): the caller names the canonical
// suffixes it wants and the rows come back only as the booleans the predicate needs; no route
// returns them.
const qNoRedirect = `SELECT pattern, scope = 'host' FROM ctrlz.catalog_no_redirect_domain WHERE pattern = ANY ($1::text[])`

// NoRedirectLookup returns the entries among the given canonical texts.
func (t Tx) NoRedirectLookup(candidates []string) ([]NoRedirectEntry, error) {
	rows, err := t.tx.Query(t.ctx, qNoRedirect, candidates)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []NoRedirectEntry
	for rows.Next() {
		var e NoRedirectEntry
		if err := rows.Scan(&e.Pattern, &e.Host); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, e)
	}
	return out, sanitize(rows.Err())
}

// wonOf is wonRow for a statement whose returned row the caller does not need.
func wonOf(err error) (Won, error) { return wonRow(err) }

const qCIDRHostBits = `SELECT x <> network(x) FROM (SELECT $1::text::inet AS x) s`

// CIDRHostBits says whether a subnet written as address/length has bits set to the right of its prefix
// (an ECS subnet must not, spec 3.7). The caller has checked the shape of the text, so the cast cannot
// fail; the database is asked because no address is taken apart in Go (the network-cut rule).
func (t Tx) CIDRHostBits(subnet string) (bool, error) {
	var dirty bool
	err := t.tx.QueryRow(t.ctx, qCIDRHostBits, subnet).Scan(&dirty)
	return dirty, sanitize(err)
}

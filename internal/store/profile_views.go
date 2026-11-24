package store

import (
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// The reads the P2 routes need beyond the write path (docs/specs/p2-profiles.md 8): counters, the catalog lists, the
// presets, one page of rules, and the lock and unlock statements (spec 7). None of them takes a ProfileWrite except the
// lock pair, which is the one place the five lock columns are written (S9).

// ---------------------------------------------------------------------------
// Counters of the profile list (T-127).

// ProfileCounts is the counter row of one profile (PS 9, tenant_profile_counts).
type ProfileCounts struct {
	Endpoints, Filters, Services, Rules, Options int
}

const qProfileCounts = `SELECT profile_id, endpoint_count, filter_count, service_count, rule_count, option_count
FROM ctrlz.tenant_profile_counts WHERE tenant_id = $1`

// qProfileCountsOne names the profile, which the view's correlated counts need to push down: without it a read of one profile
// counted the rules of all of them (20 profiles of 10,000 rules is 200,000 index tuples to show one, p2-B3-r13-2, r13-7).
const qProfileCountsOne = `SELECT profile_id, endpoint_count, filter_count, service_count, rule_count, option_count
FROM ctrlz.tenant_profile_counts WHERE tenant_id = $1 AND profile_id = $2`

func scanProfileCounts(rows pgx.Rows) (uuid.UUID, ProfileCounts, error) {
	var id uuid.UUID
	var e, f, s, r, o int64
	if err := rows.Scan(&id, &e, &f, &s, &r, &o); err != nil {
		return uuid.Nil, ProfileCounts{}, sanitize(err)
	}
	return id, ProfileCounts{Endpoints: int(e), Filters: int(f), Services: int(s), Rules: int(r), Options: int(o)}, nil
}

// ProfileCountsAll reads the counters of every profile of the tenant, by profile id: the list needs all of them.
func (t Tx) ProfileCountsAll() (map[uuid.UUID]ProfileCounts, error) {
	rows, err := t.tx.Query(t.ctx, qProfileCounts, t.tenant)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	out := map[uuid.UUID]ProfileCounts{}
	for rows.Next() {
		id, c, err := scanProfileCounts(rows)
		if err != nil {
			return nil, err
		}
		out[id] = c
	}
	return out, sanitize(rows.Err())
}

// ProfileCountsOf reads the counters of one profile; a profile that is not the tenant's has the zero value.
func (t Tx) ProfileCountsOf(profile uuid.UUID) (ProfileCounts, error) {
	rows, err := t.tx.Query(t.ctx, qProfileCountsOne, t.tenant, profile)
	if err != nil {
		return ProfileCounts{}, sanitize(err)
	}
	defer rows.Close()
	var out ProfileCounts
	for rows.Next() {
		if _, out, err = scanProfileCounts(rows); err != nil {
			return ProfileCounts{}, err
		}
	}
	return out, sanitize(rows.Err())
}

// ---------------------------------------------------------------------------
// Catalog lists.

// FilterMode is one mode of a catalog filter; Default is the one with the lowest wire id (T-146).
type FilterMode struct {
	Mode    string
	Default bool
}

// CatalogFilterRow is a filter as the catalog route lists it.
type CatalogFilterRow struct {
	ID, Kind, NameFA, NameEN, State string
	Modes                           []FilterMode
}

const qCatalogFilterList = `SELECT f.id, f.kind, f.name_fa, f.name_en, f.state, m.mode, m.wire_id
FROM ctrlz.catalog_filter f LEFT JOIN ctrlz.catalog_filter_mode m ON m.filter_id = f.id
ORDER BY f.kind DESC, f.wire_id, m.wire_id`

// CatalogFilterList reads every filter with its modes in wire order. A filter with a single mode lists none: its
// one row is internal (spec 3.7).
func (t Tx) CatalogFilterList() ([]CatalogFilterRow, error) {
	rows, err := t.tx.Query(t.ctx, qCatalogFilterList)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []CatalogFilterRow
	for rows.Next() {
		var f CatalogFilterRow
		var mode *string
		var wire *int32
		if err := rows.Scan(&f.ID, &f.Kind, &f.NameFA, &f.NameEN, &f.State, &mode, &wire); err != nil {
			return nil, sanitize(err)
		}
		if n := len(out); n == 0 || out[n-1].ID != f.ID {
			out = append(out, f)
		}
		if mode != nil {
			last := &out[len(out)-1]
			last.Modes = append(last.Modes, FilterMode{Mode: *mode, Default: len(last.Modes) == 0})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, sanitize(err)
	}
	for i := range out {
		if len(out[i].Modes) <= 1 {
			out[i].Modes = nil
		}
	}
	return out, nil
}

// CategoryRow is a service category.
type CategoryRow struct{ ID, NameFA, NameEN string }

const qCatalogCategories = `SELECT id, name_fa, name_en FROM ctrlz.catalog_service_category ORDER BY id`

// CatalogCategories reads the service categories.
func (t Tx) CatalogCategories() ([]CategoryRow, error) {
	rows, err := t.tx.Query(t.ctx, qCatalogCategories)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []CategoryRow
	for rows.Next() {
		var c CategoryRow
		if err := rows.Scan(&c.ID, &c.NameFA, &c.NameEN); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, c)
	}
	return out, sanitize(rows.Err())
}

// CatalogServiceRow is a service as the catalog route lists it.
type CatalogServiceRow struct {
	Slug, CategoryID, NameFA, NameEN, LogoRef, State string
	RiskFlag, RedirectAllowed, RegionLimited         bool
}

const qCatalogServiceList = `SELECT slug, category_id, name_fa, name_en, COALESCE(logo_ref, ''), state, risk_flag, redirect_allowed,
  allowed_regions IS NOT NULL FROM ctrlz.catalog_service ORDER BY category_id, slug`

// CatalogServiceList reads every service of the catalog.
func (t Tx) CatalogServiceList() ([]CatalogServiceRow, error) {
	rows, err := t.tx.Query(t.ctx, qCatalogServiceList)
	if err != nil {
		return nil, sanitize(err)
	}
	defer rows.Close()
	var out []CatalogServiceRow
	for rows.Next() {
		var s CatalogServiceRow
		if err := rows.Scan(&s.Slug, &s.CategoryID, &s.NameFA, &s.NameEN, &s.LogoRef, &s.State, &s.RiskFlag, &s.RedirectAllowed, &s.RegionLimited); err != nil {
			return nil, sanitize(err)
		}
		out = append(out, s)
	}
	return out, sanitize(rows.Err())
}

const qPresetGet = `SELECT content::text FROM ctrlz.profile_presets WHERE kind = $1`

// PresetGet reads the document of a profile type (spec 5). found is false for a kind with no preset.
func (t Tx) PresetGet(kind string) ([]byte, bool, error) {
	var s string
	err := t.tx.QueryRow(t.ctx, qPresetGet, kind).Scan(&s)
	ok, err := notFound(err)
	return []byte(s), ok, err
}

// ---------------------------------------------------------------------------
// One page of rules (T-196).

// RuleCursor is the position after the last row of a page: the sort key and the id.
type RuleCursor struct {
	Text string    // the rule key, for sort pattern
	At   time.Time // created_at or updated_at, for the other sorts
	ID   uuid.UUID
}

// RulePageIn asks for a page: the filter, the sort (pattern, created, updated) and the position to start after.
type RulePageIn struct {
	Selector RuleSelector
	Sort     string
	After    *RuleCursor
	Limit    int // the page size; one more row is read to tell whether there is a next page
}

// The three sorts differ in their key and direction, so each is a statement of its own: no SQL is built from text.
const ruleFilter = `r.tenant_id = $1 AND r.profile_id = $2
  AND ($3::text = '' OR ($3::text = 'root' AND r.folder_id IS NULL) OR ($3::text = 'folder' AND r.folder_id = $4::uuid))
  AND ($5::text = '' OR strpos(r.rule_key, $5::text) > 0)
  AND ($6::text = '' OR ($6::text = 'enabled' AND r.enabled AND (r.expires_at IS NULL OR r.expires_at > $8::timestamptz))
       OR ($6::text = 'disabled' AND NOT r.enabled) OR ($6::text = 'expired' AND r.expires_at IS NOT NULL AND r.expires_at <= $8::timestamptz))
  AND ($7::text = '' OR r.action = $7::text)`

const rulePageColumns = `r.id, r.folder_id, r.rule_key, r.match_kind, r.negated, r.action, r.target_kind, r.target_location_id,
  host(r.target_ipv4), host(r.target_ipv6), r.target_host, r.enabled, r.expires_at, r.comment, r.location_unavailable, r.created_at, r.updated_at`

const qRulePagePattern = `SELECT ` + rulePageColumns + ` FROM ctrlz.rules r WHERE ` + ruleFilter + `
  AND ($9::text IS NULL OR (r.rule_key, r.id) > ($9::text, $10::uuid))
ORDER BY r.rule_key, r.id LIMIT $11::int`

const qRulePageCreated = `SELECT ` + rulePageColumns + ` FROM ctrlz.rules r WHERE ` + ruleFilter + `
  AND ($9::timestamptz IS NULL OR (r.created_at, r.id) < ($9::timestamptz, $10::uuid))
ORDER BY r.created_at DESC, r.id DESC LIMIT $11::int`

const qRulePageUpdated = `SELECT ` + rulePageColumns + ` FROM ctrlz.rules r WHERE ` + ruleFilter + `
  AND ($9::timestamptz IS NULL OR (r.updated_at, r.id) < ($9::timestamptz, $10::uuid))
ORDER BY r.updated_at DESC, r.id DESC LIMIT $11::int`

// RulePage reads one page of the profile's rules, at most Limit+1 rows.
func (t Tx) RulePage(profile uuid.UUID, in RulePageIn) ([]RuleRow, error) {
	var folder any
	if in.Selector.FolderID != uuid.Nil {
		folder = in.Selector.FolderID
	}
	var key, id any
	if in.After != nil {
		id = in.After.ID
		if in.Sort == "" || in.Sort == "pattern" {
			key = in.After.Text
		} else {
			key = in.After.At
		}
	}
	s := in.Selector
	var rows pgx.Rows
	var err error
	switch in.Sort {
	case "created":
		rows, err = t.tx.Query(t.ctx, qRulePageCreated, t.tenant, profile, s.Folder, folder, s.Q, s.Status, s.Action, s.Now, key, id, int32(in.Limit+1))
	case "updated":
		rows, err = t.tx.Query(t.ctx, qRulePageUpdated, t.tenant, profile, s.Folder, folder, s.Q, s.Status, s.Action, s.Now, key, id, int32(in.Limit+1))
	default:
		rows, err = t.tx.Query(t.ctx, qRulePagePattern, t.tenant, profile, s.Folder, folder, s.Q, s.Status, s.Action, s.Now, key, id, int32(in.Limit+1))
	}
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

// ---------------------------------------------------------------------------
// Lock and unlock (spec 7). The only statements that write the five lock columns.

// The lock is one statement that requires lock_state = 'unlocked', so a lock that came between a read and the write
// is a loss (409). locked_at is the database's stamp (clocks.yaml: stamp): a lock is not a window the application
// decides on.
const qProfileLock = `UPDATE ctrlz.profiles SET lock_state = 'locked', lock_password_hash = $3, lock_message = $4, locked_by = $5, locked_at = now()
WHERE tenant_id = $1 AND id = $2 AND lock_state = 'unlocked' RETURNING id`

// ProfileLock locks an unlocked profile of the tenant with the hash of its own password. A loss is a profile that
// is already locked (or not the tenant's). It writes no outbox row and bumps no version: the lock is not compiled.
func (t Tx) ProfileLock(id uuid.UUID, hash secret.String, message string, user uuid.UUID) (Won, error) {
	var got uuid.UUID
	return wonRow(t.tx.QueryRow(t.ctx, qProfileLock, t.tenant, id, hash.Reveal(), nullIf(message), nullUUID(user)).Scan(&got))
}

const qProfileLockHash = `SELECT lock_password_hash FROM ctrlz.profiles WHERE tenant_id = $1 AND id = $2 AND lock_state = 'locked'`

// ProfileLockHash reads the hash of a locked profile's password. found is false for a profile that is missing, not
// the tenant's, or not locked. It is the one read of the column (S9).
func (t Tx) ProfileLockHash(id uuid.UUID) (secret.String, bool, error) {
	var h *string
	err := t.tx.QueryRow(t.ctx, qProfileLockHash, t.tenant, id).Scan(&h)
	ok, err := notFound(err)
	if err != nil || !ok || h == nil {
		return secret.String{}, false, err
	}
	return secret.New(*h), true, nil
}

const qProfileUnlock = `UPDATE ctrlz.profiles SET lock_state = 'unlocked', lock_password_hash = NULL, lock_message = NULL, locked_by = NULL, locked_at = NULL
WHERE tenant_id = $1 AND id = $2 AND lock_state = 'locked' AND lock_password_hash = $3 RETURNING id`

// ProfileUnlock clears the five lock columns where the profile is still locked with the hash that was read, so an
// unlock racing a relock clears nothing (spec 7.2).
func (t Tx) ProfileUnlock(id uuid.UUID, hash secret.String) (Won, error) {
	var got uuid.UUID
	return wonRow(t.tx.QueryRow(t.ctx, qProfileUnlock, t.tenant, id, hash.Reveal()).Scan(&got))
}

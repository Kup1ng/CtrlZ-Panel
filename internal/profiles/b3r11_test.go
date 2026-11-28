package profiles_test

import (
	"runtime"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Kup1ng/CtrlZ-Panel/internal/profiles"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// folderRedirect is the Folder Rule PATCH whose D42 check reads the folder's inheriting rules.
func folderRedirect() profiles.FolderPatch {
	return profiles.FolderPatch{Act: &profiles.Act{Action: "redirect", Target: profiles.Target{Kind: "host", Host: "proxy.example.net"}}}
}

// bypassFolderOf creates a folder whose Folder Rule is Bypass, the folder a PATCH to Redirect starts from.
func (f *fx) bypassFolderOf(t *testing.T, tenant, profile uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	f.must(t, tenant, func(tx store.Tx) error {
		r, err := f.env.CreateFolder(tx, profile, profiles.FolderIn{Name: "bypass", Kind: "standard", Act: profiles.Act{Action: "bypass"}})
		id = r.ID
		return err
	})
	return id
}

// seedInheriting writes n inheriting rules "k00000.example.com" and on into the folder, straight into the table:
// a profile of this size is what the check must not read.
func (f *fx) seedInheriting(t *testing.T, tenant, profile, folder uuid.UUID, n int) {
	t.Helper()
	f.exec(t, `INSERT INTO ctrlz.rules (tenant_id, profile_id, folder_id, rule_key, match_kind, action)
SELECT $1, $2, $3, 'k' || lpad(i::text, 5, '0') || '.example.com', 'domain', 'inherit' FROM generate_series(1, $4::int) i`,
		tenant, profile, folder, n)
}

// TestFolderRedirectChecksEveryPageOfInheritingRules (p2-B3-r11-1): the D42 check of a Redirect Folder Rule walks the
// keys of the folder's inheriting rules in pages of lookupChunk, so an Iranian rule on any page is found, a folder
// of exactly one page or more with none is accepted, and another tenant's Iranian rule is not seen.
func TestFolderRedirectChecksEveryPageOfInheritingRules(t *testing.T) {
	f := newFx(t)
	p := f.newProfile(t, f.A.Tenant, "paged")
	folder := f.bypassFolderOf(t, f.A.Tenant, p)

	// The other tenant has an inheriting Iranian rule in a folder of its own: it must never decide for tenant A.
	pb := f.newProfile(t, f.B.Tenant, "other")
	fb := f.bypassFolderOf(t, f.B.Tenant, pb)
	f.exec(t, `INSERT INTO ctrlz.rules (tenant_id, profile_id, folder_id, rule_key, match_kind, action) VALUES ($1, $2, $3, 'b.ir', 'domain', 'inherit')`,
		f.B.Tenant, pb, fb)

	// 1,200 clean rules: the three pages (500, 500, 200) are all asked, and none is Iranian.
	f.seedInheriting(t, f.A.Tenant, p, folder, 1200)
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.UpdateFolder(tx, p, folder, folderRedirect())
		return err
	})
	f.exec(t, `UPDATE ctrlz.rule_folders SET action = 'bypass', target_kind = NULL, target_host = NULL WHERE id = $1`, folder)

	// One Iranian rule that sorts after every other key lands on the last page.
	f.exec(t, `INSERT INTO ctrlz.rules (tenant_id, profile_id, folder_id, rule_key, match_kind, action) VALUES ($1, $2, $3, 'zzz.ir', 'domain', 'inherit')`,
		f.A.Tenant, p, folder)
	before := f.digest(t, p)
	e := f.refusal(t, f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.UpdateFolder(tx, p, folder, folderRedirect())
		return err
	})
	if !hasField(e, "/action", "iranian_name") {
		t.Fatalf("an inheriting Iranian rule on the last page: %v", e)
	}
	if f.digest(t, p) != before {
		t.Error("the refusal wrote something")
	}

	// Exactly one full page of clean rules is accepted (the walk asks for the next page and finds it empty).
	f.exec(t, `DELETE FROM ctrlz.rules WHERE profile_id = $1 AND (rule_key = 'zzz.ir' OR rule_key >= 'k00500.example.com')`, p)
	if n := f.count(t, `SELECT count(*) FROM ctrlz.rules WHERE profile_id = $1`, p); n != 499 {
		t.Fatalf("fixture: %d rules", n)
	}
	f.exec(t, `INSERT INTO ctrlz.rules (tenant_id, profile_id, folder_id, rule_key, match_kind, action) VALUES ($1, $2, $3, 'k99999.example.com', 'domain', 'inherit')`,
		f.A.Tenant, p, folder)
	f.must(t, f.A.Tenant, func(tx store.Tx) error {
		_, err := f.env.UpdateFolder(tx, p, folder, folderRedirect())
		return err
	})
}

// TestFolderRedirectCheckReadsAPageNotTheProfile (p2-B3-r11-1): PATCH of a folder is an ordinary route with no place and
// no weight, so what the D42 check allocates must not grow with the profile. The profile holds 10,000 rules with long
// keys and long redirect hosts, and the first key of the folder is Iranian, so the walk ends on its first page. Reading
// the whole profile allocates more than twice the bound.
func TestFolderRedirectCheckReadsAPageNotTheProfile(t *testing.T) {
	f := newFx(t)
	p := f.newProfile(t, f.A.Tenant, "big")
	folder := f.bypassFolderOf(t, f.A.Tenant, p)
	pad := strings.Repeat("x", 60)
	host := strings.Join([]string{pad, pad, pad, pad}, ".")
	f.exec(t, `INSERT INTO ctrlz.rules (tenant_id, profile_id, rule_key, match_kind, action, target_kind, target_host, comment)
SELECT $1, $2, 'r' || lpad(i::text, 5, '0') || '.' || $4::text || '.example.com', 'domain', 'redirect', 'host', $3::text, repeat('c', 64)
FROM generate_series(1, 9000) i`, f.A.Tenant, p, host, pad)
	f.seedInheriting(t, f.A.Tenant, p, folder, 999)
	f.exec(t, `INSERT INTO ctrlz.rules (tenant_id, profile_id, folder_id, rule_key, match_kind, action) VALUES ($1, $2, $3, 'afirst.ir', 'domain', 'inherit')`,
		f.A.Tenant, p, folder)
	if n := f.count(t, `SELECT count(*) FROM ctrlz.rules WHERE profile_id = $1`, p); n != 10000 {
		t.Fatalf("fixture: %d rules", n)
	}

	const bound = 3 << 20
	var alloc uint64
	e := f.refusal(t, f.A.Tenant, func(tx store.Tx) error {
		var a, b runtime.MemStats
		runtime.ReadMemStats(&a)
		_, err := f.env.UpdateFolder(tx, p, folder, folderRedirect())
		runtime.ReadMemStats(&b)
		alloc = b.TotalAlloc - a.TotalAlloc
		return err
	})
	if !hasField(e, "/action", "iranian_name") {
		t.Fatalf("an inheriting Iranian rule: %v", e)
	}
	if alloc > bound {
		t.Errorf("the check allocated %d KiB for a profile of 10,000 rules, bound %d KiB: it reads more than a page", alloc>>10, bound>>10)
	}
}

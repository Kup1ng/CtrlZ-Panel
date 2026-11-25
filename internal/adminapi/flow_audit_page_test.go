package adminapi

import (
	"testing"

	"github.com/google/uuid"
)

type auditItem struct {
	ID        int64   `json:"id"`
	Action    string  `json:"action"`
	AdminID   *string `json:"admin_id"`
	AdminName *string `json:"admin_name"`
}

type auditPageBody struct {
	Items []auditItem `json:"items"`
	Next  *string     `json:"next_cursor"`
}

// pageAudit follows next_cursor from the newest row to the end and returns the rows in the order they came;
// between, when given, runs once after the first page, so a test can add rows while a reader is mid-log.
func pageAudit(t *testing.T, b *browser, query string, between func()) []auditItem {
	t.Helper()
	var all []auditItem
	cursor := ""
	for pages := 0; pages < 60; pages++ {
		path := "/audit?" + query
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		var p auditPageBody
		b.get(path).want(200, "").json(&p)
		all = append(all, p.Items...)
		if p.Next == nil {
			return all
		}
		cursor = *p.Next
		if pages == 0 && between != nil {
			between()
		}
	}
	t.Fatal("the audit log did not end after 60 pages")
	return nil
}

// TestAuditPaging is T-352: GET /audit by cursor, with and without the action filter, loses no row and repeats
// none while rows are written during the read, and names the admin of a row, with the row of a deleted admin
// still in the page.
func TestAuditPaging(t *testing.T) {
	r := newRig(t)
	b, _ := r.admin(t)

	// A second admin who is deleted again, so some rows name an admin that no longer exists.
	gone := uuid.New()
	r.env.Exec(t, `INSERT INTO ctrlz.admin_users (id, username, password_hash) VALUES ($1, 'gone-admin', 'x')`, gone)
	insert := func(n int, action string, admin any) {
		for i := 0; i < n; i++ {
			r.env.Exec(t, `INSERT INTO ctrlz.audit_log (at, admin_id, action, target, params, entry_hash) VALUES (now(), $1, $2, 'test', '{}', '\x00')`, admin, action)
		}
	}
	insert(7, "test.a", seedAdmin)
	insert(6, "test.b", gone)
	insert(5, "test.a", nil)
	insert(4, "test.b", seedAdmin)
	r.env.Exec(t, `DELETE FROM ctrlz.admin_users WHERE id = $1`, gone)

	// What the log held when the reading began, newest first.
	var base auditPageBody
	b.get("/audit?limit=100").want(200, "").json(&base)
	if base.Next != nil || len(base.Items) < 22 {
		t.Fatalf("the baseline holds %d rows (next %v)", len(base.Items), base.Next)
	}

	t.Run("every row once, newest first, while new rows arrive", func(t *testing.T) {
		got := pageAudit(t, b, "limit=5", func() { insert(3, "test.late", seedAdmin) })
		seen := map[int64]bool{}
		var prev int64
		for i, it := range got {
			if seen[it.ID] {
				t.Fatalf("row %d came twice", it.ID)
			}
			seen[it.ID] = true
			if i > 0 && it.ID >= prev {
				t.Fatalf("row %d follows row %d: not newest first", it.ID, prev)
			}
			prev = it.ID
		}
		for _, it := range base.Items {
			if !seen[it.ID] {
				t.Fatalf("row %d (%s) of the baseline never came", it.ID, it.Action)
			}
		}
		// The three late rows were written after the first page was read, above its cursor, so they stay out of this
		// walk: the reader sees the log as it was when it began, and a new walk sees them.
		for _, it := range got {
			if it.Action == "test.late" {
				t.Fatalf("a row written during the read came into it: %+v", it)
			}
		}
		if again := pageAudit(t, b, "limit=100", nil); len(again) != len(got)+3 {
			t.Fatalf("a new walk holds %d rows, want %d", len(again), len(got)+3)
		}
	})

	t.Run("the filter and the cursor together", func(t *testing.T) {
		want := 0
		for _, it := range base.Items {
			if it.Action == "test.a" {
				want++
			}
		}
		if want != 12 {
			t.Fatalf("the baseline holds %d test.a rows, want 12", want)
		}
		got := pageAudit(t, b, "limit=3&action=test.a", func() { insert(2, "test.a", seedAdmin) })
		if len(got) != want {
			t.Fatalf("filtered walk returned %d rows, want %d", len(got), want)
		}
		seen := map[int64]bool{}
		for _, it := range got {
			if it.Action != "test.a" || seen[it.ID] {
				t.Fatalf("filtered walk: %+v (repeat %v)", it, seen[it.ID])
			}
			seen[it.ID] = true
		}
	})

	t.Run("the admin of a row is named, and a deleted admin leaves the row", func(t *testing.T) {
		for _, it := range base.Items {
			switch {
			case it.AdminID == nil:
				if it.AdminName != nil {
					t.Fatalf("row %d has no admin and a name %q", it.ID, *it.AdminName)
				}
			case *it.AdminID == seedAdmin.String():
				if it.AdminName == nil || *it.AdminName != adminName {
					t.Fatalf("row %d of the seed admin shows the name %v", it.ID, it.AdminName)
				}
			case *it.AdminID == gone.String():
				if it.AdminName != nil {
					t.Fatalf("row %d of a deleted admin shows the name %q", it.ID, *it.AdminName)
				}
			}
		}
		count := 0
		for _, it := range base.Items {
			if it.AdminID != nil && *it.AdminID == gone.String() {
				count++
			}
		}
		if count != 6 {
			t.Fatalf("%d rows of the deleted admin are in the page, want 6", count)
		}
	})
}

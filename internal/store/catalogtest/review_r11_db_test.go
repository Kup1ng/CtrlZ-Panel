package catalogtest_test

import (
	"regexp"
	"strings"
	"testing"

	pgmigrations "github.com/Kup1ng/CtrlZ-Panel/migrations/postgres"

	"github.com/Kup1ng/CtrlZ-Panel/internal/testpg"
)

// P1 auth review round 11, SMS area (sms-r11-2, sms-r11-5; owner decision D58).

// TestTheOTPBodyMigrationLeavesAnEditedRowAlone runs 0041 against a database that is already
// migrated, with one Persian OTP row edited by an operator and one put back to the 0011 seed.
// The edited row must keep its text (the guard is `body = <old seed>`), the seed row must take the
// owner's text, and the English rows and the other templates must not move. It is the control of
// the length test in internal/sms, which reads the same file: a guard that overwrote any row
// would pass that test and destroy an operator's copy.
func TestTheOTPBodyMigrationLeavesAnEditedRowAlone(t *testing.T) {
	h := newHarness(t, testpg.Need(t, cluster))
	raw, err := pgmigrations.Migrations.ReadFile("0041_review_round11_sms.sql")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`UPDATE ctrlz\.sms_templates SET body = '((?:[^']|'')*)'\s+WHERE key = '(\w+)' AND locale = 'fa' AND body = '((?:[^']|'')*)';`)
	ups := re.FindAllStringSubmatch(string(raw), -1)
	if len(ups) != 3 {
		t.Fatalf("0041 holds %d guarded updates, want the three OTP bodies", len(ups))
	}
	body := func(key, locale string) string {
		var b string
		if err := h.super.QueryRow(h.ctx, `SELECT body FROM ctrlz.sms_templates WHERE key = $1 AND locale = $2`, key, locale).Scan(&b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	unq := func(s string) string { return strings.ReplaceAll(s, "''", "'") }
	snapshot := map[string]string{}
	for _, k := range []string{"otp", "otp_reset", "otp_phone", "account_exists", "notice_passkey", "notice_recovery"} {
		for _, l := range []string{"fa", "en"} {
			snapshot[k+"/"+l] = body(k, l)
		}
	}
	// A migrated database already holds the new text.
	for _, u := range ups {
		if got := body(u[2], "fa"); got != unq(u[1]) {
			t.Fatalf("%s/fa after migrating is %q, want the new body", u[2], got)
		}
	}
	// One row is the operator's, one is back at the seed text of 0011.
	h.exec(`UPDATE ctrlz.sms_templates SET body = $1 WHERE key = 'otp' AND locale = 'fa'`, "کد {code} - متن اپراتور")
	for _, u := range ups {
		if u[2] == "otp_reset" {
			h.exec(`UPDATE ctrlz.sms_templates SET body = $1 WHERE key = 'otp_reset' AND locale = 'fa'`, unq(u[3]))
		}
	}
	snapshot["otp/fa"] = "کد {code} - متن اپراتور"
	for _, u := range ups {
		if u[2] == "otp_reset" {
			snapshot["otp_reset/fa"] = unq(u[1])
		}
	}
	h.exec(string(raw))
	for k, want := range snapshot {
		key, locale, _ := strings.Cut(k, "/")
		if got := body(key, locale); got != want {
			t.Errorf("%s after 0041 is %q, want %q", k, got, want)
		}
	}
	// Running it a second time changes nothing.
	h.exec(string(raw))
	for k, want := range snapshot {
		key, locale, _ := strings.Cut(k, "/")
		if got := body(key, locale); got != want {
			t.Errorf("%s after a second run is %q, want %q", k, got, want)
		}
	}
}

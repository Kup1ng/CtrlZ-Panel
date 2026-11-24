package admincli_test

import (
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/authtest"
)

// TestCLIOutputCanaries is the CLI part of the canary of spec 18.4 (T-323): the
// one-time password that bootstrap, reset-password and reset-totp issue appears in
// the --out-file the command was given and nowhere else: not on stdout (the path
// only), not on stderr, not in audit_log, admin_sessions or any other sink table,
// and not in the Postgres server log. The Compose smoke repeats the check with
// `docker logs` of real containers (scripts/compose-smoke.sh).
func TestCLIOutputCanaries(t *testing.T) {
	r := newRig(t)
	r.noAdmin()

	var printed []string
	if code := r.run("bootstrap", "--username", "root"); code != 0 {
		t.Fatalf("bootstrap: exit %d, stderr %q", code, r.errb.String())
	}
	printed = append(printed, r.printed())
	if strings.Contains(r.errb.String(), printed[0]) {
		t.Error("bootstrap printed the password on stderr")
	}
	for _, cmd := range [][]string{{"reset-password", "--user", "root"}, {"reset-totp", "--user", "root"}} {
		if code := r.run(cmd...); code != 0 {
			t.Fatalf("%v: exit %d, stderr %q", cmd, code, r.errb.String())
		}
		pw := r.printed()
		if strings.Contains(r.errb.String(), pw) {
			t.Errorf("%s printed the password on stderr", cmd[0])
		}
		printed = append(printed, pw)
	}
	if printed[0] == printed[1] || printed[1] == printed[2] {
		t.Fatal("two commands printed the same password")
	}

	// The seed admin's own session rows and the audit rows are among the sinks.
	authtest.AssertTextClean(t, "stderr of the last command", r.errb.String(), printed...)
	r.env.AssertSinksClean(t, printed...)
	if r.count(`SELECT count(*) FROM ctrlz.admin_sessions t WHERE strpos(t::text, $1) > 0 OR strpos(t::text, $2) > 0 OR strpos(t::text, $3) > 0`, printed[0], printed[1], printed[2]) != 0 {
		t.Error("a one-time password is in admin_sessions")
	}
	r.env.AssertServerLogClean(t, printed...)
}

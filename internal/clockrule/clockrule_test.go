package clockrule

import (
	"strings"
	"testing"
)

func TestRegistryLoadsAndIsConsistent(t *testing.T) {
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if r.Class("sessions", "idle_expires_at") != App || r.Class("users", "password_expires_at") != DB || r.Class("sessions", "revoked_at") != Stamp {
		t.Errorf("the registry does not say what the rule says: %v", r.Tables["sessions"])
	}
	if len(r.Windows()) == 0 {
		t.Error("no windows")
	}
}

func TestParseRefusesWhatWeakensTheRule(t *testing.T) {
	for name, text := range map[string]string{
		"an unknown class":             "tables: {t: {c: wall}}",
		"read of a column not db":      "tables: {t: {c: app}}\nread: {t.c: why}",
		"carry of an unknown column":   "tables: {t: {c: db}}\ncarry: {t.d: why}",
		"a db column returned raw":     "tables: {t: {c: db}}\nfunctions: {f.c: t.c}",
		"a function mapped to nothing": "tables: {t: {c: app}}\nfunctions: {f.c: t.x}",
		"an unknown key":               "tables: {}\nunknown: 1",
	} {
		if _, err := Parse([]byte(text)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Parse([]byte("tables: {t: {c: db}}\nread: {t.c: shown}\nfunctions: {f.c: t.c}")); err != nil {
		t.Errorf("a listed read was refused: %v", err)
	}
}

func TestAnalyzeReadsQuotingAndAliases(t *testing.T) {
	r, err := Parse([]byte("tables: {sessions: {idle_expires_at: app, revoked_at: stamp}, users: {password_expires_at: db}}"))
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		sql  string
		rule string
	}{
		"a quoted name is the same name":         {`UPDATE "ctrlz"."sessions" SET "idle_expires_at" = pg_catalog.now()`, "app-clock"},
		"spaces around the dot":                  {`UPDATE ctrlz . sessions SET idle_expires_at = now()`, "app-clock"},
		"an alias resolves":                      {`SELECT 1 FROM ctrlz.sessions AS s WHERE s.idle_expires_at > now()`, "app-clock"},
		"a clock in a string is not":             {`SELECT 1 FROM ctrlz.sessions WHERE idle_expires_at > $1 AND 'clock_timestamp()' = $2`, ""},
		"a comment is not":                       {"SELECT 1 FROM ctrlz.sessions WHERE idle_expires_at > $1 -- now()", ""},
		"a stamp is free":                        {`UPDATE ctrlz.sessions SET revoked_at = now()`, ""},
		"CURRENT_TIMESTAMP counts":               {`UPDATE ctrlz.sessions SET idle_expires_at = CURRENT_TIMESTAMP`, "app-clock"},
		"the state function reads the clock":     {`SELECT ctrlz.credential_state(u.must_reset, u.password_expires_at, false), s.idle_expires_at FROM ctrlz.users u, ctrlz.sessions s`, "app-clock"},
		"the state function beside a db column":  {`SELECT ctrlz.credential_state(u.must_reset, u.password_expires_at, false) FROM ctrlz.users u`, ""},
		"the display helper reads the clock too": {`SELECT ctrlz.one_time_expiry(u.must_reset, u.password_expires_at), s.idle_expires_at FROM ctrlz.users u, ctrlz.sessions s`, "app-clock"},
		"a second statement counts":              {`SELECT 1; UPDATE ctrlz.sessions SET idle_expires_at = now()`, "app-clock"},
		"a tenant-qualified name":                {`SELECT 1 FROM ctrlz.sessions WHERE ctrlz.sessions.idle_expires_at > now()`, "app-clock"},
	} {
		got := r.Analyze(c.sql, Options{GoBound: true})
		switch {
		case c.rule == "" && len(got) != 0:
			t.Errorf("%s: %v", name, got)
		case c.rule != "" && !strings.Contains(strings.Join(func() []string {
			var s []string
			for _, f := range got {
				s = append(s, f.Rule)
			}
			return s
		}(), ","), c.rule):
			t.Errorf("%s: want %s, got %v", name, c.rule, got)
		}
	}
}

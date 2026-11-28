package domainapply

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// The script reads the exit code of Run, so the codes are tested through Run and not through failureCode: a helper that no
// caller uses proved nothing in R34-r3-2 (R34-r4-1).
func TestRunCommitExitCodes(t *testing.T) {
	// setup prints the first run's .env into place, as the script does between the two runs.
	setup := func(t *testing.T, commitErr error) (*world, *fakeSource, Env) {
		w := newWorld(t)
		src := &fakeSource{settings: settings(), commitErr: commitErr}
		printed, _, err := w.apply(src)
		if err != nil {
			t.Fatal(err)
		}
		w.writeEnv(printed)
		keyFile := filepath.Join(t.TempDir(), "web_intake_key")
		if err := os.WriteFile(keyFile, w.webPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		vars := map[string]string{varKeyFile: keyFile, varEnvFile: w.envf, varTLSDir: w.dir}
		return w, src, Env{
			Getenv: func(k string) string { return vars[k] },
			Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{},
			Now: func() time.Time { return now }, Source: src,
		}
	}
	run := func(e Env, args ...string) int { return Run(context.Background(), args, e) }

	_, _, e := setup(t, nil)
	if code := run(e, "--commit"); code != 0 {
		t.Errorf("a good commit answered %d", code)
	}

	_, _, e = setup(t, errors.New("connection lost"))
	if code := run(e, "--commit"); code != 1 {
		t.Errorf("an UPDATE whose answer was lost answered %d, want 1", code)
	}

	_, _, e = setup(t, store.ErrDomainChanged)
	if code := run(e, "--commit"); code != exitNothingRecorded {
		t.Errorf("an UPDATE that matched no row answered %d, want %d", code, exitNothingRecorded)
	}

	// A .env that does not hold the planned hosts (a host withdrawn between the two runs): refused before the UPDATE.
	w, src, e := setup(t, nil)
	w.writeEnv("CTRLZ_ENV_FORMAT_2=1\nCTRLZ_PANEL_HOST=other.example.ir\n")
	if code := run(e, "--commit"); code != exitNothingRecorded || len(src.commits) != 0 {
		t.Errorf("a refused plan answered %d with %d commits, want %d and none", code, len(src.commits), exitNothingRecorded)
	}

	// Any other failure before the UPDATE, a missing key file here, recorded nothing either.
	_, _, e = setup(t, nil)
	get := e.Getenv
	e.Getenv = func(k string) string {
		if k == varKeyFile {
			return filepath.Join(t.TempDir(), "absent")
		}
		return get(k)
	}
	if code := run(e, "--commit"); code != exitNothingRecorded {
		t.Errorf("a missing key answered %d, want %d", code, exitNothingRecorded)
	}

	// The first run and the usage error keep their codes.
	if code := run(e); code != 1 {
		t.Errorf("a failed first run answered %d, want 1", code)
	}
	if code := run(e, "--nope"); code != 2 {
		t.Errorf("a usage error answered %d, want 2", code)
	}
}

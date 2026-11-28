package domainapply

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/app"
	"github.com/Kup1ng/CtrlZ-Panel/internal/appclock"
	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// Env is what Run takes from the process; tests replace the parts they need.
type Env struct {
	Getenv func(string) string
	Stdout io.Writer // receives the new .env and nothing else, so the script can put it in place as it is
	Stderr io.Writer // receives the summary and errors
	Now    func() time.Time
	// Source replaces the database login. Only tests set it: Run must be tested through its exit codes, since the script reads them.
	Source Source
}

// exitNothingRecorded is the exit code of a refused --commit: no applied_* column moved. scripts/domain-apply.sh restores
// the previous .env on this code only (R34-r3-2). Keep the two in step.
const exitNothingRecorded = 3

// The variables of the one-shot (docker-compose.yml, service domain-apply). The database variables are the ones of
// every role (app.LoadConfig).
//
//	CTRLZ_WEB_INTAKE_KEY_FILE   the web_intake_key secret that opens the sealed keys
//	CTRLZ_DOMAIN_ENV_FILE       the current .env, mounted read-only
//	CTRLZ_CADDY_TLS_DIR         the directory of the Caddy data volume this tool fills
//
// --commit also reads the .env as it was before the script's rename from varEnvFile + ".prev", when the script mounted it
// beside the .env (a file that is not there means the script replaced nothing).
const (
	varKeyFile = "CTRLZ_WEB_INTAKE_KEY_FILE"
	varEnvFile = "CTRLZ_DOMAIN_ENV_FILE"
	varTLSDir  = "CTRLZ_CADDY_TLS_DIR"
)

// Run is `ctrlz domain-apply`, with --commit its second half after the script has replaced the .env, and with --prune its
// clean-up after the recreate. It returns the exit code: 0 done, 1 refused or failed, 2 usage. --commit says more, because
// the script decides from it whether the old .env goes back: exitNothingRecorded when the failure came before the UPDATE
// or the UPDATE matched no row, 1 when the UPDATE was sent and its result is unknown.
func Run(ctx context.Context, args []string, env Env) int {
	if env.Getenv == nil {
		env.Getenv = os.Getenv
	}
	if env.Stdout == nil {
		env.Stdout = os.Stdout
	}
	if env.Stderr == nil {
		env.Stderr = os.Stderr
	}
	if env.Now == nil {
		env.Now = appclock.Now
	}
	commit := len(args) == 1 && args[0] == "--commit"
	prune := len(args) == 1 && args[0] == "--prune"
	if len(args) != 0 && !commit && !prune {
		fmt.Fprintln(env.Stderr, "usage: ctrlz domain-apply [--commit|--prune]")
		return 2
	}
	var err error
	if prune {
		err = runPrune(env)
	} else {
		err = run(ctx, env, commit)
	}
	if err != nil {
		// The text of every error here names a variable, a path, a host or a certificate id, never a key or a password.
		fmt.Fprintf(env.Stderr, "ctrlz domain-apply: %v\n", err)
		// The script reads this code, so only failureCode decides it (R34-r4-1).
		return failureCode(commit, err)
	}
	return 0
}

// failureCode is the exit code of a failed run.
func failureCode(commit bool, err error) int {
	if commit && !OutcomeUnknown(err) {
		return exitNothingRecorded
	}
	return 1
}

// runPrune needs the .env and the directory only: no database login and no key.
func runPrune(env Env) error {
	envFile, tlsDir := env.Getenv(varEnvFile), env.Getenv(varTLSDir)
	if envFile == "" {
		return errors.New(varEnvFile + " is not set")
	}
	if tlsDir == "" {
		return errors.New(varTLSDir + " is not set")
	}
	return Prune(Inputs{EnvFile: envFile, TLSDir: tlsDir})
}

func run(ctx context.Context, env Env, commit bool) error {
	keyFile := env.Getenv(varKeyFile)
	if keyFile == "" {
		return errors.New(varKeyFile + " is not set")
	}
	envFile := env.Getenv(varEnvFile)
	if envFile == "" {
		return errors.New(varEnvFile + " is not set")
	}
	tlsDir := env.Getenv(varTLSDir)
	if tlsDir == "" {
		return errors.New(varTLSDir + " is not set")
	}
	webKey, err := secret.FromFile(keyFile)
	if err != nil {
		return fmt.Errorf("read web_intake_key: %w", err)
	}
	src := env.Source
	if src == nil {
		st, err := app.ConnectDomainApply(ctx, app.Getenv(env.Getenv))
		if err != nil {
			return err
		}
		defer st.Close()
		src = st
	}
	in := Inputs{
		Source:  src,
		EnvFile: envFile,
		TLSDir:  tlsDir,
		WebKey:  []byte(webKey.Reveal()),
		Now:     env.Now(),
		Out:     env.Stdout,
		Log:     env.Stderr,
	}
	if commit {
		prev := envFile + ".prev"
		if _, err := os.Stat(prev); err == nil {
			in.PrevEnvFile = prev
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("look for the previous .env file: %w", err)
		}
		return Commit(ctx, in)
	}
	return Apply(ctx, in)
}

// Package admincli is the ctrlz-admin command line (spec 10.1) and the key
// tools of spec 8: `keys derive`, `keys status`, `keys declare-lost`, `rekey`
// and `audit-note`.
//
// It runs inside the admin container (`docker compose exec admin ctrlz-admin`),
// inherits that container's environment and secret files, and connects to
// Postgres as ctrlz_admin with one connection. Its output is the command's
// output and never goes through slog: `exec` output is not captured by the
// json-file log driver, so a one-time password printed here does not reach
// `docker logs` (10.1, 18.4).
//
// A one-time password is never printed: it goes to the file --out-file names,
// created with mode 0600, and stdout carries only that path. A command that issues
// one and has no --out-file exits before it changes anything (output.go). Nothing
// here tries to tell a terminal from a log; that guess failed in four review
// rounds (admin-r1-2, admin-r1-18, admin-r2-6, admin-r3-6).
package admincli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/app"
	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/password"
	"github.com/Kup1ng/CtrlZ-Panel/internal/keyring"
	"github.com/Kup1ng/CtrlZ-Panel/internal/ratelimit"
	"github.com/Kup1ng/CtrlZ-Panel/internal/store"
)

// Exit codes. 1 is a failed command, 2 is a usage error, 3 a refusal.
const (
	ExitOK    = 0
	ExitFail  = 1
	ExitUsage = 2
	// ExitRefused is a key tool declining because the key files are not the root's. It
	// is its own code so scripts/gen-secrets.sh can tell "nothing was written, take
	// back the root I just made" from a failure part way (review round 5, key-identity).
	ExitRefused = 3
	// ExitRefusedMissing is ExitRefused with a key file also missing (admin-r14-7): the refusal wrote
	// nothing, so the missing file was not made either, and a script that carries on after exit 3 because
	// the root is off the host must not carry on here, or the stack fails later at `docker compose up`
	// with a missing secret and nothing pointing back to the root.
	ExitRefusedMissing = 4
)

// Env is everything a command touches outside its own arguments, so a test can
// replace it. A zero Env is the real process.
type Env struct {
	Getenv func(string) string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Now    func() time.Time

	// Open replaces the connection to Postgres and the key ring, for tests that
	// already hold a store. Nil connects from the environment (app.ConnectAdmin).
	Open func(ctx context.Context) (*Tools, error)
	// OpenRekey is Open for the user_totp rekey tool.
	OpenRekey func(ctx context.Context) (*RekeyTools, error)
	// OpenOut replaces os.OpenFile for the --out-file of a command that issues a one-time password, so a
	// test can make the write fail after a real O_EXCL create (admin-r12-1). Nil opens the file itself.
	OpenOut func(name string, flag int, perm os.FileMode) (io.WriteCloser, error)
}

// Tools is what an admin command works with.
type Tools struct {
	Store  *store.Store
	Keys   *keyring.Ring
	Hasher *password.Hasher
	// ClearRateLimits removes the admin service's request limits from Valkey (`unlock`). Nil when
	// there is no Valkey to clear: the limits are then in the process and not in the console's reach.
	ClearRateLimits func(ctx context.Context) error
	Close           func()
}

// RekeyTools is what the user_totp rekey tool works with.
type RekeyTools struct {
	Store *store.Store
	Keys  *keyring.Ring
	Close func()
}

func (e Env) withDefaults() Env {
	if e.Getenv == nil {
		e.Getenv = os.Getenv
	}
	if e.Stdin == nil {
		e.Stdin = os.Stdin
	}
	if e.Stdout == nil {
		e.Stdout = os.Stdout
	}
	if e.Stderr == nil {
		e.Stderr = os.Stderr
	}
	if e.Now == nil {
		e.Now = time.Now
	}
	if e.Open == nil {
		getenv := e.Getenv
		e.Open = func(ctx context.Context) (*Tools, error) {
			cfg, rt, st, err := app.ConnectAdmin(ctx, getenv)
			if err != nil {
				return nil, err
			}
			t := &Tools{Store: st, Keys: rt.Keys, Hasher: rt.Hasher, Close: st.Close}
			if cfg.ValkeyAddr != "" {
				v := ratelimit.NewValkey(ratelimit.ValkeyConfig{Addr: cfg.ValkeyAddr, Username: cfg.ValkeyUsername, Password: cfg.ValkeyPassword, IndexKey: ratelimit.IndexKey(ratelimit.Admin)})
				t.ClearRateLimits = func(ctx context.Context) error {
					_, err := v.ResetIndexed(ctx)
					return err
				}
				t.Close = func() { v.Close(); st.Close() }
			}
			return t, nil
		}
	}
	if e.OpenRekey == nil {
		getenv := e.Getenv
		e.OpenRekey = func(ctx context.Context) (*RekeyTools, error) {
			_, ring, st, err := app.ConnectRekey(ctx, getenv)
			if err != nil {
				return nil, err
			}
			return &RekeyTools{Store: st, Keys: ring, Close: st.Close}, nil
		}
	}
	return e
}

// Commands lists the commands RunWith dispatches (help aside). The coverage test of the
// one-time-state rule (internal/auth/credstate) takes its operations from it, so a command
// added to the switch without a line here, or without a row in the table of what each
// credential state may do, fails TestCommandsMatchTheDispatch or TestEveryOperationHasARow.
func Commands() []string {
	return []string{"bootstrap", "reset-password", "reset-totp", "unlock", "keys", "rekey", "audit-note", "audit"}
}

// Run is `ctrlz-admin <command>`. It returns the process exit code.
func Run(ctx context.Context, args []string) int { return RunWith(ctx, args, Env{}) }

// RunWith is Run on a given environment.
func RunWith(ctx context.Context, args []string, env Env) int {
	env = env.withDefaults()
	if len(args) == 0 {
		return usage(env.Stderr)
	}
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "-h", "--help", "help":
		usageTo(env.Stdout)
		return ExitOK
	case "bootstrap":
		err = runBootstrap(ctx, env, rest)
	case "reset-password":
		err = runReset(ctx, env, rest, false)
	case "reset-totp":
		err = runReset(ctx, env, rest, true)
	case "unlock":
		err = runUnlock(ctx, env, rest)
	case "keys":
		err = runKeysAdmin(ctx, env, rest)
	case "rekey":
		err = runRekeyAdmin(ctx, env, rest)
	case "audit-note":
		err = runAuditNote(ctx, env, rest)
	case "audit":
		err = runAudit(ctx, env, rest)
	default:
		fmt.Fprintf(env.Stderr, "ctrlz-admin: unknown command %q\n", cmd)
		return usage(env.Stderr)
	}
	return finish(env, err)
}

// finish prints an error and picks the exit code. Errors here are fixed strings
// and store errors, which carry no driver detail, so printing them is safe.
func finish(env Env, err error) int {
	switch {
	case err == nil:
		return ExitOK
	case errors.Is(err, flag.ErrHelp):
		return ExitOK
	case errors.As(err, new(missingKeyFilesError)):
		fmt.Fprintf(env.Stderr, "ctrlz-admin: %v\n", err)
		return ExitRefusedMissing
	case errors.Is(err, keyring.ErrRootMismatch):
		fmt.Fprintf(env.Stderr, "ctrlz-admin: %v\n", err)
		return ExitRefused
	case errors.As(err, new(usageError)):
		fmt.Fprintf(env.Stderr, "ctrlz-admin: %v\n", err)
		return ExitUsage
	}
	fmt.Fprintf(env.Stderr, "ctrlz-admin: %v\n", err)
	return ExitFail
}

// usageError is a mistake in the arguments, not a failed command.
type usageError string

func (e usageError) Error() string { return string(e) }

func usageErr(format string, a ...any) error { return usageError(fmt.Sprintf(format, a...)) }

func usageTo(w io.Writer) {
	fmt.Fprint(w, `usage: ctrlz-admin <command>

  bootstrap [--username X] --out-file PATH     create the first admin (refuses if one exists)
  reset-password --user X --out-file PATH      new one-time password, sessions ended
  reset-totp --user X --out-file PATH          reset-password, and forget the authenticator
                                               (the password goes to PATH, mode 0600, and PATH is printed)
  unlock --user X                              clear that admin's login throttle
  keys status <domain>                         count stored ciphertext by key number, and how many open
  keys declare-lost <domain> --key-number N --yes   record the loss (user_totp seeds are then cleared by "ctrlz declare-lost" in the tools container)
  rekey <domain>                               re-encrypt admin_totp or sms_cred under the newest key
  audit-note <key.rotated|key.declared_lost> --domain D --key-number N
  audit verify                                 walk the audit hash chain
`)
}

func usage(w io.Writer) int {
	usageTo(w)
	return ExitUsage
}

// newFlags makes a flag set that reports to stderr and never exits the process.
func newFlags(env Env, name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	return fs
}

// parse parses args, flags and positionals in any order (`audit-note key.rotated
// --domain x` as well as `--domain x key.rotated`), and returns the positionals.
// A flag mistake is a usage error.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, err
			}
			return nil, usageErr("%v", err)
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// withTools opens the connection for a command and closes it afterwards.
func withTools(ctx context.Context, env Env, fn func(*Tools) error) error {
	t, err := env.Open(ctx)
	if err != nil {
		return err
	}
	if t.Close != nil {
		defer t.Close()
	}
	return fn(t)
}

// prompt reads one line from stdin after printing a question.
func prompt(env Env, question string) (string, error) {
	fmt.Fprint(env.Stderr, question)
	line, err := bufio.NewReader(env.Stdin).ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || line == "") {
		return "", errors.New("no input")
	}
	return strings.TrimSpace(line), nil
}

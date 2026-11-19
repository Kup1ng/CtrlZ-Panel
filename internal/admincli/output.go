package admincli

import (
	"errors"
	"io"
	"os"

	"github.com/Kup1ng/CtrlZ-Panel/internal/secret"
)

// noOutFileText is the refusal of the output rule (10.1): a one-time password is
// never printed, so a command that issues one needs a file to put it in. The text
// says what to do instead, because the operator sees it with nothing else to go on.
const noOutFileText = "--out-file PATH is required: ctrlz-admin never prints a one-time password, it writes it to a new file (mode 0600) and prints the path; PATH must be on a host mount, for example docker compose run --rm --no-deps -v \"$dir:/out\" admin ctrlz-admin <command> --out-file /out/otp"

// output is where a command's one-time password goes: a file and nothing else.
// There is no terminal branch on purpose (review rounds 1 to 4, admin-r1-2,
// admin-r1-18, admin-r2-6, admin-r3-6). Whether stdout was safe from `docker logs`
// was guessed from the process (a character device, PID 1, PPID 0), and every
// round found a launch form (`compose run`, `docker run -t`, `--init`, `exec`) for
// which the guess was wrong. A file cannot be mistaken for a log, and the lint
// TestAdminCLINeverWritesASecretOutsideAFile fails for any other sink.
//
// It is prepared before the command changes anything, so a refusal leaves no
// half-done reset behind.
type output struct {
	file io.WriteCloser
	path string
}

// prepareOutput creates the file with O_CREATE|O_EXCL and mode 0600, so an
// existing file is never overwritten and nobody else can read the new one. An
// empty path is a usage error.
func prepareOutput(env Env, outFile string) (*output, error) {
	if outFile == "" {
		return nil, usageError(noOutFileText)
	}
	open := env.OpenOut
	if open == nil {
		open = func(name string, flag int, perm os.FileMode) (io.WriteCloser, error) {
			return os.OpenFile(name, flag, perm)
		}
	}
	f, err := open(outFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		// The path is the operator's own, but the OS error can name more than
		// they typed, so report the class.
		if errors.Is(err, os.ErrExist) {
			return nil, errors.New("--out-file: the file already exists")
		}
		return nil, errors.New("--out-file: the file cannot be created")
	}
	return &output{file: f, path: outFile}, nil
}

// write puts the password in the file after the change committed and closes it.
// It is the one place a one-time password is revealed, and the one function of
// this package that the secret-output lint lets write a secret to a descriptor.
func (o *output) write(label string, pw secret.String) error {
	line := []byte(label + ": " + pw.Reveal() + "\n")
	_, err := o.file.Write(line)
	clear(line)
	if cerr := o.file.Close(); err == nil {
		err = cerr
	}
	o.file = nil
	if err != nil {
		// The file is removed with the failure (admin-r12-1): the password in it is empty or cut, nobody
		// can use it, and an O_EXCL file left behind would refuse the same --out-file path when the
		// operator runs reset-password again, as the message tells them to. Nothing of the password is
		// left on disk either way. A failed write does not run the throttle clear of reset-password: the
		// operator's next reset does (spec 10.1).
		_ = os.Remove(o.path)
		return errors.New("the change was made but the one-time password could not be written; run reset-password to get a new one")
	}
	return nil
}

// announce prints where the password went. The path is the operator's own
// argument and holds no secret, so it is the only thing a command prints to
// stdout about a password.
func (o *output) announce(w io.Writer) { _, _ = io.WriteString(w, o.path+"\n") }

// abandon removes a file that was created for a command that then failed, so an
// empty file does not look like a result.
func (o *output) abandon() {
	if o.file != nil {
		_ = o.file.Close()
		_ = os.Remove(o.path)
		o.file = nil
	}
}

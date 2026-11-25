// Package toolcmd is the one place Go code starts `go` and `git` (round 18, admin-r18-13): the two programs
// besides a container runtime that a test or a tool of this repository starts. deploy.DockerRun is the place for
// the runtime. It is a package of its own and not a part of deploy because deploy is a test harness that
// production code may not import, and the mutation tool (a tool, not a test) starts both programs.
//
// Both programs can run any command a caller can spell: `git -c alias.x='!cmd' x`, `git -c core.sshCommand=...`,
// `go test -exec cmd`, `go build -toolexec cmd`, a GOFLAGS or a GIT_SSH_COMMAND in the environment. The exec lint
// (internal/lint TestGoRunsNoContainerCommandOutsideDeploy) used to let a file start them by literal name and left
// their arguments and environment unjudged, so the command line of a container could ride in them, past
// deploy.DockerRun and its digest check. The class is closed the way DockerRun closed the image: the arguments are
// judged HERE, by value, so a wrapper, an append and a spread all meet the check, and the lint refuses every other
// way to start them.
//
//   - the verb is on a closed list and the only option before it is `-C dir` (git) or none (go), so `-c`,
//     `--exec-path`, `--config-env` and the rest of git's global options cannot come first;
//   - after the verb a flag is accepted only when it is on the verb's own list (toolFlags), which are the ones the
//     repository uses and none of which chooses a program; everything else that starts with `-` panics, so a flag a
//     later toolchain adds starts refused;
//   - the environment is BUILT from an allow list (toolPassName: the variables a toolchain needs to find its
//     caches and its machine, and nothing else), never copied from the process with a deny list in front, so a
//     variable nobody thought of (GIT_EXEC_PATH, GIT_CONFIG_PARAMETERS, PAGER, GOAUTH, GOROOT) does not reach
//     the child; the few settings that choose a program and could also come from a file are forced to a neutral
//     value (toolNeutral; GOENV=off makes go ignore its own settings file, where `go env -w GOFLAGS=-toolexec=x`
//     lives, and GIT_CONFIG_GLOBAL makes git ignore ~/.gitconfig), and the caller's extra variables are limited
//     to the names of toolEnvNames (admin-r18-17);
//   - the command is returned as a ToolCmd that exposes none of the fields of exec.Cmd, so Path, Args and Env cannot
//     be reassigned after the check from a file that never imports os/exec.
package toolcmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// toolFlags are the flags a verb accepts after it, by program and verb, written without their dashes.
func toolFlags(prog, verb string) (flags map[string]bool, ok bool) {
	switch prog + " " + verb {
	case "go list":
		return map[string]bool{"find": true, "e": true, "f": true, "deps": true, "json": true}, true
	case "go test":
		return map[string]bool{"count": true, "json": true, "timeout": true, "run": true, "short": true, "v": true}, true
	case "go mod":
		return map[string]bool{"json": true}, true // `go mod edit -json`: edit with no other flag writes nothing
	case "go help":
		return map[string]bool{}, true
	case "go env":
		// Names only, as in `go env GOVERSION`: no flag, so `-w` and `-u` (which write the settings file go reads) are refused.
		return map[string]bool{}, true
	case "git ls-files":
		return map[string]bool{"z": true, "cached": true, "others": true, "exclude-standard": true}, true
	case "git merge-base":
		return map[string]bool{}, true
	case "git init", "git add", "git commit", "git show", "git diff", "git rev-parse", "git log", "git rm":
		return map[string]bool{"A": true, "verify": true, "q": true, "quiet": true, "m": true, "a": true, "all": true, "name-only": true,
			"allow-empty": true, "no-gpg-sign": true, "initial-branch": true, "b": true, "no-edit": true, "format": true, "pretty": true,
			"git-dir": true, "show-toplevel": true, "n": true, "max-count": true, "porcelain": true, "stat": true}, true
	}
	return nil, false
}

// toolEnvNames are the variables a caller may add to the environment of Go or Git.
func toolEnvNames(name string) bool {
	switch name {
	case "CGO_ENABLED", "GOWORK", "GOOS", "GOARCH", "GOFLAGS", "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL":
		return true
	}
	return strings.HasPrefix(name, "CTRLZ_")
}

// toolPassName reports whether a variable of the process may reach the child. It is an allow list: the
// location and machine variables a toolchain needs (cache directories, the proxy of a module download, the
// Docker settings and image names of the container tests that `go test` starts), and the CTRLZ_ names the tests
// of this repository read. Names are matched without regard to case, as Windows does. The settings that can run
// a program (GOFLAGS, GOENV, GOAUTH, GOROOT, GOTOOLCHAIN, CC, every GIT_ variable) are not here.
func toolPassName(name string) bool {
	up := strings.ToUpper(name)
	switch up {
	case "PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "TEMP", "TMP", "TMPDIR",
		"HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA", "APPDATA", "PROGRAMDATA",
		"PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMW6432", "USERNAME", "USERDOMAIN", "COMPUTERNAME",
		"NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "OS", "LANG", "LC_ALL", "TZ", "XDG_CACHE_HOME",
		"GOPATH", "GOCACHE", "GOMODCACHE", "GOTMPDIR", "GOPROXY", "GOSUMDB", "GONOSUMDB", "GONOSUMCHECK",
		"GOPRIVATE", "GONOPROXY", "GOINSECURE", "GOVCS",
		"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR",
		"POSTGRES_IMAGE", "TIMING_SAMPLES":
		return true
	}
	return strings.HasPrefix(up, "CTRLZ_") || strings.HasPrefix(up, "DOCKER_") || strings.HasPrefix(up, "TESTCONTAINERS_")
}

// toolNeutral are the settings that make go or git run another program, forced to a value that does not. They
// are set last, so neither the process environment nor a caller's extra variable can move them. GOENV=off is
// the one that matters most for go: cmd/go reads GOFLAGS from its settings file when the variable is empty, so
// GOFLAGS= alone does not keep a `go env -w GOFLAGS=-toolexec=x` out (admin-r18-17).
func toolNeutral() []string {
	return []string{
		"GOFLAGS=", "GOENV=off",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_EXTERNAL_DIFF=", "GIT_SSH_COMMAND=", "GIT_SSH=", "GIT_ASKPASS=", "GIT_PAGER=cat", "GIT_EDITOR=true",
		"GIT_CONFIG_COUNT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0",
	}
}

// Cmd is a command of Go or Git whose program, arguments and environment are fixed by the constructor. It wraps
// the exec.Cmd and exposes none of its fields (they are assignable from any file, whether it imports os/exec or
// not, which no lint of the call sites can see); it offers what the callers need: the directory, where the error
// output goes, and the ways to run it and read its output.
type Cmd struct{ c *exec.Cmd }

// InDir sets the working directory.
func (t *Cmd) InDir(dir string) *Cmd { t.c.Dir = dir; return t }

// StderrTo sends the error output to w.
func (t *Cmd) StderrTo(w io.Writer) *Cmd { t.c.Stderr = w; return t }

// Output runs the command and returns its standard output.
func (t *Cmd) Output() ([]byte, error) { return t.c.Output() }

// CombinedOutput runs the command and returns its standard output and error output together.
func (t *Cmd) CombinedOutput() ([]byte, error) { return t.c.CombinedOutput() }

// StdoutPipe, Start and Wait run the command with its output read as it comes.
func (t *Cmd) StdoutPipe() (io.ReadCloser, error) { return t.c.StdoutPipe() }
func (t *Cmd) Start() error                       { return t.c.Start() }
func (t *Cmd) Wait() error                        { return t.c.Wait() }

func newCmd(ctx context.Context, prog string, pre []string, verb string, env []string, args []string) *Cmd {
	flags, ok := toolFlags(prog, verb)
	if !ok {
		panic(fmt.Sprintf("toolcmd: %s %s is not a command a test may run", prog, verb))
	}
	for _, a := range args {
		if !strings.HasPrefix(a, "-") || a == "-" {
			continue // a value, a package, a path
		}
		name, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !flags[name] {
			panic(fmt.Sprintf("toolcmd: %s %s does not take the flag %s here", prog, verb, strings.SplitN(a, "=", 2)[0]))
		}
	}
	cmd := exec.CommandContext(ctx, prog, append(append(append([]string{}, pre...), verb), args...)...)
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); toolPassName(name) {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if !toolEnvNames(name) {
			panic(fmt.Sprintf("toolcmd: %s may not be set for %s", name, prog))
		}
		// GOFLAGS may be given by the caller only as the empty value that clears a developer's flags.
		if name == "GOFLAGS" && kv != "GOFLAGS=" {
			panic("toolcmd: GOFLAGS is not settable for go")
		}
		cmd.Env = append(cmd.Env, kv)
	}
	cmd.Env = append(cmd.Env, toolNeutral()...)
	return &Cmd{cmd}
}

// Go is `go <verb> <args...>` with the extra environment `env` (names of toolEnvNames only).
func Go(ctx context.Context, env []string, verb string, args ...string) *Cmd {
	return newCmd(ctx, "go", nil, verb, env, args)
}

// Git is `git [-C dir] <verb> <args...>` with the extra environment `env` (names of toolEnvNames only, such as
// the identity of a commit). dir may be empty. The only option before the verb is -C.
func Git(ctx context.Context, dir string, env []string, verb string, args ...string) *Cmd {
	var pre []string
	if dir != "" {
		pre = []string{"-C", dir}
	}
	return newCmd(ctx, "git", pre, verb, env, args)
}

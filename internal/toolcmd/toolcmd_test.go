package toolcmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustPanic(t *testing.T, name string, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s was accepted", name)
		}
	}()
	f()
}

// TestGoAndGitJudgeTheirCommandLine (admin-r18-13): the forms that run another program through go or git are
// refused when the command is made, whatever shape the caller's code has (a wrapper, an append and a spread all
// reach the same check), and the environment cannot move the settings that make either tool run a program.
func TestGoAndGitJudgeTheirCommandLine(t *testing.T) {
	ctx := context.Background()
	for name, f := range map[string]func(){
		"git -c before the verb":       func() { Git(ctx, "", nil, "-c", "alias.r=!docker run alpine:3.20") },
		"git config":                   func() { Git(ctx, "", nil, "config", "alias.r", "!docker run alpine") },
		"git an alias verb":            func() { Git(ctx, "", nil, "r") },
		"git a flag nobody listed":     func() { Git(ctx, "", nil, "diff", "--ext-diff") },
		"git -c after the verb":        func() { Git(ctx, "", nil, "log", "-c", "core.pager=docker run x") },
		"git an extra variable":        func() { Git(ctx, "", []string{"GIT_SSH_COMMAND=docker run x"}, "show", "HEAD") },
		"git a config variable":        func() { Git(ctx, "", []string{"GIT_CONFIG_COUNT=1"}, "show", "HEAD") },
		"go test -exec":                func() { Go(ctx, nil, "test", "-exec", "docker run x", "./x") },
		"go test -exec=":               func() { Go(ctx, nil, "test", "-exec=docker run x", "./x") },
		"go build -toolexec":           func() { Go(ctx, nil, "build", "-toolexec", "docker run x") },
		"go list -toolexec":            func() { Go(ctx, nil, "list", "-toolexec=docker run x") },
		"go run":                       func() { Go(ctx, nil, "run", "./x") },
		"go generate":                  func() { Go(ctx, nil, "generate", "./...") },
		"go with GOFLAGS":              func() { Go(ctx, []string{"GOFLAGS=-toolexec=docker"}, "list") },
		"go with a name nobody listed": func() { Go(ctx, []string{"GOTOOLCHAIN=local"}, "list") },
		"go mod edit with a replace":   func() { Go(ctx, nil, "mod", "edit", "-replace=a=b") },
		"go env -w":                    func() { Go(ctx, nil, "env", "-w", "GOFLAGS=-toolexec=docker") },
		"go env -u":                    func() { Go(ctx, nil, "env", "-u", "GOFLAGS") },
	} {
		mustPanic(t, name, f)
	}
	if got := strings.Join(Go(ctx, []string{"GOWORK=off", "GOFLAGS="}, "env", "GOVERSION").c.Args, " "); got != "go env GOVERSION" {
		t.Errorf("go env args = %q", got)
	}
	ok := Go(ctx, []string{"CGO_ENABLED=1", "GOWORK=off", "GOFLAGS=", "GOOS=linux", "CTRLZ_SPEC=x"}, "test", "-count=1", "-json", "-timeout", "20m", "-run", "^(A|B)$", "./x")
	if got := strings.Join(ok.c.Args, " "); got != "go test -count=1 -json -timeout 20m -run ^(A|B)$ ./x" {
		t.Errorf("go args = %q", got)
	}
	g := Git(ctx, "/repo", []string{"GIT_AUTHOR_NAME=t"}, "commit", "-q", "--no-gpg-sign", "-m", "x")
	if got := strings.Join(g.c.Args, " "); got != "git -C /repo commit -q --no-gpg-sign -m x" {
		t.Errorf("git args = %q", got)
	}
	// The neutral settings come last, so nothing before them (the process, the caller) wins.
	t.Setenv("GIT_SSH_COMMAND", "docker run x")
	t.Setenv("GOFLAGS", "-toolexec=docker")
	env := Git(ctx, "", nil, "show", "HEAD").c.Env
	last := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		last[k] = v
	}
	for _, k := range []string{"GIT_SSH_COMMAND", "GIT_EXTERNAL_DIFF", "GIT_CONFIG_COUNT"} {
		if v := last[k]; k != "GIT_CONFIG_COUNT" && v != "" || k == "GIT_CONFIG_COUNT" && v != "0" {
			t.Errorf("%s = %q after the constructor", k, v)
		}
	}
	if v := Go(ctx, nil, "list").c.Env; func() string {
		out := ""
		for _, kv := range v {
			if strings.HasPrefix(kv, "GOFLAGS=") {
				out = kv
			}
		}
		return out
	}() != "GOFLAGS=" {
		t.Error("the GOFLAGS of the process reached go")
	}
}

// TestTheEnvironmentIsBuiltFromAnAllowList (admin-r18-17): a variable nobody listed does not reach the child, a
// listed one does (in any letter case, as Windows has it), and the settings that choose a program are forced.
func TestTheEnvironmentIsBuiltFromAnAllowList(t *testing.T) {
	ctx := context.Background()
	for _, k := range []string{"GIT_EXEC_PATH", "GIT_CONFIG_PARAMETERS", "GIT_SEQUENCE_EDITOR", "GIT_PROXY_COMMAND", "PAGER", "GOAUTH", "GOROOT", "GOTOOLCHAIN", "CC"} {
		t.Setenv(k, "docker-run-x")
	}
	t.Setenv("CTRLZ_SPEC", "spec")
	t.Setenv("DOCKER_HOST", "tcp://d:1")
	t.Setenv("GOENV", "/elsewhere")
	for prog, cmd := range map[string]*Cmd{"git": Git(ctx, "", nil, "show", "HEAD"), "go": Go(ctx, nil, "list")} {
		got := map[string]string{}
		for _, kv := range cmd.c.Env {
			k, v, _ := strings.Cut(kv, "=")
			got[k] = v
		}
		for _, k := range []string{"GIT_EXEC_PATH", "GIT_CONFIG_PARAMETERS", "GIT_SEQUENCE_EDITOR", "GIT_PROXY_COMMAND", "PAGER", "GOAUTH", "GOROOT", "GOTOOLCHAIN", "CC"} {
			if _, ok := got[k]; ok {
				t.Errorf("%s: %s reached the child", prog, k)
			}
		}
		if got["CTRLZ_SPEC"] != "spec" || got["DOCKER_HOST"] != "tcp://d:1" {
			t.Errorf("%s: a listed variable did not reach the child", prog)
		}
		if prog == "git" && got["GIT_CONFIG_GLOBAL"] != os.DevNull {
			t.Errorf("git reads the global settings file: GIT_CONFIG_GLOBAL = %q", got["GIT_CONFIG_GLOBAL"])
		}
		if got["GOENV"] != "off" {
			t.Errorf("%s: GOENV = %q, want off (go reads GOFLAGS from its settings file otherwise)", prog, got["GOENV"])
		}
	}
	for _, c := range []struct {
		name string
		want bool
	}{{"Path", true}, {"SystemRoot", true}, {"GOFLAGS", false}, {"GIT_DIR", false}, {"CTRLZ_X", true}, {"ctrlz_x", true}, {"", false}, {"GOPATH", true}} {
		if toolPassName(c.name) != c.want {
			t.Errorf("toolPassName(%q) != %v", c.name, c.want)
		}
	}
}

// TestGoIgnoresItsSettingsFile (admin-r18-17): the real behaviour. cmd/go reads GOFLAGS from its settings file
// when the variable is empty, so a developer's `go env -w GOFLAGS=-toolexec=x` reached every toolcmd.Go call.
// The file is planted where go looks for it by default, with a flag that makes any go command fail; the command
// has to run anyway.
func TestGoIgnoresItsSettingsFile(t *testing.T) {
	dir := t.TempDir()
	// The settings file is os.UserConfigDir()/go/env: %AppData% on Windows, and on Linux $XDG_CONFIG_HOME,
	// which toolPassName does not pass to the child, so the default $HOME/.config. The file is planted at
	// both, because the CI runner is Linux and a file at the wrong place left the mutant that drops GOENV=off
	// alive there (first full run of round 18, mutant images-are-pinned-toolcmd-go-reads-its-settings-file).
	for _, d := range []string{filepath.Join(dir, "go"), filepath.Join(dir, ".config", "go")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "env"), []byte("GOFLAGS=-nosuchflag-r18\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, k := range []string{"APPDATA", "XDG_CONFIG_HOME", "HOME"} {
		t.Setenv(k, dir)
	}
	t.Setenv("GOENV", "")
	out, err := Go(context.Background(), nil, "list", "-find", "-e", "-f", "{{.ImportPath}}", "std").CombinedOutput()
	if err != nil {
		t.Fatalf("go list failed (its settings file reached it?): %v\n%s", err, out)
	}
}

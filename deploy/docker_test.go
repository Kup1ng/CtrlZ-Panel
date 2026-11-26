package deploy

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

// TestDockerRunsOnlyAPinnedImage (admin-r17-10): the image is a parameter that is checked, and it ends up
// after the flags and before the command whatever they hold.
func TestDockerRunsOnlyAPinnedImage(t *testing.T) {
	ref := Image("CADDY_IMAGE")
	cmd := DockerRun(context.Background(), ref, []string{"-d", "--name", "x", "--entrypoint", "sh"}, "-c", "true")
	got := strings.Join(cmd.c.Args, " ")
	if want := "docker run -d --name x --entrypoint sh " + ref + " -c true"; got != want {
		t.Errorf("args = %q, want %q", got, want)
	}
	for _, bad := range []string{"alpine:3.20", "alpine", "alpine@sha256:" + strings.Repeat("a", 64), ""} {
		mustPanic(t, "DockerRun of "+bad, func() { DockerRun(context.Background(), bad, nil) })
	}
	mustPanic(t, "a second image among the flags", func() { DockerRun(context.Background(), ref, []string{"-d", ref}) })
}

// TestDockerTakesOnlyTheVerbsThatBringNoImage: run, create, pull, build and the rest are refused, and so is a
// flag in front of the verb.
func TestDockerTakesOnlyTheVerbsThatBringNoImage(t *testing.T) {
	ctx := context.Background()
	for _, ok := range [][]string{{"exec", "c", "true"}, {"logs", "c"}, {"inspect", "c"}, {"rm", "-f", "c"}, {"network", "create", "n"}, {"image", "inspect", "i"}, {"port", "c", "80/tcp"}} {
		if got := Docker(ctx, ok...).c.Args; got[0] != "docker" || got[1] != ok[0] {
			t.Errorf("%v became %v", ok, got)
		}
	}
	for _, bad := range [][]string{nil, {"run", "alpine"}, {"create", "alpine"}, {"pull", "alpine"}, {"image", "pull", "alpine"}, {"image", "load"}, {"build", "."}, {"load"}, {"import", "x"}, {"tag", "a", "b"}, {"push", "a"}, {"commit", "c"}, {"compose", "up"}, {"compose", "pull"}, {"compose"}, {"container", "run", "alpine"}, {"-H", "tcp://x", "ps"}, {"network"}, {"network", "prune"}} {
		bad := bad
		mustPanic(t, "docker "+strings.Join(bad, " "), func() { Docker(ctx, bad...) })
	}
}

// fakeDocker answers pinReaper's commands from a state, and records them.
type fakeDocker struct {
	digests  []string // the repo digests the local tag has
	pullFail bool
	tagMoves bool // whether `tag` makes the local tag carry the reviewed digest
	calls    []string
}

func (f *fakeDocker) run(_ context.Context, args ...string) (string, error) {
	f.calls = append(f.calls, strings.Join(args[:2], " "))
	switch args[0] {
	case "image":
		return strings.Join(f.digests, "\n"), nil
	case "pull":
		if f.pullFail {
			return "no route to host", context.DeadlineExceeded
		}
	case "tag":
		if f.tagMoves {
			f.digests = []string{reaperRef}
		}
	}
	return "", nil
}

// TestPinReaperChoosesTheReviewedBytes (admin-r17-2, -8): a local tag that carries the reviewed digest is left
// alone; any other state pulls the digest and moves the tag; and a run that cannot end with the reviewed bytes
// under the tag fails and does not go on.
func TestPinReaperChoosesTheReviewedBytes(t *testing.T) {
	ctx := context.Background()
	f := &fakeDocker{digests: []string{reaperRef}}
	if err := pinReaper(ctx, f.run); err != nil || len(f.calls) != 1 {
		t.Errorf("the reviewed image was on the machine: err %v, calls %v", err, f.calls)
	}
	f = &fakeDocker{digests: []string{"testcontainers/ryuk@sha256:" + strings.Repeat("b", 64)}, tagMoves: true}
	if err := pinReaper(ctx, f.run); err != nil || strings.Join(f.calls, ",") != "image inspect,pull --quiet,tag testcontainers/ryuk@"+ReaperDigest+",image inspect" {
		t.Errorf("another image under the tag: err %v, calls %v", err, f.calls)
	}
	f = &fakeDocker{pullFail: true}
	if err := pinReaper(ctx, f.run); err == nil {
		t.Error("an unreachable registry with no local copy was accepted")
	}
	f = &fakeDocker{digests: []string{"testcontainers/ryuk@sha256:" + strings.Repeat("b", 64)}}
	if err := pinReaper(ctx, f.run); err == nil {
		t.Error("a tag that still holds other bytes after the move was accepted")
	}
	if !strings.HasPrefix(ReaperDigest, "sha256:") || len(ReaperDigest) != 71 {
		t.Errorf("ReaperDigest %q is not a sha256 digest", ReaperDigest)
	}
}

// TestPinReaperAgainstDocker runs the real thing once: after PinReaper the local tag carries the reviewed
// digest, whatever it held before. It needs Docker and the registry (or a local copy), so -short skips it.
func TestPinReaperAgainstDocker(t *testing.T) {
	if testing.Short() {
		t.Skip("-short: needs Docker")
	}
	ctx := context.Background()
	if err := PinReaper(ctx); err != nil {
		t.Fatal(err)
	}
	if !reaperHasDigest(ctx, realDocker) {
		t.Errorf("%s does not carry %s after PinReaper", ReaperTag, ReaperDigest)
	}
}

// TestThePinRefusesAMachineWhoseLibrarySettingsSendTheReaperElsewhere (admin-r18-11): a hub prefix, a daemon
// override, a legacy variable or a property nobody listed each make the library ask for another name or another
// daemon than the one PinReaper pinned, and anything unlisted of those namespaces fails closed.
func TestThePinRefusesAMachineWhoseLibrarySettingsSendTheReaperElsewhere(t *testing.T) {
	dir := t.TempDir()
	write := func(text string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, ".testcontainers.properties"), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		name    string
		environ []string
		props   string
		bad     bool
	}{
		{"nothing set", []string{"PATH=/bin", "HOME=/h"}, "", false},
		{"the CI switch", []string{"TESTCONTAINERS_RYUK_DISABLED=true"}, "", false},
		{"a daemon both read", []string{"DOCKER_HOST=tcp://10.0.0.1:2375"}, "", false},
		{"a hub prefix", []string{"TESTCONTAINERS_HUB_IMAGE_NAME_PREFIX=registry.mirror.example"}, "", true},
		{"a daemon override", []string{"TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/other.sock"}, "", true},
		{"a legacy variable", []string{"TC_HOST=elsewhere"}, "", true},
		{"a variable of the library nobody knows", []string{"TESTCONTAINERS_SOMETHING_NEW=1"}, "", true},
		{"a Docker variable nobody listed", []string{"DOCKER_CONTEXT=remote"}, "", true},
		{"the same name in lower case", []string{"testcontainers_hub_image_name_prefix=x"}, "", true},
		{"a harmless property", nil, "# a comment\nryuk.verbose=true\n", false},
		{"a hub prefix in the file", nil, "hub.image.name.prefix=registry.mirror.example\n", true},
		{"a daemon in the file", nil, "tc.host=tcp://elsewhere\n", true},
		{"docker.host in the file", nil, "docker.host : tcp://elsewhere\n", true},
		{"a property with a space separator", nil, "docker.host tcp://elsewhere\n", true},
	} {
		os.Remove(filepath.Join(dir, ".testcontainers.properties"))
		if c.props != "" {
			write(c.props)
		}
		got := libraryConfigProblems(c.environ, dir)
		if (len(got) > 0) != c.bad {
			t.Errorf("%s: problems %v, want a problem: %v", c.name, got, c.bad)
		}
	}
	// A file that exists and cannot be read is a problem, not a pass (a directory of that name cannot be read as
	// a file). The loop left the last case's file in place, so it goes first, and the setup must work: this block
	// was silently skipped when the Mkdir failed, which made it a test that could not fail (admin-r18-22).
	if err := os.Remove(filepath.Join(dir, ".testcontainers.properties")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, ".testcontainers.properties"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := libraryConfigProblems(nil, dir); len(got) != 1 || !strings.Contains(got[0], "cannot be read") {
		t.Errorf("an unreadable properties file gave %v, want the one problem", got)
	}
}

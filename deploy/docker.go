package deploy

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// This file is the one place Go code builds a docker command line (round 17, admin-r17-10). The image rule
// (rules.md, images-are-pinned) reads every place an image is NAMED, but a test that appended an image to
// the arguments of `docker run` (`args = append(args, "alpine:3.20", ...)`) put it where no reader of the
// source can find its position, so a floating image could run with every lint green. The construction is that
// the arguments are not built by the caller any more:
//
//   - DockerRun takes the image as its own parameter, puts it in the one position where docker reads it, and
//     refuses (panics) anything that is not tag@sha256. A test cannot run an image it did not get from Image.
//   - Docker takes a verb that only looks at something that already runs or is already here (exec, logs,
//     inspect, ...), and refuses every other: run, create, pull, build, load, import, tag, push, commit, compose
//     and a flag before the verb (`-H`, `--context`, which would point the client at another daemon).
//
// internal/lint TestGoRunsNoContainerCommandOutsideDeploy fails for any other os/exec call whose command is a
// container runtime or is not a literal.

// dockerVerb reports whether Docker accepts the verb, and for the verbs that have sub-commands which of them (a
// nil set means the verb has none to judge). A function and not a package variable (rule: no package-level
// mutable state).
func dockerVerb(verb string) (subs map[string]bool, ok bool) {
	switch verb {
	case "exec", "inspect", "logs", "port", "restart", "kill", "rm", "ps", "cp", "stop", "start", "wait", "top":
		return nil, true
	case "network":
		return map[string]bool{"create": true, "rm": true, "connect": true, "disconnect": true, "inspect": true}, true
	case "compose":
		// compose config reads the file and prints it; it starts and pulls nothing.
		return map[string]bool{"config": true}, true
	case "image":
		return map[string]bool{"inspect": true}, true
	}
	return nil, false
}

// Docker is `docker <args...>` for a verb of dockerVerbs. It panics for any other: a verb that can bring an
// image in (run, create, pull, build, load, import) belongs to DockerRun, which checks the image, and the rest
// has no use in a test.
func Docker(ctx context.Context, args ...string) *exec.Cmd {
	if len(args) == 0 {
		panic("deploy: docker with no verb")
	}
	subs, ok := dockerVerb(args[0])
	if !ok {
		panic(fmt.Sprintf("deploy: the docker verb %q is not one a test may run (images come in through DockerRun)", args[0]))
	}
	if subs != nil && (len(args) < 2 || !subs[args[1]]) {
		panic(fmt.Sprintf("deploy: docker %s needs one of its allowed sub-commands", args[0]))
	}
	return exec.CommandContext(ctx, "docker", args...)
}

// DockerRun is `docker run <flags...> <image> <cmd...>`. The image is checked against the pin shape and set after
// the flags by this function, so no flag list can carry it; the flags are the caller's reviewed text (a name,
// a network, a mount, an entrypoint). A flag that is itself an image-shaped word is refused, because it
// would be read as the image when it follows a flag that takes no value.
func DockerRun(ctx context.Context, image string, flags []string, cmd ...string) *exec.Cmd {
	if !pinned.MatchString(image) {
		panic("deploy: DockerRun needs an image pinned by tag and sha256 digest")
	}
	for _, f := range flags {
		if len(f) > 0 && f[0] != '-' && pinned.MatchString(f) {
			panic("deploy: a flag of DockerRun is a second image reference")
		}
	}
	args := append([]string{"run"}, flags...)
	args = append(args, image)
	args = append(args, cmd...)
	return exec.CommandContext(ctx, "docker", args...)
}

// ReaperTag is the image testcontainers starts beside every container test. Its reference is a constant of the
// library (testcontainers.ReaperDefaultImage, v0.45.0 reads no override), it holds the Docker socket to remove
// what a killed test left behind, and the library names it by tag alone, so a registry that moves the tag would
// run other bytes with the socket mounted (admin-r17-2, -8). PinReaper makes the local copy of that tag the
// reviewed bytes before the library asks for it; internal/lint TestTheReaperImageIsTheReviewedOne fails when a
// library bump changes the tag, which is when somebody has to read the new one and read its digest.
const (
	ReaperTag = "testcontainers/ryuk:0.14.0"
	// ReaperDigest is the digest of the image INDEX (read with `docker buildx imagetools inspect`, which does not
	// move a local tag), so the same bytes are chosen on every platform.
	ReaperDigest = "sha256:7c1a8a9a47c780ed0f983770a662f80deb115d95cce3e2daa3d12115b8cd28f0"
)

// reaperRef is the reference by digest.
const reaperRef = "testcontainers/ryuk@" + ReaperDigest

// dockerCmd runs one docker command and returns its output; PinReaper takes it as a parameter so that the
// decision it makes can be tested without a daemon.
type dockerCmd func(ctx context.Context, args ...string) (string, error)

func realDocker(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	return string(out), err
}

// PinReaper makes the local image named ReaperTag the reviewed one: when its repo digests do not include
// ReaperDigest, the image of that digest is pulled and the tag is moved to it, and the answer is checked again.
// Docker pulls a tag only when it is missing, so after this the library finds the reviewed bytes locally and
// fetches nothing. It fails when the reviewed image cannot be had (offline with no local copy), so a run never
// starts the reaper from a tag it did not check. Every starter of a container test calls it first (the harnesses
// of testpg and testvalkey, which internal/lint TestEveryTestcontainersStarterPinsTheReaper requires). It keeps
// no state of its own: after the first success the question is one `docker image inspect`, so a second start
// pays one cheap call, and no lock is held across I/O.
func PinReaper(ctx context.Context) error {
	return pinReaper(ctx, realDocker)
}

func pinReaper(ctx context.Context, run dockerCmd) error {
	if reaperHasDigest(ctx, run) {
		return nil
	}
	if out, err := run(ctx, "pull", "--quiet", reaperRef); err != nil {
		return fmt.Errorf("deploy: the reaper image %s is not on this machine and could not be pulled: %w (%s)", reaperRef, err, firstLine(out))
	}
	if out, err := run(ctx, "tag", reaperRef, ReaperTag); err != nil {
		return fmt.Errorf("deploy: could not tag the reviewed reaper image as %s: %w (%s)", ReaperTag, err, firstLine(out))
	}
	if !reaperHasDigest(ctx, run) {
		return fmt.Errorf("deploy: %s still is not the reviewed image %s after the tag was moved", ReaperTag, ReaperDigest)
	}
	return nil
}

// reaperHasDigest asks whether the local ReaperTag carries the reviewed digest among its repo digests.
func reaperHasDigest(ctx context.Context, run dockerCmd) bool {
	out, err := run(ctx, "image", "inspect", "--format", "{{range .RepoDigests}}{{println .}}{{end}}", ReaperTag)
	if err != nil {
		return false
	}
	for _, ln := range strings.Split(out, "\n") {
		if strings.TrimSpace(ln) == reaperRef {
			return true
		}
	}
	return false
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

package deploy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// What the testcontainers library reads before it names an image or a daemon (round 18, admin-r18-11).
//
// PinReaper makes the local image named ReaperTag the reviewed bytes, on the daemon the docker CLI talks to,
// under that exact name. The library does not always ask for that name on that daemon: it prepends
// hub.image.name.prefix (TESTCONTAINERS_HUB_IMAGE_NAME_PREFIX) to the reaper's reference, so with a mirror
// configured it pulls <prefix>/testcontainers/ryuk:0.14.0 by tag with the Docker socket mounted, and it picks its
// daemon from tc.host, docker.host or TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE independently of the CLI, so the
// pin can land on another daemon than the one that runs the reaper. Both are settings a host of this project
// may well have (a registry mirror is common where Docker Hub is slow), and neither moves any line of source.
//
// So the guard does not try to follow the library's settings. It lists the settings that are harmless and
// refuses to start a container when anything else of the library's namespaces is set, in the environment
// (TESTCONTAINERS_*, TC_*, DOCKER_*) or in ~/.testcontainers.properties: a setting the library adds later, or
// one nobody thought of, fails closed until a person reads it and adds it here.

// libraryEnvOK reports whether a variable of the library's or Docker's namespaces may be set for a test run.
// DOCKER_HOST and the TLS pair point the CLI and the library at the same daemon, because both read them; BUILDKIT
// and the hints only shape the CLI's output; the two TESTCONTAINERS_RYUK switches only switch the reaper off or
// make it talk. A function and not a package variable (rule: no package-level mutable state).
func libraryEnvOK(name string) bool {
	switch name {
	case "DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_BUILDKIT", "DOCKER_CLI_HINTS",
		"TESTCONTAINERS_RYUK_DISABLED", "TESTCONTAINERS_RYUK_VERBOSE":
		return true
	}
	return false
}

// libraryPropertyOK reports whether a key of ~/.testcontainers.properties moves neither an image name nor a daemon.
func libraryPropertyOK(key string) bool {
	switch key {
	case "ryuk.verbose", "ryuk.reconnection.timeout", "ryuk.connection.timeout":
		return true
	}
	return false
}

// libraryConfigProblems returns what in the environment or in the properties file the guard does not accept.
// environ is `KEY=value` lines as os.Environ gives them; home is the directory of the properties file, or empty.
func libraryConfigProblems(environ []string, home string) []string {
	var out []string
	for _, kv := range environ {
		k, _, _ := strings.Cut(kv, "=")
		// Windows keeps the case of a name and compares without it; the libraries read it upper case.
		u := strings.ToUpper(k)
		if (strings.HasPrefix(u, "TESTCONTAINERS_") || strings.HasPrefix(u, "TC_") || strings.HasPrefix(u, "DOCKER_")) && !libraryEnvOK(u) {
			out = append(out, "the environment variable "+k)
		}
	}
	if home != "" {
		// ReadFile and not Open plus a scanner: opening a directory succeeds on Windows and the scanner then
		// stops without an error, so an unreadable file would have passed as an empty one.
		text, err := os.ReadFile(filepath.Join(home, ".testcontainers.properties"))
		if err == nil {
			for _, raw := range strings.Split(string(text), "\n") {
				ln := strings.TrimSpace(raw)
				if ln == "" || ln[0] == '#' || ln[0] == '!' {
					continue
				}
				i := strings.IndexAny(ln, "=: \t")
				key := ln
				if i >= 0 {
					key = ln[:i]
				}
				if !libraryPropertyOK(key) {
					out = append(out, "the property "+key+" of ~/.testcontainers.properties")
				}
			}
		} else if !os.IsNotExist(err) {
			out = append(out, "the file ~/.testcontainers.properties, which cannot be read")
		}
	}
	sort.Strings(out)
	return out
}

// checkLibraryConfig is the part of PinReaper that reads the machine it runs on.
func checkLibraryConfig() error {
	home, _ := os.UserHomeDir()
	if p := libraryConfigProblems(os.Environ(), home); len(p) > 0 {
		return fmt.Errorf("deploy: the testcontainers library would not ask for the reviewed reaper image on this machine, because of %s; unset it for the test run (or add a setting that moves no image name and no daemon to deploy.libraryEnvOK or libraryPropertyOK after reading it)", strings.Join(p, ", "))
	}
	return nil
}

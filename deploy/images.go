// Package deploy gives Go code the one thing the deploy directory owns that code needs: the image
// references. docker-compose.yml names each third-party image once, as a literal `tag@sha256:digest`, and a
// container test (a Valkey, a Caddy, a ClickHouse, a Postgres) asks for the same reference here instead of
// keeping a tag of its own. Before round 16 (admin-r16-15) every test fixture had its own floating tag beside
// the Compose default, so the tests judged a server that nobody deploys. This is the construction that removes
// the class: there is no second place to write a reference, and internal/lint TestEveryImageIsPinnedByDigest
// fails for one that appears anyway. Since round 17 (admin-r17-6) the reference in the Compose file has no
// variable around it either: an .env written before the pins would override it, and Compose would run bytes
// nobody reviewed.
package deploy

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// pinned is the one shape a reference may have: a tag AND a sha256 digest of the image index.
var pinned = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$`)

// serviceOf maps the name a caller asks for to the Compose service whose `image:` is the reference. The names
// are the ones the variables had before round 17; a test process may still set one of them to try another
// build on purpose (below), but Compose reads none of them. A function and not a package variable: the table is
// read-only by construction (internal/lint TestNoPackageLevelMutableState), and the lint that keeps scripts
// from assigning these names reads the switch (deployImageNames).
func serviceOf(name string) (string, bool) {
	switch name {
	case "POSTGRES_IMAGE":
		return "postgres", true
	case "VALKEY_IMAGE":
		return "valkey-api", true
	case "CADDY_IMAGE":
		return "caddy", true
	case "CLICKHOUSE_IMAGE":
		return "clickhouse", true
	case "PLACEHOLDER_IMAGE":
		// The web containers run their own images now (spec 3.2). The throw-away placeholder is the busybox that
		// caddy-init runs, which is the one pinned literal left for it.
		return "caddy-init", true
	}
	return "", false
}

// imageNames are the names serviceOf answers to, for the test that every one resolves.
func imageNames() []string {
	return []string{"POSTGRES_IMAGE", "VALKEY_IMAGE", "CADDY_IMAGE", "CLICKHOUSE_IMAGE", "PLACEHOLDER_IMAGE"}
}

// Image is the literal reference docker-compose.yml gives the service behind name (POSTGRES_IMAGE,
// VALKEY_IMAGE, CADDY_IMAGE, CLICKHOUSE_IMAGE, PLACEHOLDER_IMAGE). A value of that variable in the process
// wins, for a developer who tries another build on purpose, but only a pinned one: an override that is a bare
// tag would run bytes nobody reviewed, which is what the pin is for (admin-r16-19; testpg used to take any
// reference from CTRLZ_TEST_PG_IMAGE). It panics for such a value and when the name or the file's reference
// is not usable: both are mistakes, and a test that ran on a guessed image would prove nothing.
func Image(name string) string {
	if v := os.Getenv(name); v != "" {
		if !pinned.MatchString(v) {
			panic(fmt.Sprintf("deploy: %s is set to a reference without a tag and sha256 digest", name))
		}
		return v
	}
	svc, ok := serviceOf(name)
	if !ok {
		panic(fmt.Sprintf("deploy: %s is not an image name", name))
	}
	ref := composeImage(svc)
	if !pinned.MatchString(ref) {
		panic(fmt.Sprintf("deploy: the image of %s in docker-compose.yml is not a pinned literal reference", svc))
	}
	return ref
}

// composeImage reads `services.<svc>.image` of the embedded Compose file, with anchors and merges resolved.
func composeImage(svc string) string {
	var doc struct {
		Services map[string]struct {
			Image string `yaml:"image"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(composeFile(), &doc); err != nil {
		panic(fmt.Sprintf("deploy: docker-compose.yml: %v", err))
	}
	s, ok := doc.Services[svc]
	if !ok || strings.TrimSpace(s.Image) == "" {
		panic(fmt.Sprintf("deploy: docker-compose.yml has no image for the service %s", svc))
	}
	return s.Image
}

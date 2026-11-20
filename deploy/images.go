// Package deploy gives Go code the one thing the deploy directory owns that code needs: the image
// references. docker-compose.yml names each image once, as `${VAR:-tag@sha256:digest}`, and a container
// test (a Valkey, a Caddy, a ClickHouse, a Postgres) asks for the same reference here instead of keeping a
// tag of its own. Before round 16 (admin-r16-15) every test fixture had its own floating tag beside the
// Compose default, so the tests judged a server that nobody deploys. This is the construction that removes
// the class: there is no second place to write a reference, and internal/lint TestEveryImageIsPinnedByDigest
// fails for one that appears anyway.
package deploy

import (
	"embed"
	"fmt"
	"os"
	"regexp"
)

// composeFS holds the Compose file as it was at build time, read-only.
//
//go:embed compose/docker-compose.yml
var composeFS embed.FS

// pinned is the one shape a reference may have: a tag AND a sha256 digest of the image index.
var pinned = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$`)

// Image is the reference docker-compose.yml gives the variable name (POSTGRES_IMAGE, VALKEY_IMAGE,
// CADDY_IMAGE, CLICKHOUSE_IMAGE, PLACEHOLDER_IMAGE). A value of that variable in the process wins, as it does
// for Compose, so a developer can try another build on purpose, but only a pinned one: an override that is a
// bare tag would run bytes nobody reviewed, which is what the pin is for (admin-r16-19; testpg used to take
// any reference from CTRLZ_TEST_PG_IMAGE). It panics for such a value and when the variable is not in the
// file: both are mistakes, and a test that ran on a guessed image would prove nothing.
func Image(name string) string {
	if v := os.Getenv(name); v != "" {
		if !pinned.MatchString(v) {
			panic(fmt.Sprintf("deploy: %s is set to a reference without a tag and sha256 digest", name))
		}
		return v
	}
	b, err := composeFS.ReadFile("compose/docker-compose.yml")
	if err != nil {
		panic(fmt.Sprintf("deploy: %v", err))
	}
	m := regexp.MustCompile(`\$\{` + regexp.QuoteMeta(name) + `:-([^}]+)\}`).FindSubmatch(b)
	if m == nil {
		panic(fmt.Sprintf("deploy: docker-compose.yml has no default for %s", name))
	}
	return string(m[1])
}

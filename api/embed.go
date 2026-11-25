// Package api embeds the OpenAPI documents so the routers can read the
// x-ctrlz-* extensions of every operation at start-up from the same bytes the
// code was generated from, and a test can read them without a path.
package api

import "embed"

//go:embed openapi.yaml admin-openapi.yaml public-openapi.yaml
var files embed.FS

// Tenant returns api/openapi.yaml.
func Tenant() []byte { return mustRead("openapi.yaml") }

// Admin returns api/admin-openapi.yaml.
func Admin() []byte { return mustRead("admin-openapi.yaml") }

// Public returns api/public-openapi.yaml, the document of the operations an API token may call (generated, P3 6.5).
func Public() []byte { return mustRead("public-openapi.yaml") }

func mustRead(name string) []byte {
	b, err := files.ReadFile(name)
	if err != nil {
		// embed guarantees the files exist; a failure here is a build problem.
		panic("api: embedded document missing: " + name)
	}
	return b
}

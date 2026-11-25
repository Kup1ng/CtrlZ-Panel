// Package catalogfixtures carries the expected state of the database catalog:
// tables, policies, grants, functions, views and roles. The catalog tests in
// internal/store/catalogtest compare what Postgres holds with these files in
// both directions, so an extra object fails as surely as a missing one.
package catalogfixtures

import "embed"

//go:embed *.yaml *.golden
var FS embed.FS

// Package chmigrations carries the ClickHouse migrations inside the binary, so the one-shot
// migrate-analytics container needs no files next to it.
package chmigrations

import (
	"embed"
	"fmt"
)

// Migrations holds the NNNN_name.sql files at its root.
//
//go:embed 0*.sql
var Migrations embed.FS

// accessFS holds access.sql, the row policies and the quota. It is outside Migrations because the runner
// applies it before the first migration and on every run, not once: see the file's own comment. It is an
// embed.FS (read-only, baked in at build time) and not a string variable, which the no-package-state rule
// would refuse.
//
//go:embed access.sql
var accessFS embed.FS

// Access returns the text of access.sql.
func Access() (string, error) {
	b, err := accessFS.ReadFile("access.sql")
	if err != nil {
		return "", fmt.Errorf("migrations/clickhouse: access.sql is not embedded: %w", err)
	}
	return string(b), nil
}

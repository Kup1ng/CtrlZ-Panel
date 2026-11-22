// Package pgmigrations carries the Postgres migrations and the bootstrap SQL
// inside the binary, so ctrlz-migrate needs no files next to it.
package pgmigrations

import "embed"

// Migrations holds the expanded NNNN_name.sql files at its root. The macro
// sources in src/ are deliberately not embedded.
//
//go:embed 0*.sql
var Migrations embed.FS

// Bootstrap holds the superuser steps (roles, database, revokes). The service
// binary never runs them; the installer and the test harness do.
//
//go:embed bootstrap/*.sql
var Bootstrap embed.FS

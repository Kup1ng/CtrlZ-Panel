// Package chmigrations carries the ClickHouse migrations inside the binary, so the one-shot
// migrate-analytics container needs no files next to it.
package chmigrations

import "embed"

// Migrations holds the NNNN_name.sql files at its root.
//
//go:embed 0*.sql
var Migrations embed.FS

// Access is the row policies and the quota (access.sql). It is outside Migrations because the runner applies
// it before the first migration and on every run, not once: see the file's own comment.
//
//go:embed access.sql
var Access string

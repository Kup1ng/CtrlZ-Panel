// Package clockrule is the reader of the clock rule (P1 auth review round 5,
// rule clock-source; spec 3.3, 3.5, 4.5, 10.2, 10.5, 16.1).
//
// Every security timestamp column has exactly one clock, declared once in
// migrations/catalog/clocks.yaml:
//
//   - app: the application clock. Go stamps the column from a parameter and
//     compares it with its own clock. No SQL text and no DEFAULT names a database
//     clock function in a statement that names such a column.
//   - db: the database clock. SQL stamps it with now() and SQL compares it (often
//     inside a SECURITY DEFINER function). Go never decides on it, so a statement
//     never hands it to Go as a time (unless clocks.yaml lists the column under
//     `read` with the reason), and never writes it from, or compares it with, a Go
//     value.
//   - stamp: the database clock, kept as a record. Nothing compares it with a
//     clock, and Go may read it to show it.
//
// Why a registry: windows were open coded in Go and in SQL, so reauth_at,
// totp_verified_at, the ack cutoff and the password expiry each crossed clocks in a
// different round, and a skew of the two machines opened or closed a window on the
// wrong side. The same package judges Go's SQL constants (internal/lint), the live
// bodies of the definer functions and the column defaults (internal/store/catalogtest,
// check 24).
package clockrule

import (
	"bytes"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	catalogfixtures "github.com/Kup1ng/CtrlZ-Panel/migrations/catalog"
)

// Class is the clock of one column.
type Class string

// The three clocks.
const (
	App   Class = "app"
	DB    Class = "db"
	Stamp Class = "stamp"
)

// Registry is clocks.yaml.
type Registry struct {
	// Tables maps a table to its timestamp columns (timestamptz, timestamp and date)
	// and the clock of each.
	Tables map[string]map[string]Class `yaml:"tables"`
	// Read lists the db columns Go may select, each with the reason: a time that is
	// shown, or an identity token that is compared for equality and never with a
	// clock. A column listed here keeps its class; only the select is allowed.
	Read map[string]string `yaml:"read"`
	// Carry lists the db columns SQL may compare with, or write from, a value Go read
	// from the database and hands back unchanged (a day key, an identity token). The
	// value is never the application clock; the reason says where it comes from.
	Carry map[string]string `yaml:"carry"`
	// Functions maps "function.column" for every timestamp column a SECURITY DEFINER
	// function returns to the "table.column" it is read from, or to "none" for a
	// value the function computes. A db column returned raw must also be in Read.
	Functions map[string]string `yaml:"functions"`
}

// Load reads clocks.yaml from the embedded catalog.
func Load() (*Registry, error) {
	b, err := fs.ReadFile(catalogfixtures.FS, "clocks.yaml")
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse reads the text of clocks.yaml and checks that it is well formed.
func Parse(b []byte) (*Registry, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	r := &Registry{}
	if err := dec.Decode(r); err != nil {
		return nil, fmt.Errorf("clocks.yaml: %w", err)
	}
	for t, cols := range r.Tables {
		for c, k := range cols {
			if k != App && k != DB && k != Stamp {
				return nil, fmt.Errorf("clocks.yaml: %s.%s: %q is not app, db or stamp", t, c, k)
			}
		}
	}
	for ref := range r.Carry {
		t, c, ok := strings.Cut(ref, ".")
		if !ok || r.Tables[t][c] != DB {
			return nil, fmt.Errorf("clocks.yaml: carry lists %s, which is not a db column of a listed table", ref)
		}
	}
	for ref := range r.Read {
		t, c, ok := strings.Cut(ref, ".")
		if !ok || r.Tables[t][c] != DB {
			return nil, fmt.Errorf("clocks.yaml: read lists %s, which is not a db column of a listed table", ref)
		}
	}
	for ref, src := range r.Functions {
		if src == "none" {
			continue
		}
		t, c, ok := strings.Cut(src, ".")
		if !ok || r.Tables[t][c] == "" {
			return nil, fmt.Errorf("clocks.yaml: functions.%s reads %s, which is not a registered column", ref, src)
		}
		if r.Tables[t][c] == DB && r.Read[src] == "" {
			return nil, fmt.Errorf("clocks.yaml: functions.%s hands the db column %s to Go; list it under read with the reason", ref, src)
		}
	}
	return r, nil
}

// Class returns the clock of table.column, or "" when it is not registered.
func (r *Registry) Class(table, col string) Class { return r.Tables[table][col] }

// Windows returns every table.column whose clock decides something (app and db),
// sorted. These are the ones the boundary test must cover.
func (r *Registry) Windows() []string {
	var out []string
	for t, cols := range r.Tables {
		for c, k := range cols {
			if k == App || k == DB {
				out = append(out, t+"."+c)
			}
		}
	}
	sort.Strings(out)
	return out
}

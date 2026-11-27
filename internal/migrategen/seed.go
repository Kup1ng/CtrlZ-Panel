package migrategen

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// seedFile is the shape of migrations/seed/<name>.json: one table, its columns, and rows
// as arrays in column order. Rows as arrays keep a 100-row file readable in a diff.
type seedFile struct {
	Table   string              `json:"table"`
	Columns []string            `json:"columns"`
	Rows    [][]json.RawMessage `json:"rows"`
}

// seedSQL turns a seed file into one INSERT. A JSON string is a text literal, a number or a
// boolean is itself, null is NULL, an array of strings is a text[] and an object is jsonb.
// The type of each value is therefore fixed by the file and never guessed from the column.
func seedSQL(dir, name string) (string, error) {
	if dir == "" {
		return "", fmt.Errorf("seed %q: no seed directory", name)
	}
	if name == "" || strings.ContainsAny(name, `/\.`) {
		return "", fmt.Errorf("seed %q: a bare file name without extension is expected", name)
	}
	raw, err := os.ReadFile(filepath.Join(dir, name+".json"))
	if err != nil {
		return "", fmt.Errorf("seed %q: %w", name, err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var f seedFile
	if err := dec.Decode(&f); err != nil {
		return "", fmt.Errorf("seed %q: %w", name, err)
	}
	if f.Table == "" || len(f.Columns) == 0 || len(f.Rows) == 0 {
		return "", fmt.Errorf("seed %q: table, columns and rows are all required", name)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "INSERT INTO ctrlz.%s (%s) VALUES\n", f.Table, strings.Join(f.Columns, ", "))
	for i, row := range f.Rows {
		if len(row) != len(f.Columns) {
			return "", fmt.Errorf("seed %q: row %d has %d values for %d columns", name, i, len(row), len(f.Columns))
		}
		vals := make([]string, len(row))
		for j, v := range row {
			lit, err := seedLiteral(v)
			if err != nil {
				return "", fmt.Errorf("seed %q: row %d column %s: %w", name, i, f.Columns[j], err)
			}
			vals[j] = lit
		}
		sep := ",\n"
		if i == len(f.Rows)-1 {
			sep = ";"
		}
		fmt.Fprintf(&b, "  (%s)%s", strings.Join(vals, ", "), sep)
	}
	return b.String(), nil
}

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func seedLiteral(v json.RawMessage) (string, error) {
	var x any
	d := json.NewDecoder(strings.NewReader(string(v)))
	d.UseNumber()
	if err := d.Decode(&x); err != nil {
		return "", err
	}
	switch t := x.(type) {
	case nil:
		return "NULL", nil
	case bool:
		if t {
			return "true", nil
		}
		return "false", nil
	case json.Number:
		return t.String(), nil
	case string:
		if strings.ContainsRune(t, 0) {
			return "", fmt.Errorf("NUL in a string")
		}
		return quote(t), nil
	case []any:
		parts := make([]string, len(t))
		for i, e := range t {
			s, ok := e.(string)
			if !ok {
				return "", fmt.Errorf("only arrays of strings are supported")
			}
			parts[i] = quote(s)
		}
		return "ARRAY[" + strings.Join(parts, ", ") + "]::text[]", nil
	default:
		// An object: compact JSON, with the key order of the file.
		var compact bytes.Buffer
		if err := json.Compact(&compact, v); err != nil {
			return "", err
		}
		return quote(compact.String()) + "::jsonb", nil
	}
}

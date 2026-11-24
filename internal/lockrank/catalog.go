package lockrank

import (
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	catalogfixtures "github.com/Kup1ng/CtrlZ-Panel/migrations/catalog"
)

// This file reads the two catalog fixtures the order depends on, so that the
// foreign keys and the ranks of the definer functions have one source of truth:
// the files the catalog tests already compare with the database in both
// directions. They are embedded, so a binary and the tests agree by
// construction.

// Child is a foreign key seen from its parent.
type Child struct {
	Table    string
	OnDelete string // cascade, set_null, restrict, no_action
}

type fkIndex struct {
	parents  map[string][]string
	children map[string][]Child
}

var fkRe = regexp.MustCompile(`^(\w+)\([^)]*\) -> (\w+)\([^)]*\) (\w+)`)

var fks = sync.OnceValue(func() fkIndex {
	idx := fkIndex{parents: map[string][]string{}, children: map[string][]Child{}}
	b, err := fs.ReadFile(catalogfixtures.FS, "foreign_keys.yaml")
	if err != nil {
		panic(fmt.Sprintf("lockrank: foreign_keys.yaml: %v", err))
	}
	var f struct {
		ForeignKeys []string `yaml:"foreign_keys"`
	}
	if err := yaml.Unmarshal(b, &f); err != nil {
		panic(fmt.Sprintf("lockrank: foreign_keys.yaml: %v", err))
	}
	seenP := map[[2]string]bool{}
	for _, line := range f.ForeignKeys {
		m := fkRe.FindStringSubmatch(line)
		if m == nil {
			panic("lockrank: foreign_keys.yaml: cannot read " + line)
		}
		child, parent, on := m[1], m[2], m[3]
		if !seenP[[2]string{child, parent}] {
			seenP[[2]string{child, parent}] = true
			idx.parents[child] = append(idx.parents[child], parent)
		}
		idx.children[parent] = append(idx.children[parent], Child{child, on})
	}
	for _, l := range idx.parents {
		sort.Strings(l)
	}
	return idx
})

// Parents lists the tables a row of the table points at. Inserting a row takes
// FOR KEY SHARE on one row of each.
func Parents(table string) []string { return fks().parents[table] }

// Children lists the foreign keys that point at the table.
func Children(table string) []Child { return fks().children[table] }

// definers maps a function of schema ctrlz_fn to the touches it declares.
var definers = sync.OnceValue(func() map[string][]Touch {
	b, err := fs.ReadFile(catalogfixtures.FS, "functions.yaml")
	if err != nil {
		panic(fmt.Sprintf("lockrank: functions.yaml: %v", err))
	}
	var f struct {
		SD []struct {
			Name  string    `yaml:"name"`
			Ranks *[]string `yaml:"ranks"`
		} `yaml:"security_definer"`
	}
	if err := yaml.Unmarshal(b, &f); err != nil {
		panic(fmt.Sprintf("lockrank: functions.yaml: %v", err))
	}
	out := map[string][]Touch{}
	for _, fn := range f.SD {
		if fn.Ranks == nil {
			continue // undeclared: Analyze refuses a call to it
		}
		ts, err := ParseDeclared(*fn.Ranks)
		if err != nil {
			panic(fmt.Sprintf("lockrank: functions.yaml: %s: %v", fn.Name, err))
		}
		out[fn.Name] = ts
	}
	return out
})

func definerTouches(name string) ([]Touch, bool) {
	ts, ok := definers()[name]
	return ts, ok
}

// ParseDeclared reads the "ranks" list of a function in functions.yaml. An
// entry is a table (a write), "table:ks" (a key share), "table:ins" (an insert)
// or "table:skip" (a write that never waits).
func ParseDeclared(entries []string) ([]Touch, error) {
	var out []Touch
	for _, e := range entries {
		table, suffix, _ := strings.Cut(e, ":")
		if _, ok := Of(table); !ok {
			return nil, fmt.Errorf("table %q is not ranked", table)
		}
		t := Touch{Table: table, Mode: Write}
		switch suffix {
		case "":
		case "ks":
			t.Mode = KeyShare
		case "ins":
			t.Mode = Insert
		case "skip":
			t.NoWait = true
		default:
			return nil, fmt.Errorf("unknown suffix %q", suffix)
		}
		out = append(out, t)
	}
	return out, nil
}

// Declare turns the touches of a function body into the list its entry in
// functions.yaml must hold: the first acquisition of each table, in order,
// leaving out key shares on inert tables and anything a stronger touch of the
// same table already covers (the same rule State uses).
func Declare(ts []Touch) []string {
	held := map[string]Mode{}
	var out []string
	for _, t := range ts {
		if t.Mode == KeyShare && Inert(t.Table) {
			continue
		}
		eff := t.Mode
		if held[t.Table] >= eff {
			continue
		}
		held[t.Table] = eff
		if eff == Insert {
			held[t.Table] = Write // the rows of a table this transaction inserted are its own
		}
		s := t.Table
		switch {
		case t.Mode == KeyShare:
			s += ":ks"
		case t.Mode == Insert:
			s += ":ins"
		case t.NoWait:
			s += ":skip"
		}
		out = append(out, s)
	}
	return out
}

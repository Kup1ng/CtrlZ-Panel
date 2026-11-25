package migrategen_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kup1ng/CtrlZ-Panel/internal/migrategen"
)

// TestSeedMacro: each JSON type has one SQL form, a quote in a string cannot end its literal, and a
// malformed file fails the expansion instead of producing half a seed.
func TestSeedMacro(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name+".json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("t", `{"table":"things","columns":["a","b","c","d","e","f"],"rows":[
  ["it's",1,true,null,["US","DE"],{"k": [1, 2]}],
  ["x",2,false,null,null,{}]
]}`)
	out, err := migrategen.ExpandWithSeed("x.sql", `{{seed "t"}}`, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"INSERT INTO ctrlz.things (a, b, c, d, e, f) VALUES",
		`('it''s', 1, true, NULL, ARRAY['US', 'DE']::text[], '{"k":[1,2]}'::jsonb),`,
		`('x', 2, false, NULL, NULL, '{}'::jsonb);`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expansion lacks %q:\n%s", want, out)
		}
	}
	write("short", `{"table":"things","columns":["a","b"],"rows":[["only one"]]}`)
	write("unknown", `{"table":"things","columns":["a"],"rows":[["x"]],"extra":1}`)
	for _, name := range []string{"short", "unknown", "missing", "../t"} {
		if _, err := migrategen.ExpandWithSeed("x.sql", `{{seed "`+name+`"}}`, dir); err == nil {
			t.Errorf("seed %q expanded", name)
		}
	}
	if _, err := migrategen.Expand("x.sql", `{{seed "t"}}`); err == nil {
		t.Error("seed expanded with no directory")
	}
}

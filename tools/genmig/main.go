// Command genmig expands migrations/postgres/src into migrations/postgres and keeps the
// manifest of applied migrations (migrations/postgres/applied.sum).
//
//	go run ./tools/genmig                   write the expanded files, add the line of a new migration
//	go run ./tools/genmig -check            fail if the committed files or the manifest differ
//	go run ./tools/genmig -bump 0033_x.sql  accept an edit of a listed migration (a reviewed decision)
//	go run ./tools/genmig -init             list every migration of a tree that has no manifest yet (first listing only)
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Kup1ng/CtrlZ-Panel/internal/migrategen"
)

func main() {
	check := flag.Bool("check", false, "verify instead of writing")
	src := flag.String("src", "migrations/postgres/src", "macro sources")
	out := flag.String("out", "migrations/postgres", "expanded migrations")
	sum := flag.String("sum", "migrations/postgres/applied.sum", "manifest of applied migrations")
	init := flag.Bool("init", false, "start a manifest that is missing or empty (first listing only; a deleted manifest is restored from version control, not started again)")
	bump := flag.String("bump", "", "comma separated migration files whose edit is accepted into the manifest")
	flag.Parse()
	names, err := migrategen.Generate(*src, *out, *check)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *check {
		if err := migrategen.VerifyManifest(*out, *sum); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	var bumps []string
	if *bump != "" {
		bumps = strings.Split(*bump, ",")
	}
	added, bumped, err := migrategen.UpdateManifest(*out, *sum, bumps, *init)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("expanded %d migration files, listed %d new, bumped %d\n", len(names), len(added), len(bumped))
}

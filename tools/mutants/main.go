// Command mutants applies every mutant of mutants.yaml in a scratch copy of the tree
// and fails when a test that should notice it does not (rule tests-that-cannot-fail).
//
//	go run ./tools/mutants              all mutants
//	go run ./tools/mutants -short       skip the ones that start containers
//	go run ./tools/mutants -j 3         three at a time
//	go run ./tools/mutants -only id,id  some mutants
//	go run ./tools/mutants -diff        show each applied edit
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/Kup1ng/CtrlZ-Panel/internal/mutant"
)

func main() {
	short := flag.Bool("short", false, "skip mutants whose tests start containers")
	only := flag.String("only", "", "comma separated mutant ids")
	diff := flag.Bool("diff", false, "print each applied edit")
	timeout := flag.Duration("timeout", 20*time.Minute, "go test timeout of each package run")
	jobs := flag.Int("j", 1, "mutants to run at once, each in its own copy of the tree")
	file := flag.String("file", "mutants.yaml", "registry")
	flag.Parse()

	root, err := os.Getwd()
	if err != nil {
		fail(err)
	}
	reg, err := mutant.Load(filepath.Join(root, *file))
	if err != nil {
		fail(err)
	}
	opt := mutant.Options{Root: root, Short: *short, Timeout: *timeout, Jobs: *jobs, Log: os.Stdout, ShowDiff: *diff}
	if *only != "" {
		opt.Only = strings.Split(*only, ",")
	}
	// The scratch copy has no workspace around it, so point the lint tests at the real
	// documents. A repository checked out alone has none and its workspace mutants skip.
	ws := filepath.Dir(root)
	spec := filepath.Join(ws, "docs", "specs", "p1-auth.md")
	rules := filepath.Join(ws, "docs", "reviews", "p1-auth", "rules.md")
	if _, e1 := os.Stat(spec); e1 == nil {
		if _, e2 := os.Stat(rules); e2 == nil {
			opt.HaveWorkspace = true
			opt.Env = []string{"CTRLZ_SPEC=" + spec, "CTRLZ_RULES=" + rules}
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	results, err := mutant.Run(ctx, reg, opt)
	killed, skipped := 0, 0
	for _, r := range results {
		switch r.Status {
		case mutant.Killed:
			killed++
		case mutant.Skipped:
			skipped++
		}
	}
	fmt.Printf("mutants: %d killed, %d skipped, %d total\n", killed, skipped, len(results))
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

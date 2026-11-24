// Command gen writes layouts_gen.go of pwstrength from the layout data files.
package main

import (
	"fmt"
	"os"

	"github.com/Kup1ng/CtrlZ-Panel/internal/auth/pwstrength/layouts"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: gen <output file>")
		os.Exit(2)
	}
	src, err := layouts.Generate()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(os.Args[1], src, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

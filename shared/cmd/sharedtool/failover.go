package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/Kup1ng/CtrlZ-Shared/internal/failovergen"
)

// cmdFailover writes vectors/zone-failover.json, or with --check compares a
// file with a fresh run and exits 1 when it differs (contract 8a.10: nobody
// edits the file, and a checked-in file that is not what the generator writes
// is a failure).
func cmdFailover(args []string, out, errw io.Writer) int {
	fset := flag.NewFlagSet("failover-vectors", flag.ContinueOnError)
	fset.SetOutput(errw)
	to := fset.String("out", "", "write the group file here")
	check := fset.String("check", "", "compare this file with a fresh run")
	if err := fset.Parse(args); err != nil || fset.NArg() != 0 || (*to == "") == (*check == "") {
		fmt.Fprintln(errw, "usage: sharedtool failover-vectors (--out <file> | --check <file>)")
		return exitUsage
	}
	data, err := failovergen.Generate()
	if err != nil {
		fmt.Fprintln(errw, "error:", err)
		return exitUsage
	}
	if *to != "" {
		if err := writeAtomic(*to, data); err != nil {
			fmt.Fprintln(errw, "error:", err)
			return exitUsage
		}
		fmt.Fprintf(out, "wrote %s bytes=%d\n", *to, len(data))
		return exitOK
	}
	have, err := os.ReadFile(*check)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintln(errw, "error:", err)
		return exitUsage
	}
	if !bytes.Equal(have, data) {
		fmt.Fprintf(out, "FAIL %s differs from a fresh run of the generator\n", *check)
		return exitMismatch
	}
	fmt.Fprintf(out, "ok %s\n", *check)
	return exitOK
}

// Command genpublicapi writes api/public-openapi.yaml, the public API document, from api/openapi.yaml (P3 6.5, T-320).
//
//	go run ./tools/genpublicapi           write the file
//	go run ./tools/genpublicapi -check    fail if the committed file is not what the command would write
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"

	"github.com/Kup1ng/CtrlZ-Panel/internal/publicapi"
)

func main() {
	check := flag.Bool("check", false, "verify instead of writing")
	in := flag.String("in", "api/openapi.yaml", "the tenant document")
	out := flag.String("out", "api/public-openapi.yaml", "the public document")
	flag.Parse()
	src, err := os.ReadFile(*in)
	if err != nil {
		fail(err)
	}
	want, err := publicapi.Generate(src)
	if err != nil {
		fail(err)
	}
	if *check {
		have, err := os.ReadFile(*out)
		if err != nil {
			fail(err)
		}
		// A checkout on Windows may convert line endings; the content is what matters.
		if !bytes.Equal(bytes.ReplaceAll(have, []byte("\r\n"), []byte("\n")), want) {
			fail(fmt.Errorf("%s is stale; run `go run ./tools/genpublicapi` and commit the result", *out))
		}
		return
	}
	if err := os.WriteFile(*out, want, 0o644); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "genpublicapi:", err)
	os.Exit(1)
}

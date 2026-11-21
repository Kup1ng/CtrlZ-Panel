package testpg

import (
	"reflect"
	"testing"
)

// TestSplitStatementsKeepsADollarQuotedBlockWhole covers the bootstrap's DO block (db-r14-3): a
// semicolon inside $tag$ ... $tag$ is part of the body, and psql, which the installer uses, reads
// it the same way.
func TestSplitStatementsKeepsADollarQuotedBlockWhole(t *testing.T) {
	text := "-- a comment; with a semicolon\nGRANT a TO b;\nDO $x$\nBEGIN\n  PERFORM 1; PERFORM 2;\nEND\n$x$;\nDO $$ SELECT ';' $$;\nREVOKE c FROM d"
	got := splitStatements(text)
	want := []string{
		"GRANT a TO b",
		"DO $x$\nBEGIN\n  PERFORM 1; PERFORM 2;\nEND\n$x$",
		"DO $$ SELECT ';' $$",
		"REVOKE c FROM d",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

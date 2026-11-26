//go:build windows

package compiler

// syncDir does nothing: Windows has no flush of a directory, and the store runs on Linux in production (it is a file of its
// own so that the package imports no runtime for the choice).
func syncDir(string) error { return nil }

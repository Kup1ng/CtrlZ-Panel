//go:build !windows

package compiler

import (
	"fmt"
	"os"
)

// syncDir flushes a directory, which is what makes a rename in it durable: until then a power loss can drop the name of a
// file whose entry Postgres has already committed.
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("compiler: artifact directory: %w", err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("compiler: artifact directory sync: %w", err)
	}
	return nil
}

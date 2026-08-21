//go:build darwin || linux

package pairing

import (
	"os"
	"testing"
)

func assertPrivateFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("state file %q mode = %v, want regular 0600", path, info.Mode())
	}
}

//go:build darwin || linux

package identity

import (
	"os"
	"path/filepath"
	"testing"
)

// requirePrivateIdentity asserts the POSIX form of the guarantee: the identity
// file and the state directory holding it are reachable only by their owner,
// which mode bits express exactly.
func requirePrivateIdentity(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("identity mode = %04o, want 0600", got)
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("state directory mode = %04o, want 0700", got)
	}
}

func TestLoadRejectsPubliclyReadableIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	if _, err := LoadOrCreate(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(path); err == nil {
		t.Fatal("expected unsafe identity permissions to be rejected")
	}
}

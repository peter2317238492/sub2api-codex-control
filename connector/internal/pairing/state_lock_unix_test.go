//go:build darwin || linux

package pairing

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPairingStateLockRejectsLinksWithoutModifyingTarget(t *testing.T) {
	for _, test := range []struct {
		name string
		link func(oldname, newname string) error
	}{
		{name: "symbolic", link: os.Symlink},
		{name: "hard", link: os.Link},
	} {
		t.Run(test.name, func(t *testing.T) {
			stateDir := t.TempDir()
			target := filepath.Join(t.TempDir(), "target")
			if err := os.WriteFile(target, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := test.link(target, filepath.Join(stateDir, "pairing.lock")); err != nil {
				t.Skipf("%s links unavailable: %v", test.name, err)
			}
			if release, err := acquirePairingStateLock(stateDir); err == nil {
				_ = release()
				t.Fatalf("%s-link pairing state lock was accepted", test.name)
			}
			info, err := os.Stat(target)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o644 {
				t.Fatalf("%s-link target mode = %04o, want 0644", test.name, info.Mode().Perm())
			}
		})
	}
}

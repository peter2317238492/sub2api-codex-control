//go:build darwin

package pairing

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPairingStateLockRejectsDarwinAllowACL(t *testing.T) {
	stateDir := t.TempDir()
	path := filepath.Join(stateDir, "pairing.lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/chmod", "+a", "everyone allow read", path)
	if output, err := command.CombinedOutput(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			t.Skip("Darwin chmod is unavailable")
		}
		t.Fatalf("set pairing lock ACL: %v: %s", err, output)
	}
	t.Cleanup(func() {
		_ = exec.Command("/bin/chmod", "-N", path).Run()
	})
	if release, err := acquirePairingStateLock(stateDir); err == nil {
		_ = release()
		t.Fatal("pairing state lock with an allow ACL was accepted")
	}
}

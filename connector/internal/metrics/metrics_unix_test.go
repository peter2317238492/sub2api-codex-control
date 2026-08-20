//go:build darwin || linux

package metrics

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func assertPrivateStateDirectory(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("metrics state directory mode = %s, want 0700", info.Mode())
	}
}

func assertPrivateRegularFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("%s mode = %s, want private regular 0600", path, info.Mode())
	}
}

func TestOpenRejectsUnsafeCounterStateAccess(t *testing.T) {
	for name, tamper := range map[string]func(*testing.T, string){
		"mode": func(t *testing.T, path string) {
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"darwin ACL": func(t *testing.T, path string) {
			if runtime.GOOS != "darwin" {
				t.Skip("macOS ACL regression")
			}
			if output, err := exec.Command("chmod", "+a", "everyone allow read", path).CombinedOutput(); err != nil {
				t.Fatalf("add test ACL: %v: %s", err, output)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			stateDir := privateStateDir(t)
			path := filepath.Join(stateDir, stateName)
			writePrivateStateFile(t, path, validCounterStateJSON)
			tamper(t, path)
			if _, err := Open(stateDir, func(time.Time) (SpoolSnapshot, error) {
				return SpoolSnapshot{CapacityBytes: 1}, nil
			}); err == nil {
				t.Fatal("counter state reachable by another user was accepted")
			}
		})
	}
}

// readReplaceable reads a file the exporter may be replacing right now. POSIX
// rename(2) never locks a reader out, so no retry is needed here; the Windows
// counterpart explains why one is.
func readReplaceable(path string) ([]byte, error) {
	return os.ReadFile(path)
}

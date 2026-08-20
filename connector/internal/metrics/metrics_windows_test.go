package metrics

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/securefile"
)

// usersGroupSID is BUILTIN\Users. It exists on every Windows install, the
// interactive user belongs to it, and it is never a trusted connector
// principal, which makes it the local analogue of POSIX "other".
const usersGroupSID = "*S-1-5-32-545"

// Windows permission bits encode only the read-only attribute, so the POSIX
// 0700 assertion becomes "no untrusted principal appears in the discretionary
// access control list", which is what securefile validates.
func assertPrivateStateDirectory(t *testing.T, path string) {
	t.Helper()
	directory, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	info, err := securefile.ValidateOwnerAndACL(directory, false)
	if err != nil {
		t.Fatalf("metrics state directory is not private: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("metrics state path mode = %s, want a directory", info.Mode())
	}
}

func assertPrivateRegularFile(t *testing.T, path string) {
	t.Helper()
	info, err := securefile.StatPrivateFile(path)
	if err != nil {
		t.Fatalf("%s is not a private regular file: %v", path, err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("%s mode = %s, want a regular file", path, info.Mode())
	}
}

// TestOpenRejectsUnsafeCounterStateAccess is the Windows half of the POSIX
// world-readable rejection: granting a foreign trustee read access is the local
// equivalent of relaxing 0600 to 0644.
func TestOpenRejectsUnsafeCounterStateAccess(t *testing.T) {
	stateDir := privateStateDir(t)
	path := filepath.Join(stateDir, stateName)
	writePrivateStateFile(t, path, validCounterStateJSON)
	if output, err := exec.Command("icacls", path, "/grant", usersGroupSID+":(R)").CombinedOutput(); err != nil {
		t.Fatalf("add test access control entry: %v: %s", err, output)
	}
	_, err := Open(stateDir, func(time.Time) (SpoolSnapshot, error) {
		return SpoolSnapshot{CapacityBytes: 1}, nil
	})
	if err == nil || !strings.Contains(err.Error(), "unsafe access control list") {
		t.Fatalf("Open error = %v, want rejection of the foreign access control entry", err)
	}
}

// readReplaceable reads a file the exporter may be replacing right now. An
// atomic replacement has to hold DELETE access on the destination for an
// instant, and a reader that did not grant FILE_SHARE_DELETE - every Go reader,
// windows_exporter included - is locked out for exactly that instant. Retrying
// the open is what a real collector does; observing partial content is not, and
// that is what this file's callers still assert.
func readReplaceable(path string) ([]byte, error) {
	deadline := time.Now().Add(replaceBudget)
	for {
		data, err := os.ReadFile(path)
		if err == nil || !replaceCollision(err) || !time.Now().Before(deadline) {
			return data, err
		}
		time.Sleep(replaceInterval)
	}
}

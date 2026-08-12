//go:build darwin

package securefile

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const everyoneAllowACL = "everyone allow read,write,execute,delete,append,readattr,writeattr,readextattr,writeextattr,readsecurity"

func TestEnsureDirRejectsDarwinAllowACL(t *testing.T) {
	directory := t.TempDir()
	setDarwinACL(t, directory, everyoneAllowACL)
	if err := EnsureDir(directory); err == nil || !strings.Contains(err.Error(), "unsafe access control list") {
		t.Fatalf("EnsureDir error = %v, want unsafe ACL rejection", err)
	}
}

func TestEnsureDirAllowsRestrictiveDarwinACL(t *testing.T) {
	directory := t.TempDir()
	setDarwinACL(t, directory, "everyone deny delete")
	if err := EnsureDir(directory); err != nil {
		t.Fatalf("EnsureDir rejected deny-only ACL: %v", err)
	}
}

func TestReadJSONRejectsDarwinAllowACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setDarwinACL(t, path, "everyone allow read")
	var value map[string]any
	if err := ReadJSON(path, &value); err == nil || !strings.Contains(err.Error(), "unsafe access control list") {
		t.Fatalf("ReadJSON error = %v, want unsafe ACL rejection", err)
	}
}

func TestDarwinACLInspectionErrorsFailClosed(t *testing.T) {
	if err := darwinACLInspectionError(0); err != nil {
		t.Fatalf("successful ACL inspection classified as an error: %v", err)
	}
	for _, errno := range []syscall.Errno{syscall.ENOTSUP, syscall.EOPNOTSUPP, syscall.EIO} {
		if err := darwinACLInspectionError(errno); err == nil {
			t.Fatalf("ACL inspection error %v was accepted", errno)
		}
	}
}

func setDarwinACL(t *testing.T, path, entry string) {
	t.Helper()
	command := exec.Command("/bin/chmod", "+a", entry, path)
	if output, err := command.CombinedOutput(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			t.Skip("Darwin chmod is unavailable")
		}
		t.Fatalf("set ACL: %v: %s", err, output)
	}
	t.Cleanup(func() {
		_ = exec.Command("/bin/chmod", "-N", path).Run()
	})
}

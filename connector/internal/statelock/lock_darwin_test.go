//go:build darwin

package statelock

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const darwinEveryoneAllowACL = "everyone allow read,write,execute,delete,append,readattr,writeattr,readextattr,writeextattr,readsecurity"

func TestStateLockRejectsDarwinAllowACLOnStateDirectory(t *testing.T) {
	stateDir := canonicalTestPath(t, t.TempDir())
	setDarwinStateACL(t, stateDir, darwinEveryoneAllowACL)
	if lock, err := Acquire(stateDir); err == nil {
		_ = lock.Release()
		t.Fatal("state directory with an allow ACL was accepted")
	}
}

func TestStateLockRejectsDarwinAllowACLOnAncestor(t *testing.T) {
	ancestor := filepath.Join(canonicalTestPath(t, t.TempDir()), "ancestor")
	if err := os.Mkdir(ancestor, 0o700); err != nil {
		t.Fatal(err)
	}
	setDarwinStateACL(t, ancestor, darwinEveryoneAllowACL)
	stateDir := filepath.Join(ancestor, "state")
	if lock, err := Acquire(stateDir); err == nil {
		_ = lock.Release()
		t.Fatal("state directory below an ACL-writable ancestor was accepted")
	}
	if _, err := os.Lstat(stateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state directory was created below an ACL-writable ancestor: %v", err)
	}
}

func TestStateLockRejectsDarwinAllowACLOnLockFile(t *testing.T) {
	stateDir := filepath.Join(canonicalTestPath(t, t.TempDir()), "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(stateDir, lockFileName)
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	setDarwinStateACL(t, lockPath, "everyone allow read")
	if lock, err := Acquire(stateDir); err == nil {
		_ = lock.Release()
		t.Fatal("lock file with an allow ACL was accepted")
	}
}

func TestStateLockAllowsRestrictiveDarwinACL(t *testing.T) {
	stateDir := filepath.Join(canonicalTestPath(t, t.TempDir()), "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	setDarwinStateACL(t, stateDir, "everyone deny delete")
	lock, err := Acquire(stateDir)
	if err != nil {
		t.Fatalf("deny-only ACL was rejected: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
}

func setDarwinStateACL(t *testing.T, path, entry string) {
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
	action := strings.Fields(entry)[1]
	if output, err := exec.Command("/bin/ls", "-lde", path).CombinedOutput(); err != nil || !strings.Contains(string(output), action) {
		t.Fatalf("ACL fixture was not visible: %v: %s", err, output)
	}
}

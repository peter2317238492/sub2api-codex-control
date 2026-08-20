//go:build windows

package pairing

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/securefile"
)

const (
	seFileObject            = 1
	daclSecurityInformation = 0x00000004
	seDACLProtected         = 0x1000
)

var (
	testAdvapi32                     = syscall.NewLazyDLL("advapi32.dll")
	procGetSecurityInfo              = testAdvapi32.NewProc("GetSecurityInfo")
	procGetSecurityDescriptorControl = testAdvapi32.NewProc("GetSecurityDescriptorControl")
)

// assertPrivateFile is the Windows analogue of the POSIX 0600 assertion. Mode
// bits carry no access control meaning here, so the file must instead be
// reachable only by the connector principal and the fully privileged system
// principals, with inheritance severed so the inheritable entries of the user
// profile cannot reach it.
func assertPrivateFile(t *testing.T, path string) {
	t.Helper()
	info, err := securefile.StatPrivateFile(path)
	if err != nil {
		t.Fatalf("state file %q is not private: %v", path, err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("state file %q mode = %v, want a regular file", path, info.Mode())
	}
	protected, err := daclIsProtected(path)
	if err != nil {
		t.Fatal(err)
	}
	if !protected {
		t.Fatalf("state file %q inherits its access control list", path)
	}
}

func daclIsProtected(path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	var descriptor uintptr
	status, _, _ := procGetSecurityInfo.Call(
		file.Fd(),
		seFileObject,
		daclSecurityInformation,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&descriptor)),
	)
	if status != 0 {
		return false, fmt.Errorf("read security descriptor of %s: %w", path, syscall.Errno(status))
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))
	var control uint16
	var revision uint32
	ok, _, callErr := procGetSecurityDescriptorControl.Call(
		descriptor,
		uintptr(unsafe.Pointer(&control)),
		uintptr(unsafe.Pointer(&revision)),
	)
	if ok == 0 {
		return false, fmt.Errorf("read descriptor control of %s: %w", path, callErr)
	}
	return control&seDACLProtected != 0, nil
}

// A second name for the lock object would let a writer outside the state
// directory reach it, which is what the POSIX build rejects through Nlink.
func TestPairingStateLockRejectsAdditionallyLinkedLockFile(t *testing.T) {
	stateDir := newPairingStateDir(t)
	release, err := acquirePairingStateLock(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(stateDir, "pairing.lock")
	alias := filepath.Join(filepath.Dir(stateDir), "pairing.lock.alias")
	if err := hardLink(alias, lock); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	if release, err := acquirePairingStateLock(stateDir); err == nil {
		_ = release()
		t.Fatal("additionally linked pairing state lock was accepted")
	}
}

func hardLink(name, existing string) error {
	encodedName, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	encodedExisting, err := syscall.UTF16PtrFromString(existing)
	if err != nil {
		return err
	}
	return syscall.CreateHardLink(encodedName, encodedExisting, 0)
}

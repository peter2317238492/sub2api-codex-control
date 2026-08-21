//go:build windows

package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/securefile"
)

const (
	seFileObject               = 1
	daclSecurityInformation    = 0x00000004
	protectedDACLSecurityInfo  = 0x80000000
	securityDescriptorRevision = 1
	seDACLProtected            = 0x1000
	fileGenericRead            = 0x001200A9
)

var (
	advapi32                         = syscall.NewLazyDLL("advapi32.dll")
	procConvertStringSecurityToSD    = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procGetSecurityDescriptorControl = advapi32.NewProc("GetSecurityDescriptorControl")
	procGetSecurityDescriptorDacl    = advapi32.NewProc("GetSecurityDescriptorDacl")
	procGetSecurityInfo              = advapi32.NewProc("GetSecurityInfo")
	procSetSecurityInfo              = advapi32.NewProc("SetSecurityInfo")
)

// requirePrivateIdentity asserts the Windows form of the guarantee. Mode bits
// carry no access-control meaning here — os.FileInfo reports 0666 for every
// writable file and 0444 for a read-only one — so the properties to check are
// the ones the descriptor records: inheritance is severed, the owner is the
// connector principal, and no other trustee than LocalSystem or Administrators
// is allowed anything.
func requirePrivateIdentity(t *testing.T, path string) {
	t.Helper()
	for _, target := range []string{path, filepath.Dir(path)} {
		object, err := os.Open(target)
		if err != nil {
			t.Fatal(err)
		}
		_, validateErr := securefile.ValidateOwnerAndACL(object, false)
		protected := daclIsProtected(t, object)
		if err := object.Close(); err != nil {
			t.Fatal(err)
		}
		if validateErr != nil {
			t.Fatalf("%s is reachable by an untrusted principal: %v", target, validateErr)
		}
		if !protected {
			t.Fatalf("%s does not carry a protected access control list", target)
		}
	}
}

func TestLoadRejectsIdentityReachableByOtherPrincipals(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "identity.json")
	if _, err := LoadOrCreate(path); err != nil {
		t.Fatal(err)
	}
	grantForeignRead(t, path)
	if _, err := LoadOrCreate(path); err == nil ||
		!strings.Contains(err.Error(), "unsafe access control list") {
		t.Fatalf("widened identity error = %v, want unsafe access control list", err)
	}
}

// grantForeignRead is the Windows analogue of chmod 0644 on the identity file:
// it leaves the owner in full control and adds a read grant for BUILTIN\Users.
func grantForeignRead(t *testing.T, path string) {
	t.Helper()
	file, err := securefile.CreatePrivateFile(path, os.O_RDONLY)
	if err != nil {
		t.Fatalf("open identity: %v", err)
	}
	defer file.Close()
	descriptor, dacl := testDACL(t, fmt.Sprintf("D:P(A;;FA;;;%s)(A;;0x%X;;;BU)", processOwnerSID(t), fileGenericRead))
	defer syscall.LocalFree(syscall.Handle(descriptor))
	status, _, _ := procSetSecurityInfo.Call(
		file.Fd(),
		seFileObject,
		daclSecurityInformation|protectedDACLSecurityInfo,
		0,
		0,
		dacl,
		0,
	)
	if status != 0 {
		t.Fatalf("widen identity access control list: %v", syscall.Errno(status))
	}
}

// testDACL returns the discretionary access control list of an SDDL string
// together with the descriptor that owns its storage; the caller frees it.
func testDACL(t *testing.T, sddl string) (uintptr, uintptr) {
	t.Helper()
	encoded, err := syscall.UTF16PtrFromString(sddl)
	if err != nil {
		t.Fatalf("encode test security descriptor: %v", err)
	}
	var descriptor uintptr
	ok, _, callErr := procConvertStringSecurityToSD.Call(
		uintptr(unsafe.Pointer(encoded)),
		securityDescriptorRevision,
		uintptr(unsafe.Pointer(&descriptor)),
		0,
	)
	if ok == 0 || descriptor == 0 {
		t.Fatalf("build test security descriptor: %v", callErr)
	}
	var present, defaulted uint32
	var dacl uintptr
	ok, _, callErr = procGetSecurityDescriptorDacl.Call(
		descriptor,
		uintptr(unsafe.Pointer(&present)),
		uintptr(unsafe.Pointer(&dacl)),
		uintptr(unsafe.Pointer(&defaulted)),
	)
	if ok == 0 || present == 0 || dacl == 0 {
		_, _ = syscall.LocalFree(syscall.Handle(descriptor))
		t.Fatalf("read test security descriptor: %v", callErr)
	}
	return descriptor, dacl
}

func daclIsProtected(t *testing.T, object *os.File) bool {
	t.Helper()
	var owner, group, dacl, sacl, descriptor uintptr
	status, _, _ := procGetSecurityInfo.Call(
		object.Fd(),
		seFileObject,
		daclSecurityInformation,
		uintptr(unsafe.Pointer(&owner)),
		uintptr(unsafe.Pointer(&group)),
		uintptr(unsafe.Pointer(&dacl)),
		uintptr(unsafe.Pointer(&sacl)),
		uintptr(unsafe.Pointer(&descriptor)),
	)
	if status != 0 || descriptor == 0 {
		t.Fatalf("read %s security descriptor: %v", object.Name(), syscall.Errno(status))
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
		t.Fatalf("read %s security descriptor control: %v", object.Name(), callErr)
	}
	return control&seDACLProtected != 0
}

func processOwnerSID(t *testing.T) string {
	t.Helper()
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		t.Fatalf("open current process: %v", err)
	}
	var token syscall.Token
	if err := syscall.OpenProcessToken(process, syscall.TOKEN_QUERY, &token); err != nil {
		t.Fatalf("open process token: %v", err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatalf("read process token user: %v", err)
	}
	owner, err := user.User.Sid.String()
	if err != nil {
		t.Fatalf("format process token user: %v", err)
	}
	return owner
}

//go:build windows

package securefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

const (
	builtinUsersSID       = "S-1-5-32-545"
	authenticatedUsersSID = "S-1-5-11"
	everyoneSID           = "S-1-1-0"
)

func TestTrustedWindowsOwnerPolicy(t *testing.T) {
	principals, err := processPrincipals()
	if err != nil {
		t.Fatalf("resolve process principals: %v", err)
	}
	tests := []struct {
		name      string
		owner     string
		allowRoot bool
		want      bool
	}{
		{name: "process principal", owner: ownerSIDString(t), want: true},
		{name: "process principal ancestor", owner: ownerSIDString(t), allowRoot: true, want: true},
		{name: "local system ancestor", owner: localSystemSID, allowRoot: true, want: true},
		{name: "administrators ancestor", owner: administratorsSID, allowRoot: true, want: true},
		{name: "local system state object", owner: localSystemSID, want: false},
		{name: "administrators state object", owner: administratorsSID, want: false},
		{name: "builtin users ancestor", owner: builtinUsersSID, allowRoot: true, want: false},
		{name: "everyone ancestor", owner: everyoneSID, allowRoot: true, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sid := namedSID(t, test.owner)
			if got := principals.trustsOwner(sidPointer(sid), test.allowRoot); got != test.want {
				t.Fatalf("trustsOwner(%s, %t) = %t, want %t", test.owner, test.allowRoot, got, test.want)
			}
		})
	}
}

func TestEnsureDirSeversInheritedAccessControlEntries(t *testing.T) {
	parent := t.TempDir()
	if !hasInheritableForeignEntries(t, parent) {
		t.Logf("%s carries no inheritable foreign entries, so severing is only checked positively", parent)
	}
	path := filepath.Join(parent, "state")
	if err := EnsureDir(path); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	directory, err := openStateDirectory(path)
	if err != nil {
		t.Fatalf("open state directory: %v", err)
	}
	defer directory.Close()

	descriptor, err := readSecurityDescriptor(syscall.Handle(directory.Fd()))
	if err != nil {
		t.Fatalf("read security descriptor: %v", err)
	}
	defer descriptor.close()
	if descriptor.control&seDACLProtected == 0 {
		t.Fatal("state directory access control list is not protected")
	}
	entries, err := descriptor.entries()
	if err != nil {
		t.Fatalf("read access control entries: %v", err)
	}
	principals, err := processPrincipals()
	if err != nil {
		t.Fatalf("resolve process principals: %v", err)
	}
	for _, foreign := range []string{builtinUsersSID, authenticatedUsersSID, everyoneSID} {
		sid := namedSID(t, foreign)
		for _, entry := range entries {
			if equalSID(entry.sid, sid) {
				t.Fatalf("state directory access control list still names %s", foreign)
			}
		}
	}
	for _, entry := range entries {
		if !principals.trustsTrustee(entry.sid) {
			t.Fatal("state directory access control list names an untrusted principal")
		}
	}
}

func TestCreatePrivateFileProducesProtectedDescriptor(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	if err := EnsureDir(directory); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	path := filepath.Join(directory, "state.json")
	file, err := CreatePrivateFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		t.Fatalf("CreatePrivateFile: %v", err)
	}
	defer file.Close()
	matched, err := objectMatchesProtected(syscall.Handle(file.Fd()), false)
	if err != nil {
		t.Fatalf("inspect created state file: %v", err)
	}
	if !matched {
		t.Fatal("created state file does not carry the protected access control list")
	}
	if _, err := CreatePrivateFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL); !errors.Is(err, os.ErrExist) {
		t.Fatalf("exclusive re-create error = %v, want os.ErrExist", err)
	}
}

func TestValidateOwnerAndACLRejectsForeignAllowEntry(t *testing.T) {
	directory := openTestStateDirectory(t)
	applyTestDACL(t, directory, fmt.Sprintf("D:P(A;;FA;;;%s)(A;;0x1200a9;;;BU)", ownerSIDString(t)))
	if _, err := ValidateOwnerAndACL(directory, false); err == nil ||
		!strings.Contains(err.Error(), "unsafe access control list") {
		t.Fatalf("foreign allow entry error = %v, want unsafe access control list", err)
	}
}

func TestValidateOwnerAndACLAcceptsForeignDenyEntry(t *testing.T) {
	directory := openTestStateDirectory(t)
	applyTestDACL(t, directory, fmt.Sprintf("D:P(D;;FW;;;WD)(A;;FA;;;%s)(A;;FA;;;SY)(A;;FA;;;BA)", ownerSIDString(t)))
	if _, err := ValidateOwnerAndACL(directory, false); err != nil {
		t.Fatalf("deny-only foreign entry rejected: %v", err)
	}
}

func TestValidateOwnerAndACLRejectsNullAccessControlList(t *testing.T) {
	directory := openTestStateDirectory(t)
	setTestDACL(t, syscall.Handle(directory.Fd()), 0)
	if _, err := ValidateOwnerAndACL(directory, false); err == nil ||
		!strings.Contains(err.Error(), "unsafe access control list") {
		t.Fatalf("null access control list error = %v, want unsafe access control list", err)
	}
}

func TestValidateOwnerAndACLAncestorEntryRules(t *testing.T) {
	owner := ownerSIDString(t)
	tests := []struct {
		name      string
		entry     string
		allowRoot bool
		wantError string
	}{
		{name: "foreign read on ancestor", entry: "(A;;0x1200a9;;;BU)", allowRoot: true},
		{name: "foreign create on ancestor", entry: "(A;;LC;;;AU)", allowRoot: true},
		{name: "inherit only foreign entry", entry: "(A;OICIIO;FA;;;WD)", allowRoot: true},
		{name: "inherit only foreign entry on state object", entry: "(A;OICIIO;FA;;;WD)"},
		{name: "foreign read on state object", entry: "(A;;0x1200a9;;;BU)", wantError: "unsafe access control list"},
		{name: "foreign delete child on ancestor", entry: "(A;;0x40;;;BU)", allowRoot: true, wantError: "writable by an untrusted principal"},
		{name: "foreign delete on ancestor", entry: "(A;;SD;;;BU)", allowRoot: true, wantError: "writable by an untrusted principal"},
		{name: "foreign control on ancestor", entry: "(A;;0x40000;;;BU)", allowRoot: true, wantError: "writable by an untrusted principal"},
		{name: "foreign generic on ancestor", entry: "(A;;GA;;;BU)", allowRoot: true, wantError: "writable by an untrusted principal"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := openTestStateDirectory(t)
			applyTestDACL(t, directory, fmt.Sprintf("D:P(A;;FA;;;%s)%s", owner, test.entry))
			_, err := ValidateOwnerAndACL(directory, test.allowRoot)
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("entry %s rejected: %v", test.entry, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("entry %s error = %v, want %s", test.entry, err, test.wantError)
			}
		})
	}
}

func TestRequirePersistentACLsRejectsVolumeWithoutAccessControl(t *testing.T) {
	if err := RequirePersistentACLs(t.TempDir()); err != nil {
		t.Fatalf("temporary directory rejected: %v", err)
	}
	volume := volumeWithoutPersistentACLs(t)
	err := RequirePersistentACLs(volume)
	if !errors.Is(err, ErrUnsupportedVolume) {
		t.Fatalf("volume rejection error = %v, want unsupported volume", err)
	}
	if !strings.Contains(err.Error(), volume) {
		t.Fatalf("volume rejection does not name the path: %v", err)
	}
	t.Logf("volume rejection: %v", err)
}

func TestEnsureDirRefusesVolumeWithoutAccessControlBeforeCreating(t *testing.T) {
	path := filepath.Join(volumeWithoutPersistentACLs(t), "sub2api-securefile-volume-check")
	if err := EnsureDir(path); !errors.Is(err, ErrUnsupportedVolume) {
		t.Fatalf("EnsureDir error = %v, want unsupported volume", err)
	}
	if _, err := os.Stat(path); err == nil {
		_ = os.Remove(path)
		t.Fatal("EnsureDir created a directory on a volume without persistent access control lists")
	}
}

func TestValidateStatePathRejectsStreamsAndWildcards(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantError string
	}{
		{name: "drive rooted path", path: `C:\ProgramData\connector\state`},
		{name: "unc path", path: `\\nas\share\connector\state`},
		{name: "relative path", path: `connector\state`},
		{name: "alternate data stream", path: `C:\state\file.json:hidden`, wantError: "alternate data stream"},
		{name: "relative alternate data stream", path: `state:hidden`, wantError: "alternate data stream"},
		{name: "extended length prefix", path: `\\?\C:\state`, wantError: "wildcard"},
		{name: "wildcard star", path: `C:\state\*.json`, wantError: "wildcard"},
		{name: "wildcard question", path: `C:\state\file?.json`, wantError: "wildcard"},
		{name: "empty path", path: "", wantError: "empty"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateStatePath(test.path)
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("validateStatePath(%q) = %v, want nil", test.path, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("validateStatePath(%q) = %v, want %s", test.path, err, test.wantError)
			}
		})
	}
}

// FlushFileBuffers fails with ERROR_ACCESS_DENIED on a directory handle that
// carries no write right and succeeds on one that does, so a directory flush
// that "tolerates" that errno is not a flush at all. Both halves are asserted
// here: the read-only handle must be refused, and the handle this package
// actually opens must flush.
func TestDirectoryFlushRequiresAWriteRightAndIsNotSilentlySkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	if err := EnsureDir(path); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	if err := syncDirectory(path); err != nil {
		t.Fatalf("syncDirectory: %v", err)
	}
	directory, err := openStateDirectory(path)
	if err != nil {
		t.Fatalf("open state directory: %v", err)
	}
	defer directory.Close()
	if err := syncDirectoryHandle(directory); err != nil {
		t.Fatalf("syncDirectoryHandle: %v", err)
	}

	readOnly, err := openObjectHandle(
		path,
		syscall.FILE_LIST_DIRECTORY|readControl,
		syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		syscall.OPEN_EXISTING,
	)
	if err != nil {
		t.Fatalf("open read-only directory handle: %v", err)
	}
	defer syscall.CloseHandle(readOnly)
	if err := flushDirectory(readOnly); !errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
		t.Fatalf("flush of a read-only directory handle = %v, want ERROR_ACCESS_DENIED", err)
	}
}

func openTestStateDirectory(t *testing.T) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state")
	if err := EnsureDir(path); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	directory, err := openStateDirectory(path)
	if err != nil {
		t.Fatalf("open state directory: %v", err)
	}
	t.Cleanup(func() { _ = directory.Close() })
	return directory
}

func applyTestDACL(t *testing.T, object *os.File, sddl string) {
	t.Helper()
	descriptor, err := buildProtectedDescriptor(sddl)
	if err != nil {
		t.Fatalf("build test security descriptor: %v", err)
	}
	defer syscall.LocalFree(syscall.Handle(descriptor.attributes.SecurityDescriptor))
	setTestDACL(t, syscall.Handle(object.Fd()), descriptor.dacl)
}

func setTestDACL(t *testing.T, handle syscall.Handle, dacl uintptr) {
	t.Helper()
	status, _, _ := procSetSecurityInfo.Call(
		uintptr(handle),
		seFileObject,
		daclSecurityInformation|protectedDACLSecurityInfo,
		0,
		0,
		dacl,
		0,
	)
	if status != 0 {
		t.Fatalf("set test access control list: %v", syscall.Errno(status))
	}
}

func hasInheritableForeignEntries(t *testing.T, path string) bool {
	t.Helper()
	directory, err := openStateDirectory(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer directory.Close()
	descriptor, err := readSecurityDescriptor(syscall.Handle(directory.Fd()))
	if err != nil {
		t.Fatalf("read security descriptor for %s: %v", path, err)
	}
	defer descriptor.close()
	principals, err := processPrincipals()
	if err != nil {
		t.Fatalf("resolve process principals: %v", err)
	}
	entries, err := descriptor.entries()
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.kind != accessAllowedACEType {
			continue
		}
		if entry.flags&(objectInheritACE|containerInheritACE) == 0 {
			continue
		}
		if !principals.trustsTrustee(entry.sid) {
			return true
		}
	}
	return false
}

func volumeWithoutPersistentACLs(t *testing.T) string {
	t.Helper()
	for letter := 'A'; letter <= 'Z'; letter++ {
		root := string(letter) + `:\`
		if _, err := os.Stat(root); err != nil {
			continue
		}
		if err := RequirePersistentACLs(root); errors.Is(err, ErrUnsupportedVolume) {
			return root
		}
	}
	t.Skip("no reachable volume lacks persistent access control lists")
	return ""
}

func sidPointer(sid *syscall.SID) uintptr {
	return uintptr(unsafe.Pointer(sid))
}

func namedSID(t *testing.T, value string) *syscall.SID {
	t.Helper()
	sid, err := syscall.StringToSid(value)
	if err != nil {
		t.Fatalf("resolve %s: %v", value, err)
	}
	return sid
}

func ownerSIDString(t *testing.T) string {
	t.Helper()
	principals, err := processPrincipals()
	if err != nil {
		t.Fatalf("resolve process principals: %v", err)
	}
	owner, err := principals.owner.String()
	if err != nil {
		t.Fatalf("format process principal: %v", err)
	}
	return owner
}

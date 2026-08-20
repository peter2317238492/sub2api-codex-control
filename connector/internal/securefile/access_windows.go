//go:build windows

package securefile

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

const (
	localSystemSID    = "S-1-5-18"
	administratorsSID = "S-1-5-32-544"
	// NT SERVICE\TrustedInstaller owns the volume roots and the OS-managed
	// directories on a stock Windows install, so it is the analogue of a
	// root-owned "/" that allowRoot exists for. The SID is derived from the
	// service name and is therefore identical on every machine. Only SYSTEM and
	// Administrators can take ownership from it, so an unprivileged principal
	// cannot assume it; the whole S-1-5-80 service-SID class is deliberately
	// not trusted, because any installed service gets one.
	trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

	seFileObject = 1

	ownerSecurityInformation     = 0x00000001
	daclSecurityInformation      = 0x00000004
	protectedDACLSecurityInfo    = 0x80000000
	securityDescriptorRevision   = 1
	aclSizeInformationClass      = 2
	filePersistentACLs           = 0x00000008
	windowsFileSystemNameMaximum = 64

	seDACLPresent   = 0x0004
	seDACLDefaulted = 0x0008
	seDACLProtected = 0x1000

	accessAllowedACEType = 0x00
	accessDeniedACEType  = 0x01

	objectInheritACE    = 0x01
	containerInheritACE = 0x02
	inheritOnlyACE      = 0x08

	fileAllAccess   = 0x001F01FF
	fileAppendData  = 0x00000004
	fileDeleteChild = 0x00000040
	standardDelete  = 0x00010000
	readControl     = 0x00020000
	writeDAC        = 0x00040000
	writeOwner      = 0x00080000
	genericRights   = 0xF0000000

	// A trustee holding any of these on an ancestor can delete, rename, or take
	// control of what sits beneath it. Creating entries is not enough, which is
	// exactly what the POSIX sticky bit permits.
	ancestorForbiddenRights = standardDelete | writeDAC | writeOwner | fileDeleteChild | genericRights
)

var (
	advapi32                         = syscall.NewLazyDLL("advapi32.dll")
	procConvertStringSecurityToSD    = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procEqualSid                     = advapi32.NewProc("EqualSid")
	procGetAce                       = advapi32.NewProc("GetAce")
	procGetAclInformation            = advapi32.NewProc("GetAclInformation")
	procGetSecurityDescriptorControl = advapi32.NewProc("GetSecurityDescriptorControl")
	procGetSecurityDescriptorDacl    = advapi32.NewProc("GetSecurityDescriptorDacl")
	procGetSecurityInfo              = advapi32.NewProc("GetSecurityInfo")
	procSetSecurityInfo              = advapi32.NewProc("SetSecurityInfo")

	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procGetVolumeInformationW = kernel32.NewProc("GetVolumeInformationW")
	procGetVolumePathNameW    = kernel32.NewProc("GetVolumePathNameW")
)

type aceHeader struct {
	AceType  byte
	AceFlags byte
	AceSize  uint16
}

type knownACE struct {
	Header   aceHeader
	Mask     uint32
	SidStart uint32
}

type aclSizeInfo struct {
	AceCount      uint32
	AclBytesInUse uint32
	AclBytesFree  uint32
}

const aceSIDOffset = unsafe.Offsetof(knownACE{}.SidStart)

type accessEntry struct {
	kind  byte
	flags byte
	mask  uint32
	sid   uintptr
}

type trustedPrincipals struct {
	owner     *syscall.SID
	system    *syscall.SID
	admins    *syscall.SID
	installer *syscall.SID
}

type protectedDescriptor struct {
	attributes *syscall.SecurityAttributes
	dacl       uintptr
}

var (
	principalsOnce  sync.Once
	principalsValue trustedPrincipals
	principalsErr   error

	descriptorsOnce     sync.Once
	fileDescriptor      protectedDescriptor
	directoryDescriptor protectedDescriptor
	descriptorsBuildErr error
)

func processPrincipals() (trustedPrincipals, error) {
	principalsOnce.Do(func() {
		process, err := syscall.GetCurrentProcess()
		if err != nil {
			principalsErr = fmt.Errorf("open current process: %w", err)
			return
		}
		var token syscall.Token
		if err := syscall.OpenProcessToken(process, syscall.TOKEN_QUERY, &token); err != nil {
			principalsErr = fmt.Errorf("open process token: %w", err)
			return
		}
		defer token.Close()
		user, err := token.GetTokenUser()
		if err != nil {
			principalsErr = fmt.Errorf("read process token user: %w", err)
			return
		}
		owner, err := user.User.Sid.Copy()
		if err != nil {
			principalsErr = fmt.Errorf("copy process token user: %w", err)
			return
		}
		system, err := syscall.StringToSid(localSystemSID)
		if err != nil {
			principalsErr = fmt.Errorf("resolve %s: %w", localSystemSID, err)
			return
		}
		admins, err := syscall.StringToSid(administratorsSID)
		if err != nil {
			principalsErr = fmt.Errorf("resolve %s: %w", administratorsSID, err)
			return
		}
		installer, err := syscall.StringToSid(trustedInstallerSID)
		if err != nil {
			principalsErr = fmt.Errorf("resolve %s: %w", trustedInstallerSID, err)
			return
		}
		principalsValue = trustedPrincipals{owner: owner, system: system, admins: admins, installer: installer}
	})
	return principalsValue, principalsErr
}

func (p trustedPrincipals) trustsTrustee(sid uintptr) bool {
	return equalSID(sid, p.owner) || equalSID(sid, p.system) || equalSID(sid, p.admins) ||
		equalSID(sid, p.installer)
}

func (p trustedPrincipals) trustsOwner(sid uintptr, allowRoot bool) bool {
	if equalSID(sid, p.owner) {
		return true
	}
	return allowRoot && (equalSID(sid, p.system) || equalSID(sid, p.admins) || equalSID(sid, p.installer))
}

func equalSID(sid uintptr, other *syscall.SID) bool {
	if sid == 0 || other == nil {
		return false
	}
	equal, _, _ := procEqualSid.Call(sid, uintptr(unsafe.Pointer(other)))
	return equal != 0
}

func desiredDescriptor(directory bool) (protectedDescriptor, error) {
	descriptorsOnce.Do(func() {
		principals, err := processPrincipals()
		if err != nil {
			descriptorsBuildErr = err
			return
		}
		owner, err := principals.owner.String()
		if err != nil {
			descriptorsBuildErr = fmt.Errorf("format process token user: %w", err)
			return
		}
		fileDescriptor, descriptorsBuildErr = buildProtectedDescriptor(
			fmt.Sprintf("D:P(A;;FA;;;%s)(A;;FA;;;SY)(A;;FA;;;BA)", owner))
		if descriptorsBuildErr != nil {
			return
		}
		directoryDescriptor, descriptorsBuildErr = buildProtectedDescriptor(
			fmt.Sprintf("D:P(A;OICI;FA;;;%s)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", owner))
	})
	if descriptorsBuildErr != nil {
		return protectedDescriptor{}, descriptorsBuildErr
	}
	if directory {
		return directoryDescriptor, nil
	}
	return fileDescriptor, nil
}

func buildProtectedDescriptor(sddl string) (protectedDescriptor, error) {
	encoded, err := syscall.UTF16PtrFromString(sddl)
	if err != nil {
		return protectedDescriptor{}, fmt.Errorf("encode state security descriptor: %w", err)
	}
	var descriptor uintptr
	ok, _, callErr := procConvertStringSecurityToSD.Call(
		uintptr(unsafe.Pointer(encoded)),
		securityDescriptorRevision,
		uintptr(unsafe.Pointer(&descriptor)),
		0,
	)
	if ok == 0 || descriptor == 0 {
		return protectedDescriptor{}, fmt.Errorf("build state security descriptor: %w", securityCallError(callErr))
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
		return protectedDescriptor{}, fmt.Errorf("read state security descriptor: %w", securityCallError(callErr))
	}
	attributes := &syscall.SecurityAttributes{SecurityDescriptor: descriptor}
	attributes.Length = uint32(unsafe.Sizeof(*attributes))
	return protectedDescriptor{attributes: attributes, dacl: dacl}, nil
}

type securityDescriptor struct {
	descriptor uintptr
	owner      uintptr
	dacl       uintptr
	control    uint16
}

func readSecurityDescriptor(handle syscall.Handle) (*securityDescriptor, error) {
	var owner, group, dacl, sacl, descriptor uintptr
	status, _, _ := procGetSecurityInfo.Call(
		uintptr(handle),
		seFileObject,
		ownerSecurityInformation|daclSecurityInformation,
		uintptr(unsafe.Pointer(&owner)),
		uintptr(unsafe.Pointer(&group)),
		uintptr(unsafe.Pointer(&dacl)),
		uintptr(unsafe.Pointer(&sacl)),
		uintptr(unsafe.Pointer(&descriptor)),
	)
	if status != 0 || descriptor == 0 {
		return nil, fmt.Errorf("inspect state object access control list: %w", syscall.Errno(status))
	}
	result := &securityDescriptor{descriptor: descriptor, owner: owner, dacl: dacl}
	var revision uint32
	ok, _, callErr := procGetSecurityDescriptorControl.Call(
		descriptor,
		uintptr(unsafe.Pointer(&result.control)),
		uintptr(unsafe.Pointer(&revision)),
	)
	if ok == 0 {
		result.close()
		return nil, fmt.Errorf("inspect state object access control list: %w", securityCallError(callErr))
	}
	return result, nil
}

func (d *securityDescriptor) close() {
	if d.descriptor != 0 {
		_, _ = syscall.LocalFree(syscall.Handle(d.descriptor))
		d.descriptor = 0
	}
}

func (d *securityDescriptor) entries() ([]accessEntry, error) {
	if d.control&seDACLPresent == 0 || d.dacl == 0 {
		return nil, untrustedLocation("state object has an unsafe access control list")
	}
	if d.control&seDACLDefaulted != 0 {
		return nil, errors.New("state object has a defaulted access control list")
	}
	var size aclSizeInfo
	ok, _, callErr := procGetAclInformation.Call(
		d.dacl,
		uintptr(unsafe.Pointer(&size)),
		unsafe.Sizeof(size),
		aclSizeInformationClass,
	)
	if ok == 0 {
		return nil, fmt.Errorf("inspect state object access control list: %w", securityCallError(callErr))
	}
	entries := make([]accessEntry, 0, size.AceCount)
	for index := uint32(0); index < size.AceCount; index++ {
		var ace unsafe.Pointer
		ok, _, callErr := procGetAce.Call(d.dacl, uintptr(index), uintptr(unsafe.Pointer(&ace)))
		if ok == 0 || ace == nil {
			return nil, fmt.Errorf("inspect state object access control list: %w", securityCallError(callErr))
		}
		header := (*knownACE)(ace)
		if header.Header.AceType != accessAllowedACEType && header.Header.AceType != accessDeniedACEType {
			return nil, errors.New("state object has an unsupported access control entry")
		}
		if uintptr(header.Header.AceSize) <= aceSIDOffset {
			return nil, errors.New("state object has a malformed access control entry")
		}
		entries = append(entries, accessEntry{
			kind:  header.Header.AceType,
			flags: header.Header.AceFlags,
			mask:  header.Mask,
			sid:   uintptr(ace) + aceSIDOffset,
		})
	}
	return entries, nil
}

func (d *securityDescriptor) validateOwner(allowRoot bool) error {
	principals, err := processPrincipals()
	if err != nil {
		return err
	}
	if !principals.trustsOwner(d.owner, allowRoot) {
		return untrustedLocation("state object has an untrusted owner")
	}
	return nil
}

// validateDACL enforces the final-object rule when allowRoot is false: every
// effective allow entry must name the connector principal, LocalSystem, or
// Administrators. When allowRoot is true the object is a trusted ancestor, and
// a foreign trustee may hold rights that cannot replace what lives beneath it —
// the mapping of the POSIX "group/other writable is fine when sticky" rule.
func (d *securityDescriptor) validateDACL(allowRoot bool) error {
	entries, err := d.entries()
	if err != nil {
		return err
	}
	principals, err := processPrincipals()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.kind == accessDeniedACEType || entry.flags&inheritOnlyACE != 0 {
			continue
		}
		if principals.trustsTrustee(entry.sid) {
			continue
		}
		if !allowRoot {
			return untrustedLocation("state object has an unsafe access control list")
		}
		if entry.mask&ancestorForbiddenRights != 0 {
			return untrustedLocation("state ancestor is writable by an untrusted principal")
		}
	}
	return nil
}

func (d *securityDescriptor) matchesProtected(directory bool) bool {
	if d.control&seDACLProtected == 0 {
		return false
	}
	principals, err := processPrincipals()
	if err != nil {
		return false
	}
	entries, err := d.entries()
	if err != nil {
		return false
	}
	expected := []*syscall.SID{principals.owner, principals.system, principals.admins}
	if len(entries) != len(expected) {
		return false
	}
	flags := byte(0)
	if directory {
		flags = objectInheritACE | containerInheritACE
	}
	for index, entry := range entries {
		if entry.kind != accessAllowedACEType || entry.flags != flags || entry.mask != fileAllAccess {
			return false
		}
		if !equalSID(entry.sid, expected[index]) {
			return false
		}
	}
	return true
}

func validateAccess(file *os.File, info os.FileInfo, allowRoot bool) error {
	if err := rejectReparsePoint(info); err != nil {
		return err
	}
	descriptor, err := readSecurityDescriptor(syscall.Handle(file.Fd()))
	if err != nil {
		return err
	}
	defer descriptor.close()
	if err := descriptor.validateOwner(allowRoot); err != nil {
		return err
	}
	return descriptor.validateDACL(allowRoot)
}

func rejectReparsePoint(info os.FileInfo) error {
	data, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return errors.New("state object attributes are unavailable")
	}
	if data.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("state object is a reparse point")
	}
	return nil
}

func validateStatePath(path string) error {
	if path == "" {
		return errors.New("state path is empty")
	}
	if strings.ContainsAny(path, `*?"<>|`) {
		return fmt.Errorf("state path %s contains wildcard characters", path)
	}
	remainder := path
	if len(path) >= 2 && path[1] == ':' && isDriveLetter(path[0]) {
		remainder = path[2:]
	}
	if strings.Contains(remainder, ":") {
		return fmt.Errorf("state path %s names an alternate data stream", path)
	}
	return nil
}

func isDriveLetter(letter byte) bool {
	return letter >= 'A' && letter <= 'Z' || letter >= 'a' && letter <= 'z'
}

func requirePersistentACLs(path string) error {
	if path == "" {
		return errors.New("state path is empty")
	}
	root, err := volumeRoot(path)
	if err != nil {
		return err
	}
	flags, filesystem, err := volumeInformation(root)
	if err != nil {
		return err
	}
	if flags&filePersistentACLs == 0 {
		return fmt.Errorf("state path %s is on %s volume %s: %w, so choose a state directory on an NTFS volume",
			path, filesystem, root, ErrUnsupportedVolume)
	}
	return nil
}

func volumeRoot(path string) (string, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", fmt.Errorf("encode state path %s: %w", path, err)
	}
	buffer := make([]uint16, syscall.MAX_PATH+1)
	ok, _, callErr := procGetVolumePathNameW.Call(
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
	)
	if ok == 0 {
		return "", fmt.Errorf("resolve state volume for %s: %w", path, securityCallError(callErr))
	}
	return syscall.UTF16ToString(buffer), nil
}

func volumeInformation(root string) (uint32, string, error) {
	name, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		return 0, "", fmt.Errorf("encode state volume %s: %w", root, err)
	}
	var serial, components, flags uint32
	filesystem := make([]uint16, windowsFileSystemNameMaximum)
	ok, _, callErr := procGetVolumeInformationW.Call(
		uintptr(unsafe.Pointer(name)),
		0,
		0,
		uintptr(unsafe.Pointer(&serial)),
		uintptr(unsafe.Pointer(&components)),
		uintptr(unsafe.Pointer(&flags)),
		uintptr(unsafe.Pointer(&filesystem[0])),
		uintptr(len(filesystem)),
	)
	if ok == 0 {
		return 0, "", fmt.Errorf("inspect state volume %s: %w", root, securityCallError(callErr))
	}
	return flags, syscall.UTF16ToString(filesystem), nil
}

func openObjectHandle(path string, access, flags, disposition uint32) (syscall.Handle, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return syscall.InvalidHandle, err
	}
	return syscall.CreateFile(
		name,
		access,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		disposition,
		flags,
		0,
	)
}

func openStateDirectory(path string) (*os.File, error) {
	handle, err := openObjectHandle(
		path,
		syscall.FILE_LIST_DIRECTORY|readControl|writeDAC,
		syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		syscall.OPEN_EXISTING,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(handle), path), nil
}

func openStateFile(path string) (*os.File, error) {
	handle, err := openObjectHandle(
		path,
		syscall.GENERIC_READ,
		syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		syscall.OPEN_EXISTING,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(handle), path), nil
}

func createPrivateFile(path string, flag int) (*os.File, error) {
	descriptor, err := desiredDescriptor(false)
	if err != nil {
		return nil, err
	}
	access, disposition, err := windowsOpenMode(flag)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	handle, err := syscall.CreateFile(
		name,
		access,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		descriptor.attributes,
		disposition,
		syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(handle), path)
	if err := verifyCreatedObject(handle, false); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func windowsOpenMode(flag int) (uint32, uint32, error) {
	const supported = os.O_RDONLY | os.O_WRONLY | os.O_RDWR | os.O_CREATE | os.O_EXCL | os.O_TRUNC | os.O_APPEND
	if flag&^supported != 0 {
		return 0, 0, errors.New("unsupported state file open flags")
	}
	access := uint32(readControl | writeDAC)
	switch {
	case flag&os.O_WRONLY != 0:
		access |= syscall.GENERIC_WRITE
	case flag&os.O_RDWR != 0:
		access |= syscall.GENERIC_READ | syscall.GENERIC_WRITE
	default:
		access |= syscall.GENERIC_READ
	}
	if flag&os.O_APPEND != 0 {
		access &^= syscall.GENERIC_WRITE
		access |= fileAppendData
	}
	var disposition uint32
	switch {
	case flag&(os.O_CREATE|os.O_EXCL) == os.O_CREATE|os.O_EXCL:
		disposition = syscall.CREATE_NEW
	case flag&(os.O_CREATE|os.O_TRUNC) == os.O_CREATE|os.O_TRUNC:
		disposition = syscall.CREATE_ALWAYS
	case flag&os.O_CREATE != 0:
		disposition = syscall.OPEN_ALWAYS
	case flag&os.O_TRUNC != 0:
		disposition = syscall.TRUNCATE_EXISTING
	default:
		disposition = syscall.OPEN_EXISTING
	}
	return access, disposition, nil
}

func mkdirPrivate(path string) error {
	descriptor, err := desiredDescriptor(true)
	if err != nil {
		return err
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: path, Err: err}
	}
	if err := syscall.CreateDirectory(name, descriptor.attributes); err != nil {
		return &os.PathError{Op: "mkdir", Path: path, Err: err}
	}
	handle, err := openObjectHandle(
		path,
		syscall.FILE_LIST_DIRECTORY|readControl,
		syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		syscall.OPEN_EXISTING,
	)
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: path, Err: err}
	}
	defer syscall.CloseHandle(handle)
	return verifyCreatedObject(handle, true)
}

func verifyCreatedObject(handle syscall.Handle, directory bool) error {
	descriptor, err := readSecurityDescriptor(handle)
	if err != nil {
		return err
	}
	defer descriptor.close()
	if err := descriptor.validateOwner(false); err != nil {
		return err
	}
	if !descriptor.matchesProtected(directory) {
		return errors.New("created state object is not private")
	}
	return nil
}

func restrictDirectory(dir *os.File) error {
	return applyProtectedDACL(dir, true)
}

func restrictFile(file *os.File) error {
	return applyProtectedDACL(file, false)
}

func applyProtectedDACL(object *os.File, directory bool) error {
	if object == nil {
		return errors.New("state object is not open")
	}
	desired, err := desiredDescriptor(directory)
	if err != nil {
		return err
	}
	handle := syscall.Handle(object.Fd())
	matched, err := objectMatchesProtected(handle, directory)
	if err != nil {
		return err
	}
	if matched {
		return nil
	}
	status, _, _ := procSetSecurityInfo.Call(
		uintptr(handle),
		seFileObject,
		daclSecurityInformation|protectedDACLSecurityInfo,
		0,
		0,
		desired.dacl,
		0,
	)
	if status != 0 {
		return fmt.Errorf("apply protected access control list: %w", syscall.Errno(status))
	}
	matched, err = objectMatchesProtected(handle, directory)
	if err != nil {
		return err
	}
	if !matched {
		return errors.New("state object access control list was not applied")
	}
	return nil
}

func objectMatchesProtected(handle syscall.Handle, directory bool) (bool, error) {
	descriptor, err := readSecurityDescriptor(handle)
	if err != nil {
		return false, err
	}
	defer descriptor.close()
	return descriptor.matchesProtected(directory), nil
}

func verifyPrivateDirectory(dir *os.File, info os.FileInfo) error {
	if dir == nil {
		return errors.New("state object is not open")
	}
	if !info.IsDir() {
		return errors.New("state directory is not private")
	}
	descriptor, err := readSecurityDescriptor(syscall.Handle(dir.Fd()))
	if err != nil {
		return err
	}
	defer descriptor.close()
	if descriptor.control&seDACLProtected == 0 {
		return errors.New("state directory is not private")
	}
	if err := descriptor.validateOwner(false); err != nil {
		return err
	}
	return descriptor.validateDACL(false)
}

func verifyPrivateFile(file *os.File, info os.FileInfo) error {
	if file == nil {
		return errors.New("state object is not open")
	}
	if !info.Mode().IsRegular() {
		return errors.New("state path is not a private regular file")
	}
	return validateAccess(file, info, false)
}

func syncDirectory(path string) error {
	handle, err := openObjectHandle(
		path,
		syscall.FILE_LIST_DIRECTORY|readControl,
		syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		syscall.OPEN_EXISTING,
	)
	if err != nil {
		return &os.PathError{Op: "open", Path: path, Err: err}
	}
	defer syscall.CloseHandle(handle)
	return flushDirectory(handle)
}

func syncDirectoryHandle(dir *os.File) error {
	if dir == nil {
		return errors.New("state object is not open")
	}
	return flushDirectory(syscall.Handle(dir.Fd()))
}

func flushDirectory(handle syscall.Handle) error {
	// NTFS refuses FlushFileBuffers on a directory handle with
	// ERROR_ACCESS_DENIED even for the owner, because it journals directory
	// metadata instead of buffering it. That errno alone is safe to ignore;
	// every other failure still means the entry may not be durable.
	if err := syscall.FlushFileBuffers(handle); err != nil && !errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
		return err
	}
	return nil
}

func securityCallError(err error) error {
	var errno syscall.Errno
	if err == nil || (errors.As(err, &errno) && errno == 0) {
		return errors.New("Windows security operation failed")
	}
	return err
}

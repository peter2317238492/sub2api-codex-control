//go:build windows

package statelock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/securefile"
)

const (
	errorSharingViolation syscall.Errno = 32
	errorLockViolation    syscall.Errno = 33

	fileListDirectory  = 0x00000001
	fileReadAttributes = 0x00000080
	readControl        = 0x00020000

	lockfileFailImmediately = 0x00000001
	lockfileExclusiveLock   = 0x00000002

	lockRegionLow  = 0xFFFFFFFF
	lockRegionHigh = 0xFFFFFFFF

	extendedLengthPrefix  = `\\?\`
	deviceNamespacePrefix = `\\.\`
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = kernel32.NewProc("LockFileEx")
	procUnlockFileEx = kernel32.NewProc("UnlockFileEx")
)

type fileIdentity struct {
	volume uint32
	high   uint32
	low    uint32
}

func checkPlatform() error { return nil }

func acquireStateDir(path string) (func() error, error) {
	base, err := stateVolumeRoot(path)
	if err != nil {
		return nil, err
	}
	return acquireStateDirFrom(base, path)
}

// acquireStateDirFrom validates base and then every component below it.
// Production always passes the volume root, so the whole path is validated;
// tests pass a directory they have already made private, which is the only way
// to reach this code on a host whose profile ancestors are shared.
func acquireStateDirFrom(base, path string) (func() error, error) {
	if err := securefile.RequirePersistentACLs(path); err != nil {
		return nil, err
	}
	directory, err := openTrustedDirectory(base, path)
	if err != nil {
		return nil, err
	}
	closeDirectoryOnError := func(result error) (func() error, error) {
		_ = directory.Close()
		return nil, result
	}
	// The directory handle withholds FILE_SHARE_DELETE, so the state directory
	// cannot be renamed or deleted while the Connector holds it. It is the
	// Windows analogue of the pinned inode the Unix implementation flocks, and
	// it is what stops a replaced connector.lock name from splitting the lock.
	lock, err := openLockFile(path)
	if err != nil {
		return closeDirectoryOnError(err)
	}
	closeLockOnError := func(result error) (func() error, error) {
		_ = lock.Close()
		return closeDirectoryOnError(result)
	}
	if err := lockLockFile(lock); err != nil {
		return closeLockOnError(err)
	}
	unlockOnError := func(result error) (func() error, error) {
		_ = unlockLockFile(lock)
		return closeLockOnError(result)
	}
	info, err := securefile.ValidateOwnerAndACL(lock, false)
	if err != nil {
		return unlockOnError(err)
	}
	information, err := handleInformation(lock)
	if err != nil {
		return unlockOnError(errors.New("inspect connector state lock"))
	}
	if !info.Mode().IsRegular() || information.NumberOfLinks != 1 ||
		information.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return unlockOnError(errors.New("connector state lock is not a private regular file"))
	}
	if err := lock.Sync(); err != nil {
		return unlockOnError(fmt.Errorf("sync connector state lock: %w", err))
	}
	return func() error {
		unlockErr := unlockLockFile(lock)
		closeLockErr := lock.Close()
		closeDirectoryErr := directory.Close()
		if unlockErr != nil {
			unlockErr = fmt.Errorf("release connector state directory lock: %w", unlockErr)
		}
		if closeLockErr != nil {
			closeLockErr = fmt.Errorf("close connector state lock: %w", closeLockErr)
		}
		if closeDirectoryErr != nil {
			closeDirectoryErr = fmt.Errorf("close connector state directory: %w", closeDirectoryErr)
		}
		return errors.Join(unlockErr, closeLockErr, closeDirectoryErr)
	}, nil
}

func openLockFile(stateDir string) (*os.File, error) {
	path := filepath.Join(stateDir, lockFileName)
	// The exclusive open below withholds every share right, so it cannot also
	// carry the protected descriptor a new marker needs; securefile creates the
	// file already private instead. A competitor that already holds the lock
	// fails this creation with the same sharing violation.
	private, err := securefile.CreatePrivateFile(path, os.O_RDWR|os.O_CREATE)
	if err != nil {
		if contended(err) {
			return nil, ErrInUse
		}
		return nil, errors.New("create connector state lock")
	}
	if err := private.Close(); err != nil {
		return nil, fmt.Errorf("close connector state lock: %w", err)
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, errors.New("open connector state lock")
	}
	handle, err := syscall.CreateFile(
		name,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		0,
		nil,
		syscall.OPEN_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		if contended(err) {
			return nil, ErrInUse
		}
		return nil, errors.New("open connector state lock")
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = syscall.CloseHandle(handle)
		return nil, errors.New("open connector state lock")
	}
	return file, nil
}

func lockLockFile(file *os.File) error {
	overlapped := syscall.Overlapped{}
	locked, _, callErr := procLockFileEx.Call(
		file.Fd(),
		lockfileExclusiveLock|lockfileFailImmediately,
		0,
		lockRegionLow,
		lockRegionHigh,
		uintptr(unsafe.Pointer(&overlapped)),
	)
	if locked != 0 {
		return nil
	}
	if contended(callErr) {
		return ErrInUse
	}
	return fmt.Errorf("acquire connector state directory lock: %w", windowsCallError(callErr))
}

func unlockLockFile(file *os.File) error {
	overlapped := syscall.Overlapped{}
	unlocked, _, callErr := procUnlockFileEx.Call(
		file.Fd(),
		0,
		lockRegionLow,
		lockRegionHigh,
		uintptr(unsafe.Pointer(&overlapped)),
	)
	if unlocked != 0 {
		return nil
	}
	return windowsCallError(callErr)
}

func openTrustedDirectory(base, path string) (*os.File, error) {
	return openTrustedDirectoryWithHook(base, path, nil)
}

func openTrustedDirectoryWithHook(base, path string, beforeIdentityCheck func(string)) (*os.File, error) {
	components, err := stateComponents(base, path)
	if err != nil {
		return nil, err
	}
	current, err := openStateComponent(base, false)
	if err != nil {
		return nil, errors.New("open connector state volume root")
	}
	closeCurrentOnError := func(result error) (*os.File, error) {
		_ = current.Close()
		return nil, result
	}
	if err := validateStateComponent(current, false); err != nil {
		return closeCurrentOnError(describeComponentError(base, false, err))
	}
	parent := base
	for index, component := range components {
		child := filepath.Join(parent, component)
		final := index == len(components)-1
		if err := prepareStateComponent(child, final); err != nil {
			return closeCurrentOnError(describeComponentError(child, final, err))
		}
		directory, err := openStateComponent(child, final)
		if err != nil {
			return closeCurrentOnError(errors.New("open connector state directory component"))
		}
		if err := validateStateComponent(directory, final); err != nil {
			_ = directory.Close()
			return closeCurrentOnError(describeComponentError(child, final, err))
		}
		if beforeIdentityCheck != nil {
			beforeIdentityCheck(child)
		}
		if err := verifyStateComponentIdentity(directory, child); err != nil {
			_ = directory.Close()
			return closeCurrentOnError(err)
		}
		_ = current.Close()
		current = directory
		parent = child
	}
	return current, nil
}

// prepareStateComponent leaves an existing ancestor untouched and creates a
// missing one, and the state directory itself, through securefile so it is
// private from the moment it exists.
func prepareStateComponent(path string, final bool) error {
	if !final {
		_, err := os.Lstat(path)
		if err == nil {
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return errors.New("inspect connector state directory component")
		}
	}
	return securefile.EnsureDir(path)
}

func openStateComponent(path string, pinned bool) (*os.File, error) {
	share := uint32(syscall.FILE_SHARE_READ | syscall.FILE_SHARE_WRITE | syscall.FILE_SHARE_DELETE)
	if pinned {
		share = syscall.FILE_SHARE_READ | syscall.FILE_SHARE_WRITE
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(
		name,
		fileListDirectory|fileReadAttributes|readControl,
		share,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = syscall.CloseHandle(handle)
		return nil, errors.New("open connector state directory component")
	}
	return file, nil
}

func validateStateComponent(directory *os.File, final bool) error {
	information, err := handleInformation(directory)
	if err != nil {
		return errors.New("inspect connector state directory component")
	}
	if information.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("connector state directory component is a reparse point")
	}
	if information.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return errors.New("connector state path component is not a directory")
	}
	info, err := securefile.ValidateOwnerAndACL(directory, !final)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("connector state path component is not a directory")
	}
	return nil
}

func verifyStateComponentIdentity(directory *os.File, path string) error {
	held, err := handleInformation(directory)
	if err != nil {
		return errors.New("inspect connector state directory component")
	}
	probe, err := openStateComponent(path, false)
	if err != nil {
		return errors.New("inspect connector state directory component")
	}
	current, probeErr := handleInformation(probe)
	closeErr := probe.Close()
	if probeErr != nil || closeErr != nil {
		return errors.New("inspect connector state directory component")
	}
	if identityOf(held) != identityOf(current) {
		return errors.New("connector state directory component changed during validation")
	}
	return nil
}

// describeComponentError names the offending directory, which is what makes a
// refused start actionable: the operator has to know which ancestor is shared
// before they can move the state directory somewhere else.
func describeComponentError(path string, final bool, err error) error {
	if final {
		return fmt.Errorf("connector state directory %s: %w", path, err)
	}
	return fmt.Errorf("connector state ancestor %s: %w", path, err)
}

func handleInformation(file *os.File) (syscall.ByHandleFileInformation, error) {
	var information syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(syscall.Handle(file.Fd()), &information); err != nil {
		return syscall.ByHandleFileInformation{}, err
	}
	return information, nil
}

func identityOf(information syscall.ByHandleFileInformation) fileIdentity {
	return fileIdentity{
		volume: information.VolumeSerialNumber,
		high:   information.FileIndexHigh,
		low:    information.FileIndexLow,
	}
}

// stateVolumeRoot returns the volume the state directory lives on, which is
// where ancestor validation starts. lock.go rejects the POSIX filesystem root
// but cannot recognise a Windows volume root, so that rule is applied here.
func stateVolumeRoot(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("connector state directory must be an absolute non-root path")
	}
	clean := filepath.Clean(path)
	if strings.HasPrefix(clean, extendedLengthPrefix) || strings.HasPrefix(clean, deviceNamespacePrefix) {
		return "", errors.New("connector state directory must be a drive-letter or UNC path")
	}
	volume := filepath.VolumeName(clean)
	if volume == "" {
		return "", errors.New("connector state directory must be a drive-letter or UNC path")
	}
	root := volume + string(filepath.Separator)
	if clean == volume || clean == root {
		return "", errors.New("connector state directory must be an absolute non-root path")
	}
	return root, nil
}

func stateComponents(base, path string) ([]string, error) {
	prefix := base
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	clean := filepath.Clean(path)
	if !strings.HasPrefix(clean, prefix) {
		return nil, errors.New("connector state directory is not below its volume root")
	}
	components := strings.Split(strings.TrimPrefix(clean, prefix), string(filepath.Separator))
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			return nil, errors.New("connector state directory has an invalid component")
		}
	}
	return components, nil
}

func contended(err error) bool {
	return errors.Is(err, errorSharingViolation) || errors.Is(err, errorLockViolation)
}

func windowsCallError(err error) error {
	var errno syscall.Errno
	if err == nil || (errors.As(err, &errno) && errno == 0) {
		return errors.New("Windows state lock operation failed")
	}
	return err
}

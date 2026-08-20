//go:build windows

package pairing

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/securefile"
)

const (
	windowsErrorSharingViolation syscall.Errno = 32
	windowsErrorLockViolation    syscall.Errno = 33
)

// acquirePairingStateLock holds the pairing state lock by owning the only
// handle to it: Windows has no advisory lock a second opener can observe, so
// exclusivity comes from a zero share mode. The lock file is brought into
// existence through securefile so that its access control list is protected
// from the moment the object exists rather than applied after a window in which
// the inherited entries of the volume apply, and the exclusive handle is
// re-validated once it is held.
func acquirePairingStateLock(stateDir string) (func() error, error) {
	if err := securefile.EnsureDir(stateDir); err != nil {
		return nil, err
	}
	path := filepath.Join(stateDir, "pairing.lock")
	created, err := securefile.CreatePrivateFile(path, os.O_RDWR|os.O_CREATE)
	if err != nil {
		if pairingStateLockHeld(err) {
			return nil, ErrPairingStateLocked
		}
		return nil, fmt.Errorf("create pairing state lock: %w", err)
	}
	if err := created.Close(); err != nil {
		return nil, fmt.Errorf("close pairing state lock: %w", err)
	}
	file, err := openExclusivePairingStateLock(path)
	if err != nil {
		return nil, err
	}
	closeOnError := func(result error) (func() error, error) {
		_ = file.Close()
		return nil, result
	}
	info, err := securefile.ValidateOwnerAndACL(file, false)
	if err != nil {
		return closeOnError(err)
	}
	links, err := pairingStateLockLinkCount(file)
	if err != nil {
		return closeOnError(err)
	}
	if !info.Mode().IsRegular() || links != 1 {
		return closeOnError(errors.New("pairing state lock is not a private regular file"))
	}
	return func() error {
		if err := file.Close(); err != nil {
			return fmt.Errorf("release pairing state lock: %w", err)
		}
		return nil
	}, nil
}

func openExclusivePairingStateLock(path string) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("encode pairing state lock path: %w", err)
	}
	// The reparse-point flag keeps a redirected path from resolving to another
	// object, so ValidateOwnerAndACL sees the link itself and rejects it.
	handle, err := syscall.CreateFile(
		name,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		0,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		if pairingStateLockHeld(err) {
			return nil, ErrPairingStateLocked
		}
		return nil, fmt.Errorf("acquire pairing state lock: %w", err)
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = syscall.CloseHandle(handle)
		return nil, errors.New("open pairing state lock")
	}
	return file, nil
}

// pairingStateLockLinkCount maps the POSIX Nlink check: a second name for the
// lock object would let a writer outside the state directory reach it.
func pairingStateLockLinkCount(file *os.File) (uint32, error) {
	var information syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(syscall.Handle(file.Fd()), &information); err != nil {
		return 0, fmt.Errorf("inspect pairing state lock: %w", err)
	}
	return information.NumberOfLinks, nil
}

func pairingStateLockHeld(err error) bool {
	return errors.Is(err, windowsErrorSharingViolation) || errors.Is(err, windowsErrorLockViolation)
}

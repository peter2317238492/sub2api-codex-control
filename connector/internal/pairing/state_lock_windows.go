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

func acquirePairingStateLock(stateDir string) (func() error, error) {
	if err := securefile.EnsureDir(stateDir); err != nil {
		return nil, err
	}
	path := filepath.Join(stateDir, "pairing.lock")
	windowsPath, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("encode pairing state lock path: %w", err)
	}
	handle, err := syscall.CreateFile(
		windowsPath,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		0,
		nil,
		syscall.OPEN_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		if errors.Is(err, windowsErrorSharingViolation) || errors.Is(err, windowsErrorLockViolation) {
			return nil, ErrPairingStateLocked
		}
		return nil, fmt.Errorf("acquire pairing state lock: %w", err)
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = syscall.CloseHandle(handle)
		return nil, errors.New("open pairing state lock")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat pairing state lock: %w", err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, errors.New("pairing state lock is not a regular file")
	}
	return func() error {
		if err := file.Close(); err != nil {
			return fmt.Errorf("release pairing state lock: %w", err)
		}
		return nil
	}, nil
}

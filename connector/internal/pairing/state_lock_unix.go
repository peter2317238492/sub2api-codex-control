//go:build darwin || linux

package pairing

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/securefile"
)

func acquirePairingStateLock(stateDir string) (func() error, error) {
	if err := securefile.EnsureDir(stateDir); err != nil {
		return nil, err
	}
	path := filepath.Join(stateDir, "pairing.lock")
	file, err := openPairingStateLock(path)
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
	stat, validStat := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !validStat || stat.Nlink != 1 {
		return closeOnError(errors.New("pairing state lock is not a private regular file"))
	}
	if err := file.Chmod(0o600); err != nil {
		return closeOnError(fmt.Errorf("restrict pairing state lock: %w", err))
	}
	info, err = securefile.ValidateOwnerAndACL(file, false)
	if err != nil {
		return closeOnError(err)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return closeOnError(errors.New("inspect pairing state lock"))
	}
	stat, validStat = info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !validStat || stat.Nlink != 1 ||
		pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, pathInfo) {
		return closeOnError(errors.New("pairing state lock is not a private regular file"))
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return closeOnError(ErrPairingStateLocked)
		}
		return closeOnError(fmt.Errorf("acquire pairing state lock: %w", err))
	}
	return func() error {
		unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		closeErr := file.Close()
		if unlockErr != nil {
			unlockErr = fmt.Errorf("release pairing state lock: %w", unlockErr)
		}
		if closeErr != nil {
			closeErr = fmt.Errorf("close pairing state lock: %w", closeErr)
		}
		return errors.Join(unlockErr, closeErr)
	}, nil
}

func openPairingStateLock(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err == nil {
		return file, nil
	}
	if !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("create pairing state lock: %w", err)
	}
	info, statErr := os.Lstat(path)
	if statErr != nil || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("pairing state lock is not a private regular file")
	}
	file, err = os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open pairing state lock: %w", err)
	}
	return file, nil
}

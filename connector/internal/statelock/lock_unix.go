//go:build darwin || linux

package statelock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/securefile"
)

func checkPlatform() error { return nil }

func acquireStateDir(path string) (func() error, error) {
	root, directory, err := openTrustedDirectory(path)
	if err != nil {
		return nil, err
	}
	closeDirectoryOnError := func(result error) (func() error, error) {
		_ = directory.Close()
		_ = root.Close()
		return nil, result
	}
	// The directory inode is authoritative. The connector.lock file below is a
	// private marker, so replacing that name cannot create a second live lock.
	if err := syscall.Flock(int(directory.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return closeDirectoryOnError(ErrInUse)
		}
		return closeDirectoryOnError(fmt.Errorf("acquire connector state directory lock: %w", err))
	}
	unlockDirectoryOnError := func(result error) (func() error, error) {
		_ = syscall.Flock(int(directory.Fd()), syscall.LOCK_UN)
		_ = directory.Close()
		_ = root.Close()
		return nil, result
	}
	file, err := openLockFile(root)
	if err != nil {
		return unlockDirectoryOnError(err)
	}
	closeOnError := func(result error) (func() error, error) {
		_ = file.Close()
		return unlockDirectoryOnError(result)
	}
	info, err := securefile.ValidateOwnerAndACL(file, false)
	if err != nil {
		return closeOnError(err)
	}
	stat, validStat := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !validStat || stat.Nlink != 1 {
		return closeOnError(errors.New("connector state lock is not a private regular file"))
	}
	if err := file.Chmod(0o600); err != nil {
		return closeOnError(fmt.Errorf("restrict connector state lock: %w", err))
	}
	info, err = securefile.ValidateOwnerAndACL(file, false)
	if err != nil {
		return closeOnError(err)
	}
	pathInfo, err := root.Lstat(lockFileName)
	if err != nil {
		return closeOnError(errors.New("inspect connector state lock"))
	}
	stat, validStat = info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !validStat || stat.Nlink != 1 ||
		pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, pathInfo) {
		return closeOnError(errors.New("connector state lock is not a private regular file"))
	}
	if err := file.Sync(); err != nil {
		return closeOnError(fmt.Errorf("sync connector state lock: %w", err))
	}
	if err := directory.Sync(); err != nil {
		return closeOnError(fmt.Errorf("sync connector state directory: %w", err))
	}
	return func() error {
		closeLockErr := file.Close()
		unlockErr := syscall.Flock(int(directory.Fd()), syscall.LOCK_UN)
		closeDirectoryErr := directory.Close()
		closeRootErr := root.Close()
		if closeLockErr != nil {
			closeLockErr = fmt.Errorf("close connector state lock: %w", closeLockErr)
		}
		if unlockErr != nil {
			unlockErr = fmt.Errorf("release connector state directory lock: %w", unlockErr)
		}
		if closeDirectoryErr != nil {
			closeDirectoryErr = fmt.Errorf("close connector state directory: %w", closeDirectoryErr)
		}
		if closeRootErr != nil {
			closeRootErr = fmt.Errorf("close connector state root: %w", closeRootErr)
		}
		return errors.Join(closeLockErr, unlockErr, closeDirectoryErr, closeRootErr)
	}, nil
}

func openLockFile(root *os.Root) (*os.File, error) {
	file, err := root.OpenFile(lockFileName, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err == nil {
		return file, nil
	}
	if !errors.Is(err, os.ErrExist) {
		return nil, errors.New("create connector state lock")
	}
	info, statErr := root.Lstat(lockFileName)
	if statErr != nil || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("connector state lock is not a private regular file")
	}
	file, err = root.OpenFile(lockFileName, os.O_RDWR, 0)
	if err != nil {
		return nil, errors.New("open connector state lock")
	}
	return file, nil
}

func openTrustedDirectory(path string) (*os.Root, *os.File, error) {
	return openTrustedDirectoryWithHook(path, nil)
}

func openTrustedDirectoryWithHook(path string, beforePathCheck func()) (*os.Root, *os.File, error) {
	// Descriptor-rooted traversal plus owner/ACL/write checks establishes that
	// principals outside root and the Connector EUID cannot replace a component.
	current, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return nil, nil, errors.New("open filesystem root")
	}
	closeCurrentOnError := func(result error) (*os.Root, *os.File, error) {
		_ = current.Close()
		return nil, nil, result
	}
	if err := validateRoot(current, false); err != nil {
		return closeCurrentOnError(err)
	}

	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	for index, component := range components {
		if component == "" || component == "." || component == ".." {
			return closeCurrentOnError(errors.New("connector state directory has an invalid component"))
		}
		pathInfo, statErr := current.Lstat(component)
		if errors.Is(statErr, os.ErrNotExist) {
			if mkdirErr := current.Mkdir(component, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
				return closeCurrentOnError(errors.New("create connector state directory component"))
			}
			if syncErr := syncRootDirectory(current); syncErr != nil {
				return closeCurrentOnError(errors.New("sync connector state directory parent"))
			}
			pathInfo, statErr = current.Lstat(component)
		}
		if statErr != nil || pathInfo.Mode()&os.ModeSymlink != 0 {
			return closeCurrentOnError(errors.New("open connector state directory component"))
		}
		child, openErr := current.OpenRoot(component)
		if openErr != nil {
			return closeCurrentOnError(errors.New("open connector state directory component"))
		}
		isFinal := index == len(components)-1
		if validationErr := validateRoot(child, isFinal); validationErr != nil {
			_ = child.Close()
			return closeCurrentOnError(validationErr)
		}
		childFile, fileErr := child.Open(".")
		if fileErr != nil {
			_ = child.Close()
			return closeCurrentOnError(errors.New("open connector state directory identity"))
		}
		childInfo, fileErr := childFile.Stat()
		_ = childFile.Close()
		if fileErr != nil || !os.SameFile(childInfo, pathInfo) {
			_ = child.Close()
			return closeCurrentOnError(errors.New("connector state directory component changed during validation"))
		}
		_ = current.Close()
		current = child
	}
	directory, err := current.Open(".")
	if err != nil {
		return closeCurrentOnError(errors.New("open connector state directory"))
	}
	if beforePathCheck != nil {
		beforePathCheck()
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 {
		_ = directory.Close()
		return closeCurrentOnError(errors.New("inspect connector state directory path"))
	}
	directoryInfo, err := directory.Stat()
	if err != nil || !os.SameFile(directoryInfo, pathInfo) {
		_ = directory.Close()
		return closeCurrentOnError(errors.New("connector state directory path changed during validation"))
	}
	return current, directory, nil
}

func syncRootDirectory(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	return errors.Join(syncErr, closeErr)
}

func validateRoot(root *os.Root, final bool) error {
	directory, err := root.Open(".")
	if err != nil {
		return errors.New("open connector state directory component")
	}
	defer directory.Close()
	info, err := securefile.ValidateOwnerAndACL(directory, !final)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("connector state path component is not a directory")
	}
	if !final {
		return validateTrustedAncestor(info)
	}
	if err := directory.Chmod(0o700); err != nil {
		return errors.New("restrict connector state directory")
	}
	info, err = securefile.ValidateOwnerAndACL(directory, false)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0o700 {
		return errors.New("connector state directory is not private")
	}
	if err := directory.Sync(); err != nil {
		return errors.New("sync restricted connector state directory")
	}
	return nil
}

func validateTrustedAncestor(info os.FileInfo) error {
	if !info.IsDir() {
		return errors.New("connector state ancestor is not a directory")
	}
	if info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
		return errors.New("connector state ancestor is writable by an untrusted principal")
	}
	return nil
}

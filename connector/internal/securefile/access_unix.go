//go:build darwin || linux

package securefile

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func ownerID(info os.FileInfo) (uint32, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("state object owner is unavailable")
	}
	return stat.Uid, nil
}

func trustedOwner(owner, effectiveUID uint32, allowRoot bool) bool {
	return owner == effectiveUID || allowRoot && owner == 0
}

func validateAccess(file *os.File, info os.FileInfo, allowRoot bool) error {
	owner, err := ownerID(info)
	if err != nil {
		return err
	}
	if !trustedOwner(owner, uint32(os.Geteuid()), allowRoot) {
		return errors.New("state object has an untrusted owner")
	}
	return validateACL(file)
}

func validateStatePath(string) error {
	return nil
}

func requirePersistentACLs(string) error {
	return nil
}

func openStateDirectory(path string) (*os.File, error) {
	return os.Open(path)
}

func openStateFile(path string) (*os.File, error) {
	return os.Open(path)
}

func createPrivateFile(path string, flag int) (*os.File, error) {
	return os.OpenFile(path, flag, 0o600)
}

func mkdirPrivate(path string) error {
	return os.Mkdir(path, 0o700)
}

func restrictDirectory(dir *os.File) error {
	return dir.Chmod(0o700)
}

func restrictFile(file *os.File) error {
	return file.Chmod(0o600)
}

func verifyPrivateDirectory(_ *os.File, info os.FileInfo) error {
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("state directory is not private")
	}
	return nil
}

func verifyPrivateFile(_ *os.File, info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("state file has unsafe permissions %04o", info.Mode().Perm())
	}
	return nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func syncDirectoryHandle(dir *os.File) error {
	return dir.Sync()
}

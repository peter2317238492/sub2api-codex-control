package securefile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// EnsureDir creates a connector state directory that is inaccessible to other users.
func EnsureDir(path string) error {
	if path == "" {
		return errors.New("secure state directory is empty")
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("secure state directory must not be a symbolic link")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect secure state directory")
	}
	if err := mkdirAllDurable(filepath.Clean(path), 0o700); err != nil {
		return fmt.Errorf("create secure state directory: %w", err)
	}
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open secure state directory: %w", err)
	}
	defer directory.Close()
	info, err := ValidateOwnerAndACL(directory, false)
	if err != nil {
		return err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, pathInfo) {
		return errors.New("secure state directory path changed during validation")
	}
	if !info.IsDir() {
		return errors.New("secure state path is not a directory")
	}
	if err := directory.Chmod(0o700); err != nil {
		return fmt.Errorf("restrict secure state directory: %w", err)
	}
	info, err = ValidateOwnerAndACL(directory, false)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("state directory is not private")
	}
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync secure state directory: %w", err)
	}
	return nil
}

func mkdirAllDurable(path string, mode os.FileMode) error {
	info, err := os.Stat(path)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("%s is not a directory", path)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	parent := filepath.Dir(path)
	if parent == path {
		return err
	}
	if err := mkdirAllDurable(parent, mode); err != nil {
		return err
	}
	if err := os.Mkdir(path, mode); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		info, statErr := os.Stat(path)
		if statErr != nil {
			return statErr
		}
		if !info.IsDir() {
			return fmt.Errorf("%s is not a directory", path)
		}
	}
	if err := syncDir(parent); err != nil {
		return fmt.Errorf("sync parent directory %s: %w", parent, err)
	}
	return nil
}

// WriteJSON atomically writes a JSON file with owner-only permissions.
func WriteJSON(path string, value any) error {
	if err := EnsureDir(filepath.Dir(path)); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	data = append(data, '\n')
	tmp, err := os.OpenFile(path+".tmp", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		if removeErr := os.Remove(path + ".tmp"); removeErr != nil {
			return fmt.Errorf("remove stale temporary state file: %w", removeErr)
		}
		tmp, err = os.OpenFile(path+".tmp", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	}
	if err != nil {
		return fmt.Errorf("create temporary state file: %w", err)
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	info, err := ValidateOwnerAndACL(tmp, false)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("temporary state file is not a regular file")
	}
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("restrict temporary state file: %w", err)
	}
	if _, err := ValidateOwnerAndACL(tmp, false); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write temporary state file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temporary state file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary state file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace state file: %w", err)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, pathInfo) {
		return errors.New("state file path changed during replacement")
	}
	ok = true
	return syncDir(filepath.Dir(path))
}

// ReadJSON reads one JSON document and rejects trailing or unknown data through decode.
func ReadJSON(path string, value any) error {
	data, err := ReadPrivateFile(path)
	if err != nil {
		return err
	}
	return decodeJSON(data, value)
}

// ReadJSONLimit reads one private JSON document through a single validated file
// descriptor and rejects files that exceed maxBytes, including files that grow
// after their initial size check.
func ReadJSONLimit(path string, value any, maxBytes int64) error {
	if maxBytes <= 0 {
		return errors.New("private JSON size limit must be positive")
	}
	file, info, err := openPrivateFile(path)
	if err != nil {
		return err
	}
	if info.Size() > maxBytes {
		_ = file.Close()
		return fmt.Errorf("private JSON file exceeds %d bytes", maxBytes)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if int64(len(data)) > maxBytes {
		return fmt.Errorf("private JSON file exceeds %d bytes", maxBytes)
	}
	return decodeJSON(data, value)
}

func decodeJSON(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("state file contains multiple JSON values")
		}
		return err
	}
	return nil
}

// ReadPrivateFile reads a regular, owner-only state file after validating its
// owner, ACL, and identity against the path used to open it.
func ReadPrivateFile(path string) ([]byte, error) {
	file, _, err := openPrivateFile(path)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(file)
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return data, nil
}

// StatPrivateFile returns metadata for a regular, owner-only state file after
// validating its owner, ACL, and identity against the path used to open it.
func StatPrivateFile(path string) (os.FileInfo, error) {
	file, info, err := openPrivateFile(path)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return info, nil
}

func openPrivateFile(path string) (*os.File, os.FileInfo, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return nil, nil, errors.New("state path is not a private regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	closeOnError := func(result error) (*os.File, os.FileInfo, error) {
		_ = file.Close()
		return nil, nil, result
	}
	info, err := ValidateOwnerAndACL(file, false)
	if err != nil {
		return closeOnError(err)
	}
	currentPathInfo, err := os.Lstat(path)
	if err != nil || currentPathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, currentPathInfo) ||
		!os.SameFile(pathInfo, currentPathInfo) {
		return closeOnError(errors.New("state file path changed during validation"))
	}
	if !info.Mode().IsRegular() {
		return closeOnError(errors.New("state path is not a private regular file"))
	}
	if info.Mode().Perm()&0o077 != 0 {
		return closeOnError(fmt.Errorf("state file has unsafe permissions %04o", info.Mode().Perm()))
	}
	return file, info, nil
}

// ValidateOwnerAndACL checks an already-open state object without following a
// second path lookup. Root ownership is allowed only for trusted ancestors.
func ValidateOwnerAndACL(file *os.File, allowRoot bool) (os.FileInfo, error) {
	if file == nil {
		return nil, errors.New("state object is not open")
	}
	info, err := file.Stat()
	if err != nil {
		return nil, errors.New("stat state object")
	}
	owner, err := ownerID(info)
	if err != nil {
		return nil, err
	}
	effectiveUID := uint32(os.Geteuid())
	if !trustedOwner(owner, effectiveUID, allowRoot) {
		return nil, errors.New("state object has an untrusted owner")
	}
	if err := validateACL(file); err != nil {
		return nil, err
	}
	return info, nil
}

func trustedOwner(owner, effectiveUID uint32, allowRoot bool) bool {
	return owner == effectiveUID || allowRoot && owner == 0
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

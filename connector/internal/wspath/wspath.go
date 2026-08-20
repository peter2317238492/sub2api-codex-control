// Package wspath projects local filesystem paths into the absolute POSIX form
// the Control API accepts and maps that form back to a local path. Windows
// paths never leave the host; on Linux and macOS the projection is the
// identity.
package wspath

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"
)

// MaxPathBytes bounds both forms and matches the workspace-root limit the
// protocol package enforces on Hello.
const MaxPathBytes = 4_096

// Mapper converts between local filesystem paths and the POSIX form the
// Control API accepts. The zero value is ready for use and every method is
// safe for concurrent use.
type Mapper struct{}

func NewMapper() *Mapper { return &Mapper{} }

// Remote projects a local path into the POSIX form sent to the control plane.
// Mapping the result back yields the canonical local form, which can differ
// from the input in separator style and drive-letter case, so compare the two
// with SamePath rather than with ==.
func (m *Mapper) Remote(local string) (string, error) {
	return toRemote(local)
}

// Local maps a POSIX path received from the control plane back to a local
// path. The result is rejected unless it projects back to exactly the input,
// so no two remote paths can ever name the same local object.
func (m *Mapper) Local(remote string) (string, error) {
	return toLocal(remote)
}

// ValidateRemote reports whether a POSIX path is one this mapper accepts from
// the control plane, without producing the local form. It replaces the
// filepath.IsAbs check that rejects a projected root on Windows.
// RemotePattern projects a local glob pattern into the POSIX form the Control
// API accepts. A pattern is not a path: it never names an existing object, and
// its components carry the metacharacters Remote rejects. Volume mapping,
// separator direction, and the traversal and control-character rules are
// otherwise identical. There is no inverse, because a pattern only ever travels
// outward.
func (m *Mapper) RemotePattern(local string) (string, error) {
	return toRemotePattern(local)
}

func (m *Mapper) ValidateRemote(remote string) error {
	_, err := toLocal(remote)
	return err
}

// RemoteRoots projects configured workspace roots and drops exact duplicates,
// which the protocol forbids in a Hello payload.
func (m *Mapper) RemoteRoots(local []string) ([]string, error) {
	roots := make([]string, 0, len(local))
	seen := make(map[string]struct{}, len(local))
	for index, root := range local {
		projected, err := toRemote(root)
		if err != nil {
			return nil, fmt.Errorf("workspace root %d: %w", index, err)
		}
		if _, duplicate := seen[projected]; duplicate {
			continue
		}
		seen[projected] = struct{}{}
		roots = append(roots, projected)
	}
	return roots, nil
}

// SamePath reports whether two local paths name the same object, using the
// case sensitivity of the local filesystem. Neither path is resolved, so
// callers must canonicalise them first.
func (m *Mapper) SamePath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return pathEqual(filepath.Clean(a), filepath.Clean(b))
}

// Contains reports whether the local path child is root or lies beneath it,
// using the case sensitivity of the local filesystem. Neither path is
// resolved, so callers must canonicalise them first.
func (m *Mapper) Contains(root, child string) bool {
	if root == "" || child == "" {
		return false
	}
	cleanRoot, cleanChild := filepath.Clean(root), filepath.Clean(child)
	if pathEqual(cleanRoot, cleanChild) {
		return true
	}
	if !strings.HasSuffix(cleanRoot, string(filepath.Separator)) {
		cleanRoot += string(filepath.Separator)
	}
	return pathHasPrefix(cleanChild, cleanRoot)
}

// validatePOSIX enforces the absolute-POSIX contract the Control API applies to
// every workspace root and every cwd.
func validatePOSIX(candidate string) error {
	if candidate == "" {
		return errors.New("path is empty")
	}
	if len(candidate) > MaxPathBytes {
		return fmt.Errorf("path exceeds %d bytes", MaxPathBytes)
	}
	if !strings.HasPrefix(candidate, "/") || strings.HasPrefix(candidate, "//") {
		return errors.New("path is not an absolute POSIX path")
	}
	if candidate == "/" {
		return errors.New("path is the filesystem root")
	}
	if path.Clean(candidate) != candidate {
		return errors.New("path is not in cleaned form")
	}
	if strings.IndexFunc(candidate, func(character rune) bool { return character < 0x20 }) >= 0 {
		return errors.New("path contains a control character")
	}
	return nil
}

//go:build darwin || linux

package wspath

import "strings"

// On these platforms the local and the remote form are the same string, so both
// directions return their input unchanged. They are not a bare identity: the
// input still has to satisfy the absolute-POSIX shape the Control API requires,
// which is a deliberate tightening over the pre-port CanonicalCWD.
//
// CanonicalCWD used to run filepath.Clean over an inbound cwd, so a value such
// as "/srv/work/proj/" or "/srv/work/./proj" was normalised rather than
// refused. It is refused now. That matches the contract on both sides: the
// Control API runs canonicalize_workspace_roots over every workspace root and
// over every cwd, and internal/protocol already required path.Clean(root) ==
// root for the Hello roots before this port. Normalising here instead would
// also break ValidateRemote's promise to agree with Local.
func toRemote(local string) (string, error) {
	if err := validatePOSIX(local); err != nil {
		return "", err
	}
	return local, nil
}

func toLocal(remote string) (string, error) {
	if err := validatePOSIX(remote); err != nil {
		return "", err
	}
	return remote, nil
}

func pathEqual(a, b string) bool { return a == b }

func pathHasPrefix(child, prefix string) bool { return strings.HasPrefix(child, prefix) }

func toRemotePattern(local string) (string, error) { return toRemote(local) }

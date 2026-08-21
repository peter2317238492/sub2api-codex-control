//go:build darwin || linux

package metrics

import "os"

// restrictTemporaryFile removes the umask from the mode the state file was
// created with, so the exporter's own privacy check cannot fail on a host with
// an unusual umask.
func restrictTemporaryFile(file *os.File) error {
	return file.Chmod(0o600)
}

func privateRegularMode(mode os.FileMode) bool {
	return mode.IsRegular() && mode.Perm() == 0o600
}

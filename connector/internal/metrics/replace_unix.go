//go:build darwin || linux

package metrics

import "os"

// replaceFile installs a fully written temporary file over path in one step.
func replaceFile(temporaryPath, path string) error {
	return os.Rename(temporaryPath, path)
}

// replaceCollision reports a transient failure to replace a file. POSIX
// rename(2) has none: it always succeeds against concurrent readers.
func replaceCollision(error) bool {
	return false
}

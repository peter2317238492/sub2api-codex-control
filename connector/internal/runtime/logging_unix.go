//go:build darwin || linux

package runtime

// rotationBlocked reports a rotation that failed only because another process
// holds a generation of the log open. POSIX has no such failure: rename(2) and
// unlink(2) act on directory entries and ignore open handles.
func rotationBlocked(error) bool {
	return false
}

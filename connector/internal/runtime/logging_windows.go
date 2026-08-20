package runtime

import (
	"errors"
	"syscall"
)

const (
	errorAccessDenied     = syscall.Errno(5)
	errorSharingViolation = syscall.Errno(32)
)

// rotationBlocked reports a rotation that failed only because another process
// holds a generation of the log open. Renaming or deleting a file requires
// DELETE access on it, and a reader that opened it without FILE_SHARE_DELETE —
// which is every ordinary log viewer, Get-Content and os.Open included —
// denies exactly that. No rename mechanism escapes it: FileRenameInfoEx with
// POSIX semantics refuses for the same reason. The condition lasts as long as
// the reader rather than as long as the process, so it must not retire the
// sink.
func rotationBlocked(err error) bool {
	return errors.Is(err, errorSharingViolation) || errors.Is(err, errorAccessDenied)
}

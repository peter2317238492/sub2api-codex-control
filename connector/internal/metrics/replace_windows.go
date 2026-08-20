package metrics

import (
	"errors"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const (
	fileRenameInfoExClass = 22
	fileRenameReplace     = 0x00000001
	fileRenamePosix       = 0x00000002
	deleteAccess          = 0x00010000
	synchronizeAccess     = 0x00100000

	errorAccessDenied     = syscall.Errno(5)
	errorSharingViolation = syscall.Errno(32)
	errorInvalidParameter = syscall.Errno(87)
)

var (
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	procSetFileInformationByHandle = kernel32.NewProc("SetFileInformationByHandle")
)

// fileRenameInfo mirrors FILE_RENAME_INFO with the Flags member of its union,
// which is what the FileRenameInfoEx class reads. Go pads after Flags exactly
// as the C compiler does, so FileName lands at the offset Windows expects.
type fileRenameInfo struct {
	Flags          uint32
	RootDirectory  syscall.Handle
	FileNameLength uint32
	FileName       [1]uint16
}

const renameNameOffset = unsafe.Offsetof(fileRenameInfo{}.FileName)

// replaceFile installs a fully written temporary file over path in one step.
//
// os.Rename is not that step on Windows. MoveFileEx opens the destination
// exclusively, so it fails with "Access is denied" while any process holds
// connector.prom open and it locks that process out of its own next read.
// FileRenameInfoEx with POSIX semantics is the faithful equivalent of
// rename(2): it touches only the source handle, leaves handles on the replaced
// file valid, and points the name at the new file. It still refuses while a
// reader that did not grant FILE_SHARE_DELETE holds the destination, which is
// what every Go reader — windows_exporter included — does, so that one
// collision is retried instead of being allowed to poison the exporter.
func replaceFile(temporaryPath, path string) error {
	deadline := time.Now().Add(replaceBudget)
	for {
		err := renamePOSIXSemantics(temporaryPath, path)
		if errors.Is(err, errorInvalidParameter) {
			// The volume or the Windows build predates FileRenameInfoEx.
			err = os.Rename(temporaryPath, path)
		}
		if err == nil || !replaceCollision(err) || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(replaceInterval)
	}
}

func replaceCollision(err error) bool {
	return errors.Is(err, errorSharingViolation) || errors.Is(err, errorAccessDenied)
}

func renamePOSIXSemantics(temporaryPath, path string) error {
	fail := func(err error) error {
		return &os.LinkError{Op: "replace", Old: temporaryPath, New: path, Err: err}
	}
	source, err := syscall.UTF16PtrFromString(temporaryPath)
	if err != nil {
		return fail(err)
	}
	target, err := syscall.UTF16FromString(path)
	if err != nil {
		return fail(err)
	}
	target = target[:len(target)-1]
	if len(target) == 0 {
		return fail(syscall.EINVAL)
	}
	handle, err := syscall.CreateFile(
		source,
		deleteAccess|synchronizeAccess,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return fail(err)
	}
	defer syscall.CloseHandle(handle)

	nameBytes := len(target) * 2
	buffer := make([]byte, int(renameNameOffset)+nameBytes+2)
	info := (*fileRenameInfo)(unsafe.Pointer(&buffer[0]))
	info.Flags = fileRenameReplace | fileRenamePosix
	info.FileNameLength = uint32(nameBytes)
	copy(buffer[renameNameOffset:], unsafe.Slice((*byte)(unsafe.Pointer(&target[0])), nameBytes))
	ok, _, callErr := procSetFileInformationByHandle.Call(
		uintptr(handle),
		fileRenameInfoExClass,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
	)
	if ok == 0 {
		return fail(callErr)
	}
	return nil
}

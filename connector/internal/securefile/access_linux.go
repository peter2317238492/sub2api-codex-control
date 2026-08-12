//go:build linux

package securefile

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

func validateACL(file *os.File) error {
	for _, name := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		encoded, err := syscall.BytePtrFromString(name)
		if err != nil {
			return errors.New("encode state object access control name")
		}
		_, _, errno := syscall.Syscall6(
			syscall.SYS_FGETXATTR,
			file.Fd(),
			uintptr(unsafe.Pointer(encoded)),
			0,
			0,
			0,
			0,
		)
		if err := linuxACLInspectionResult(errno); err != nil {
			return err
		}
	}
	return nil
}

func linuxACLInspectionResult(errno syscall.Errno) error {
	switch errno {
	case 0:
		return errors.New("state object has an unsafe access control list")
	case syscall.ENODATA:
		return nil
	default:
		return errors.New("inspect state object access control list")
	}
}

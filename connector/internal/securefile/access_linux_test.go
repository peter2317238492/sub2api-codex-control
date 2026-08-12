//go:build linux

package securefile

import (
	"syscall"
	"testing"
)

func TestLinuxACLInspectionErrorsFailClosed(t *testing.T) {
	if err := linuxACLInspectionResult(syscall.ENODATA); err != nil {
		t.Fatalf("explicit no-ACL result classified as an error: %v", err)
	}
	if err := linuxACLInspectionResult(0); err == nil {
		t.Fatal("present ACL was accepted")
	}
	for _, errno := range []syscall.Errno{syscall.ENOTSUP, syscall.EOPNOTSUPP, syscall.EIO} {
		if err := linuxACLInspectionResult(errno); err == nil {
			t.Fatalf("ACL inspection error %v was accepted", errno)
		}
	}
}

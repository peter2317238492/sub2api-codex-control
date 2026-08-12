//go:build darwin

package securefile

import (
	"encoding/binary"
	"errors"
	"os"
	"syscall"
	"unsafe"
)

const (
	darwinAttrBitMapCount      = 5
	darwinAttrExtendedSecurity = 0x00400000
	darwinFileSecMagic         = 0x012cc16d
	darwinFileSecNoACL         = ^uint32(0)
	darwinACLMaxEntries        = 128
	darwinACEKindMask          = 0xf
	darwinACEDeny              = 2
	darwinFileSecHeaderSize    = 44
	darwinACESize              = 24
	darwinAttributeBufferSize  = 8192
)

type darwinAttrList struct {
	BitmapCount uint16
	Reserved    uint16
	CommonAttr  uint32
	VolAttr     uint32
	DirAttr     uint32
	FileAttr    uint32
	ForkAttr    uint32
}

func validateACL(file *os.File) error {
	attributes := darwinAttrList{
		BitmapCount: darwinAttrBitMapCount,
		CommonAttr:  darwinAttrExtendedSecurity,
	}
	buffer := make([]byte, darwinAttributeBufferSize)
	_, _, errno := syscall.Syscall6(
		syscall.SYS_FGETATTRLIST,
		file.Fd(),
		uintptr(unsafe.Pointer(&attributes)),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		0,
		0,
	)
	if err := darwinACLInspectionError(errno); err != nil {
		return err
	}
	if len(buffer) < 12 {
		return errors.New("state object access control data is invalid")
	}
	resultLength := int(binary.LittleEndian.Uint32(buffer[0:4]))
	dataOffset := int(int32(binary.LittleEndian.Uint32(buffer[4:8])))
	dataLength := int(binary.LittleEndian.Uint32(buffer[8:12]))
	dataStart := 4 + dataOffset
	if resultLength < 12 || resultLength > len(buffer) || dataOffset < 8 || dataLength < 0 ||
		dataStart < 12 || dataStart > resultLength || dataLength > resultLength-dataStart {
		return errors.New("state object access control data is invalid")
	}
	if dataLength == 0 {
		return nil
	}
	data := buffer[dataStart : dataStart+dataLength]
	if len(data) < darwinFileSecHeaderSize || binary.LittleEndian.Uint32(data[0:4]) != darwinFileSecMagic {
		return errors.New("state object access control data is invalid")
	}
	entryCount := binary.LittleEndian.Uint32(data[36:40])
	if entryCount == darwinFileSecNoACL {
		return nil
	}
	if entryCount > darwinACLMaxEntries || len(data) != darwinFileSecHeaderSize+int(entryCount)*darwinACESize {
		return errors.New("state object access control data is invalid")
	}
	for index := 0; index < int(entryCount); index++ {
		flagsOffset := darwinFileSecHeaderSize + index*darwinACESize + 16
		flags := binary.LittleEndian.Uint32(data[flagsOffset : flagsOffset+4])
		if flags&darwinACEKindMask != darwinACEDeny {
			return errors.New("state object has an unsafe access control list")
		}
	}
	return nil
}

func darwinACLInspectionError(errno syscall.Errno) error {
	if errno == 0 {
		return nil
	}
	return errors.New("inspect state object access control list")
}

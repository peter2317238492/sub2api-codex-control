//go:build windows

package appserver

import (
	"errors"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"
)

const (
	jobObjectExtendedLimitInformation = 9
	jobObjectLimitKillOnJobClose      = 0x00002000
	processTerminate                  = 0x0001
	processSetQuota                   = 0x0100
)

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procAssignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
	procCloseHandle              = kernel32.NewProc("CloseHandle")
	procCreateJobObjectW         = kernel32.NewProc("CreateJobObjectW")
	procOpenProcess              = kernel32.NewProc("OpenProcess")
	procSetInformationJobObject  = kernel32.NewProc("SetInformationJobObject")
	procTerminateJobObject       = kernel32.NewProc("TerminateJobObject")
)

type jobObjectBasicLimitInformationData struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type ioCountersData struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type jobObjectExtendedLimitInformationData struct {
	BasicLimitInformation jobObjectBasicLimitInformationData
	IOInfo                ioCountersData
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

type appServerProcessTree struct {
	mu     sync.Mutex
	handle syscall.Handle
}

func prepareAppServerProcess(command *exec.Cmd) (*appServerProcessTree, error) {
	handle, _, callErr := procCreateJobObjectW.Call(0, 0)
	if handle == 0 {
		return nil, windowsCallError(callErr)
	}
	tree := &appServerProcessTree{handle: syscall.Handle(handle)}
	limits := jobObjectExtendedLimitInformationData{}
	limits.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose
	ok, _, callErr := procSetInformationJobObject.Call(
		handle,
		jobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)),
		unsafe.Sizeof(limits),
	)
	if ok == 0 {
		_ = tree.close()
		return nil, windowsCallError(callErr)
	}
	command.Cancel = tree.kill
	command.WaitDelay = forcedShutdownWait
	return tree, nil
}

func (t *appServerProcessTree) attach(process *os.Process) error {
	if process == nil || process.Pid <= 0 {
		return errors.New("app-server process is unavailable")
	}
	t.mu.Lock()
	handle := t.handle
	t.mu.Unlock()
	if handle == 0 {
		return errors.New("app-server job object is unavailable")
	}
	processHandle, _, callErr := procOpenProcess.Call(
		processTerminate|processSetQuota,
		0,
		uintptr(uint32(process.Pid)),
	)
	if processHandle == 0 {
		return windowsCallError(callErr)
	}
	defer procCloseHandle.Call(processHandle)
	ok, _, callErr := procAssignProcessToJobObject.Call(uintptr(handle), processHandle)
	if ok == 0 {
		return windowsCallError(callErr)
	}
	return nil
}

func (t *appServerProcessTree) kill() error {
	t.mu.Lock()
	handle := t.handle
	t.mu.Unlock()
	if handle == 0 {
		return os.ErrProcessDone
	}
	ok, _, callErr := procTerminateJobObject.Call(uintptr(handle), 1)
	if ok == 0 {
		return windowsCallError(callErr)
	}
	return nil
}

func (t *appServerProcessTree) close() error {
	t.mu.Lock()
	handle := t.handle
	t.handle = 0
	t.mu.Unlock()
	if handle == 0 {
		return nil
	}
	ok, _, callErr := procCloseHandle.Call(uintptr(handle))
	if ok == 0 {
		return windowsCallError(callErr)
	}
	return nil
}

func windowsCallError(err error) error {
	var errno syscall.Errno
	if err == nil || (errors.As(err, &errno) && errno == 0) {
		return errors.New("Windows process-tree operation failed")
	}
	return err
}

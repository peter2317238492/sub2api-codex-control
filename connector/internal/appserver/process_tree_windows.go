//go:build windows

package appserver

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	jobObjectExtendedLimitInformation = 9
	jobObjectLimitKillOnJobClose      = 0x00002000
	processTerminate                  = 0x0001
	processSetQuota                   = 0x0100
	createSuspended                   = 0x00000004
	createNoWindow                    = 0x08000000
	threadSuspendResume               = 0x0002
	toolhelpSnapshotThread            = 0x00000004
	createdSuspendCount               = 1
)

// Extensions Windows hands to an interpreter instead of loading as an
// executable image. cmd.exe or powershell.exe would then own the process the
// job object was built around, leaving the real Codex one generation further
// away from it.
var codexShimExtensions = []string{".bat", ".cmd", ".com", ".ps1"}

// defaultPathExtensions mirrors the fallback os/exec uses when PATHEXT is unset.
var defaultPathExtensions = []string{".com", ".exe", ".bat", ".cmd"}

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procAssignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
	procCloseHandle              = kernel32.NewProc("CloseHandle")
	procCreateJobObjectW         = kernel32.NewProc("CreateJobObjectW")
	procCreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procOpenProcess              = kernel32.NewProc("OpenProcess")
	procOpenThread               = kernel32.NewProc("OpenThread")
	procResumeThread             = kernel32.NewProc("ResumeThread")
	procSetInformationJobObject  = kernel32.NewProc("SetInformationJobObject")
	procTerminateJobObject       = kernel32.NewProc("TerminateJobObject")
	procThread32First            = kernel32.NewProc("Thread32First")
	procThread32Next             = kernel32.NewProc("Thread32Next")
)

func init() {
	verifyBinaryImage = requireExecutableImage
}

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

type threadEntry32Data struct {
	Size           uint32
	Usage          uint32
	ThreadID       uint32
	OwnerProcessID uint32
	BasePriority   int32
	DeltaPriority  int32
	Flags          uint32
}

type appServerProcessTree struct {
	mu     sync.Mutex
	handle syscall.Handle
}

func requireExecutableImage(binary string) error {
	image := resolveExecutableImage(binary)
	extension := strings.ToLower(filepath.Ext(image))
	if !slices.Contains(codexShimExtensions, extension) {
		return nil
	}
	return fmt.Errorf(
		"codex_binary %q runs Codex through the %s shim %q, one process generation away from the Connector-owned job object; configure the Codex executable image itself",
		binary, extension, image)
}

// resolveExecutableImage reports the image os/exec would actually launch.
// A configured path carrying no extension is not that image: exec appends
// PATHEXT to it at start time, so `<npm prefix>\codex` silently becomes
// codex.cmd. Inspecting the configured string alone would miss exactly the
// shim this rejects. A path that resolves to nothing is returned unchanged so
// the process start reports the failure.
func resolveExecutableImage(binary string) string {
	if binary == "" || filepath.Base(binary) == binary {
		if resolved, err := exec.LookPath(binary); err == nil {
			return resolved
		}
		return binary
	}
	extensions := pathExtensions()
	if extension := filepath.Ext(binary); extension != "" {
		for _, candidate := range extensions {
			if strings.EqualFold(extension, candidate) {
				return binary
			}
		}
		if isExecutableFile(binary) {
			return binary
		}
	}
	for _, extension := range extensions {
		if candidate := binary + extension; isExecutableFile(candidate) {
			return candidate
		}
	}
	return binary
}

func pathExtensions() []string {
	configured := os.Getenv("PATHEXT")
	if configured == "" {
		return defaultPathExtensions
	}
	extensions := make([]string, 0, len(defaultPathExtensions))
	for _, extension := range strings.Split(strings.ToLower(configured), ";") {
		if extension == "" {
			continue
		}
		if !strings.HasPrefix(extension, ".") {
			extension = "." + extension
		}
		extensions = append(extensions, extension)
	}
	if len(extensions) == 0 {
		return defaultPathExtensions
	}
	return extensions
}

func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func prepareAppServerProcess(command *exec.Cmd, gracePeriod time.Duration) (*appServerProcessTree, error) {
	if err := requireExecutableImage(command.Path); err != nil {
		return nil, err
	}
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
	// The child is created suspended so that attach can assign it to the job
	// before it executes a single instruction; a grandchild spawned between
	// CreateProcess and AssignProcessToJobObject would otherwise escape the job
	// and survive shutdown. CREATE_NO_WINDOW keeps the scheduled task from
	// flashing a console on every app-server restart.
	command.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createSuspended | createNoWindow,
	}
	command.Cancel = tree.kill
	command.WaitDelay = waitDelayFor(gracePeriod)
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
	return resumePrimaryThread(process.Pid)
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

func resumePrimaryThread(pid int) error {
	threadID, err := primaryThreadID(uint32(pid))
	if err != nil {
		return err
	}
	threadHandle, _, callErr := procOpenThread.Call(threadSuspendResume, 0, uintptr(threadID))
	if threadHandle == 0 {
		return windowsCallError(callErr)
	}
	defer procCloseHandle.Call(threadHandle)
	previous, _, callErr := procResumeThread.Call(threadHandle)
	if uint32(previous) == ^uint32(0) {
		return windowsCallError(callErr)
	}
	// Only this call may resume a child the Connector created suspended, so any
	// other prior suspend count means the child either already ran or stays
	// suspended after the resume. Both fail closed.
	if uint32(previous) != createdSuspendCount {
		return fmt.Errorf("app-server process %d had suspend count %d before resume, want %d", pid, uint32(previous), createdSuspendCount)
	}
	return nil
}

// primaryThreadID is safe against pid reuse because os.Process still holds the
// child's process handle when attach runs, which pins the pid until Wait.
func primaryThreadID(pid uint32) (uint32, error) {
	snapshot, _, callErr := procCreateToolhelp32Snapshot.Call(toolhelpSnapshotThread, 0)
	if snapshot == 0 || snapshot == ^uintptr(0) {
		return 0, windowsCallError(callErr)
	}
	defer procCloseHandle.Call(snapshot)
	entry := threadEntry32Data{}
	entry.Size = uint32(unsafe.Sizeof(entry))
	ok, _, callErr := procThread32First.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	if ok == 0 {
		return 0, windowsCallError(callErr)
	}
	var threadID uint32
	found := 0
	for {
		if entry.OwnerProcessID == pid {
			threadID = entry.ThreadID
			found++
		}
		entry.Size = uint32(unsafe.Sizeof(entry))
		ok, _, callErr = procThread32Next.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		if ok == 0 {
			var errno syscall.Errno
			if !errors.As(callErr, &errno) || errno != syscall.ERROR_NO_MORE_FILES {
				return 0, windowsCallError(callErr)
			}
			break
		}
	}
	if found != 1 {
		return 0, fmt.Errorf("app-server process %d has %d threads before resume, want 1", pid, found)
	}
	return threadID, nil
}

func windowsCallError(err error) error {
	var errno syscall.Errno
	if err == nil || (errors.As(err, &errno) && errno == 0) {
		return errors.New("Windows process-tree operation failed")
	}
	return err
}

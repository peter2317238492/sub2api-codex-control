//go:build windows

package appserver_test

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"testing"
	"unsafe"
)

const (
	afInet  = 2
	afInet6 = 23

	// TCP_TABLE_OWNER_PID_LISTENER returns listening sockets only, so the probe
	// never has to compare a connection state. That matters here: netstat's
	// state column is localized, and this host runs a Chinese Windows.
	tcpTableOwnerPIDListener = 3
	udpTableOwnerPID         = 1

	errorInsufficientBuffer = 122
)

var (
	iphlpapi                = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTCPTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUDPTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

// newListenerProbe reports an inbound socket opened anywhere in the app-server
// process tree. Windows has no process group: the Connector owns a job object,
// and the tree is reconstructed from the parent links in a process snapshot.
func newListenerProbe(t *testing.T) func(context.Context, int) error {
	t.Helper()
	return func(ctx context.Context, rootProcessID int) error {
		tree, err := processTreeIDs(uint32(rootProcessID))
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("cannot enumerate the app-server process tree: %w", err)
		}
		for _, table := range []struct {
			name  string
			owner func() ([]uint32, error)
		}{
			{"TCP", listeningTCPOwners},
			{"UDP", boundUDPOwners},
		} {
			owners, err := table.owner()
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("cannot verify app-server %s listeners: %w", table.name, err)
			}
			for _, owner := range owners {
				if _, inTree := tree[owner]; inTree {
					return errors.New("Connector-owned app-server process tree opened an inbound socket")
				}
			}
		}
		return nil
	}
}

// processTreeIDs returns the root process and every descendant. A snapshot is
// a point-in-time view, so a process that exits mid-walk simply drops out; the
// probe runs on a ticker and would catch a listener on the next pass.
func processTreeIDs(root uint32) (map[uint32]struct{}, error) {
	snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(snapshot)
	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	parents := make(map[uint32]uint32)
	for err = syscall.Process32First(snapshot, &entry); err == nil; err = syscall.Process32Next(snapshot, &entry) {
		parents[entry.ProcessID] = entry.ParentProcessID
	}
	if err != nil && !errors.Is(err, syscall.ERROR_NO_MORE_FILES) {
		return nil, err
	}
	tree := map[uint32]struct{}{root: {}}
	// Parent links can form a cycle after a PID is reused, so each walk is
	// bounded by the number of processes in the snapshot.
	for processID := range parents {
		current, depth := processID, 0
		for depth <= len(parents) {
			if _, known := tree[current]; known {
				tree[processID] = struct{}{}
				break
			}
			parent, exists := parents[current]
			if !exists || parent == current {
				break
			}
			current, depth = parent, depth+1
		}
	}
	return tree, nil
}

func listeningTCPOwners() ([]uint32, error) {
	var owners []uint32
	for _, family := range []uint32{afInet, afInet6} {
		// MIB_TCPROW_OWNER_PID is 24 bytes and MIB_TCP6ROW_OWNER_PID is 56; the
		// owning PID is the final DWORD of each row either way.
		rowSize := 24
		if family == afInet6 {
			rowSize = 56
		}
		table, err := extendedTable(procGetExtendedTCPTable, family, tcpTableOwnerPIDListener)
		if err != nil {
			return nil, err
		}
		owners = append(owners, tableOwners(table, rowSize)...)
	}
	return owners, nil
}

func boundUDPOwners() ([]uint32, error) {
	var owners []uint32
	for _, family := range []uint32{afInet, afInet6} {
		// MIB_UDPROW_OWNER_PID is 12 bytes and MIB_UDP6ROW_OWNER_PID is 28.
		rowSize := 12
		if family == afInet6 {
			rowSize = 28
		}
		table, err := extendedTable(procGetExtendedUDPTable, family, udpTableOwnerPID)
		if err != nil {
			return nil, err
		}
		owners = append(owners, tableOwners(table, rowSize)...)
	}
	return owners, nil
}

func extendedTable(procedure *syscall.LazyProc, family, class uint32) ([]byte, error) {
	var size uint32
	// The first call reports the required size; the table can grow between the
	// two calls, so a resize is retried rather than treated as a failure.
	for attempt := 0; attempt < 8; attempt++ {
		var buffer []byte
		var pointer uintptr
		if size > 0 {
			buffer = make([]byte, size)
			pointer = uintptr(unsafe.Pointer(&buffer[0]))
		}
		result, _, _ := procedure.Call(
			pointer,
			uintptr(unsafe.Pointer(&size)),
			0,
			uintptr(family),
			uintptr(class),
			0,
		)
		switch result {
		case 0:
			if buffer == nil {
				return nil, nil
			}
			return buffer[:size], nil
		case errorInsufficientBuffer:
			continue
		default:
			return nil, syscall.Errno(result)
		}
	}
	return nil, errors.New("connection table kept growing between size and read")
}

// tableOwners reads the owning PID out of every row of a MIB_*_OWNER_PID table.
// The tables share a layout: a DWORD entry count, then fixed-size rows whose
// last DWORD is the owning process.
func tableOwners(table []byte, rowSize int) []uint32 {
	if len(table) < 4 {
		return nil
	}
	entries := int(*(*uint32)(unsafe.Pointer(&table[0])))
	owners := make([]uint32, 0, entries)
	for index := 0; index < entries; index++ {
		start := 4 + index*rowSize
		if start+rowSize > len(table) {
			break
		}
		owners = append(owners, *(*uint32)(unsafe.Pointer(&table[start+rowSize-4])))
	}
	return owners
}

// assertProcessTreeTerminated confirms neither the app-server process nor any
// process still claiming it as an ancestor is alive. This is the guarantee the
// job object provides, and it is what shutdown has to deliver.
func assertProcessTreeTerminated(t *testing.T, rootProcessID int) {
	t.Helper()
	tree, err := processTreeIDs(uint32(rootProcessID))
	if err != nil {
		t.Fatalf("cannot enumerate the app-server process tree: %v", err)
	}
	delete(tree, uint32(rootProcessID))
	if len(tree) != 0 {
		t.Fatalf("app-server process tree survived shutdown: %v", tree)
	}
	if processAlive(uint32(rootProcessID)) {
		t.Fatalf("app-server process %d survived shutdown", rootProcessID)
	}
}

func processAlive(processID uint32) bool {
	snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(snapshot)
	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err = syscall.Process32First(snapshot, &entry); err == nil; err = syscall.Process32Next(snapshot, &entry) {
		if entry.ProcessID == processID {
			return true
		}
	}
	return false
}

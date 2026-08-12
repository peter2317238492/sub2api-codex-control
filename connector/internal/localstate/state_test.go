package localstate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	managedDeviceA = "11111111-1111-4111-8111-111111111111"
	managedDeviceB = "22222222-2222-4222-8222-222222222222"
)

func TestManagedThreadsAreBoundToOneDeviceIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-threads.json")
	threads, err := OpenThreads(path, managedDeviceA)
	if err != nil {
		t.Fatal(err)
	}
	thread := Thread{ID: "thread-a", CWD: t.TempDir(), CreatedAt: time.Now().UTC()}
	if err := threads.Add(thread); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenThreads(path, managedDeviceA)
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.Contains(thread.ID) {
		t.Fatal("same device lost its managed thread")
	}

	repaired, err := OpenThreads(path, managedDeviceB)
	if err != nil {
		t.Fatal(err)
	}
	if repaired.Contains(thread.ID) || len(repaired.IDs()) != 0 {
		t.Fatal("new device inherited prior managed threads")
	}
	var disk threadDisk
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &disk); err != nil {
		t.Fatal(err)
	}
	if disk.Version != 2 || disk.DeviceID != managedDeviceB || len(disk.Threads) != 0 {
		t.Fatalf("re-paired state = %#v", disk)
	}
}

func TestUnscopedManagedThreadsFailClosedDuringUpgrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-threads.json")
	legacy := threadDisk{
		Version: 1,
		Threads: map[string]Thread{
			"legacy-thread": {
				ID: "legacy-thread", CWD: t.TempDir(), CreatedAt: time.Now().UTC(),
			},
		},
	}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	threads, err := OpenThreads(path, managedDeviceA)
	if err != nil {
		t.Fatal(err)
	}
	if threads.Contains("legacy-thread") || len(threads.IDs()) != 0 {
		t.Fatal("unscoped legacy authority survived the identity upgrade")
	}
	reopened, err := OpenThreads(path, managedDeviceA)
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened.IDs()) != 0 {
		t.Fatal("reset state did not persist")
	}
}

func TestManagedThreadsRequireValidDeviceIdentity(t *testing.T) {
	if threads, err := OpenThreads(filepath.Join(t.TempDir(), "threads.json"), "not-a-device"); err == nil || threads != nil {
		t.Fatalf("invalid device identity was accepted: threads=%v err=%v", threads, err)
	}
}

func TestOpenThreadsRejectsOversizedStateBeforeDecode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-threads.json")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxManagedThreadStateSize + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if threads, err := OpenThreads(path, managedDeviceA); err == nil || threads != nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("OpenThreads oversized state = %#v, %v", threads, err)
	}
}

func TestManagedThreadReservationsProtectCapacityBeforeDispatch(t *testing.T) {
	threads := &Threads{path: filepath.Join(t.TempDir(), "threads.json"), data: newThreadDisk(managedDeviceA)}
	for index := 0; index < maxManagedThreads-1; index++ {
		id := fmt.Sprintf("thread-%d", index)
		threads.data.Threads[id] = Thread{ID: id, CWD: "/workspace"}
	}
	if err := threads.ReserveAdd(); err != nil {
		t.Fatal(err)
	}
	if err := threads.ReserveAdd(); !errors.Is(err, ErrManagedThreadStoreFull) {
		t.Fatalf("second reservation error = %v, want store full", err)
	}
	if err := threads.Add(Thread{ID: "unreserved", CWD: "/workspace"}); !errors.Is(err, ErrManagedThreadStoreFull) {
		t.Fatalf("unreserved add error = %v, want store full", err)
	}
	threads.ReleaseAdd()
	if err := threads.ReserveAdd(); err != nil {
		t.Fatalf("released capacity could not be reserved again: %v", err)
	}
	threads.ReleaseAdd()
}

func TestAddReservedConsumesReservation(t *testing.T) {
	threads, err := OpenThreads(filepath.Join(t.TempDir(), "threads.json"), managedDeviceA)
	if err != nil {
		t.Fatal(err)
	}
	if err := threads.ReserveAdd(); err != nil {
		t.Fatal(err)
	}
	thread := Thread{ID: "reserved-thread", CWD: "/workspace", CreatedAt: time.Now().UTC()}
	if err := threads.AddReserved(thread); err != nil {
		t.Fatal(err)
	}
	if !threads.Contains(thread.ID) {
		t.Fatal("reserved managed thread was not persisted")
	}
	if err := threads.AddReserved(Thread{ID: "without-reservation", CWD: "/workspace"}); err == nil {
		t.Fatal("managed thread was added without a reservation")
	}
}

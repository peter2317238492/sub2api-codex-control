//go:build darwin || linux

package spool

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSpoolRejectsUnsafeRecordPermissions(t *testing.T) {
	dir := newSpoolDir(t)
	eventSpool, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	appendSmallRecord(t, eventSpool, "unsafe")
	recordPath := filepath.Join(dir, "00000000000000000001.json")
	if err := os.Chmod(recordPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := eventSpool.Pending(); err == nil || !strings.Contains(err.Error(), "unsafe permissions") {
		t.Fatalf("Pending error = %v, want unsafe permissions rejection", err)
	}
	if _, err := eventSpool.Stats(time.Now()); err == nil {
		t.Fatal("Stats accepted an unsafe spool record")
	}
	if err := eventSpool.Ack(1); err == nil || !strings.Contains(err.Error(), "unsafe permissions") {
		t.Fatalf("Ack error = %v, want unsafe permissions rejection", err)
	}
}

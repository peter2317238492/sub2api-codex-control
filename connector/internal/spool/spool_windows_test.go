//go:build windows

package spool

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A foreign allow entry on a spool record is the Windows analogue of a 0644
// record: the envelope waiting for transmission became readable by a principal
// other than the connector, so every path that touches it must fail closed.
func TestSpoolRejectsRecordReachableByAnotherPrincipal(t *testing.T) {
	dir := newSpoolDir(t)
	eventSpool, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	appendSmallRecord(t, eventSpool, "unsafe")
	recordPath := filepath.Join(dir, "00000000000000000001.json")
	grantForeignAccess(t, recordPath, "(RX)")
	if _, err := eventSpool.Pending(); err == nil || !strings.Contains(err.Error(), "unsafe access control list") {
		t.Fatalf("Pending error = %v, want unsafe access control list rejection", err)
	}
	if _, err := eventSpool.Stats(time.Now()); err == nil {
		t.Fatal("Stats accepted an unsafe spool record")
	}
	if err := eventSpool.Ack(1); err == nil || !strings.Contains(err.Error(), "unsafe access control list") {
		t.Fatalf("Ack error = %v, want unsafe access control list rejection", err)
	}
}

func grantForeignAccess(t *testing.T, path, rights string) {
	t.Helper()
	output, err := exec.Command("icacls", path, "/grant", "*S-1-5-32-545:"+rights).CombinedOutput()
	if err != nil {
		t.Skipf("icacls unavailable: %v: %s", err, output)
	}
}

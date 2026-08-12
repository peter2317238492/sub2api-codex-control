package spool

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/protocol"
)

func TestStatsUsesDurableRecordMetadataWithoutChangingSpoolFormat(t *testing.T) {
	dir := t.TempDir()
	limits := Limits{MaxRecords: 10, MaxBytes: 4096, MaxRecordBytes: 1024}
	eventSpool, err := OpenWithLimits(dir, limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eventSpool.Append(func(sequence uint64) ([]byte, error) {
		return json.Marshal(map[string]uint64{"sequence": sequence})
	}); err != nil {
		t.Fatal(err)
	}
	recordPath := filepath.Join(dir, "00000000000000000001.json")
	createdAt := time.Now().Add(-15 * time.Second).Round(0)
	if err := os.Chtimes(recordPath, createdAt, createdAt); err != nil {
		t.Fatal(err)
	}
	stats, err := eventSpool.Stats(createdAt.Add(20 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	if stats.PendingRecords != 1 || stats.PendingBytes != info.Size() || stats.CapacityBytes != limits.MaxBytes || stats.OldestPendingAge != 20*time.Second {
		t.Fatalf("stats = %#v", stats)
	}
	var record map[string]uint64
	recordData, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(recordData, &record); err != nil || record["sequence"] != 1 {
		t.Fatalf("spool record format changed: %#v, %v", record, err)
	}
	if err := eventSpool.Ack(1); err != nil {
		t.Fatal(err)
	}
	stats, err = eventSpool.Stats(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if stats.PendingRecords != 0 || stats.PendingBytes != 0 || stats.OldestPendingAge != 0 {
		t.Fatalf("empty stats = %#v", stats)
	}
}

func TestSpoolPersistsMonotonicSequenceAndAcknowledgements(t *testing.T) {
	dir := t.TempDir()
	spool, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	appendRecord := func() uint64 {
		sequence, err := spool.Append(func(sequence uint64) ([]byte, error) {
			return json.Marshal(map[string]uint64{"seq": sequence})
		})
		if err != nil {
			t.Fatal(err)
		}
		return sequence
	}
	if got := appendRecord(); got != 1 {
		t.Fatalf("first sequence = %d", got)
	}
	if got := appendRecord(); got != 2 {
		t.Fatalf("second sequence = %d", got)
	}
	if err := spool.Ack(1); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := reopened.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Sequence != 2 {
		t.Fatalf("pending = %#v", pending)
	}
	sequence, err := reopened.Append(func(sequence uint64) ([]byte, error) {
		return json.Marshal(map[string]uint64{"seq": sequence})
	})
	if err != nil || sequence != 3 {
		t.Fatalf("reopened sequence = %d, err = %v", sequence, err)
	}
	if err := reopened.Ack(4); err == nil {
		t.Fatal("expected future acknowledgement to be rejected")
	}
}

func TestSpoolRejectsUnsafeRecordPermissions(t *testing.T) {
	dir := t.TempDir()
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

func TestSpoolPersistsContiguousReceiveCursor(t *testing.T) {
	spool, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if fresh, err := spool.ObserveIncoming(1); err != nil || !fresh {
		t.Fatalf("observe 1 = %v, %v", fresh, err)
	}
	if fresh, err := spool.ObserveIncoming(1); err != nil || fresh {
		t.Fatalf("duplicate observe = %v, %v", fresh, err)
	}
	if _, err := spool.ObserveIncoming(3); err == nil {
		t.Fatal("expected incoming sequence gap to be rejected")
	}
	if fresh, err := spool.ObserveIncoming(2); err != nil || !fresh {
		t.Fatalf("observe 2 = %v, %v", fresh, err)
	}
}

func TestSpoolEnforcesMaxRecords(t *testing.T) {
	spool, err := OpenWithLimits(t.TempDir(), Limits{
		MaxRecords: 2, MaxBytes: 1 << 20, MaxRecordBytes: 1 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	appendSmallRecord(t, spool, "one")
	appendSmallRecord(t, spool, "two")
	if _, err := spool.Append(func(sequence uint64) ([]byte, error) {
		return json.Marshal(map[string]any{"seq": sequence, "value": "three"})
	}); err == nil || !strings.Contains(err.Error(), "spool is full") {
		t.Fatalf("third append error = %v", err)
	}
	if got := spool.LastAssigned(); got != 2 {
		t.Fatalf("last assigned = %d", got)
	}
	if err := spool.Ack(1); err != nil {
		t.Fatal(err)
	}
	if got := appendSmallRecord(t, spool, "three"); got != 3 {
		t.Fatalf("sequence after freeing capacity = %d", got)
	}
}

func TestSpoolEnforcesMaxBytes(t *testing.T) {
	payload, err := json.Marshal(map[string]any{"seq": uint64(1), "value": "payload"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.MarshalIndent(json.RawMessage(payload), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	recordBytes := int64(len(encoded) + 1)
	spool, err := OpenWithLimits(t.TempDir(), Limits{
		MaxRecords: 10, MaxBytes: 2*recordBytes - 1, MaxRecordBytes: recordBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Append(func(uint64) ([]byte, error) { return payload, nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Append(func(uint64) ([]byte, error) { return payload, nil }); err == nil || !strings.Contains(err.Error(), "spool is full") {
		t.Fatalf("second append error = %v", err)
	}
}

func TestSpoolEnforcesMaxRecordBytes(t *testing.T) {
	payload, err := json.Marshal(map[string]any{"value": strings.Repeat("x", 128)})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.MarshalIndent(json.RawMessage(payload), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	recordBytes := int64(len(encoded) + 1)
	spool, err := OpenWithLimits(t.TempDir(), Limits{
		MaxRecords: 10, MaxBytes: 1 << 20, MaxRecordBytes: recordBytes - 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Append(func(uint64) ([]byte, error) { return payload, nil }); err == nil || !strings.Contains(err.Error(), "spool record exceeds") {
		t.Fatalf("oversized append error = %v", err)
	}
	if got := spool.LastAssigned(); got != 0 {
		t.Fatalf("oversized append consumed sequence %d", got)
	}
}

func TestOpenRemovesAcknowledgedRecordsLeftByInterruptedCleanup(t *testing.T) {
	dir := t.TempDir()
	spool, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	appendSmallRecord(t, spool, "one")
	if err := spool.Ack(1); err != nil {
		t.Fatal(err)
	}
	stalePath := filepath.Join(dir, "00000000000000000001.json")
	if err := os.WriteFile(stalePath, []byte(`{"seq":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stalePath); !os.IsNotExist(err) {
		t.Fatalf("acknowledged spool record survived reopen: %v", err)
	}
}

func TestAcknowledgedRecordCleanupFailsClosedOnDirectorySyncUncertainty(t *testing.T) {
	eventSpool, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	appendSmallRecord(t, eventSpool, "one")
	syncFailure := errors.New("simulated spool directory fsync failure")
	syncCalls := 0
	eventSpool.syncDirectory = func() error {
		syncCalls++
		return syncFailure
	}
	if err := eventSpool.Ack(1); !errors.Is(err, syncFailure) {
		t.Fatalf("acknowledgement error = %v, want directory sync failure", err)
	}
	if syncCalls != 1 {
		t.Fatalf("spool directory sync calls = %d, want 1", syncCalls)
	}
	if got := eventSpool.LastAcked(); got != 1 {
		t.Fatalf("durable acknowledgement cursor = %d, want 1", got)
	}
	eventSpool.syncDirectory = func() error {
		syncCalls++
		return nil
	}
	if err := eventSpool.Ack(1); err != nil {
		t.Fatalf("retry acknowledged record cleanup: %v", err)
	}
	if syncCalls != 2 {
		t.Fatalf("spool directory sync calls after retry = %d, want 2", syncCalls)
	}
}

func TestOpenRejectsPendingSequenceGap(t *testing.T) {
	dir := t.TempDir()
	spool, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	appendSmallRecord(t, spool, "one")
	appendSmallRecord(t, spool, "two")
	if err := os.Remove(filepath.Join(dir, "00000000000000000001.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("spool with a pending sequence gap was accepted")
	}
}

func TestCommitIncomingDoesNotPublishUndurableCursor(t *testing.T) {
	dir := t.TempDir()
	spool, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	persistFailure := errors.New("metadata fsync failed")
	spool.writeMeta = func(meta) error { return persistFailure }
	if fresh, err := spool.CheckIncoming(1); err != nil || !fresh {
		t.Fatalf("check incoming = %v, %v", fresh, err)
	}
	if err := spool.CommitIncoming(1); !errors.Is(err, persistFailure) {
		t.Fatalf("commit error = %v", err)
	}
	if got := spool.LastReceived(); got != 0 {
		t.Fatalf("in-memory cursor advanced to %d after failed fsync", got)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.LastReceived(); got != 0 {
		t.Fatalf("durable cursor = %d after failed fsync", got)
	}
}

func TestSpoolAssignsMaxWireSequenceThenFailsClosed(t *testing.T) {
	spool, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	spool.meta = meta{
		Version: 1, NextSequence: protocol.MaxSequence, LastAcked: protocol.MaxSequence - 1,
	}
	if err := spool.writeMeta(spool.meta); err != nil {
		t.Fatal(err)
	}

	sequence, err := spool.Append(func(sequence uint64) ([]byte, error) {
		return json.Marshal(map[string]uint64{"seq": sequence})
	})
	if err != nil || sequence != protocol.MaxSequence {
		t.Fatalf("last wire sequence = %d, err = %v", sequence, err)
	}
	buildCalled := false
	if _, err := spool.Append(func(uint64) ([]byte, error) {
		buildCalled = true
		return []byte(`{}`), nil
	}); !errors.Is(err, ErrSequenceExhausted) {
		t.Fatalf("post-limit append error = %v", err)
	}
	if buildCalled {
		t.Fatal("exhausted spool invoked the record builder")
	}
	if got := spool.LastAssigned(); got != protocol.MaxSequence {
		t.Fatalf("last assigned = %d", got)
	}
	if err := spool.Ack(protocol.MaxSequence); err != nil {
		t.Fatal(err)
	}
	if pending, err := spool.Pending(); err != nil || len(pending) != 0 {
		t.Fatalf("pending after final ack = %#v, %v", pending, err)
	}
}

func TestOpenRecoversMaxWireRecordAsExhaustedWithoutOverflow(t *testing.T) {
	dir := t.TempDir()
	spool, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	spool.meta = meta{
		Version: 1, NextSequence: protocol.MaxSequence, LastAcked: protocol.MaxSequence - 1,
	}
	if err := spool.writeMeta(spool.meta); err != nil {
		t.Fatal(err)
	}
	record, err := json.Marshal(map[string]uint64{"seq": protocol.MaxSequence})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(spool.recordPath(protocol.MaxSequence), record, 0o600); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.LastAssigned(); got != protocol.MaxSequence {
		t.Fatalf("recovered last assigned = %d", got)
	}
	if _, err := reopened.Append(func(uint64) ([]byte, error) { return []byte(`{}`), nil }); !errors.Is(err, ErrSequenceExhausted) {
		t.Fatalf("recovered exhausted append error = %v", err)
	}
}

func TestSpoolRejectsWireSequencesAboveSignedRange(t *testing.T) {
	t.Run("metadata", func(t *testing.T) {
		spool, err := Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if err := spool.writeMeta(meta{Version: 1, NextSequence: protocol.MaxSequence + 2}); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(spool.dir); err == nil {
			t.Fatal("out-of-range sequence metadata was accepted")
		}
	})

	t.Run("record", func(t *testing.T) {
		spool, err := Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(spool.dir, fmt.Sprintf("%020d.json", protocol.MaxSequence+1))
		if err := os.WriteFile(path, []byte(`{"seq":9223372036854775808}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(spool.dir); err == nil {
			t.Fatal("out-of-range spool record was accepted")
		}
	})

	t.Run("incoming and ack", func(t *testing.T) {
		spool, err := Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		spool.meta.LastReceived = protocol.MaxSequence - 1
		if err := spool.writeMeta(spool.meta); err != nil {
			t.Fatal(err)
		}
		if fresh, err := spool.CheckIncoming(protocol.MaxSequence); err != nil || !fresh {
			t.Fatalf("last incoming check = %v, %v", fresh, err)
		}
		if err := spool.CommitIncoming(protocol.MaxSequence); err != nil {
			t.Fatal(err)
		}
		if _, err := spool.CheckIncoming(protocol.MaxSequence + 1); err == nil {
			t.Fatal("out-of-range incoming sequence was accepted")
		}
		if err := spool.Ack(protocol.MaxSequence + 1); err == nil {
			t.Fatal("out-of-range acknowledgement was accepted")
		}
	})
}

func appendSmallRecord(t *testing.T, spool *Spool, value string) uint64 {
	t.Helper()
	sequence, err := spool.Append(func(sequence uint64) ([]byte, error) {
		return json.Marshal(map[string]any{"seq": sequence, "value": value})
	})
	if err != nil {
		t.Fatal(err)
	}
	return sequence
}

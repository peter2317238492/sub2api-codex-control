package spool

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/protocol"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/securefile"
)

type meta struct {
	Version      int    `json:"version"`
	NextSequence uint64 `json:"next_sequence"`
	LastAcked    uint64 `json:"last_acked"`
	LastReceived uint64 `json:"last_received"`
}

type Record struct {
	Sequence uint64
	Data     []byte
}

type Limits struct {
	MaxRecords     int
	MaxBytes       int64
	MaxRecordBytes int64
}

type Stats struct {
	PendingRecords   int
	PendingBytes     int64
	CapacityBytes    int64
	OldestPendingAge time.Duration
}

var DefaultLimits = Limits{MaxRecords: 8192, MaxBytes: 64 << 20, MaxRecordBytes: 256 << 10}

var ErrSequenceExhausted = errors.New("spool sequence space is exhausted")

type Spool struct {
	dir            string
	metaPath       string
	limits         Limits
	pendingRecords int
	pendingBytes   int64
	mu             sync.Mutex
	meta           meta
	writeMeta      func(meta) error
	syncDirectory  func() error
}

func Open(dir string) (*Spool, error) {
	return OpenWithLimits(dir, DefaultLimits)
}

func OpenWithLimits(dir string, limits Limits) (*Spool, error) {
	if limits.MaxRecords <= 0 || limits.MaxBytes <= 0 || limits.MaxRecordBytes <= 0 || limits.MaxRecordBytes > limits.MaxBytes {
		return nil, errors.New("spool limits are invalid")
	}
	if err := securefile.EnsureDir(dir); err != nil {
		return nil, err
	}
	s := &Spool{dir: dir, metaPath: filepath.Join(dir, "meta.json"), limits: limits}
	s.writeMeta = func(value meta) error { return securefile.WriteJSON(s.metaPath, value) }
	s.syncDirectory = func() error {
		directory, err := os.Open(dir)
		if err != nil {
			return err
		}
		syncErr := directory.Sync()
		closeErr := directory.Close()
		return errors.Join(syncErr, closeErr)
	}
	err := securefile.ReadJSON(s.metaPath, &s.meta)
	if errors.Is(err, os.ErrNotExist) {
		s.meta = meta{Version: 1, NextSequence: 1}
	} else if err != nil {
		return nil, fmt.Errorf("load spool metadata: %w", err)
	}
	if s.meta.Version != 1 || s.meta.NextSequence == 0 ||
		s.meta.NextSequence > protocol.MaxSequence+1 ||
		s.meta.LastAcked > protocol.MaxSequence ||
		s.meta.LastReceived > protocol.MaxSequence {
		return nil, errors.New("spool metadata is invalid")
	}
	if err := s.removeAckedLocked(s.meta.LastAcked); err != nil {
		return nil, err
	}
	maxSequence, err := s.maxRecordSequence()
	if err != nil {
		return nil, err
	}
	if maxSequence >= s.meta.NextSequence {
		s.meta.NextSequence = maxSequence + 1
	}
	if s.meta.LastAcked >= s.meta.NextSequence {
		return nil, errors.New("spool acknowledgement exceeds assigned sequence")
	}
	pendingRecords, pendingBytes, err := s.pendingStats()
	if err != nil {
		return nil, err
	}
	s.pendingRecords = pendingRecords
	s.pendingBytes = pendingBytes
	if err := s.writeMeta(s.meta); err != nil {
		return nil, err
	}
	return s, nil
}

// Append assigns a durable, monotonically increasing sequence to one envelope.
func (s *Spool) Append(build func(sequence uint64) ([]byte, error)) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sequence := s.meta.NextSequence
	if sequence > protocol.MaxSequence {
		return 0, ErrSequenceExhausted
	}
	data, err := build(sequence)
	if err != nil {
		return 0, err
	}
	if !json.Valid(data) {
		return 0, errors.New("spool record must contain valid JSON")
	}
	encoded, err := json.MarshalIndent(json.RawMessage(data), "", "  ")
	if err != nil {
		return 0, err
	}
	recordBytes := int64(len(encoded) + 1)
	if recordBytes > s.limits.MaxRecordBytes {
		return 0, fmt.Errorf("spool record exceeds %d bytes", s.limits.MaxRecordBytes)
	}
	if s.pendingRecords+1 > s.limits.MaxRecords || s.pendingBytes+recordBytes > s.limits.MaxBytes {
		return 0, errors.New("spool is full")
	}
	path := s.recordPath(sequence)
	if err := securefile.WriteJSON(path, json.RawMessage(data)); err != nil {
		return 0, err
	}
	s.meta.NextSequence++
	s.pendingRecords++
	s.pendingBytes += recordBytes
	if err := s.writeMeta(s.meta); err != nil {
		return 0, err
	}
	return sequence, nil
}

func (s *Spool) Pending() ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	records := make([]Record, 0)
	for _, entry := range entries {
		sequence, ok := parseRecordName(entry.Name())
		if ok && sequence > protocol.MaxSequence {
			return nil, fmt.Errorf("spool record sequence %d exceeds the wire limit", sequence)
		}
		if !ok || sequence <= s.meta.LastAcked {
			continue
		}
		path := filepath.Join(s.dir, entry.Name())
		info, err := securefile.StatPrivateFile(path)
		if err != nil {
			return nil, fmt.Errorf("unsafe spool record %q: %w", path, err)
		}
		if info.Size() > s.limits.MaxRecordBytes {
			return nil, fmt.Errorf("spool record %d exceeds %d bytes", sequence, s.limits.MaxRecordBytes)
		}
		data, err := securefile.ReadPrivateFile(path)
		if err != nil {
			return nil, fmt.Errorf("unsafe spool record %q: %w", path, err)
		}
		if int64(len(data)) > s.limits.MaxRecordBytes {
			return nil, fmt.Errorf("spool record %d exceeds %d bytes", sequence, s.limits.MaxRecordBytes)
		}
		if !json.Valid(data) {
			return nil, fmt.Errorf("spool record %d is corrupt", sequence)
		}
		records = append(records, Record{Sequence: sequence, Data: data})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Sequence < records[j].Sequence })
	expected := s.meta.LastAcked + 1
	for _, record := range records {
		if record.Sequence != expected {
			return nil, fmt.Errorf("spool sequence gap: found %d after %d", record.Sequence, expected-1)
		}
		expected++
	}
	if expected != s.meta.NextSequence {
		return nil, fmt.Errorf("spool sequence gap before next assigned sequence %d", s.meta.NextSequence)
	}
	return records, nil
}

func (s *Spool) Ack(sequence uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sequence > protocol.MaxSequence {
		return fmt.Errorf("ack %d exceeds the wire sequence limit", sequence)
	}
	if sequence <= s.meta.LastAcked {
		return s.removeAckedLocked(s.meta.LastAcked)
	}
	if sequence >= s.meta.NextSequence {
		return fmt.Errorf("ack %d exceeds last assigned sequence %d", sequence, s.meta.NextSequence-1)
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	removedRecords := 0
	var removedBytes int64
	for _, entry := range entries {
		recordSequence, ok := parseRecordName(entry.Name())
		if !ok || recordSequence <= s.meta.LastAcked || recordSequence > sequence {
			continue
		}
		path := filepath.Join(s.dir, entry.Name())
		info, err := securefile.StatPrivateFile(path)
		if err != nil {
			return fmt.Errorf("unsafe spool record %q: %w", path, err)
		}
		removedRecords++
		removedBytes += info.Size()
	}
	nextMeta := s.meta
	nextMeta.LastAcked = sequence
	if err := s.writeMeta(nextMeta); err != nil {
		return err
	}
	s.meta = nextMeta
	s.pendingRecords -= removedRecords
	s.pendingBytes -= removedBytes
	if s.pendingRecords < 0 || s.pendingBytes < 0 {
		return errors.New("spool accounting became inconsistent")
	}
	return s.removeAckedLocked(sequence)
}

// CheckIncoming validates sequence continuity without acknowledging handling.
func (s *Spool) CheckIncoming(sequence uint64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sequence == 0 || sequence > protocol.MaxSequence {
		return false, errors.New("incoming sequence is outside the wire range")
	}
	if sequence <= s.meta.LastReceived {
		return false, nil
	}
	if sequence != s.meta.LastReceived+1 {
		return false, fmt.Errorf("incoming sequence gap: received %d after %d", sequence, s.meta.LastReceived)
	}
	return true, nil
}

// CommitIncoming advances the durable cursor only after semantic handling and
// any required durable response have completed successfully.
func (s *Spool) CommitIncoming(sequence uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sequence == 0 || sequence > protocol.MaxSequence {
		return errors.New("incoming sequence is outside the wire range")
	}
	if sequence != s.meta.LastReceived+1 {
		return fmt.Errorf("cannot commit incoming sequence %d after %d", sequence, s.meta.LastReceived)
	}
	nextMeta := s.meta
	nextMeta.LastReceived = sequence
	if err := s.writeMeta(nextMeta); err != nil {
		return err
	}
	s.meta = nextMeta
	return nil
}

// ObserveIncoming is retained for callers that perform no semantic work.
func (s *Spool) ObserveIncoming(sequence uint64) (bool, error) {
	fresh, err := s.CheckIncoming(sequence)
	if err != nil || !fresh {
		return fresh, err
	}
	if err := s.CommitIncoming(sequence); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Spool) LastReceived() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.meta.LastReceived
}

func (s *Spool) LastAcked() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.meta.LastAcked
}

func (s *Spool) LastAssigned() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.meta.NextSequence - 1
}

func (s *Spool) Stats(now time.Time) (Stats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	age := time.Duration(0)
	if s.pendingRecords > 0 {
		oldestPath := s.recordPath(s.meta.LastAcked + 1)
		info, err := securefile.StatPrivateFile(oldestPath)
		if err != nil {
			return Stats{}, fmt.Errorf("unsafe oldest spool record %q: %w", oldestPath, err)
		}
		if info.Size() > s.limits.MaxRecordBytes {
			return Stats{}, fmt.Errorf("unsafe oldest spool record %q", oldestPath)
		}
		if now.After(info.ModTime()) {
			age = now.Sub(info.ModTime())
		}
	}
	return Stats{
		PendingRecords:   s.pendingRecords,
		PendingBytes:     s.pendingBytes,
		CapacityBytes:    s.limits.MaxBytes,
		OldestPendingAge: age,
	}, nil
}

func (s *Spool) recordPath(sequence uint64) string {
	return filepath.Join(s.dir, fmt.Sprintf("%020d.json", sequence))
}

func (s *Spool) maxRecordSequence() (uint64, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return 0, err
	}
	var maximum uint64
	for _, entry := range entries {
		sequence, ok := parseRecordName(entry.Name())
		if ok && sequence > protocol.MaxSequence {
			return 0, fmt.Errorf("spool record sequence %d exceeds the wire limit", sequence)
		}
		if ok && sequence > maximum {
			maximum = sequence
		}
	}
	return maximum, nil
}

func (s *Spool) pendingStats() (int, int64, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return 0, 0, err
	}
	count := 0
	var bytes int64
	for _, entry := range entries {
		sequence, ok := parseRecordName(entry.Name())
		if ok && sequence > protocol.MaxSequence {
			return 0, 0, fmt.Errorf("spool record sequence %d exceeds the wire limit", sequence)
		}
		if !ok || sequence <= s.meta.LastAcked {
			continue
		}
		path := filepath.Join(s.dir, entry.Name())
		info, err := securefile.StatPrivateFile(path)
		if err != nil {
			return 0, 0, fmt.Errorf("unsafe spool record %q: %w", path, err)
		}
		if info.Size() > s.limits.MaxRecordBytes {
			return 0, 0, fmt.Errorf("spool record %d exceeds %d bytes", sequence, s.limits.MaxRecordBytes)
		}
		count++
		bytes += info.Size()
	}
	if count > s.limits.MaxRecords || bytes > s.limits.MaxBytes {
		return 0, 0, errors.New("existing spool exceeds configured capacity")
	}
	expected := s.meta.NextSequence - 1 - s.meta.LastAcked
	if uint64(count) != expected {
		return 0, 0, fmt.Errorf("spool has %d pending records but sequence metadata requires %d", count, expected)
	}
	return count, bytes, nil
}

func (s *Spool) removeAckedLocked(sequence uint64) error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		recordSequence, ok := parseRecordName(entry.Name())
		if ok && recordSequence <= sequence {
			if err := os.Remove(filepath.Join(s.dir, entry.Name())); err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					return err
				}
			}
		}
	}
	if err := s.syncDirectory(); err != nil {
		return fmt.Errorf("sync spool after acknowledged record cleanup: %w", err)
	}
	return nil
}

func parseRecordName(name string) (uint64, bool) {
	if !strings.HasSuffix(name, ".json") || name == "meta.json" {
		return 0, false
	}
	value := strings.TrimSuffix(name, ".json")
	if len(value) != 20 {
		return 0, false
	}
	sequence, err := strconv.ParseUint(value, 10, 64)
	return sequence, err == nil && sequence > 0
}

package localstate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/protocol"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/securefile"
)

type Thread struct {
	ID           string    `json:"id"`
	CWD          string    `json:"cwd"`
	ActiveTurnID string    `json:"active_turn_id,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

const (
	maxManagedThreads         = 4096
	maxThreadIDLength         = 512
	maxThreadCWDLength        = 4096
	maxManagedThreadStateSize = 192 << 20
)

type threadDisk struct {
	Version  int               `json:"version"`
	DeviceID string            `json:"device_id"`
	Threads  map[string]Thread `json:"threads"`
}

type Threads struct {
	path         string
	mu           sync.Mutex
	data         threadDisk
	reservations int
}

var ErrManagedThreadStoreFull = errors.New("managed thread store is full")

func OpenThreads(path, deviceID string) (*Threads, error) {
	if !protocol.IsUUID(deviceID) {
		return nil, errors.New("managed thread device id is invalid")
	}
	store := &Threads{path: path, data: newThreadDisk(deviceID)}
	err := securefile.ReadJSONLimit(path, &store.data, maxManagedThreadStateSize)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	if store.data.Version == 1 && store.data.Threads != nil {
		store.data = newThreadDisk(deviceID)
		if err := securefile.WriteJSON(path, store.data); err != nil {
			return nil, fmt.Errorf("reset unscoped managed thread state: %w", err)
		}
		return store, nil
	}
	if store.data.Version != 2 || !protocol.IsUUID(store.data.DeviceID) || store.data.Threads == nil {
		return nil, errors.New("managed thread state is invalid")
	}
	if store.data.DeviceID != deviceID {
		store.data = newThreadDisk(deviceID)
		if err := securefile.WriteJSON(path, store.data); err != nil {
			return nil, fmt.Errorf("reset managed thread state for a new device: %w", err)
		}
		return store, nil
	}
	if len(store.data.Threads) > maxManagedThreads {
		return nil, errors.New("managed thread state exceeds its record limit")
	}
	for id, thread := range store.data.Threads {
		if id != thread.ID || !validThread(thread) {
			return nil, errors.New("managed thread state contains an invalid binding")
		}
	}
	return store, nil
}

func (s *Threads) Add(thread Thread) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !validThread(thread) {
		return errors.New("managed thread is incomplete")
	}
	if _, exists := s.data.Threads[thread.ID]; !exists && len(s.data.Threads)+s.reservations >= maxManagedThreads {
		return ErrManagedThreadStoreFull
	}
	return s.addLocked(thread)
}

// ReserveAdd claims capacity before thread/start reaches the app-server. This
// prevents a full managed store from creating an untracked local thread.
func (s *Threads) ReserveAdd() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.data.Threads)+s.reservations >= maxManagedThreads {
		return ErrManagedThreadStoreFull
	}
	s.reservations++
	return nil
}

// ReleaseAdd releases a reservation that did not reach AddReserved.
func (s *Threads) ReleaseAdd() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reservations <= 0 {
		panic("release managed thread reservation without a reservation")
	}
	s.reservations--
}

// AddReserved consumes one reservation whether persistence succeeds or fails.
func (s *Threads) AddReserved(thread Thread) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reservations <= 0 {
		return errors.New("managed thread add has no capacity reservation")
	}
	s.reservations--
	if !validThread(thread) {
		return errors.New("managed thread is incomplete")
	}
	if _, exists := s.data.Threads[thread.ID]; !exists && len(s.data.Threads) >= maxManagedThreads {
		return ErrManagedThreadStoreFull
	}
	return s.addLocked(thread)
}

func (s *Threads) addLocked(thread Thread) error {
	next := cloneThreadDisk(s.data)
	next.Threads[thread.ID] = thread
	if err := securefile.WriteJSON(s.path, next); err != nil {
		return err
	}
	s.data = next
	return nil
}

func (s *Threads) Contains(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.data.Threads[id]
	return ok
}

func (s *Threads) Get(id string) (Thread, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	thread, ok := s.data.Threads[id]
	return thread, ok
}

func (s *Threads) SetActiveTurn(threadID, turnID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	thread, ok := s.data.Threads[threadID]
	if !ok {
		return errors.New("thread is not managed by this connector")
	}
	if utf8.RuneCountInString(turnID) > maxThreadIDLength {
		return errors.New("active turn id is too long")
	}
	thread.ActiveTurnID = turnID
	next := cloneThreadDisk(s.data)
	next.Threads[threadID] = thread
	if err := securefile.WriteJSON(s.path, next); err != nil {
		if turnID == "" {
			// Clearing authority must fail closed in the running process even if
			// the disk is temporarily unavailable. Startup clears turns again
			// before reconnecting.
			s.data = next
		}
		return err
	}
	s.data = next
	return nil
}

func validThread(thread Thread) bool {
	return thread.ID != "" && utf8.RuneCountInString(thread.ID) <= maxThreadIDLength &&
		thread.CWD != "" && utf8.RuneCountInString(thread.CWD) <= maxThreadCWDLength &&
		utf8.RuneCountInString(thread.ActiveTurnID) <= maxThreadIDLength
}

func (s *Threads) ClearActiveTurns() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneThreadDisk(s.data)
	changed := false
	for id, thread := range next.Threads {
		if thread.ActiveTurnID != "" {
			thread.ActiveTurnID = ""
			next.Threads[id] = thread
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if err := securefile.WriteJSON(s.path, next); err != nil {
		s.data = next
		return err
	}
	s.data = next
	return nil
}

func (s *Threads) IDs() map[string]struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make(map[string]struct{}, len(s.data.Threads))
	for id := range s.data.Threads {
		result[id] = struct{}{}
	}
	return result
}

func cloneThreadDisk(source threadDisk) threadDisk {
	result := threadDisk{
		Version: source.Version, DeviceID: source.DeviceID,
		Threads: make(map[string]Thread, len(source.Threads)),
	}
	for id, thread := range source.Threads {
		result.Threads[id] = thread
	}
	return result
}

func newThreadDisk(deviceID string) threadDisk {
	return threadDisk{Version: 2, DeviceID: deviceID, Threads: make(map[string]Thread)}
}

type CommandStore struct {
	dir           string
	limits        CommandStoreLimits
	now           func() time.Time
	syncDirectory func() error
	mu            sync.Mutex
}

type CommandStoreLimits struct {
	MaxRecords     int
	MaxBytes       int64
	MaxRecordBytes int64
	Retention      time.Duration
}

var DefaultCommandStoreLimits = CommandStoreLimits{
	MaxRecords: 4096, MaxBytes: 128 << 20, MaxRecordBytes: 2 << 20, Retention: 24 * time.Hour,
}

type CommandBeginState string

const (
	CommandExecuting     CommandBeginState = "executing"
	CommandTerminal      CommandBeginState = "terminal"
	CommandIndeterminate CommandBeginState = "indeterminate"
	CommandConflict      CommandBeginState = "conflict"
)

type CommandBeginResult struct {
	State  CommandBeginState
	Ack    json.RawMessage
	Reason string
}

type commandRecord struct {
	Version     int             `json:"version"`
	Key         string          `json:"key"`
	Fingerprint string          `json:"fingerprint"`
	CommandID   string          `json:"command_id"`
	Epoch       string          `json:"epoch"`
	State       string          `json:"state"`
	Ack         json.RawMessage `json:"ack,omitempty"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

func OpenCommands(dir string) (*CommandStore, error) {
	return OpenCommandsWithLimits(dir, DefaultCommandStoreLimits)
}

func OpenCommandsWithLimits(dir string, limits CommandStoreLimits) (*CommandStore, error) {
	if err := securefile.EnsureDir(dir); err != nil {
		return nil, err
	}
	if limits.MaxRecords <= 0 || limits.MaxBytes <= 0 || limits.MaxRecordBytes <= 0 ||
		limits.MaxRecordBytes > limits.MaxBytes || limits.Retention <= 0 {
		return nil, errors.New("command store limits are invalid")
	}
	store := &CommandStore{dir: dir, limits: limits, now: time.Now}
	// securefile opens the directory itself, because a directory flush needs a
	// write right that os.Open does not ask for.
	store.syncDirectory = func() error { return securefile.SyncDirectory(dir) }
	store.mu.Lock()
	now := store.now().UTC()
	err := store.recoverExecutingLocked(now)
	store.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return store, nil
}

func (s *CommandStore) Begin(key, fingerprint, commandID, epoch string) (CommandBeginResult, error) {
	if key == "" || fingerprint == "" || commandID == "" || len(epoch) < 16 {
		return CommandBeginResult{}, errors.New("invalid command journal identity")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	path := s.path(key)
	record, err := s.readRecordLocked(path)
	if errors.Is(err, os.ErrNotExist) {
		record = commandRecord{
			Version: 2, Key: key, Fingerprint: fingerprint, CommandID: commandID,
			Epoch: epoch, State: string(CommandExecuting), UpdatedAt: now,
		}
		if err := s.writeRecordLocked(path, record); err != nil {
			return CommandBeginResult{}, err
		}
		return CommandBeginResult{State: CommandExecuting}, nil
	}
	if err != nil {
		return CommandBeginResult{}, err
	}
	if record.Key != key || record.Fingerprint != fingerprint || record.CommandID != commandID {
		return CommandBeginResult{State: CommandConflict, Reason: "idempotency key was reused for a different command"}, nil
	}
	switch CommandBeginState(record.State) {
	case CommandTerminal:
		return CommandBeginResult{State: CommandTerminal, Ack: append(json.RawMessage(nil), record.Ack...)}, nil
	case CommandExecuting:
		if record.Epoch != epoch {
			return CommandBeginResult{State: CommandIndeterminate, Reason: "command belongs to an earlier app-server epoch"}, nil
		}
		return CommandBeginResult{State: CommandIndeterminate, Reason: "previous command execution did not reach a durable terminal state"}, nil
	default:
		return CommandBeginResult{}, errors.New("stored command state is corrupt")
	}
}

// Replay returns a matching durable result without ever creating or dispatching
// a command. It is the only path used for a stale-epoch command replay.
func (s *CommandStore) Replay(key, fingerprint, commandID string) (CommandBeginResult, error) {
	if key == "" || fingerprint == "" || commandID == "" {
		return CommandBeginResult{}, errors.New("invalid command replay identity")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.readRecordLocked(s.path(key))
	if errors.Is(err, os.ErrNotExist) {
		return CommandBeginResult{State: CommandConflict, Reason: "stale command has no durable journal record"}, nil
	}
	if err != nil {
		return CommandBeginResult{}, err
	}
	if record.Key != key || record.Fingerprint != fingerprint || record.CommandID != commandID {
		return CommandBeginResult{State: CommandConflict, Reason: "stale command does not match its durable journal record"}, nil
	}
	switch CommandBeginState(record.State) {
	case CommandTerminal:
		return CommandBeginResult{State: CommandTerminal, Ack: append(json.RawMessage(nil), record.Ack...)}, nil
	case CommandExecuting:
		return CommandBeginResult{State: CommandIndeterminate, Reason: "stale command did not reach a durable terminal state"}, nil
	default:
		return CommandBeginResult{}, errors.New("stored command state is corrupt")
	}
}

func (s *CommandStore) Complete(key, fingerprint, commandID, epoch string, value json.RawMessage) error {
	return s.complete(key, fingerprint, commandID, epoch, value, false)
}

func (s *CommandStore) ResolveIndeterminate(key, fingerprint, commandID, epoch string, value json.RawMessage) error {
	return s.complete(key, fingerprint, commandID, epoch, value, true)
}

// PolicyDenialReceiptKeys returns the durable telemetry outbox represented by
// terminal policy-denial command records. Callers must reconcile these keys
// before pruning the journal so a crash between terminal commit and metrics
// persistence cannot permanently lose the denial.
func (s *CommandStore) PolicyDenialReceiptKeys() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	files, err := s.inventoryLocked()
	if err != nil {
		return nil, err
	}
	unique := make(map[string]struct{})
	for _, file := range files {
		if file.record.State != string(CommandTerminal) {
			continue
		}
		var acknowledgement protocol.CommandAckPayload
		if err := json.Unmarshal(file.record.Ack, &acknowledgement); err != nil {
			return nil, errors.New("stored terminal command result is corrupt")
		}
		if acknowledgement.State != "denied" || acknowledgement.Error == nil || acknowledgement.Error.Code != "policy_denied" {
			continue
		}
		if acknowledgement.CommandID != file.record.CommandID {
			return nil, errors.New("stored policy denial command identity is corrupt")
		}
		unique[PolicyDenialReceiptKey(file.record.CommandID)] = struct{}{}
	}
	keys := make([]string, 0, len(unique))
	for key := range unique {
		keys = append(keys, key)
	}
	return keys, nil
}

// PruneExpired removes terminal records only after their telemetry outbox has
// been reconciled by the runtime. Begin also enforces these bounds after the
// startup reconciliation gate has completed.
func (s *CommandStore) PruneExpired() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.pruneLocked(s.now().UTC(), "", 0, false); err != nil {
		return err
	}
	if err := s.syncDirectory(); err != nil {
		return fmt.Errorf("sync command journal after pruning: %w", err)
	}
	return nil
}

func PolicyDenialReceiptKey(commandID string) string {
	digest := sha256.Sum256([]byte(commandID))
	return hex.EncodeToString(digest[:])
}

func (s *CommandStore) complete(key, fingerprint, commandID, epoch string, value json.RawMessage, allowPriorEpoch bool) error {
	if key == "" || fingerprint == "" || commandID == "" || len(epoch) < 16 || !json.Valid(value) {
		return errors.New("invalid terminal command record")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	path := s.path(key)
	record, err := s.readRecordLocked(path)
	if err != nil {
		return err
	}
	if record.Key != key || record.Fingerprint != fingerprint || record.CommandID != commandID {
		return errors.New("command journal identity changed before completion")
	}
	if record.Epoch != epoch && !allowPriorEpoch {
		return errors.New("command journal epoch changed before completion")
	}
	if record.State == string(CommandTerminal) {
		if record.Epoch == epoch && string(record.Ack) == string(value) {
			return nil
		}
		return errors.New("terminal command result cannot be replaced")
	}
	if record.State != string(CommandExecuting) {
		return errors.New("command was not executing at completion")
	}
	record.Version = 2
	record.Epoch = epoch
	record.State = string(CommandTerminal)
	record.Ack = append(json.RawMessage(nil), value...)
	record.UpdatedAt = s.now().UTC()
	return s.writeRecordLocked(path, record)
}

func (s *CommandStore) path(key string) string {
	digest := sha256.Sum256([]byte(key))
	return filepath.Join(s.dir, hex.EncodeToString(digest[:])+".json")
}

type commandFile struct {
	path   string
	record commandRecord
	size   int64
}

func (s *CommandStore) readRecordLocked(path string) (commandRecord, error) {
	var record commandRecord
	if err := securefile.ReadJSONLimit(path, &record, s.limits.MaxRecordBytes); err != nil {
		return commandRecord{}, err
	}
	if record.Version != 2 || record.Key == "" || record.Fingerprint == "" || record.CommandID == "" ||
		len(record.Epoch) < 16 || record.UpdatedAt.IsZero() {
		return commandRecord{}, errors.New("stored command journal is corrupt")
	}
	if record.State == string(CommandTerminal) {
		if len(record.Ack) == 0 || !json.Valid(record.Ack) {
			return commandRecord{}, errors.New("stored terminal command result is corrupt")
		}
	} else if record.State != string(CommandExecuting) || len(record.Ack) != 0 {
		return commandRecord{}, errors.New("stored command state is corrupt")
	}
	return record, nil
}

func (s *CommandStore) writeRecordLocked(path string, record commandRecord) error {
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	recordBytes := int64(len(encoded) + 1)
	if recordBytes > s.limits.MaxRecordBytes {
		return fmt.Errorf("command record exceeds %d bytes", s.limits.MaxRecordBytes)
	}
	if err := s.pruneLocked(s.now().UTC(), path, recordBytes, true); err != nil {
		return err
	}
	return securefile.WriteJSON(path, record)
}

func (s *CommandStore) pruneLocked(now time.Time, replacementPath string, replacementBytes int64, adding bool) error {
	files, err := s.inventoryLocked()
	if err != nil {
		return err
	}
	removed := false
	for _, file := range files {
		if file.path == replacementPath || file.record.State != string(CommandTerminal) {
			continue
		}
		if now.Sub(file.record.UpdatedAt) >= s.limits.Retention {
			if err := os.Remove(file.path); err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					return err
				}
				removed = true
			} else {
				removed = true
			}
		}
	}
	if removed {
		if err := s.syncDirectory(); err != nil {
			return fmt.Errorf("sync command journal after pruning: %w", err)
		}
	}
	files, err = s.inventoryLocked()
	if err != nil {
		return err
	}
	var bytes int64
	count := 0
	for _, file := range files {
		if file.path == replacementPath {
			continue
		}
		count++
		bytes += file.size
	}
	if adding {
		count++
		bytes += replacementBytes
	}
	if count <= s.limits.MaxRecords && bytes <= s.limits.MaxBytes {
		return nil
	}
	return errors.New("command journal is full and has no expired terminal records eligible for pruning")
}

func (s *CommandStore) recoverExecutingLocked(now time.Time) error {
	files, err := s.inventoryLocked()
	if err != nil {
		return err
	}
	for _, file := range files {
		if file.record.State != string(CommandExecuting) {
			continue
		}
		ack, err := json.Marshal(protocol.CommandAckPayload{
			CommandID: file.record.CommandID,
			State:     "failed",
			Error: &protocol.ProtocolError{
				Code: "indeterminate", Message: "connector restarted before command completion was durably recorded; the mutation will not be replayed", Retryable: false,
			},
		})
		if err != nil {
			return err
		}
		file.record.State = string(CommandTerminal)
		file.record.Ack = ack
		file.record.UpdatedAt = now
		encoded, err := json.MarshalIndent(file.record, "", "  ")
		if err != nil {
			return err
		}
		if int64(len(encoded)+1) > s.limits.MaxRecordBytes {
			return errors.New("recovered command record exceeds its size limit")
		}
		if err := securefile.WriteJSON(file.path, file.record); err != nil {
			return err
		}
	}
	return nil
}

func (s *CommandStore) inventoryLocked() ([]commandFile, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	files := make([]commandFile, 0, len(entries))
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(s.dir, entry.Name())
		info, err := securefile.StatPrivateFile(path)
		if err != nil {
			return nil, fmt.Errorf("unsafe command journal file %q: %w", path, err)
		}
		if info.Size() > s.limits.MaxRecordBytes {
			return nil, fmt.Errorf("command journal file %q exceeds %d bytes", path, s.limits.MaxRecordBytes)
		}
		record, err := s.readRecordLocked(path)
		if err != nil {
			return nil, fmt.Errorf("read command journal %q: %w", path, err)
		}
		if path != s.path(record.Key) {
			return nil, fmt.Errorf("command journal file %q has a noncanonical name", path)
		}
		files = append(files, commandFile{path: path, record: record, size: info.Size()})
	}
	return files, nil
}

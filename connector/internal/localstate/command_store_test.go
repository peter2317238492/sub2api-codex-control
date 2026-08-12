package localstate

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/protocol"
)

const testEpoch = "epoch-0123456789abcdef"

func TestCommandStorePersistsExecutingAndTerminalStates(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenCommands(dir)
	if err != nil {
		t.Fatal(err)
	}
	begin, err := store.Begin("key", "fingerprint", "command", testEpoch)
	if err != nil || begin.State != CommandExecuting {
		t.Fatalf("begin = %#v, %v", begin, err)
	}

	reopened, err := OpenCommands(dir)
	if err != nil {
		t.Fatal(err)
	}
	begin, err = reopened.Begin("key", "fingerprint", "command", testEpoch)
	if err != nil || begin.State != CommandTerminal {
		t.Fatalf("reopened begin = %#v, %v", begin, err)
	}
	var gotAck map[string]any
	_ = json.Unmarshal(begin.Ack, &gotAck)
	errorValue, _ := gotAck["error"].(map[string]any)
	if err != nil || begin.State != CommandTerminal || errorValue["code"] != "indeterminate" || errorValue["retryable"] != false {
		t.Fatalf("terminal begin = %#v, %v", begin, err)
	}
}

func TestRecoveredExecutingRecordDoesNotReplayAcrossEpochs(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenCommands(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Begin("key", "fingerprint", "command", testEpoch); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenCommands(dir)
	if err != nil {
		t.Fatal(err)
	}
	begin, err := reopened.Begin("key", "fingerprint", "command", "new-epoch-0123456789abcdef")
	if err != nil || begin.State != CommandTerminal {
		t.Fatalf("cross-epoch begin = %#v, %v", begin, err)
	}
	var acknowledgement protocol.CommandAckPayload
	if err := json.Unmarshal(begin.Ack, &acknowledgement); err != nil {
		t.Fatal(err)
	}
	if acknowledgement.Error == nil || acknowledgement.Error.Code != "indeterminate" || acknowledgement.Error.Retryable {
		t.Fatalf("recovered acknowledgement = %#v", acknowledgement)
	}
}

func TestTerminalResultReplaysAcrossEpochs(t *testing.T) {
	store, err := OpenCommands(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Begin("key", "fingerprint", "command", testEpoch); err != nil {
		t.Fatal(err)
	}
	ack := json.RawMessage(`{"command_id":"command","state":"completed","result":{"ok":true}}`)
	if err := store.Complete("key", "fingerprint", "command", testEpoch, ack); err != nil {
		t.Fatal(err)
	}
	begin, err := store.Begin("key", "fingerprint", "command", "new-epoch-0123456789abcdef")
	if err != nil || begin.State != CommandTerminal {
		t.Fatalf("cross-epoch terminal replay = %#v, %v", begin, err)
	}
	var acknowledgement protocol.CommandAckPayload
	if err := json.Unmarshal(begin.Ack, &acknowledgement); err != nil {
		t.Fatal(err)
	}
	if acknowledgement.CommandID != "command" || acknowledgement.State != "completed" {
		t.Fatalf("cross-epoch terminal acknowledgement = %#v", acknowledgement)
	}
	if err := store.ResolveIndeterminate(
		"key", "fingerprint", "command", "new-epoch-0123456789abcdef",
		json.RawMessage(`{"command_id":"command","state":"failed"}`),
	); err == nil {
		t.Fatal("cross-epoch recovery replaced an existing terminal result")
	}
}

func TestCommandStoreRejectsNoncanonicalJournalFilename(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenCommands(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Begin("key", "fingerprint", "command", testEpoch); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("journal entries = %d, %v", len(entries), err)
	}
	renamed := filepath.Join(dir, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json")
	if err := os.Rename(filepath.Join(dir, entries[0].Name()), renamed); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCommands(dir); err == nil || !strings.Contains(err.Error(), "noncanonical name") {
		t.Fatalf("renamed command journal error = %v", err)
	}
}

func TestCommandStorePrunesExpiredTerminalRecordsButNeverExecutingRecords(t *testing.T) {
	now := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	limits := CommandStoreLimits{MaxRecords: 1, MaxBytes: 4096, MaxRecordBytes: 2048, Retention: time.Hour}
	store, err := OpenCommandsWithLimits(t.TempDir(), limits)
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now }
	if _, err := store.Begin("first", "fingerprint", "command-1", testEpoch); err != nil {
		t.Fatal(err)
	}
	ack := json.RawMessage(`{"command_id":"command-1","state":"completed"}`)
	if err := store.Complete("first", "fingerprint", "command-1", testEpoch, ack); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	if _, err := store.Begin("second", "fingerprint", "command-2", testEpoch); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(store.dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("journal entries after pruning = %d", len(entries))
	}
	if _, err := store.Begin("third", "fingerprint", "command-3", testEpoch); err == nil {
		t.Fatal("executing record was pruned to admit another command")
	}
}

func TestCommandStoreDefersPolicyDenialPruningUntilReceiptReconciliation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "commands")
	limits := CommandStoreLimits{MaxRecords: 4, MaxBytes: 16 << 10, MaxRecordBytes: 4 << 10, Retention: time.Hour}
	store, err := OpenCommandsWithLimits(dir, limits)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-2 * time.Hour).UTC()
	store.now = func() time.Time { return now }
	commandID := "33333333-3333-4333-8333-333333333333"
	if _, err := store.Begin("policy-key", "fingerprint", commandID, testEpoch); err != nil {
		t.Fatal(err)
	}
	ack, err := json.Marshal(protocol.CommandAckPayload{
		CommandID: commandID,
		State:     "denied",
		Error:     &protocol.ProtocolError{Code: "policy_denied", Message: "blocked", Retryable: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Complete("policy-key", "fingerprint", commandID, testEpoch, ack); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenCommandsWithLimits(dir, limits)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := reopened.PolicyDenialReceiptKeys()
	if err != nil {
		t.Fatal(err)
	}
	wantKey := PolicyDenialReceiptKey(commandID)
	if len(keys) != 1 || keys[0] != wantKey {
		t.Fatalf("policy denial receipt keys = %#v, want %q", keys, wantKey)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("journal entries before reconciliation = %d, want 1", len(entries))
	}
	if err := reopened.PruneExpired(); err != nil {
		t.Fatal(err)
	}
	entries, err = os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("journal entries after explicit pruning = %d, want 0", len(entries))
	}
}

func TestCommandStorePruneFailsClosedWhenDirectorySyncIsUncertain(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "commands")
	limits := CommandStoreLimits{MaxRecords: 4, MaxBytes: 16 << 10, MaxRecordBytes: 4 << 10, Retention: time.Hour}
	store, err := OpenCommandsWithLimits(dir, limits)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-2 * time.Hour).UTC()
	store.now = func() time.Time { return now }
	if _, err := store.Begin("expired", "fingerprint", "command", testEpoch); err != nil {
		t.Fatal(err)
	}
	if err := store.Complete("expired", "fingerprint", "command", testEpoch, json.RawMessage(`{"command_id":"command","state":"completed"}`)); err != nil {
		t.Fatal(err)
	}
	store.now = time.Now
	syncFailure := errors.New("simulated command directory fsync failure")
	syncCalls := 0
	store.syncDirectory = func() error {
		syncCalls++
		return syncFailure
	}
	if err := store.PruneExpired(); !errors.Is(err, syncFailure) {
		t.Fatalf("prune error = %v, want directory sync failure", err)
	}
	if syncCalls != 1 {
		t.Fatalf("command directory sync calls = %d, want 1", syncCalls)
	}
	store.syncDirectory = func() error {
		syncCalls++
		return nil
	}
	if err := store.PruneExpired(); err != nil {
		t.Fatalf("retry pruning after directory sync uncertainty: %v", err)
	}
	if syncCalls != 2 {
		t.Fatalf("command directory sync calls after retry = %d, want 2", syncCalls)
	}
}

package control

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/localstate"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/metrics"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/policy"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/protocol"
)

const testCommandID = "33333333-3333-4333-8333-333333333333"

type fakeRouter struct{ calls int }

func (f *fakeRouter) Call(context.Context, string, json.RawMessage) (json.RawMessage, error) {
	f.calls++
	return json.RawMessage(`{"data":[{"id":"gpt-5","displayName":"GPT-5"}]}`), nil
}

type errorRouter struct {
	calls int
	err   error
}

func (r *errorRouter) Call(context.Context, string, json.RawMessage) (json.RawMessage, error) {
	r.calls++
	return nil, r.err
}

type captureEmitter struct {
	values []protocol.CommandAckPayload
	epochs []string
}

func (c *captureEmitter) Emit(_ context.Context, typeName string, value any) error {
	if typeName == protocol.TypeCommandAck {
		c.values = append(c.values, value.(protocol.CommandAckPayload))
		c.epochs = append(c.epochs, "")
	}
	return nil
}

func (c *captureEmitter) EmitForEpoch(_ context.Context, epoch, typeName string, value any) error {
	if typeName == protocol.TypeCommandAck {
		c.values = append(c.values, value.(protocol.CommandAckPayload))
		c.epochs = append(c.epochs, epoch)
	}
	return nil
}

type failingEmitter struct{ err error }

func (f failingEmitter) Emit(context.Context, string, any) error { return f.err }

type crashAfterMutationRouter struct {
	markerPath string
	block      bool
}

func (r crashAfterMutationRouter) Call(ctx context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
	marker, err := os.OpenFile(r.markerPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := marker.WriteString("applied\n"); err != nil {
		_ = marker.Close()
		return nil, err
	}
	if err := marker.Sync(); err != nil {
		_ = marker.Close()
		return nil, err
	}
	if err := marker.Close(); err != nil {
		return nil, err
	}
	directory, err := os.Open(filepath.Dir(r.markerPath))
	if err != nil {
		return nil, err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return nil, err
	}
	if err := directory.Close(); err != nil {
		return nil, err
	}
	if r.block {
		if _, err := os.Stdout.WriteString("mutation-applied\n"); err != nil {
			return nil, err
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return json.RawMessage(`{"thread":{"id":"thread-created"},"model":"gpt-5","cwd":"/work"}`), nil

}

type crashBeforeAckEmitter struct{}

func (crashBeforeAckEmitter) Emit(ctx context.Context, typeName string, _ any) error {
	if typeName != protocol.TypeCommandAck {
		return errors.New("crash helper received an unexpected envelope type")
	}
	if _, err := os.Stdout.WriteString("terminal-durable\n"); err != nil {
		return err
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestHandlerReportsPolicyDenialOnTerminalReplay(t *testing.T) {
	commands, err := localstate.OpenCommands(filepath.Join(t.TempDir(), "commands"))
	if err != nil {
		t.Fatal(err)
	}
	router := &fakeRouter{}
	emitter := &captureEmitter{}
	epoch := "epoch-0123456789abcdef"
	var receiptKeys []string
	handler := &Handler{
		Epoch: epoch, Router: router, Commands: commands, Emitter: emitter,
		OnPolicyDenial: func(receiptKey string) error {
			receiptKeys = append(receiptKeys, receiptKey)
			return nil
		},
	}
	payload, _ := json.Marshal(protocol.CommandPayload{
		CommandID: testCommandID, IdempotencyKey: "key", Method: "command/exec",
		Params: json.RawMessage(`{"command":"whoami"}`), DeadlineAt: time.Now().Add(time.Minute),
	})
	if err := handler.Handle(t.Context(), protocol.Envelope{Type: protocol.TypeCommand, Epoch: epoch, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if router.calls != 0 || len(emitter.values) != 1 || emitter.values[0].State != "denied" || emitter.values[0].Error.Code != "policy_denied" {
		t.Fatalf("router calls = %d, acknowledgements = %#v", router.calls, emitter.values)
	}
	if err := handler.Handle(t.Context(), protocol.Envelope{Type: protocol.TypeCommand, Epoch: epoch, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if len(receiptKeys) != 2 || receiptKeys[0] != receiptKeys[1] || len(receiptKeys[0]) != 64 {
		t.Fatalf("policy denial receipt keys = %#v, want the same fixed digest on initial handling and replay", receiptKeys)
	}
}

func TestPolicyDenialMetricsFailurePreventsAckUntilDurableTerminalReplay(t *testing.T) {
	commands, err := localstate.OpenCommands(filepath.Join(t.TempDir(), "commands"))
	if err != nil {
		t.Fatal(err)
	}
	epoch := "epoch-0123456789abcdef"
	emitter := &captureEmitter{}
	metricFailure := errors.New("durable metrics unavailable")
	metricCalls := 0
	handler := &Handler{
		Epoch: epoch, Router: &fakeRouter{}, Commands: commands, Emitter: emitter,
		OnPolicyDenial: func(string) error {
			metricCalls++
			if metricCalls == 1 {
				return metricFailure
			}
			return nil
		},
	}
	payload, err := json.Marshal(protocol.CommandPayload{
		CommandID: testCommandID, IdempotencyKey: "metrics-failure", Method: "command/exec",
		Params: json.RawMessage(`{"command":"whoami"}`), DeadlineAt: time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope := protocol.Envelope{Type: protocol.TypeCommand, Epoch: epoch, Payload: payload}
	if err := handler.Handle(t.Context(), envelope); !errors.Is(err, metricFailure) {
		t.Fatalf("first denial error = %v, want durable metrics failure", err)
	}
	if len(emitter.values) != 0 {
		t.Fatalf("acknowledgements before metrics durability = %#v", emitter.values)
	}
	if err := handler.Handle(t.Context(), envelope); err != nil {
		t.Fatal(err)
	}
	if metricCalls != 2 || len(emitter.values) != 1 || emitter.values[0].State != "denied" {
		t.Fatalf("replayed denial = metric calls %d, acknowledgements %#v", metricCalls, emitter.values)
	}
}

func TestHandlerRecoversPolicyDenialMetricFromDurableTerminalReplay(t *testing.T) {
	root := t.TempDir()
	commands, err := localstate.OpenCommands(filepath.Join(root, "commands"))
	if err != nil {
		t.Fatal(err)
	}
	epoch := "epoch-0123456789abcdef"
	command := protocol.CommandPayload{
		CommandID: testCommandID, IdempotencyKey: "durable-policy-denial", Method: "command/exec",
		Params: json.RawMessage(`{"command":"whoami"}`), DeadlineAt: time.Now().Add(time.Minute),
	}
	fingerprint := commandFingerprint(command)
	if begin, err := commands.Begin(command.IdempotencyKey, fingerprint, command.CommandID, epoch); err != nil || begin.State != localstate.CommandExecuting {
		t.Fatalf("begin = %#v, %v", begin, err)
	}
	ack := normalizeCommandAck(protocol.CommandAckPayload{
		CommandID: command.CommandID, State: "denied",
		Error: &protocol.ProtocolError{Code: "policy_denied", Message: "blocked by policy", Retryable: false},
	})
	encodedAck, err := json.Marshal(ack)
	if err != nil {
		t.Fatal(err)
	}
	if err := commands.Complete(command.IdempotencyKey, fingerprint, command.CommandID, epoch, encodedAck); err != nil {
		t.Fatal(err)
	}

	exporter, err := metrics.Open(filepath.Join(root, "metrics"), func(time.Time) (metrics.SpoolSnapshot, error) {
		return metrics.SpoolSnapshot{CapacityBytes: 1}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exporter.Close() })
	var metricErr error
	handler := &Handler{
		Epoch: epoch, Router: &fakeRouter{}, Commands: commands, Emitter: &captureEmitter{},
		OnPolicyDenial: func(receiptKey string) error {
			metricErr = exporter.ReconcilePolicyDenials(metrics.PolicyCommand, []string{receiptKey})
			return metricErr
		},
	}
	payload, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	envelope := protocol.Envelope{Type: protocol.TypeCommand, Epoch: epoch, Payload: payload}
	if err := handler.Handle(t.Context(), envelope); err != nil {
		t.Fatal(err)
	}
	if err := handler.Handle(t.Context(), envelope); err != nil {
		t.Fatal(err)
	}
	if metricErr != nil {
		t.Fatal(metricErr)
	}
	if err := exporter.Refresh(); err != nil {
		t.Fatal(err)
	}
	text, err := os.ReadFile(filepath.Join(root, "metrics", metrics.TextfileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(text), `codex_control_connector_policy_denials_total{reason="command"} 1`+"\n") {
		t.Fatalf("recovered policy denial metric was not recorded exactly once:\n%s", text)
	}
}

func TestHandlerReplaysIdempotentResultWithoutSecondCall(t *testing.T) {
	commands, _ := localstate.OpenCommands(filepath.Join(t.TempDir(), "commands"))
	router := &fakeRouter{}
	emitter := &captureEmitter{}
	epoch := "epoch-0123456789abcdef"
	handler := &Handler{Epoch: epoch, Router: router, Commands: commands, Emitter: emitter}
	payload, _ := json.Marshal(protocol.CommandPayload{
		CommandID: testCommandID, IdempotencyKey: "same-key", Method: "model/list",
		Params: json.RawMessage(`{}`), DeadlineAt: time.Now().Add(time.Minute),
	})
	envelope := protocol.Envelope{Type: protocol.TypeCommand, Epoch: epoch, Payload: payload}
	if err := handler.Handle(t.Context(), envelope); err != nil {
		t.Fatal(err)
	}
	if err := handler.Handle(t.Context(), envelope); err != nil {
		t.Fatal(err)
	}
	if router.calls != 1 || len(emitter.values) != 2 || emitter.values[1].State != "completed" {
		t.Fatalf("router calls = %d, acknowledgements = %#v", router.calls, emitter.values)
	}
}

func TestHandlerReplaysStaleEpochTerminalWithoutDispatch(t *testing.T) {
	commands, err := localstate.OpenCommands(filepath.Join(t.TempDir(), "commands"))
	if err != nil {
		t.Fatal(err)
	}
	oldEpoch := "old-epoch-0123456789abcdef"
	newEpoch := "new-epoch-0123456789abcdef"
	command := protocol.CommandPayload{
		CommandID: testCommandID, IdempotencyKey: "stale-terminal", Method: "model/list",
		Params: json.RawMessage(`{}`), DeadlineAt: time.Now().Add(time.Minute),
	}
	fingerprint := commandFingerprint(command)
	if _, err := commands.Begin(command.IdempotencyKey, fingerprint, command.CommandID, oldEpoch); err != nil {
		t.Fatal(err)
	}
	ack := normalizeCommandAck(protocol.CommandAckPayload{
		CommandID: command.CommandID, State: "completed", Result: json.RawMessage(`{"data":[]}`),
	})
	encodedAck, err := json.Marshal(ack)
	if err != nil {
		t.Fatal(err)
	}
	if err := commands.Complete(command.IdempotencyKey, fingerprint, command.CommandID, oldEpoch, encodedAck); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	router := &fakeRouter{}
	emitter := &captureEmitter{}
	handler := &Handler{Epoch: newEpoch, Router: router, Commands: commands, Emitter: emitter}
	if err := handler.Handle(t.Context(), protocol.Envelope{Type: protocol.TypeCommand, Epoch: oldEpoch, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if router.calls != 0 || len(emitter.values) != 1 || emitter.values[0].State != "completed" {
		t.Fatalf("stale terminal replay = router calls %d, acknowledgements %#v", router.calls, emitter.values)
	}
	if emitter.epochs[0] != oldEpoch {
		t.Fatalf("stale terminal replay epoch = %q, want %q", emitter.epochs[0], oldEpoch)
	}
	result, err := json.Marshal(emitter.values[0].Result)
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != `{"data":[]}` {
		t.Fatalf("stale terminal replay = router calls %d, acknowledgements %#v", router.calls, emitter.values)
	}
}

func TestHandlerResolvesStaleEpochExecutingCommandWithOriginalEpoch(t *testing.T) {
	commands, err := localstate.OpenCommands(filepath.Join(t.TempDir(), "commands"))
	if err != nil {
		t.Fatal(err)
	}
	oldEpoch := "old-epoch-0123456789abcdef"
	newEpoch := "new-epoch-0123456789abcdef"
	command := protocol.CommandPayload{
		CommandID: testCommandID, IdempotencyKey: "stale-executing", Method: "thread/start",
		Params: json.RawMessage(`{"cwd":"/work"}`), DeadlineAt: time.Now().Add(time.Minute),
	}
	fingerprint := commandFingerprint(command)
	if _, err := commands.Begin(command.IdempotencyKey, fingerprint, command.CommandID, oldEpoch); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	router := &fakeRouter{}
	emitter := &captureEmitter{}
	handler := &Handler{Epoch: newEpoch, Router: router, Commands: commands, Emitter: emitter}
	if err := handler.Handle(t.Context(), protocol.Envelope{Type: protocol.TypeCommand, Epoch: oldEpoch, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if router.calls != 0 || len(emitter.values) != 1 || emitter.values[0].Error == nil || emitter.values[0].Error.Code != "indeterminate" {
		t.Fatalf("stale executing recovery = router calls %d, acknowledgements %#v", router.calls, emitter.values)
	}
	if emitter.epochs[0] != oldEpoch {
		t.Fatalf("stale executing recovery epoch = %q, want %q", emitter.epochs[0], oldEpoch)
	}
	replay, err := commands.Replay(command.IdempotencyKey, fingerprint, command.CommandID)
	if err != nil {
		t.Fatal(err)
	}
	if replay.State != localstate.CommandTerminal {
		t.Fatalf("durable stale executing resolution = %#v, want terminal", replay)
	}
}

func TestHandlerRechecksDeadlineAfterDurableBeginBeforeDispatch(t *testing.T) {
	commands, err := localstate.OpenCommands(filepath.Join(t.TempDir(), "commands"))
	if err != nil {
		t.Fatal(err)
	}
	router := &fakeRouter{}
	emitter := &captureEmitter{}
	epoch := "epoch-0123456789abcdef"
	start := time.Now().UTC()
	clockCalls := 0
	handler := &Handler{
		Epoch: epoch, Router: router, Commands: commands, Emitter: emitter,
		Now: func() time.Time {
			clockCalls++
			if clockCalls == 1 {
				return start
			}
			return start.Add(time.Minute)
		},
	}
	payload, err := json.Marshal(protocol.CommandPayload{
		CommandID: testCommandID, IdempotencyKey: "deadline-crossed-during-begin", Method: "model/list",
		Params: json.RawMessage(`{}`), DeadlineAt: start.Add(30 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.Handle(t.Context(), protocol.Envelope{Type: protocol.TypeCommand, Epoch: epoch, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if clockCalls < 2 || router.calls != 0 || len(emitter.values) != 1 || emitter.values[0].State != "expired" {
		t.Fatalf("deadline crossing = clock calls %d, router calls %d, acknowledgements %#v", clockCalls, router.calls, emitter.values)
	}
}

func TestHandlerDefaultClockSupportsConcurrentCalls(t *testing.T) {
	handler := &Handler{Emitter: failingEmitter{}}
	var workers sync.WaitGroup
	for range 32 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := handler.Handle(t.Context(), protocol.Envelope{Type: protocol.TypeHelloAck}); err != nil {
				t.Errorf("concurrent handler call: %v", err)
			}
		}()
	}
	workers.Wait()
}

func TestHandlerRejectsIdempotencyKeyReuseForDifferentCommand(t *testing.T) {
	commands, _ := localstate.OpenCommands(filepath.Join(t.TempDir(), "commands"))
	router := &fakeRouter{}
	emitter := &captureEmitter{}
	epoch := "epoch-0123456789abcdef"
	handler := &Handler{Epoch: epoch, Router: router, Commands: commands, Emitter: emitter}
	makeEnvelope := func(method string) protocol.Envelope {
		payload, _ := json.Marshal(protocol.CommandPayload{
			CommandID: testCommandID, IdempotencyKey: "reused", Method: method,
			Params: json.RawMessage(`{}`), DeadlineAt: time.Now().Add(time.Minute),
		})
		return protocol.Envelope{Type: protocol.TypeCommand, Epoch: epoch, Payload: payload}
	}
	if err := handler.Handle(t.Context(), makeEnvelope("model/list")); err != nil {
		t.Fatal(err)
	}
	if err := handler.Handle(t.Context(), makeEnvelope("thread/list")); err != nil {
		t.Fatal(err)
	}
	if router.calls != 1 || len(emitter.values) != 2 || emitter.values[1].State != "denied" || emitter.values[1].Error.Code != "conflict" {
		t.Fatalf("conflicting command reached router or was not denied; calls = %d, acknowledgements = %#v", router.calls, emitter.values)
	}
}

func TestHandlerDoesNotReplayIndeterminateCommandAfterRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "commands")
	commands, err := localstate.OpenCommands(dir)
	if err != nil {
		t.Fatal(err)
	}
	epoch := "epoch-0123456789abcdef"
	command := protocol.CommandPayload{
		CommandID: testCommandID, IdempotencyKey: "crash-key", Method: "thread/start",
		Params: json.RawMessage(`{"cwd":"/work"}`), DeadlineAt: time.Now().Add(time.Minute),
	}
	if begin, err := commands.Begin(command.IdempotencyKey, commandFingerprint(command), command.CommandID, epoch); err != nil || begin.State != localstate.CommandExecuting {
		t.Fatalf("begin = %#v, %v", begin, err)
	}

	reopened, err := localstate.OpenCommands(dir)
	if err != nil {
		t.Fatal(err)
	}
	router := &fakeRouter{}
	emitter := &captureEmitter{}
	handler := &Handler{Epoch: epoch, Router: router, Commands: reopened, Emitter: emitter}
	payload, _ := json.Marshal(command)
	if err := handler.Handle(t.Context(), protocol.Envelope{Type: protocol.TypeCommand, Epoch: epoch, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if router.calls != 0 || len(emitter.values) != 1 || emitter.values[0].State != "failed" || emitter.values[0].Error.Code != "indeterminate" {
		t.Fatalf("indeterminate command was replayed; calls = %d, acknowledgements = %#v", router.calls, emitter.values)
	}
	if err := handler.Handle(t.Context(), protocol.Envelope{Type: protocol.TypeCommand, Epoch: epoch, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if router.calls != 0 || len(emitter.values) != 2 || emitter.values[1].Error.Code != "indeterminate" {
		t.Fatalf("terminal indeterminate result was not replayed safely; calls = %d, acknowledgements = %#v", router.calls, emitter.values)
	}
}

func TestHandlerProcessCrashAfterDurableBeginDoesNotReplayMutation(t *testing.T) {
	assertProcessCrashDoesNotReplayMutation(t, "executing", string(localstate.CommandExecuting), "mutation-applied\n")
}

func TestHandlerProcessCrashAfterDurableTerminalBeforeAckDoesNotReplayMutation(t *testing.T) {
	assertProcessCrashDoesNotReplayMutation(t, "terminal", string(localstate.CommandTerminal), "terminal-durable\n")
}

func TestPolicyDenialMetricRecoversAfterCrashBetweenTerminalCommitAndCounterPersistence(t *testing.T) {
	stateDir := t.TempDir()
	commandDir := filepath.Join(stateDir, "commands")
	command := exec.Command(os.Args[0], "-test.run=^TestCommandJournalCrashHelper$")
	command.Env = append(
		os.Environ(),
		"SUB2API_COMMAND_JOURNAL_CRASH_HELPER=1",
		"SUB2API_COMMAND_JOURNAL_DIR="+commandDir,
		"SUB2API_COMMAND_JOURNAL_STAGE=policy_metric",
	)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		if waited {
			return
		}
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	ready := make(chan error, 1)
	go func() {
		line, readErr := bufio.NewReader(stdout).ReadString('\n')
		if readErr == nil && line != "policy-terminal-durable\n" {
			readErr = errors.New("policy denial crash helper returned an invalid readiness message")
		}
		ready <- readErr
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatalf("wait for durable policy denial: %v (stderr: %s)", err, stderr.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("policy denial crash helper did not report durability (stderr: %s)", stderr.String())
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("policy denial crash helper exited cleanly instead of being killed")
	}
	waited = true

	commands, err := localstate.OpenCommands(commandDir)
	if err != nil {
		t.Fatal(err)
	}
	receiptKeys, err := commands.PolicyDenialReceiptKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(receiptKeys) != 1 {
		t.Fatalf("recovered policy denial receipt keys = %#v", receiptKeys)
	}
	exporter, err := metrics.Open(filepath.Join(stateDir, "metrics"), func(time.Time) (metrics.SpoolSnapshot, error) {
		return metrics.SpoolSnapshot{CapacityBytes: 1}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exporter.Close() })
	if err := exporter.ReconcilePolicyDenials(metrics.PolicyCommand, receiptKeys); err != nil {
		t.Fatal(err)
	}
	if err := exporter.Refresh(); err != nil {
		t.Fatal(err)
	}
	text, err := os.ReadFile(filepath.Join(stateDir, "metrics", metrics.TextfileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(text), `codex_control_connector_policy_denials_total{reason="command"} 1`+"\n") {
		t.Fatalf("crash-recovered policy denial metric was not recorded:\n%s", text)
	}
}

func assertProcessCrashDoesNotReplayMutation(t *testing.T, stage, expectedState, readyLine string) {
	t.Helper()
	stateDir := t.TempDir()
	dir := filepath.Join(stateDir, "commands")
	markerPath := filepath.Join(stateDir, "mutation-applied")
	command := exec.Command(os.Args[0], "-test.run=^TestCommandJournalCrashHelper$")
	command.Env = append(
		os.Environ(),
		"SUB2API_COMMAND_JOURNAL_CRASH_HELPER=1",
		"SUB2API_COMMAND_JOURNAL_DIR="+dir,
		"SUB2API_COMMAND_JOURNAL_MARKER="+markerPath,
		"SUB2API_COMMAND_JOURNAL_STAGE="+stage,
	)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		if waited {
			return
		}
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	ready := make(chan error, 1)
	go func() {
		line, readErr := bufio.NewReader(stdout).ReadString('\n')
		if readErr == nil && line != readyLine {
			readErr = errors.New("command journal helper returned an invalid readiness message")
		}
		ready <- readErr
	}()
	select {
	case err := <-ready:
		if err != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			waited = true
			t.Fatalf("wait for durable journal: %v (stderr: %s)", err, stderr.String())
		}
	case <-time.After(3 * time.Second):
		_ = command.Process.Kill()
		_ = command.Wait()
		waited = true
		t.Fatalf("command journal helper did not report durability (stderr: %s)", stderr.String())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("durable command journal entries = %d, want 1", len(entries))
	}
	var diskRecord map[string]any
	data, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &diskRecord); err != nil {
		t.Fatal(err)
	}
	if diskRecord["state"] != expectedState {
		t.Fatalf("journal state before process kill = %#v", diskRecord["state"])
	}
	if expectedState == string(localstate.CommandTerminal) {
		ack, ok := diskRecord["ack"].(map[string]any)
		if !ok || ack["state"] != "completed" {
			t.Fatalf("durable terminal acknowledgement = %#v", diskRecord["ack"])
		}
	}
	marker, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(marker) != "applied\n" {
		t.Fatalf("mutation marker before process kill = %q", marker)
	}

	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("command journal helper exited cleanly instead of being killed")
	}
	waited = true

	reopened, err := localstate.OpenCommands(dir)
	if err != nil {
		t.Fatal(err)
	}
	commandPayload := protocol.CommandPayload{
		CommandID: testCommandID, IdempotencyKey: "process-crash-key", Method: "thread/start",
		Params: json.RawMessage(`{"cwd":"/work"}`), DeadlineAt: time.Now().Add(time.Minute),
	}
	payload, err := json.Marshal(commandPayload)
	if err != nil {
		t.Fatal(err)
	}
	newEpoch := "new-epoch-0123456789abcdef"
	router := &fakeRouter{}
	emitter := &captureEmitter{}
	handler := &Handler{Epoch: newEpoch, Router: router, Commands: reopened, Emitter: emitter}
	envelope := protocol.Envelope{Type: protocol.TypeCommand, Epoch: "old-epoch-0123456789abcdef", Payload: payload}
	if err := handler.Handle(t.Context(), envelope); err != nil {
		t.Fatal(err)
	}
	wantState := "failed"
	wantCode := "indeterminate"
	if expectedState == string(localstate.CommandTerminal) {
		wantState = "completed"
		wantCode = ""
	}
	assertRecovered := func(label string, acknowledgement protocol.CommandAckPayload) {
		t.Helper()
		gotCode := ""
		if acknowledgement.Error != nil {
			gotCode = acknowledgement.Error.Code
			if acknowledgement.Error.Retryable {
				t.Fatalf("%s acknowledgement was retryable: %#v", label, acknowledgement)
			}
		}
		if acknowledgement.State != wantState || gotCode != wantCode {
			t.Fatalf("%s acknowledgement = %#v, want state %q code %q", label, acknowledgement, wantState, wantCode)
		}
	}
	if router.calls != 0 || len(emitter.values) != 1 {
		t.Fatalf("post-crash handling = calls %d, acknowledgements %#v", router.calls, emitter.values)
	}
	assertRecovered("post-crash", emitter.values[0])
	if err := handler.Handle(t.Context(), envelope); err != nil {
		t.Fatal(err)
	}
	if router.calls != 0 || len(emitter.values) != 2 {
		t.Fatalf("post-crash terminal replay = calls %d, acknowledgements %#v", router.calls, emitter.values)
	}
	assertRecovered("post-crash terminal replay", emitter.values[1])
	marker, err = os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(marker) != "applied\n" {
		t.Fatalf("mutation was replayed after process crash: %q", marker)
	}
}

func TestCommandJournalCrashHelper(t *testing.T) {
	if os.Getenv("SUB2API_COMMAND_JOURNAL_CRASH_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	commands, err := localstate.OpenCommands(os.Getenv("SUB2API_COMMAND_JOURNAL_DIR"))
	if err != nil {
		t.Fatal(err)
	}
	command := protocol.CommandPayload{
		CommandID: testCommandID, IdempotencyKey: "process-crash-key", Method: "thread/start",
		Params: json.RawMessage(`{"cwd":"/work"}`), DeadlineAt: time.Now().Add(time.Minute),
	}
	stage := os.Getenv("SUB2API_COMMAND_JOURNAL_STAGE")
	if stage == "policy_metric" {
		command.IdempotencyKey = "policy-metric-crash-key"
		command.Method = "command/exec"
		command.Params = json.RawMessage(`{"command":"whoami"}`)
	}
	epoch := "old-epoch-0123456789abcdef"
	payload, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	handler := &Handler{
		Epoch: epoch, Commands: commands,
		Router: crashAfterMutationRouter{markerPath: os.Getenv("SUB2API_COMMAND_JOURNAL_MARKER")},
	}
	switch stage {
	case "executing":
		handler.Router = crashAfterMutationRouter{
			markerPath: os.Getenv("SUB2API_COMMAND_JOURNAL_MARKER"), block: true,
		}
		handler.Emitter = &captureEmitter{}
	case "terminal":
		handler.Emitter = crashBeforeAckEmitter{}
	case "policy_metric":
		handler.Router = &fakeRouter{}
		handler.Emitter = &captureEmitter{}
		handler.OnPolicyDenial = func(string) error {
			if _, err := os.Stdout.WriteString("policy-terminal-durable\n"); err != nil {
				return err
			}
			select {}
		}
	default:
		t.Fatal("command journal helper stage is invalid")
	}
	if err := handler.Handle(t.Context(), protocol.Envelope{Type: protocol.TypeCommand, Epoch: epoch, Payload: payload}); err != nil {
		t.Fatal(err)
	}
}

func TestHandlerReplaysDurableTerminalResultAfterEmitterFailure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "commands")
	commands, err := localstate.OpenCommands(dir)
	if err != nil {
		t.Fatal(err)
	}
	epoch := "epoch-0123456789abcdef"
	command := protocol.CommandPayload{
		CommandID: testCommandID, IdempotencyKey: "terminal-before-emit", Method: "model/list",
		Params: json.RawMessage(`{}`), DeadlineAt: time.Now().Add(time.Minute),
	}
	payload, _ := json.Marshal(command)
	envelope := protocol.Envelope{Type: protocol.TypeCommand, Epoch: epoch, Payload: payload}
	router := &fakeRouter{}
	emitFailure := errors.New("spool unavailable")
	handler := &Handler{Epoch: epoch, Router: router, Commands: commands, Emitter: failingEmitter{err: emitFailure}}
	if err := handler.Handle(t.Context(), envelope); !errors.Is(err, emitFailure) {
		t.Fatalf("first handle error = %v", err)
	}
	if router.calls != 1 {
		t.Fatalf("router calls after first attempt = %d", router.calls)
	}

	reopened, err := localstate.OpenCommands(dir)
	if err != nil {
		t.Fatal(err)
	}
	replayRouter := &fakeRouter{}
	emitter := &captureEmitter{}
	handler = &Handler{Epoch: epoch, Router: replayRouter, Commands: reopened, Emitter: emitter}
	if err := handler.Handle(t.Context(), envelope); err != nil {
		t.Fatal(err)
	}
	if replayRouter.calls != 0 || len(emitter.values) != 1 || emitter.values[0].State != "completed" {
		t.Fatalf("terminal result was not replayed; calls=%d acknowledgements=%#v", replayRouter.calls, emitter.values)
	}
}

func TestHandlerNeverMarksDispatchedMutationAsRetryable(t *testing.T) {
	commands, _ := localstate.OpenCommands(filepath.Join(t.TempDir(), "commands"))
	router := &errorRouter{err: errors.New("app-server stopped")}
	emitter := &captureEmitter{}
	epoch := "epoch-0123456789abcdef"
	payload, _ := json.Marshal(protocol.CommandPayload{
		CommandID: testCommandID, IdempotencyKey: "mutation-error", Method: "turn/start",
		Params:     json.RawMessage(`{"threadId":"thread","input":[{"type":"text","text":"hello"}]}`),
		DeadlineAt: time.Now().Add(time.Minute),
	})
	handler := &Handler{Epoch: epoch, Router: router, Commands: commands, Emitter: emitter}
	if err := handler.Handle(t.Context(), protocol.Envelope{Type: protocol.TypeCommand, Epoch: epoch, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if router.calls != 1 || len(emitter.values) != 1 || emitter.values[0].Error == nil ||
		emitter.values[0].Error.Code != "indeterminate" || emitter.values[0].Error.Retryable {
		t.Fatalf("mutation failure = calls %d, acknowledgements %#v", router.calls, emitter.values)
	}
}

func TestPolicyDenialDoesNotExposeLocalPathInWireAcknowledgement(t *testing.T) {
	const pathSentinel = "/private/workspace/PATH-SENTINEL"
	commands, err := localstate.OpenCommands(filepath.Join(t.TempDir(), "commands"))
	if err != nil {
		t.Fatal(err)
	}
	emitter := &captureEmitter{}
	epoch := "epoch-0123456789abcdef"
	handler := &Handler{
		Epoch: epoch, Commands: commands, Emitter: emitter,
		Router: &errorRouter{err: policy.Denied("cwd " + pathSentinel + " is outside configured roots")},
	}
	payload, err := json.Marshal(protocol.CommandPayload{
		CommandID: testCommandID, IdempotencyKey: "path-redaction", Method: "model/list",
		Params: json.RawMessage(`{}`), DeadlineAt: time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.Handle(t.Context(), protocol.Envelope{Type: protocol.TypeCommand, Epoch: epoch, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if len(emitter.values) != 1 || emitter.values[0].Error == nil || emitter.values[0].Error.Code != "policy_denied" {
		t.Fatalf("acknowledgements = %#v", emitter.values)
	}
	if strings.Contains(emitter.values[0].Error.Message, pathSentinel) {
		t.Fatalf("wire acknowledgement leaked local path: %#v", emitter.values[0])
	}
}

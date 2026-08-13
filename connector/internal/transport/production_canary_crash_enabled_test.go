//go:build productioncanary && (darwin || linux)

package transport

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/protocol"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/spool"
)

func TestProductionCanaryCrashHookPreservesExactTerminalAck(t *testing.T) {
	dir := t.TempDir()
	command := exec.Command(os.Args[0], "-test.run=^TestProductionCanaryCrashHookHelper$")
	command.Env = append(
		os.Environ(),
		"SUB2API_PRODUCTION_CANARY_CRASH_HELPER=1",
		"SUB2API_PRODUCTION_CANARY_CRASH_DIR="+dir,
	)
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
	marker := filepath.Join(dir, "production-canary-crash-armed.json")
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("production canary crash hook did not arm")
		}
		time.Sleep(10 * time.Millisecond)
	}
	err := command.Wait()
	waited = true
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() != productionCanaryCrashExitCode {
		t.Fatalf("crash helper error = %v", err)
	}

	eventSpool, err := spool.Open(filepath.Join(dir, "spool"))
	if err != nil {
		t.Fatal(err)
	}
	records, err := eventSpool.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Sequence != 1 {
		t.Fatalf("pending records = %#v", records)
	}
	var envelope protocol.Envelope
	if err := decodeStrict(records[0].Data, &envelope); err != nil {
		t.Fatal(err)
	}
	var acknowledgement protocol.CommandAckPayload
	if err := decodeStrict(envelope.Payload, &acknowledgement); err != nil {
		t.Fatal(err)
	}
	if envelope.Type != protocol.TypeCommandAck || envelope.Seq != 1 ||
		acknowledgement.CommandID != testConnectionID || acknowledgement.State != "completed" {
		t.Fatalf("preserved envelope = %#v; acknowledgement = %#v", envelope, acknowledgement)
	}
}

func TestProductionCanaryCommandAckExcludesConcurrentFlush(t *testing.T) {
	productionCanaryCrashArmed.Store(true)
	locked := productionCanaryLockEmit(protocol.TypeCommandAck)
	if !locked {
		t.Fatal("armed command acknowledgement did not acquire the flush barrier")
	}
	flushed := make(chan struct{})
	go func() {
		productionCanaryLockFlush()
		productionCanaryUnlockFlush()
		close(flushed)
	}()
	select {
	case <-flushed:
		t.Fatal("write loop entered while the command acknowledgement barrier was held")
	case <-time.After(25 * time.Millisecond):
	}
	productionCanaryCrashArmed.Store(false)
	productionCanaryUnlockEmit(locked)
	select {
	case <-flushed:
	case <-time.After(time.Second):
		t.Fatal("write loop did not resume after the barrier was released")
	}
}

func TestProductionCanaryCrashHookHelper(t *testing.T) {
	if os.Getenv("SUB2API_PRODUCTION_CANARY_CRASH_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	dir := os.Getenv("SUB2API_PRODUCTION_CANARY_CRASH_DIR")
	eventSpool, err := spool.Open(filepath.Join(dir, "spool"))
	if err != nil {
		t.Fatal(err)
	}
	disable, err := EnableProductionCanaryCrashHook(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer disable()
	if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "production-canary-crash-armed.json")
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("crash hook marker was not written")
		}
		time.Sleep(time.Millisecond)
	}
	if !productionCanaryCrashArmed.Load() {
		t.Fatal("crash marker was visible before the hook was armed")
	}
	client := newTestClient(
		t,
		"wss://control.example/device",
		eventSpool,
		func(context.Context, protocol.Envelope) error { return nil },
	)
	if err := client.Emit(t.Context(), protocol.TypeCommandAck, protocol.CommandAckPayload{
		CommandID: testConnectionID,
		State:     "completed",
		Result:    json.RawMessage(`{"ok":true}`),
	}); err != nil {
		t.Fatal(err)
	}
	t.Fatal("production canary crash hook did not terminate after durable spooling")
}

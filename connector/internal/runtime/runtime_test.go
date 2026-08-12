package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/appserver"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/config"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/localstate"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/metrics"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/pairing"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/protocol"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/transport"
)

type blockingSessionChild struct {
	stop         chan struct{}
	waitReturned chan struct{}
	stopOnce     sync.Once
}

type quiescentSessionChild struct {
	canceled     <-chan struct{}
	closeEntered chan struct{}
	closeRelease chan struct{}
	revokedFirst bool
}

func (child *quiescentSessionChild) Wait() error { return errors.New("child stopped") }

func (child *quiescentSessionChild) Close() {
	select {
	case <-child.canceled:
		child.revokedFirst = true
	default:
	}
	close(child.closeEntered)
	<-child.closeRelease
}

func TestVersionMismatchPublishesPersistentContractFailure(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	binary := filepath.Join(t.TempDir(), "fake-codex")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf 'codex-cli 9.9.9\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	err := Run(t.Context(), Options{Config: config.Config{
		StateDir: stateDir, WorkspaceRoots: []string{t.TempDir()}, SandboxCap: "read-only",
		CodexBinary: binary, CodexVersion: config.DefaultCodexVersion,
	}, Credentials: pairing.Credentials{
		Version: 1, DeviceID: "11111111-1111-4111-8111-111111111111", RefreshCredential: "test",
	}})
	if !errors.Is(err, appserver.ErrVersionMismatch) {
		t.Fatalf("runtime error = %v, want version mismatch", err)
	}
	data, err := os.ReadFile(filepath.Join(stateDir, "connector.prom"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `codex_control_connector_contract_failures_total{kind="version"} 1`+"\n") {
		t.Fatalf("version failure metric was not persisted:\n%s", text)
	}
	timestampPrefix := `codex_control_connector_contract_last_failure_timestamp_seconds{kind="version"} `
	timestampFound := false
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, timestampPrefix) {
			timestampFound = true
			if strings.HasSuffix(line, " 0") {
				t.Fatalf("version failure timestamp was not persisted:\n%s", text)
			}
		}
	}
	if !timestampFound {
		t.Fatalf("version failure timestamp metric is absent:\n%s", text)
	}
	if !strings.Contains(text, "codex_control_connector_up 0\n") {
		t.Fatal("terminal version mismatch did not publish graceful process down")
	}
}

func TestContractFailureCancelsEpochBeforeBlockingMetricsWrite(t *testing.T) {
	epochCanceled := make(chan struct{})
	metricsEntered := make(chan struct{})
	releaseMetrics := make(chan struct{})
	done := make(chan struct{})
	go func() {
		recordAfterEpochCancellation(
			func() { close(epochCanceled) },
			func() {
				close(metricsEntered)
				<-releaseMetrics
			},
		)
		close(done)
	}()
	select {
	case <-metricsEntered:
	case <-time.After(time.Second):
		t.Fatal("blocking metrics write was not entered")
	}
	select {
	case <-epochCanceled:
	default:
		t.Fatal("metrics write began before app-server epoch cancellation")
	}
	close(releaseMetrics)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("contract failure callback did not finish")
	}
}

func TestRuntimeReconcilesDurablePolicyDenialExactlyOnce(t *testing.T) {
	root := t.TempDir()
	commands, err := localstate.OpenCommands(filepath.Join(root, "commands"))
	if err != nil {
		t.Fatal(err)
	}
	epoch := "epoch-0123456789abcdef"
	commandID := "33333333-3333-4333-8333-333333333333"
	if _, err := commands.Begin("policy-key", "fingerprint", commandID, epoch); err != nil {
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
	if err := commands.Complete("policy-key", "fingerprint", commandID, epoch, ack); err != nil {
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
	reconciler := &policyDenialReconciler{commands: commands, exporter: exporter}
	receiptKey := localstate.PolicyDenialReceiptKey(commandID)
	if err := reconciler.Reconcile(receiptKey); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Reconcile(""); err != nil {
		t.Fatal(err)
	}
	if err := exporter.Refresh(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "metrics", metrics.TextfileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `codex_control_connector_policy_denials_total{reason="command"} 1`+"\n") {
		t.Fatalf("runtime policy denial reconciliation was not idempotent:\n%s", data)
	}
}

func newBlockingSessionChild() *blockingSessionChild {
	return &blockingSessionChild{stop: make(chan struct{}), waitReturned: make(chan struct{})}
}

func (child *blockingSessionChild) Wait() error {
	<-child.stop
	close(child.waitReturned)
	return errors.New("child stopped")
}

func (child *blockingSessionChild) Close() {
	child.stopOnce.Do(func() { close(child.stop) })
}

func TestTransportExitCancelsSessionAndReapsChild(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	child := newBlockingSessionChild()
	transportDone := make(chan error, 1)
	transportDone <- errors.New("fatal transport failure with untrusted details")

	result := make(chan sessionExit, 1)
	go func() { result <- waitForSessionExit(child, cancel, transportDone) }()

	select {
	case exit := <-result:
		if exit.source != transportExit || exit.err == nil {
			t.Fatalf("session exit = %#v", exit)
		}
	case <-time.After(time.Second):
		t.Fatal("transport failure left the session waiting on the app-server child")
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("transport failure did not cancel the session")
	}
	select {
	case <-child.waitReturned:
	default:
		t.Fatal("transport failure did not reap the app-server child")
	}
}

func TestChildExitCancelsAndJoinsTransport(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	child := newBlockingSessionChild()
	transportDone := make(chan error, 1)
	go func() {
		<-ctx.Done()
		transportDone <- ctx.Err()
	}()
	child.Close()

	if exit := waitForSessionExit(child, cancel, transportDone); exit.source != childExit {
		t.Fatalf("session exit = %#v", exit)
	}
}

func TestChildExitRevokesEpochBeforeQuiescentCloseReturns(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	child := &quiescentSessionChild{
		canceled: ctx.Done(), closeEntered: make(chan struct{}), closeRelease: make(chan struct{}),
	}
	transportDone := make(chan error, 1)
	go func() {
		<-ctx.Done()
		transportDone <- ctx.Err()
	}()
	result := make(chan sessionExit, 1)
	go func() { result <- waitForSessionExit(child, cancel, transportDone) }()
	select {
	case <-child.closeEntered:
	case <-time.After(time.Second):
		t.Fatal("child exit did not enter the quiescent close barrier")
	}
	if !child.revokedFirst {
		t.Fatal("child close started before the session epoch was revoked")
	}
	select {
	case <-result:
		t.Fatal("session exit returned before the child quiescence barrier")
	default:
	}
	close(child.closeRelease)
	select {
	case exit := <-result:
		if exit.source != childExit {
			t.Fatalf("session exit = %#v, want child exit", exit)
		}
	case <-time.After(time.Second):
		t.Fatal("session exit did not return after child quiescence")
	}
}

func TestConcurrentChildAndFatalTransportExitRemainsTerminal(t *testing.T) {
	for range 100 {
		ctx, cancel := context.WithCancel(t.Context())
		child := newBlockingSessionChild()
		child.Close()
		fatalErr := errors.New("fatal transport invariant")
		transportDone := make(chan error, 1)
		transportDone <- fatalErr

		exit := waitForSessionExit(child, cancel, transportDone)
		if exit.source != transportExit || !errors.Is(exit.err, fatalErr) {
			t.Fatalf("concurrent session exit = %#v", exit)
		}
		if ctx.Err() == nil {
			t.Fatal("concurrent session exit was not canceled")
		}
	}
}

func TestTransportFailuresAreTerminalForRuntime(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "network reconnect circuit", err: transport.ErrReconnectCircuit},
		{name: "fatal handler", err: errors.New("untrusted handler failure")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reason, err := classifySessionExit(sessionExit{source: transportExit, err: test.err}, nil)
			if reason != "" || !errors.Is(err, errDeviceTransportTerminated) {
				t.Fatalf("classification = (%q, %v)", reason, err)
			}
			if strings.Contains(err.Error(), test.err.Error()) {
				t.Fatal("terminal runtime error exposed dynamic transport details")
			}
		})
	}
}

func TestNotificationFailureStillUsesBoundedChildRestartPolicy(t *testing.T) {
	reason, err := classifySessionExit(
		sessionExit{source: transportExit, err: context.Canceled},
		errors.New("notification projection failed"),
	)
	if err != nil || reason != "notification_failure" {
		t.Fatalf("classification = (%q, %v)", reason, err)
	}
}

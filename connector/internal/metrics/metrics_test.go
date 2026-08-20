package metrics

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/securefile"
)

const metricsCrashHelperEnvironment = "SUB2API_CONNECTOR_METRICS_CRASH_HELPER"

const validCounterStateJSON = `{"version":3,"reconnects":[0,0,0,0],"app_server_restarts":[0,0,0],"contract_failures":[0,0],"contract_failure_timestamps":[0,0],"policy_denials":[0],"policy_denial_receipts":[]}`

// privateStateDir returns a state directory that securefile created, so it
// carries the protected access control list the connector requires. A directory
// that already exists - t.TempDir() included - inherits foreign access control
// entries from the user profile on Windows.
func privateStateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	if err := securefile.EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

// writePrivateStateFile plants a state file the way the connector creates one,
// so a test exercises rejection of the document rather than rejection of its
// access control list.
func writePrivateStateFile(t *testing.T, path, body string) {
	t.Helper()
	file, err := securefile.CreatePrivateFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(body); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestExporterWritesPrivateBoundedTextfileAndPersistsCounters(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state-TOKEN-SENTINEL")
	fixedNow := time.Unix(1_900_000_000, 0).UTC()
	exporter, err := Open(stateDir, func(now time.Time) (SpoolSnapshot, error) {
		if !now.Equal(fixedNow) {
			t.Fatalf("snapshot time = %s, want %s", now, fixedNow)
		}
		return SpoolSnapshot{
			Events: 2, Bytes: 321, CapacityBytes: 1024,
			OldestUnacknowledgedAge: 12*time.Second + 250*time.Millisecond,
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	exporter.now = func() time.Time { return fixedNow }
	if err := exporter.Start(); err != nil {
		t.Fatal(err)
	}
	for _, record := range []func() error{
		func() error { return exporter.RecordReconnect(ReconnectDial) },
		func() error { return exporter.RecordAppServerRestart(AppServerChildExit) },
		func() error { return exporter.RecordContractFailure(ContractSchema) },
		func() error {
			return exporter.ReconcilePolicyDenials(PolicyCommand, []string{strings.Repeat("a", receiptKeyHexLength)})
		},
	} {
		if err := record(); err != nil {
			t.Fatal(err)
		}
	}
	if err := exporter.RecordReconnect(ReconnectReason(255)); err == nil {
		t.Fatal("out-of-range reconnect reason was accepted")
	}
	if err := exporter.Refresh(); err != nil {
		t.Fatal(err)
	}

	textPath := filepath.Join(stateDir, TextfileName)
	assertPrivateStateDirectory(t, stateDir)
	assertPrivateRegularFile(t, textPath)
	assertPrivateRegularFile(t, filepath.Join(stateDir, stateName))
	data, err := os.ReadFile(textPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, expected := range []string{
		"codex_control_connector_up 1",
		"codex_control_connector_last_update_timestamp_seconds 1900000000",
		`codex_control_connector_reconnects_total{reason="dial"} 1`,
		"codex_control_connector_spool_bytes 321",
		"codex_control_connector_spool_capacity_bytes 1024",
		"codex_control_connector_spool_events 2",
		"codex_control_connector_spool_oldest_unacknowledged_age_seconds 12.250",
		`codex_control_connector_app_server_restarts_total{reason="child_exit"} 1`,
		`codex_control_connector_contract_failures_total{kind="schema"} 1`,
		`codex_control_connector_contract_last_failure_timestamp_seconds{kind="schema"} 1900000000`,
		`codex_control_connector_policy_denials_total{reason="command"} 1`,
	} {
		if !strings.Contains(text, expected+"\n") {
			t.Errorf("textfile lacks %q:\n%s", expected, text)
		}
	}
	if strings.Contains(text, "TOKEN-SENTINEL") || strings.Contains(text, stateDir) {
		t.Fatal("metrics textfile leaked its sensitive state path")
	}
	stateData, err := os.ReadFile(filepath.Join(stateDir, stateName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stateData), "TOKEN-SENTINEL") || strings.Contains(string(stateData), stateDir) {
		t.Fatal("metrics counter state leaked its sensitive state path")
	}
	assertFixedLabels(t, text, "codex_control_connector_reconnects_total", "reason", reconnectLabels)
	assertFixedLabels(t, text, "codex_control_connector_app_server_restarts_total", "reason", restartLabels)
	assertFixedLabels(t, text, "codex_control_connector_contract_failures_total", "kind", contractLabels)
	assertFixedLabels(t, text, "codex_control_connector_contract_last_failure_timestamp_seconds", "kind", contractLabels)
	assertFixedLabels(t, text, "codex_control_connector_policy_denials_total", "reason", policyLabels)

	if err := exporter.Close(); err != nil {
		t.Fatal(err)
	}
	closed, err := os.ReadFile(textPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(closed), "codex_control_connector_up 0\n") {
		t.Fatal("graceful close did not publish process down")
	}

	reopened, err := Open(stateDir, func(time.Time) (SpoolSnapshot, error) {
		return SpoolSnapshot{CapacityBytes: 1024}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	reopened.now = func() time.Time { return fixedNow.Add(time.Minute) }
	if err := reopened.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	persisted, err := os.ReadFile(textPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`codex_control_connector_reconnects_total{reason="dial"} 1`,
		`codex_control_connector_app_server_restarts_total{reason="child_exit"} 1`,
		`codex_control_connector_contract_failures_total{kind="schema"} 1`,
		`codex_control_connector_contract_last_failure_timestamp_seconds{kind="schema"} 1900000000`,
		`codex_control_connector_policy_denials_total{reason="command"} 1`,
	} {
		if !strings.Contains(string(persisted), expected+"\n") {
			t.Errorf("reopened textfile lacks %q", expected)
		}
	}
}

func TestTextfileReplacementIsAtomicUnderConcurrentReads(t *testing.T) {
	stateDir := privateStateDir(t)
	exporter, err := Open(stateDir, func(time.Time) (SpoolSnapshot, error) {
		return SpoolSnapshot{CapacityBytes: 64 << 20}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exporter.Close() })

	path := filepath.Join(stateDir, TextfileName)
	var wait sync.WaitGroup
	errChannel := make(chan error, 1)
	done := make(chan struct{})
	wait.Add(1)
	go func() {
		defer wait.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			data, readErr := readReplaceable(path)
			if readErr != nil {
				select {
				case errChannel <- readErr:
				default:
				}
				return
			}
			if !completeTextfile(data) {
				select {
				case errChannel <- errors.New("reader observed a partial metrics textfile"):
				default:
				}
				return
			}
			stateData, readErr := readReplaceable(filepath.Join(stateDir, stateName))
			if readErr != nil {
				select {
				case errChannel <- readErr:
				default:
				}
				return
			}
			var state counterState
			if json.Unmarshal(stateData, &state) != nil || validateState(state) != nil {
				select {
				case errChannel <- errors.New("reader observed a partial metrics counter state"):
				default:
				}
				return
			}
		}
	}()
	for range 100 {
		if err := exporter.RecordReconnect(ReconnectConnectionIO); err != nil {
			close(done)
			wait.Wait()
			t.Fatal(err)
		}
		if err := exporter.Refresh(); err != nil {
			close(done)
			wait.Wait()
			t.Fatal(err)
		}
	}
	close(done)
	wait.Wait()
	select {
	case err := <-errChannel:
		t.Fatal(err)
	default:
	}
	matches, err := filepath.Glob(filepath.Join(stateDir, ".connector-metrics-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary metrics files remain: %v", matches)
	}
}

func TestRefreshLoopPublishesIndependentProcessHeartbeat(t *testing.T) {
	var snapshots atomic.Int32
	var clock atomic.Int64
	clock.Store(2_000_000_000)
	exporter, err := Open(privateStateDir(t), func(time.Time) (SpoolSnapshot, error) {
		snapshots.Add(1)
		return SpoolSnapshot{CapacityBytes: 64 << 20}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	exporter.now = func() time.Time { return time.Unix(clock.Add(1), 0) }
	if err := exporter.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exporter.Close() })
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- exporter.RunRefreshLoop(ctx, 5*time.Millisecond, 2*time.Millisecond, nil) }()
	deadline := time.After(time.Second)
	for snapshots.Load() < 3 {
		select {
		case <-deadline:
			t.Fatal("independent metrics heartbeat did not refresh the textfile")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("refresh loop result = %v, want cancellation", err)
	}
	data, err := os.ReadFile(exporter.textPath)
	if err != nil {
		t.Fatal(err)
	}
	if value := metricScalar(t, string(data), "codex_control_connector_last_update_timestamp_seconds"); value < 2_000_000_003 {
		t.Fatalf("last-update timestamp = %d, want at least three independent writes", value)
	}
}

func TestOpenRemovesOrphanedMetricsTemporaryFiles(t *testing.T) {
	stateDir := privateStateDir(t)
	stale := []string{
		filepath.Join(stateDir, temporaryPrefix+"crash-one"+temporarySuffix),
		filepath.Join(stateDir, temporaryPrefix+"crash-two"+temporarySuffix),
	}
	for _, path := range stale {
		writePrivateStateFile(t, path, "partial metrics")
	}
	if _, err := Open(stateDir, func(time.Time) (SpoolSnapshot, error) {
		return SpoolSnapshot{CapacityBytes: 1}, nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, path := range stale {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale metrics temporary file still exists: %s (%v)", path, err)
		}
	}
}

func TestRefreshLoopCoalescesHighFrequencyNotifications(t *testing.T) {
	var snapshots atomic.Int32
	exporter, err := Open(privateStateDir(t), func(time.Time) (SpoolSnapshot, error) {
		snapshots.Add(1)
		return SpoolSnapshot{CapacityBytes: 64 << 20}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exporter.Close() })

	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- exporter.RunRefreshLoop(ctx, time.Hour, 20*time.Millisecond, nil) }()
	for range 1_000 {
		exporter.Notify()
	}
	deadline := time.After(time.Second)
	for snapshots.Load() < 2 {
		select {
		case <-deadline:
			t.Fatal("coalesced notification did not refresh the textfile")
		case <-time.After(time.Millisecond):
		}
	}
	time.Sleep(60 * time.Millisecond)
	if got := snapshots.Load(); got != 2 {
		t.Fatalf("snapshot calls = %d, want start plus one coalesced refresh", got)
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("refresh loop result = %v, want cancellation", err)
	}
}

func TestCounterRecordIsDurableBeforeTextfileRefresh(t *testing.T) {
	stateDir := privateStateDir(t)
	exporter, err := Open(stateDir, func(time.Time) (SpoolSnapshot, error) {
		return SpoolSnapshot{CapacityBytes: 64 << 20}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exporter.Close() })
	if err := exporter.RecordReconnect(ReconnectHandshake); err != nil {
		t.Fatal(err)
	}

	var persisted counterState
	if err := securefile.ReadJSON(filepath.Join(stateDir, stateName), &persisted); err != nil {
		t.Fatal(err)
	}
	if got := persisted.Reconnects[int(ReconnectHandshake)-1]; got != 1 {
		t.Fatalf("durable handshake reconnects = %d, want 1", got)
	}
	text, err := os.ReadFile(filepath.Join(stateDir, TextfileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(text), `codex_control_connector_reconnects_total{reason="handshake"} 0`+"\n") {
		t.Fatal("counter textfile was synchronously rewritten instead of using the refresh loop")
	}
}

func TestOpenRejectsOversizedCounterStateBeforeDecode(t *testing.T) {
	stateDir := privateStateDir(t)
	path := filepath.Join(stateDir, stateName)
	file, err := securefile.CreatePrivateFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxCounterStateBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if exporter, err := Open(stateDir, func(time.Time) (SpoolSnapshot, error) {
		return SpoolSnapshot{CapacityBytes: 1}, nil
	}); err == nil || exporter != nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("Open oversized counter state = %#v, %v", exporter, err)
	}
}

func TestPolicyDenialReceiptIsDurableAndIdempotentAcrossRestart(t *testing.T) {
	stateDir := privateStateDir(t)
	fixedNow := time.Unix(2_200_000_000, 0).UTC()
	open := func() *Exporter {
		exporter, err := Open(stateDir, func(time.Time) (SpoolSnapshot, error) {
			return SpoolSnapshot{CapacityBytes: 64 << 20}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		exporter.now = func() time.Time { return fixedNow }
		if err := exporter.Start(); err != nil {
			t.Fatal(err)
		}
		return exporter
	}

	firstKey := strings.Repeat("a", receiptKeyHexLength)
	secondKey := strings.Repeat("b", receiptKeyHexLength)
	exporter := open()
	if err := exporter.ReconcilePolicyDenials(PolicyCommand, []string{firstKey}); err != nil {
		t.Fatal(err)
	}
	if err := exporter.ReconcilePolicyDenials(PolicyCommand, []string{firstKey}); err != nil {
		t.Fatal(err)
	}
	if err := exporter.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := open()
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.ReconcilePolicyDenials(PolicyCommand, []string{firstKey}); err != nil {
		t.Fatal(err)
	}
	if err := reopened.ReconcilePolicyDenials(PolicyCommand, []string{firstKey, secondKey}); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Refresh(); err != nil {
		t.Fatal(err)
	}
	text, err := os.ReadFile(filepath.Join(stateDir, TextfileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(text), `codex_control_connector_policy_denials_total{reason="command"} 2`+"\n") {
		t.Fatalf("policy denial counter was not idempotent across restart:\n%s", text)
	}
	var state counterState
	if err := securefile.ReadJSON(filepath.Join(stateDir, stateName), &state); err != nil {
		t.Fatal(err)
	}
	if len(state.PolicyDenialReceipts) != 2 {
		t.Fatalf("durable policy denial receipts = %d, want 2", len(state.PolicyDenialReceipts))
	}
}

func TestReconcileRetainsOldMatchingReceiptAndPrunesOnlyAbsentReceipts(t *testing.T) {
	stateDir := privateStateDir(t)
	state := newCounterState()
	state.PolicyDenials[int(PolicyCommand)-1] = 2
	firstKey := strings.Repeat("a", receiptKeyHexLength)
	secondKey := strings.Repeat("b", receiptKeyHexLength)
	thirdKey := strings.Repeat("c", receiptKeyHexLength)
	state.PolicyDenialReceipts = []policyDenialReceipt{
		{Key: firstKey, RecordedAt: time.Now().Add(-30 * 24 * time.Hour).Unix()},
		{Key: secondKey, RecordedAt: time.Now().Add(-time.Minute).Unix()},
	}
	if err := securefile.WriteJSON(filepath.Join(stateDir, stateName), state); err != nil {
		t.Fatal(err)
	}
	exporter, err := Open(stateDir, func(time.Time) (SpoolSnapshot, error) {
		return SpoolSnapshot{CapacityBytes: 1}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exporter.Close() })
	if err := exporter.ReconcilePolicyDenials(PolicyCommand, []string{firstKey, thirdKey}); err != nil {
		t.Fatal(err)
	}
	var persisted counterState
	if err := securefile.ReadJSON(filepath.Join(stateDir, stateName), &persisted); err != nil {
		t.Fatal(err)
	}
	if len(persisted.PolicyDenialReceipts) != 2 || persisted.PolicyDenialReceipts[0].Key != firstKey || persisted.PolicyDenialReceipts[1].Key != thirdKey {
		t.Fatalf("persisted policy denial receipts = %#v, want the authoritative journal set", persisted.PolicyDenialReceipts)
	}
	if persisted.PolicyDenials[int(PolicyCommand)-1] != 3 {
		t.Fatalf("policy denial counter = %d, want one new receipt without recounting the old matching receipt", persisted.PolicyDenials[int(PolicyCommand)-1])
	}
}

func TestTextfileReplacementNeverFollowsExistingSymlink(t *testing.T) {
	stateDir := privateStateDir(t)
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("DO-NOT-REPLACE"), 0o600); err != nil {
		t.Fatal(err)
	}
	exporter, err := Open(stateDir, func(time.Time) (SpoolSnapshot, error) {
		return SpoolSnapshot{CapacityBytes: 64 << 20}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(stateDir, TextfileName)); err != nil {
		t.Fatal(err)
	}
	if err := exporter.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exporter.Close() })
	assertPrivateRegularFile(t, filepath.Join(stateDir, TextfileName))
	outsideData, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(outsideData) != "DO-NOT-REPLACE" {
		t.Fatal("metrics replacement followed and modified an existing symlink")
	}
}

func TestCountersSurviveAbruptProcessTermination(t *testing.T) {
	stateDir := privateStateDir(t)
	command := exec.Command(os.Args[0], "-test.run=^TestMetricsCrashHelper$")
	command.Env = append(os.Environ(), metricsCrashHelperEnvironment+"="+stateDir)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	ready := make(chan error, 1)
	go func() {
		line, readErr := bufio.NewReader(stdout).ReadString('\n')
		if readErr == nil && line != "metrics-durable\n" {
			readErr = fmt.Errorf("unexpected helper output %q", line)
		}
		ready <- readErr
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("metrics crash helper did not become ready")
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("metrics crash helper exited cleanly instead of being killed")
	}
	waited = true
	crashSnapshot, err := os.ReadFile(filepath.Join(stateDir, TextfileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(crashSnapshot), "codex_control_connector_up 1\n") {
		t.Fatal("abrupt termination unexpectedly rewrote the last atomic up value")
	}

	exporter, err := Open(stateDir, func(time.Time) (SpoolSnapshot, error) {
		return SpoolSnapshot{CapacityBytes: 64 << 20}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exporter.Close() })
	data, err := os.ReadFile(filepath.Join(stateDir, TextfileName))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`codex_control_connector_reconnects_total{reason="handshake"} 1`,
		`codex_control_connector_contract_failures_total{kind="version"} 1`,
	} {
		if !strings.Contains(string(data), expected+"\n") {
			t.Errorf("post-crash textfile lacks %q", expected)
		}
	}
	timestampPrefix := `codex_control_connector_contract_last_failure_timestamp_seconds{kind="version"} `
	timestampFound := false
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, timestampPrefix) {
			timestampFound = true
			if strings.HasSuffix(line, " 0") {
				t.Fatal("post-crash contract failure timestamp was not durable")
			}
		}
	}
	if !timestampFound {
		t.Fatal("post-crash contract failure timestamp metric is absent")
	}
}

func TestMetricsCrashHelper(t *testing.T) {
	stateDir := os.Getenv(metricsCrashHelperEnvironment)
	if stateDir == "" {
		t.Skip("subprocess helper")
	}
	exporter, err := Open(stateDir, func(time.Time) (SpoolSnapshot, error) {
		return SpoolSnapshot{CapacityBytes: 64 << 20}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.Start(); err != nil {
		t.Fatal(err)
	}
	if err := exporter.RecordReconnect(ReconnectHandshake); err != nil {
		t.Fatal(err)
	}
	if err := exporter.RecordContractFailure(ContractVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stdout.WriteString("metrics-durable\n"); err != nil {
		t.Fatal(err)
	}
	select {}
}

func TestUncertainCounterCommitPoisonsExporterAndStopsFreshness(t *testing.T) {
	stateDir := privateStateDir(t)
	exporter, err := Open(stateDir, func(time.Time) (SpoolSnapshot, error) {
		return SpoolSnapshot{CapacityBytes: 64 << 20}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(2_100_000_000, 0)
	exporter.now = func() time.Time { return clock }
	if err := exporter.Start(); err != nil {
		t.Fatal(err)
	}
	baseline, err := os.ReadFile(exporter.textPath)
	if err != nil {
		t.Fatal(err)
	}
	exporter.writeState = func(state counterState) error {
		if err := securefile.WriteJSON(exporter.statePath, state); err != nil {
			return err
		}
		return errors.New("simulated directory sync uncertainty")
	}
	clock = clock.Add(time.Minute)
	firstErr := exporter.RecordReconnect(ReconnectDial)
	if firstErr == nil {
		t.Fatal("uncertain durable counter commit did not poison the exporter")
	}
	clock = clock.Add(time.Minute)
	if err := exporter.Refresh(); err == nil || err.Error() != firstErr.Error() {
		t.Fatalf("poisoned refresh error = %v, want stable failure %v", err, firstErr)
	}
	after, err := os.ReadFile(exporter.textPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(baseline) {
		t.Fatal("poisoned exporter continued refreshing a healthy-looking timestamp")
	}
	var persisted counterState
	if err := securefile.ReadJSON(exporter.statePath, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Reconnects[int(ReconnectDial)-1] != 1 {
		t.Fatalf("committed state = %#v, want retained dial increment", persisted)
	}
	_ = exporter.Close()
}

func TestOpenRejectsMalformedOrUnexpectedCounterState(t *testing.T) {
	for name, body := range map[string]string{
		"unknown field":          `{"version":3,"reconnects":[0,0,0,0],"app_server_restarts":[0,0,0],"contract_failures":[0,0],"contract_failure_timestamps":[0,0],"policy_denials":[0],"policy_denial_receipts":[],"secret":"TOKEN-SENTINEL"}`,
		"wrong cardinality":      `{"version":3,"reconnects":[0],"app_server_restarts":[0,0,0],"contract_failures":[0,0],"contract_failure_timestamps":[0,0],"policy_denials":[0],"policy_denial_receipts":[]}`,
		"trailing data":          `{"version":3,"reconnects":[0,0,0,0],"app_server_restarts":[0,0,0],"contract_failures":[0,0],"contract_failure_timestamps":[0,0],"policy_denials":[0],"policy_denial_receipts":[]} {}`,
		"negative timestamp":     `{"version":3,"reconnects":[0,0,0,0],"app_server_restarts":[0,0,0],"contract_failures":[0,0],"contract_failure_timestamps":[-1,0],"policy_denials":[0],"policy_denial_receipts":[]}`,
		"inconsistent timestamp": `{"version":3,"reconnects":[0,0,0,0],"app_server_restarts":[0,0,0],"contract_failures":[1,0],"contract_failure_timestamps":[0,0],"policy_denials":[0],"policy_denial_receipts":[]}`,
		"missing receipts":       `{"version":3,"reconnects":[0,0,0,0],"app_server_restarts":[0,0,0],"contract_failures":[0,0],"contract_failure_timestamps":[0,0],"policy_denials":[0]}`,
		"invalid receipt":        `{"version":3,"reconnects":[0,0,0,0],"app_server_restarts":[0,0,0],"contract_failures":[0,0],"contract_failure_timestamps":[0,0],"policy_denials":[1],"policy_denial_receipts":[{"key":"not-a-digest","recorded_at":1}]}`,
		"duplicate receipt":      `{"version":3,"reconnects":[0,0,0,0],"app_server_restarts":[0,0,0],"contract_failures":[0,0],"contract_failure_timestamps":[0,0],"policy_denials":[2],"policy_denial_receipts":[{"key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","recorded_at":1},{"key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","recorded_at":2}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			stateDir := privateStateDir(t)
			writePrivateStateFile(t, filepath.Join(stateDir, stateName), body)
			if _, err := Open(stateDir, func(time.Time) (SpoolSnapshot, error) {
				return SpoolSnapshot{CapacityBytes: 1}, nil
			}); err == nil {
				t.Fatal("invalid counter state was accepted")
			}
		})
	}
}

// The platform halves of unsafe-access rejection live in metrics_unix_test.go
// and metrics_windows_test.go, because owner-only means mode bits on POSIX and
// an access control list on Windows.
func TestOpenRejectsSymlinkedCounterState(t *testing.T) {
	stateDir := privateStateDir(t)
	target := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(target, []byte(validCounterStateJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(stateDir, stateName)); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if _, err := Open(stateDir, func(time.Time) (SpoolSnapshot, error) {
		return SpoolSnapshot{CapacityBytes: 1}, nil
	}); err == nil {
		t.Fatal("symlinked counter state was accepted")
	}
}

func assertFixedLabels(t *testing.T, text, family, labelName string, want []string) {
	t.Helper()
	expression := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(family) + `\{` + regexp.QuoteMeta(labelName) + `="([a-z_]+)"\} [0-9]+$`)
	matches := expression.FindAllStringSubmatch(text, -1)
	got := make([]string, 0, len(matches))
	for _, match := range matches {
		got = append(got, match[1])
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%s labels = %v, want %v", family, got, want)
	}
}

func completeTextfile(data []byte) bool {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return false
	}
	counts := make(map[string]int)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "# TYPE ") {
			fields := strings.Fields(line)
			if len(fields) != 4 || (fields[3] != "counter" && fields[3] != "gauge") {
				return false
			}
			counts[fields[2]]++
		}
		if strings.HasPrefix(line, "codex_control_connector_last_update_timestamp_seconds ") {
			value := strings.TrimPrefix(line, "codex_control_connector_last_update_timestamp_seconds ")
			if _, err := strconv.ParseInt(value, 10, 64); err != nil {
				return false
			}
		}
	}
	return scanner.Err() == nil && len(counts) == 11 && counts["codex_control_connector_up"] == 1
}

func metricScalar(t *testing.T, text, family string) int64 {
	t.Helper()
	prefix := family + " "
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		value, err := strconv.ParseInt(strings.TrimPrefix(line, prefix), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	t.Fatalf("metric %s is absent", family)
	return 0
}

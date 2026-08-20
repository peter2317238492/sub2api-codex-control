package metrics

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/securefile"
)

const (
	TextfileName            = "connector.prom"
	DefaultRefreshInterval  = 15 * time.Second
	DefaultChangeDebounce   = time.Second
	stateName               = "connector-metrics.json"
	stateVersion            = 3
	receiptKeyHexLength     = 64
	maxPolicyDenialReceipts = 4096
	maxCounterStateBytes    = 1 << 20
	temporaryPrefix         = ".connector-metrics-"
	temporarySuffix         = ".tmp"
	temporaryNameAttempts   = 10_000

	// Windows refuses to replace a file while another process holds it open,
	// and a collector reads connector.prom for only microseconds at a time.
	// Waiting out that collision is always better than the alternative, which
	// is poisoning the exporter for the lifetime of the process.
	replaceBudget   = 2 * time.Second
	replaceInterval = 2 * time.Millisecond
)

type ReconnectReason uint8

const (
	ReconnectToken ReconnectReason = iota + 1
	ReconnectDial
	ReconnectHandshake
	ReconnectConnectionIO
)

type AppServerRestartReason uint8

const (
	AppServerStartFailure AppServerRestartReason = iota + 1
	AppServerNotificationFailure
	AppServerChildExit
)

type ContractKind uint8

const (
	ContractVersion ContractKind = iota + 1
	ContractSchema
)

type PolicyDenialReason uint8

const (
	PolicyCommand PolicyDenialReason = iota + 1
)

var (
	reconnectLabels = []string{"token", "dial", "handshake", "connection_io"}
	restartLabels   = []string{"start_failure", "notification_failure", "child_exit"}
	contractLabels  = []string{"version", "schema"}
	policyLabels    = []string{"command"}
)

type SpoolSnapshot struct {
	Events                  int
	Bytes                   int64
	CapacityBytes           int64
	OldestUnacknowledgedAge time.Duration
}

type SnapshotFunc func(time.Time) (SpoolSnapshot, error)

type counterState struct {
	Version                   int                   `json:"version"`
	Reconnects                []uint64              `json:"reconnects"`
	AppServerRestarts         []uint64              `json:"app_server_restarts"`
	ContractFailures          []uint64              `json:"contract_failures"`
	ContractFailureTimestamps []int64               `json:"contract_failure_timestamps"`
	PolicyDenials             []uint64              `json:"policy_denials"`
	PolicyDenialReceipts      []policyDenialReceipt `json:"policy_denial_receipts"`
}

type policyDenialReceipt struct {
	Key        string `json:"key"`
	RecordedAt int64  `json:"recorded_at"`
}

type Exporter struct {
	mu         sync.Mutex
	statePath  string
	textPath   string
	snapshot   SnapshotFunc
	now        func() time.Time
	writeState func(counterState) error
	wake       chan struct{}
	state      counterState
	started    bool
	up         bool
	fatalErr   error
}

func Open(stateDir string, snapshot SnapshotFunc) (*Exporter, error) {
	if snapshot == nil {
		return nil, errors.New("metrics spool snapshot is required")
	}
	if err := securefile.EnsureDir(stateDir); err != nil {
		return nil, err
	}
	if err := cleanupTemporaryFiles(stateDir); err != nil {
		return nil, err
	}
	exporter := &Exporter{
		statePath: filepath.Join(stateDir, stateName),
		textPath:  filepath.Join(stateDir, TextfileName),
		snapshot:  snapshot,
		now:       time.Now,
		wake:      make(chan struct{}, 1),
		state:     newCounterState(),
	}
	exporter.writeState = func(state counterState) error {
		return securefile.WriteJSON(exporter.statePath, state)
	}
	if err := exporter.load(); err != nil {
		return nil, err
	}
	return exporter, nil
}

func (e *Exporter) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.started {
		return errors.New("metrics exporter is already started")
	}
	e.started = true
	e.up = true
	if err := e.flushLocked(); err != nil {
		e.started = false
		e.up = false
		return err
	}
	return nil
}

func (e *Exporter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.started {
		return nil
	}
	e.up = false
	err := e.flushLocked()
	e.started = false
	return err
}

func (e *Exporter) Refresh() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.started {
		return errors.New("metrics exporter is not started")
	}
	return e.flushLocked()
}

func (e *Exporter) Notify() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

func (e *Exporter) RunRefreshLoop(ctx context.Context, interval, debounce time.Duration, onError func(error)) error {
	if interval <= 0 || debounce <= 0 {
		return errors.New("metrics refresh and debounce intervals must be positive")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var changeTimer *time.Timer
	var change <-chan time.Time
	stopChangeTimer := func() {
		if changeTimer == nil {
			return
		}
		if !changeTimer.Stop() {
			select {
			case <-changeTimer.C:
			default:
			}
		}
		changeTimer = nil
		change = nil
	}
	defer stopChangeTimer()
	refresh := func() {
		if err := e.Refresh(); err != nil && onError != nil {
			onError(err)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			stopChangeTimer()
			refresh()
		case <-e.wake:
			if changeTimer == nil {
				changeTimer = time.NewTimer(debounce)
				change = changeTimer.C
			}
		case <-change:
			changeTimer = nil
			change = nil
			refresh()
		}
	}
}

func (e *Exporter) RecordReconnect(reason ReconnectReason) error {
	return e.increment(reconnectCounter, int(reason)-1, len(reconnectLabels), 0)
}

func (e *Exporter) RecordAppServerRestart(reason AppServerRestartReason) error {
	return e.increment(restartCounter, int(reason)-1, len(restartLabels), 0)
}

func (e *Exporter) RecordContractFailure(kind ContractKind) error {
	return e.increment(contractCounter, int(kind)-1, len(contractLabels), e.now().UTC().Unix())
}

// ReconcilePolicyDenials makes the durable command journal authoritative for
// receipt lifetime. Old receipts loaded after a long outage prevent duplicate
// counts until the journal confirms that their command records are gone.
func (e *Exporter) ReconcilePolicyDenials(reason PolicyDenialReason, receiptKeys []string) error {
	index := int(reason) - 1
	if index < 0 || index >= len(policyLabels) || len(receiptKeys) > maxPolicyDenialReceipts {
		return errors.New("metrics policy denial is outside the fixed enumeration")
	}
	now := e.now().UTC()
	if now.Unix() <= 0 {
		return errors.New("metrics policy denial timestamp is invalid")
	}
	unique := make(map[string]struct{}, len(receiptKeys))
	for _, key := range receiptKeys {
		if !validReceiptKey(key) {
			return errors.New("metrics policy denial is outside the fixed enumeration")
		}
		unique[key] = struct{}{}
	}
	if len(unique) != len(receiptKeys) {
		return errors.New("metrics policy denial receipt set contains duplicates")
	}
	sortedKeys := append([]string(nil), receiptKeys...)
	sort.Strings(sortedKeys)

	e.mu.Lock()
	if !e.started {
		e.mu.Unlock()
		return errors.New("metrics exporter is not started")
	}
	if e.fatalErr != nil {
		err := e.fatalErr
		e.mu.Unlock()
		return err
	}
	existing := make(map[string]policyDenialReceipt, len(e.state.PolicyDenialReceipts))
	for _, receipt := range e.state.PolicyDenialReceipts {
		existing[receipt.Key] = receipt
	}
	missing := 0
	for _, key := range sortedKeys {
		if _, found := existing[key]; !found {
			missing++
		}
	}
	if uint64(missing) > math.MaxUint64-e.state.PolicyDenials[index] {
		e.mu.Unlock()
		return errors.New("metrics counter is exhausted")
	}

	next := cloneState(e.state)
	next.PolicyDenials[index] += uint64(missing)
	next.PolicyDenialReceipts = make([]policyDenialReceipt, 0, len(sortedKeys))
	for _, key := range sortedKeys {
		receipt, found := existing[key]
		if !found {
			receipt = policyDenialReceipt{Key: key, RecordedAt: now.Unix()}
		}
		next.PolicyDenialReceipts = append(next.PolicyDenialReceipts, receipt)
	}
	if err := e.persistLocked(next); err != nil {
		e.state = next
		err = e.poisonLocked(fmt.Errorf("persist connector metrics counters: %w", err))
		e.mu.Unlock()
		return err
	}
	e.state = next
	e.mu.Unlock()
	e.Notify()
	return nil
}

type counterKind uint8

const (
	reconnectCounter counterKind = iota + 1
	restartCounter
	contractCounter
)

func (e *Exporter) increment(kind counterKind, index, labelCount int, contractFailureTimestamp int64) error {
	e.mu.Lock()
	if !e.started {
		e.mu.Unlock()
		return errors.New("metrics exporter is not started")
	}
	if e.fatalErr != nil {
		err := e.fatalErr
		e.mu.Unlock()
		return err
	}
	values := counterSlice(&e.state, kind)
	if index < 0 || index >= labelCount || len(values) != labelCount {
		e.mu.Unlock()
		return errors.New("metrics reason is outside the fixed enumeration")
	}
	if values[index] == math.MaxUint64 {
		e.mu.Unlock()
		return errors.New("metrics counter is exhausted")
	}
	next := cloneState(e.state)
	counterSlice(&next, kind)[index]++
	if kind == contractCounter {
		if contractFailureTimestamp <= 0 {
			e.mu.Unlock()
			return errors.New("metrics contract failure timestamp is invalid")
		}
		next.ContractFailureTimestamps[index] = contractFailureTimestamp
	}
	if err := e.persistLocked(next); err != nil {
		e.state = next
		err = e.poisonLocked(fmt.Errorf("persist connector metrics counters: %w", err))
		e.mu.Unlock()
		return err
	}
	e.state = next
	e.mu.Unlock()
	e.Notify()
	return nil
}

// persistLocked commits the counter state before the recording call returns.
//
// securefile installs the new counter state with os.Rename, which Windows
// refuses while any process holds the destination open. The collision is
// transient and the failed attempt leaves the previous state intact, so it is
// waited out rather than treated as an uncertain commit.
func (e *Exporter) persistLocked(state counterState) error {
	deadline := time.Now().Add(replaceBudget)
	for {
		err := e.writeState(state)
		if err == nil || !replaceCollision(err) || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(replaceInterval)
	}
}

func counterSlice(state *counterState, kind counterKind) []uint64 {
	switch kind {
	case reconnectCounter:
		return state.Reconnects
	case restartCounter:
		return state.AppServerRestarts
	case contractCounter:
		return state.ContractFailures
	default:
		return nil
	}
}

func (e *Exporter) load() error {
	var state counterState
	err := securefile.ReadJSONLimit(e.statePath, &state, maxCounterStateBytes)
	if errors.Is(err, os.ErrNotExist) {
		return securefile.WriteJSON(e.statePath, e.state)
	}
	if err != nil {
		return fmt.Errorf("load connector metrics counters: %w", err)
	}
	if err := validateState(state); err != nil {
		return err
	}
	e.state = state
	return nil
}

func (e *Exporter) flushLocked() error {
	if e.fatalErr != nil {
		return e.fatalErr
	}
	now := e.now().UTC()
	spool, err := e.snapshot(now)
	if err != nil {
		return e.poisonLocked(fmt.Errorf("snapshot connector spool metrics: %w", err))
	}
	if spool.Events < 0 || spool.Bytes < 0 || spool.CapacityBytes <= 0 ||
		spool.Bytes > spool.CapacityBytes || spool.OldestUnacknowledgedAge < 0 {
		return e.poisonLocked(errors.New("connector spool metrics are invalid"))
	}
	body := render(e.up, now, spool, e.state)
	if err := writeAtomic(e.textPath, body); err != nil {
		return e.poisonLocked(fmt.Errorf("write connector metrics textfile: %w", err))
	}
	return nil
}

func (e *Exporter) poisonLocked(err error) error {
	if e.fatalErr == nil {
		e.fatalErr = fmt.Errorf("connector metrics exporter is unhealthy: %w", err)
	}
	return e.fatalErr
}

func newCounterState() counterState {
	return counterState{
		Version:                   stateVersion,
		Reconnects:                make([]uint64, len(reconnectLabels)),
		AppServerRestarts:         make([]uint64, len(restartLabels)),
		ContractFailures:          make([]uint64, len(contractLabels)),
		ContractFailureTimestamps: make([]int64, len(contractLabels)),
		PolicyDenials:             make([]uint64, len(policyLabels)),
		PolicyDenialReceipts:      make([]policyDenialReceipt, 0),
	}
}

func cloneState(state counterState) counterState {
	return counterState{
		Version:                   state.Version,
		Reconnects:                append([]uint64(nil), state.Reconnects...),
		AppServerRestarts:         append([]uint64(nil), state.AppServerRestarts...),
		ContractFailures:          append([]uint64(nil), state.ContractFailures...),
		ContractFailureTimestamps: append([]int64(nil), state.ContractFailureTimestamps...),
		PolicyDenials:             append([]uint64(nil), state.PolicyDenials...),
		PolicyDenialReceipts:      append(make([]policyDenialReceipt, 0, len(state.PolicyDenialReceipts)), state.PolicyDenialReceipts...),
	}
}

func validateState(state counterState) error {
	if state.Version != stateVersion ||
		len(state.Reconnects) != len(reconnectLabels) ||
		len(state.AppServerRestarts) != len(restartLabels) ||
		len(state.ContractFailures) != len(contractLabels) ||
		len(state.ContractFailureTimestamps) != len(contractLabels) ||
		len(state.PolicyDenials) != len(policyLabels) || state.PolicyDenialReceipts == nil ||
		len(state.PolicyDenialReceipts) > maxPolicyDenialReceipts {
		return errors.New("connector metrics counter state has an unsupported shape")
	}
	for index, timestamp := range state.ContractFailureTimestamps {
		if timestamp < 0 || (state.ContractFailures[index] == 0) != (timestamp == 0) {
			return errors.New("connector metrics counter state has an invalid timestamp")
		}
	}
	seenReceipts := make(map[string]struct{}, len(state.PolicyDenialReceipts))
	for _, receipt := range state.PolicyDenialReceipts {
		if !validReceiptKey(receipt.Key) || receipt.RecordedAt <= 0 {
			return errors.New("connector metrics counter state has an invalid policy denial receipt")
		}
		if _, exists := seenReceipts[receipt.Key]; exists {
			return errors.New("connector metrics counter state has a duplicate policy denial receipt")
		}
		seenReceipts[receipt.Key] = struct{}{}
	}
	if uint64(len(state.PolicyDenialReceipts)) > state.PolicyDenials[int(PolicyCommand)-1] {
		return errors.New("connector metrics counter state has inconsistent policy denial receipts")
	}
	return nil
}

func validReceiptKey(key string) bool {
	if len(key) != receiptKeyHexLength || key != strings.ToLower(key) {
		return false
	}
	_, err := hex.DecodeString(key)
	return err == nil
}

func render(up bool, now time.Time, spool SpoolSnapshot, state counterState) []byte {
	var output bytes.Buffer
	writeGauge(&output, "codex_control_connector_up", "Whether the Connector process is running.", boolValue(up))
	writeGauge(&output, "codex_control_connector_last_update_timestamp_seconds", "Unix timestamp of the latest Connector textfile update.", now.Unix())
	writeCounterFamily(&output, "codex_control_connector_reconnects_total", "Connector reconnect attempts by fixed reason.", "reason", reconnectLabels, state.Reconnects)
	writeGauge(&output, "codex_control_connector_spool_bytes", "Bytes held in the durable outbound Connector spool.", spool.Bytes)
	writeGauge(&output, "codex_control_connector_spool_capacity_bytes", "Configured byte capacity of the durable outbound Connector spool.", spool.CapacityBytes)
	writeGauge(&output, "codex_control_connector_spool_events", "Events held in the durable outbound Connector spool.", spool.Events)
	writeGaugeFloat(&output, "codex_control_connector_spool_oldest_unacknowledged_age_seconds", "Age of the oldest unacknowledged Connector spool event.", spool.OldestUnacknowledgedAge.Seconds())
	writeCounterFamily(&output, "codex_control_connector_app_server_restarts_total", "Connector app-server restart attempts by fixed reason.", "reason", restartLabels, state.AppServerRestarts)
	writeCounterFamily(&output, "codex_control_connector_contract_failures_total", "Connector version or schema contract failures.", "kind", contractLabels, state.ContractFailures)
	writeGaugeFamily(&output, "codex_control_connector_contract_last_failure_timestamp_seconds", "Unix timestamp of the latest Connector contract failure by fixed kind, or zero if none.", "kind", contractLabels, state.ContractFailureTimestamps)
	writeCounterFamily(&output, "codex_control_connector_policy_denials_total", "Connector remote-control policy denials.", "reason", policyLabels, state.PolicyDenials)
	return output.Bytes()
}

func writeCounterFamily(output *bytes.Buffer, name, help, labelName string, labels []string, values []uint64) {
	fmt.Fprintf(output, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
	for index, label := range labels {
		fmt.Fprintf(output, "%s{%s=%q} %d\n", name, labelName, label, values[index])
	}
}

func writeGaugeFamily(output *bytes.Buffer, name, help, labelName string, labels []string, values []int64) {
	fmt.Fprintf(output, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
	for index, label := range labels {
		fmt.Fprintf(output, "%s{%s=%q} %d\n", name, labelName, label, values[index])
	}
}

func writeGauge(output *bytes.Buffer, name, help string, value any) {
	fmt.Fprintf(output, "# HELP %s %s\n# TYPE %s gauge\n%s %v\n", name, help, name, name, value)
}

func writeGaugeFloat(output *bytes.Buffer, name, help string, value float64) {
	fmt.Fprintf(output, "# HELP %s %s\n# TYPE %s gauge\n%s %.3f\n", name, help, name, name, value)
}

func boolValue(value bool) int {
	if value {
		return 1
	}
	return 0
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := securefile.EnsureDir(dir); err != nil {
		return err
	}
	temporary, err := createTemporaryFile(dir)
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := restrictTemporaryFile(temporary); err != nil {
		return err
	}
	info, err := securefile.ValidateOwnerAndACL(temporary, false)
	if err != nil {
		return err
	}
	if !privateRegularMode(info.Mode()) {
		return errors.New("temporary metrics file is not private and regular")
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := replaceFile(temporaryPath, path); err != nil {
		return err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, pathInfo) {
		return errors.New("metrics textfile path changed during replacement")
	}
	committed = true
	return securefile.SyncDirectory(dir)
}

// createTemporaryFile replaces os.CreateTemp because a state object must be
// private from the moment it exists. A Windows file created with a default
// descriptor inherits whatever its parent volume grants, and the exporter would
// then correctly refuse the file it had just written.
func createTemporaryFile(dir string) (*os.File, error) {
	var suffix [8]byte
	for range temporaryNameAttempts {
		if _, err := rand.Read(suffix[:]); err != nil {
			return nil, fmt.Errorf("name temporary metrics file: %w", err)
		}
		path := filepath.Join(dir, temporaryPrefix+hex.EncodeToString(suffix[:])+temporarySuffix)
		file, err := securefile.CreatePrivateFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
		if err == nil {
			return file, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	return nil, errors.New("create temporary metrics file")
}

func cleanupTemporaryFiles(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	removed := false
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, temporaryPrefix) || !strings.HasSuffix(name, temporarySuffix) ||
			len(name) <= len(temporaryPrefix)+len(temporarySuffix) {
			continue
		}
		path := filepath.Join(dir, name)
		info, err := securefile.StatPrivateFile(path)
		if err != nil {
			return fmt.Errorf("inspect stale metrics temporary file: %w", err)
		}
		if !privateRegularMode(info.Mode()) {
			return errors.New("stale metrics temporary file is not private and regular")
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove stale metrics temporary file: %w", err)
		}
		removed = true
	}
	if !removed {
		return nil
	}
	return securefile.SyncDirectory(dir)
}

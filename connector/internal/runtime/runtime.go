package runtime

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"time"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/approval"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/appserver"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/auth"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/config"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/control"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/identity"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/localstate"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/metrics"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/pairing"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/policy"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/protocol"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/spool"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/transport"
)

type Options struct {
	Config      config.Config
	Identity    *identity.Identity
	Credentials pairing.Credentials
	TokenSource auth.TokenSource
	Stderr      io.Writer
}

type sessionChild interface {
	Wait() error
	Close()
}

type sessionExitSource uint8

const (
	childExit sessionExitSource = iota + 1
	transportExit
)

var errDeviceTransportTerminated = errors.New("device transport terminated")

type sessionExit struct {
	source sessionExitSource
	err    error
}

func Run(ctx context.Context, options Options) (resultErr error) {
	disableProductionCanaryHook, err := transport.EnableProductionCanaryCrashHook(options.Config.StateDir)
	if err != nil {
		return err
	}
	defer disableProductionCanaryHook()
	guard, err := policy.NewGuard(options.Config.WorkspaceRoots, options.Config.SandboxCap)
	if err != nil {
		return err
	}
	eventSpool, err := spool.Open(filepath.Join(options.Config.StateDir, "spool"))
	if err != nil {
		return err
	}
	threads, err := localstate.OpenThreads(
		filepath.Join(options.Config.StateDir, "managed-threads.json"),
		options.Credentials.DeviceID,
	)
	if err != nil {
		return err
	}
	// Recovery deliberately leaves terminal records in place until the metrics
	// receipt set has been reconciled from the command journal below.
	commands, err := localstate.OpenCommands(filepath.Join(options.Config.StateDir, "commands"))
	if err != nil {
		return err
	}
	metricsExporter, err := metrics.Open(options.Config.StateDir, func(now time.Time) (metrics.SpoolSnapshot, error) {
		stats, statsErr := eventSpool.Stats(now)
		if statsErr != nil {
			return metrics.SpoolSnapshot{}, statsErr
		}
		return metrics.SpoolSnapshot{
			Events: stats.PendingRecords, Bytes: stats.PendingBytes,
			CapacityBytes: stats.CapacityBytes, OldestUnacknowledgedAge: stats.OldestPendingAge,
		}, nil
	})
	if err != nil {
		return err
	}
	if err := metricsExporter.Start(); err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, metricsExporter.Close())
	}()
	var metricsWarningOnce sync.Once
	recordMetricsError := func(updateErr error) {
		if updateErr == nil || options.Stderr == nil {
			return
		}
		metricsWarningOnce.Do(func() {
			_, _ = fmt.Fprintln(options.Stderr, "connector metrics update failed (details suppressed)")
		})
	}
	policyDenials := &policyDenialReconciler{commands: commands, exporter: metricsExporter}
	if err := policyDenials.Reconcile(""); err != nil {
		recordMetricsError(err)
		return err
	}
	metricsCtx, stopMetrics := context.WithCancel(ctx)
	metricsDone := make(chan error, 1)
	go func() {
		metricsDone <- metricsExporter.RunRefreshLoop(
			metricsCtx, metrics.DefaultRefreshInterval, metrics.DefaultChangeDebounce, recordMetricsError,
		)
	}()
	defer func() {
		stopMetrics()
		loopErr := <-metricsDone
		if !errors.Is(loopErr, context.Canceled) {
			resultErr = errors.Join(resultErr, loopErr)
		}
	}()
	restarts := newRestartPolicy(options.Config.ReconnectMin.Value(), options.Config.ReconnectMax.Value())
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		epoch, err := newEpoch()
		if err != nil {
			return err
		}
		if err := threads.ClearActiveTurns(); err != nil {
			return err
		}
		sessionCtx, cancel := context.WithCancel(ctx)
		var deviceTransport *transport.Client
		var router *control.Router
		var referencesMu sync.RWMutex
		emit := func(callCtx context.Context, envelopeType string, payload any) error {
			referencesMu.RLock()
			currentTransport := deviceTransport
			referencesMu.RUnlock()
			if currentTransport == nil {
				return errors.New("device transport is not ready")
			}
			return currentTransport.Emit(callCtx, envelopeType, payload)
		}
		observe := func(method string, projected json.RawMessage) (bool, error) {
			referencesMu.RLock()
			currentRouter := router
			referencesMu.RUnlock()
			if currentRouter == nil {
				return false, errors.New("command router is not ready")
			}
			return currentRouter.ObserveNotification(method, projected), nil
		}
		broker := approval.New(options.Config.ApprovalTimeout.Value(), emit)
		broker.SetEpoch(epoch)
		cancelEpoch := func() {
			broker.SetEpoch("")
			cancel()
		}
		failure := newSessionFailure(cancelEpoch)
		notifications := newNotificationHandler(sessionCtx, emit, observe, failure.Fail)
		broker.SetValidators(func(kind string, details map[string]any) error {
			threadID := stringField(details, "threadId", "thread_id", "conversationId")
			thread, managed := threads.Get(threadID)
			if threadID == "" || !managed || !guard.ContainsCWD(thread.CWD) {
				return errors.New("approval does not belong to a connector-managed thread")
			}
			turnID := stringField(details, "turnId", "turn_id")
			if turnID != "" && turnID != thread.ActiveTurnID {
				return errors.New("approval does not belong to the connector-bound active turn")
			}
			if turnID == "" && thread.ActiveTurnID == "" {
				return errors.New("approval has no connector-bound active turn")
			}
			return guard.ValidateApprovalDetails(kind, details)
		}, guard.ValidatePermissions)
		handler := appserver.HandlerFuncs{
			NotificationFunc: notifications.Handle,
			RequestFunc:      broker.Request,
		}
		startedAt := time.Now()
		app, err := appserver.Start(sessionCtx, appserver.StartOptions{
			Binary: options.Config.CodexBinary, ExpectedVersion: options.Config.CodexVersion,
			ConnectorVersion: config.DefaultConnectorVersion,
			Stderr:           options.Stderr, Handler: handler,
			OnContractFailure: func() {
				recordAfterEpochCancellation(cancelEpoch, func() {
					recordMetricsError(metricsExporter.RecordContractFailure(metrics.ContractSchema))
				})
			},
		})
		if err != nil {
			cancelEpoch()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, appserver.ErrVersionMismatch) {
				recordMetricsError(metricsExporter.RecordContractFailure(metrics.ContractVersion))
				return err
			}
			reason := "start_failure"
			if failure.Err() != nil {
				reason = "notification_failure"
			}
			delay, rapidFailures, restartErr := restarts.afterFailure(time.Since(startedAt))
			if restartErr != nil {
				return fmt.Errorf("%w after %d consecutive failures below the %s stable-run threshold", restartErr, rapidFailures, options.Config.ReconnectMax.Value())
			}
			recordMetricsError(metricsExporter.RecordAppServerRestart(appServerRestartMetric(reason)))
			if options.Stderr != nil {
				_, _ = fmt.Fprintf(options.Stderr, "codex app-server unavailable (reason=%s); retrying in %s (rapid_restart=%d/%d)\n", reason, delay, rapidFailures, maxRapidAppServerRestarts)
			}
			if !waitRetry(ctx, delay) {
				return ctx.Err()
			}
			continue
		}
		referencesMu.Lock()
		router = &control.Router{App: app, Guard: guard, Threads: threads}
		referencesMu.Unlock()
		controller := &control.Handler{
			Epoch: epoch, Router: router, Broker: broker, Commands: commands,
			OnPolicyDenial: func(receiptKey string) error {
				err := policyDenials.Reconcile(receiptKey)
				recordMetricsError(err)
				return err
			},
		}
		handleEnvelope := func(callCtx context.Context, envelope protocol.Envelope) error {
			err := controller.Handle(callCtx, envelope)
			if errors.Is(err, control.ErrRefreshToken) {
				options.TokenSource.Invalidate()
				return transport.ErrRefreshToken
			}
			return err
		}
		newTransport, err := transport.New(transport.Options{
			URL: options.Config.ControlURL, DeviceID: options.Credentials.DeviceID, Epoch: epoch,
			TokenSource: options.TokenSource, Spool: eventSpool,
			HeartbeatInterval: options.Config.HeartbeatInterval.Value(),
			ReconnectMin:      options.Config.ReconnectMin.Value(), ReconnectMax: options.Config.ReconnectMax.Value(),
			Hello: protocol.HelloPayload{
				ConnectorVersion: config.DefaultConnectorVersion, CodexVersion: options.Config.CodexVersion,
				SchemaDigest: options.Config.SchemaDigest, PublicKey: options.Identity.PublicKeyString(),
				Capabilities:   policy.AllowedMethods(),
				WorkspaceRoots: append([]string(nil), options.Config.RemoteWorkspaceRoots...),
			},
			Handler:             handleEnvelope,
			StaleCommandHandler: handleEnvelope,
			OnConnected:         func() { broker.SetConnected(true) },
			OnDisconnect:        func() { broker.SetConnected(false) },
			OnReconnect: func(reason transport.ReconnectReason) {
				recordMetricsError(metricsExporter.RecordReconnect(reconnectMetric(reason)))
			},
			OnSpoolChanged: func() {
				metricsExporter.Notify()
			},
			OnSchemaFailure: func() {
				recordAfterEpochCancellation(cancelEpoch, func() {
					recordMetricsError(metricsExporter.RecordContractFailure(metrics.ContractSchema))
				})
			},
		})
		if err != nil {
			cancelEpoch()
			app.Close()
			return err
		}
		referencesMu.Lock()
		deviceTransport = newTransport
		referencesMu.Unlock()
		controller.Emitter = newTransport
		transportDone := make(chan error, 1)
		go func() { transportDone <- newTransport.Run(sessionCtx) }()
		exit := waitForSessionExit(app, cancelEpoch, transportDone)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		reason, terminalErr := classifySessionExit(exit, failure.Err())
		if terminalErr != nil {
			return terminalErr
		}
		delay, rapidFailures, restartErr := restarts.afterFailure(time.Since(startedAt))
		if restartErr != nil {
			return fmt.Errorf("%w after %d consecutive failures below the %s stable-run threshold", restartErr, rapidFailures, options.Config.ReconnectMax.Value())
		}
		recordMetricsError(metricsExporter.RecordAppServerRestart(appServerRestartMetric(reason)))
		if options.Stderr != nil {
			_, _ = fmt.Fprintf(options.Stderr, "codex app-server unavailable (reason=%s); retrying in %s with a new epoch (rapid_restart=%d/%d)\n", reason, delay, rapidFailures, maxRapidAppServerRestarts)
		}
		if !waitRetry(ctx, delay) {
			return ctx.Err()
		}
	}
}

func recordAfterEpochCancellation(cancelEpoch func(), record func()) {
	cancelEpoch()
	record()
}

type policyDenialReconciler struct {
	mu       sync.Mutex
	commands *localstate.CommandStore
	exporter *metrics.Exporter
}

// Reconcile serializes journal snapshots through receipt persistence and
// pruning. This prevents an older snapshot from replacing receipts committed
// by a newer reconciliation generation.
func (r *policyDenialReconciler) Reconcile(expectedKey string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	keys, err := r.commands.PolicyDenialReceiptKeys()
	if err != nil {
		return err
	}
	if expectedKey != "" {
		found := false
		for _, key := range keys {
			if key == expectedKey {
				found = true
				break
			}
		}
		if !found {
			return errors.New("durable policy denial receipt is missing from the command journal")
		}
	}
	if err := r.exporter.ReconcilePolicyDenials(metrics.PolicyCommand, keys); err != nil {
		return err
	}
	if err := r.commands.PruneExpired(); err != nil {
		return err
	}
	keys, err = r.commands.PolicyDenialReceiptKeys()
	if err != nil {
		return err
	}
	return r.exporter.ReconcilePolicyDenials(metrics.PolicyCommand, keys)
}

func reconnectMetric(reason transport.ReconnectReason) metrics.ReconnectReason {
	switch reason {
	case transport.ReconnectToken:
		return metrics.ReconnectToken
	case transport.ReconnectDial:
		return metrics.ReconnectDial
	case transport.ReconnectHandshake:
		return metrics.ReconnectHandshake
	case transport.ReconnectConnectionIO:
		return metrics.ReconnectConnectionIO
	default:
		return metrics.ReconnectConnectionIO
	}
}

func appServerRestartMetric(reason string) metrics.AppServerRestartReason {
	switch reason {
	case "notification_failure":
		return metrics.AppServerNotificationFailure
	case "child_exit":
		return metrics.AppServerChildExit
	default:
		return metrics.AppServerStartFailure
	}
}

func waitForSessionExit(child sessionChild, cancel context.CancelFunc, transportDone <-chan error) sessionExit {
	childDone := make(chan error, 1)
	go func() { childDone <- child.Wait() }()

	select {
	case err := <-childDone:
		cancel()
		child.Close()
		transportErr := <-transportDone
		if transportErr == nil {
			return sessionExit{source: transportExit, err: errors.New("device transport stopped without an error")}
		}
		if !errors.Is(transportErr, context.Canceled) {
			return sessionExit{source: transportExit, err: transportErr}
		}
		return sessionExit{source: childExit, err: err}
	case err := <-transportDone:
		cancel()
		child.Close()
		<-childDone
		return sessionExit{source: transportExit, err: err}
	}
}

func classifySessionExit(exit sessionExit, notificationErr error) (string, error) {
	if exit.source == transportExit {
		if notificationErr != nil && errors.Is(exit.err, context.Canceled) {
			return "notification_failure", nil
		}
		return "", errDeviceTransportTerminated
	}
	if notificationErr != nil {
		return "notification_failure", nil
	}
	return "child_exit", nil
}

func stringField(value map[string]any, keys ...string) string {
	for _, key := range keys {
		if field, ok := value[key].(string); ok {
			return field
		}
	}
	return ""
}

func newEpoch() (string, error) {
	value := make([]byte, 24)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func waitRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

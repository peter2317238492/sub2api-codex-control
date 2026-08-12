package transport

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/approval"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/auth"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/control"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/localstate"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/protocol"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/spool"
)

const (
	testDeviceID     = "11111111-1111-4111-8111-111111111111"
	testConnectionID = "22222222-2222-4222-8222-222222222222"
	testEpoch        = "epoch-0123456789abcdef"
	testSchemaDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

type staticTokenSource struct{}

func (staticTokenSource) Token(context.Context) (auth.DeviceToken, error) {
	return auth.DeviceToken{Value: "token", ExpiresAt: time.Now().Add(time.Minute)}, nil
}
func (staticTokenSource) Invalidate() {}

type failingTokenSource struct{ calls atomic.Int32 }

func (source *failingTokenSource) Token(context.Context) (auth.DeviceToken, error) {
	source.calls.Add(1)
	return auth.DeviceToken{}, errors.New("temporary authentication failure")
}

func (*failingTokenSource) Invalidate() {}

type fixedTokenSource struct{ token auth.DeviceToken }

func (source fixedTokenSource) Token(context.Context) (auth.DeviceToken, error) {
	return source.token, nil
}
func (fixedTokenSource) Invalidate() {}

func TestEmitDurablyAssignsEnvelopeSequenceAndAck(t *testing.T) {
	eventSpool, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eventSpool.ObserveIncoming(1); err != nil {
		t.Fatal(err)
	}
	spoolChanges := 0
	client, err := New(Options{
		URL: "wss://control.example/device", DeviceID: "11111111-1111-4111-8111-111111111111", Epoch: "epoch-0123456789abcdef",
		TokenSource: staticTokenSource{}, Spool: eventSpool,
		Handler:        func(context.Context, protocol.Envelope) error { return nil },
		OnSpoolChanged: func() { spoolChanges++ },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Emit(t.Context(), protocol.TypeEvent, protocol.EventPayload{
		Method: "turn/completed", Params: map[string]any{"value": "one"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := client.Emit(t.Context(), protocol.TypeEvent, protocol.EventPayload{
		Method: "turn/completed", Params: map[string]any{"value": "two"},
	}); err != nil {
		t.Fatal(err)
	}
	records, err := eventSpool.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("records = %d", len(records))
	}
	if spoolChanges != 2 {
		t.Fatalf("spool metric callbacks = %d, want 2", spoolChanges)
	}
	for index, record := range records {
		var envelope protocol.Envelope
		if err := json.Unmarshal(record.Data, &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.Seq != uint64(index+1) || envelope.Ack == nil || *envelope.Ack != 1 {
			t.Fatalf("envelope = %#v", envelope)
		}
	}
}

func TestEmitForEpochDurablyPreservesRecoveredCommandEpoch(t *testing.T) {
	eventSpool, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	client := newTestClient(t, "wss://control.example/device", eventSpool, func(context.Context, protocol.Envelope) error {
		return nil
	})
	oldEpoch := "old-epoch-0123456789abcdef"
	if err := client.EmitForEpoch(t.Context(), oldEpoch, protocol.TypeCommandAck, protocol.CommandAckPayload{
		CommandID: testConnectionID, State: "completed", Result: json.RawMessage(`{"ok":true}`),
	}); err != nil {
		t.Fatal(err)
	}
	records, err := eventSpool.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("pending recovered acknowledgements = %d, want 1", len(records))
	}
	var envelope protocol.Envelope
	if err := decodeStrict(records[0].Data, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Epoch != oldEpoch || envelope.Type != protocol.TypeCommandAck {
		t.Fatalf("recovered terminal acknowledgement envelope = %#v", envelope)
	}
}

func TestTerminalAckSpoolSurvivesProcessCrashWithOriginalEpoch(t *testing.T) {
	dir := t.TempDir()
	command := exec.Command(os.Args[0], "-test.run=^TestTerminalAckSpoolCrashHelper$")
	command.Env = append(
		os.Environ(),
		"SUB2API_ACK_SPOOL_CRASH_HELPER=1",
		"SUB2API_ACK_SPOOL_DIR="+dir,
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
		if readErr == nil && line != "ack-spooled\n" {
			readErr = errors.New("terminal acknowledgement helper returned an invalid readiness message")
		}
		ready <- readErr
	}()
	select {
	case err := <-ready:
		if err != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			waited = true
			t.Fatalf("wait for durable terminal acknowledgement: %v (stderr: %s)", err, stderr.String())
		}
	case <-time.After(3 * time.Second):
		_ = command.Process.Kill()
		_ = command.Wait()
		waited = true
		t.Fatalf("terminal acknowledgement helper did not report durability (stderr: %s)", stderr.String())
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("terminal acknowledgement helper exited cleanly instead of being killed")
	}
	waited = true

	reopened, err := spool.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	records, err := reopened.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Sequence != 1 {
		t.Fatalf("pending terminal acknowledgements = %#v", records)
	}
	client := newTestClient(t, "wss://control.example/device", reopened, func(context.Context, protocol.Envelope) error {
		return nil
	})
	client.options.Epoch = "new-epoch-0123456789abcdef"
	projected, err := client.projectPendingRecord(records[0], true)
	if err != nil {
		t.Fatal(err)
	}
	var envelope protocol.Envelope
	if err := decodeStrict(projected, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Type != protocol.TypeCommandAck || envelope.Epoch != testEpoch {
		t.Fatalf("recovered terminal acknowledgement envelope = %#v", envelope)
	}
	var acknowledgement protocol.CommandAckPayload
	if err := decodeStrict(envelope.Payload, &acknowledgement); err != nil {
		t.Fatal(err)
	}
	if acknowledgement.CommandID != testConnectionID || acknowledgement.State != "completed" {
		t.Fatalf("recovered terminal acknowledgement = %#v", acknowledgement)
	}
}

func TestTerminalAckSpoolCrashHelper(t *testing.T) {
	if os.Getenv("SUB2API_ACK_SPOOL_CRASH_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	eventSpool, err := spool.Open(os.Getenv("SUB2API_ACK_SPOOL_DIR"))
	if err != nil {
		t.Fatal(err)
	}
	client := newTestClient(t, "wss://control.example/device", eventSpool, func(context.Context, protocol.Envelope) error {
		return nil
	})
	if err := client.Emit(t.Context(), protocol.TypeCommandAck, protocol.CommandAckPayload{
		CommandID: testConnectionID, State: "completed", Result: json.RawMessage(`{"ok":true}`),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stdout.WriteString("ack-spooled\n"); err != nil {
		t.Fatal(err)
	}
	<-t.Context().Done()
}

func TestEmitRejectsOversizedPayloadBeforeSpooling(t *testing.T) {
	eventSpool, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	client := newTestClient(t, "wss://control.example/device", eventSpool, func(context.Context, protocol.Envelope) error {
		return nil
	})
	if err := client.Emit(t.Context(), protocol.TypeEvent, protocol.EventPayload{
		Method: "turn/completed", Params: map[string]any{
			"value": strings.Repeat("x", protocol.MaxProjectedPayloadBytes),
		},
	}); err == nil {
		t.Fatal("oversized payload was accepted")
	}
	if eventSpool.LastAssigned() != 0 {
		t.Fatal("oversized payload consumed a spool sequence")
	}
}

func TestEmitRejectsInvalidDiscriminatorPayloadBeforeSpooling(t *testing.T) {
	eventSpool, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	client := newTestClient(t, "wss://control.example/device", eventSpool, func(context.Context, protocol.Envelope) error {
		return nil
	})
	if err := client.Emit(t.Context(), protocol.TypeEvent, map[string]string{"value": "not-an-event"}); err == nil {
		t.Fatal("invalid event payload was accepted")
	}
	if eventSpool.LastAssigned() != 0 {
		t.Fatal("invalid event payload consumed a spool sequence")
	}
}

func TestReconnectJitterIsBounded(t *testing.T) {
	base := 10 * time.Second
	for index := 0; index < 20; index++ {
		value := jitter(base)
		if value < 8*time.Second || value > 12*time.Second {
			t.Fatalf("jitter = %s", value)
		}
	}
}

func TestReconnectPolicyBacksOffAndResetsAfterStableConnection(t *testing.T) {
	policy := newReconnectPolicy(10*time.Millisecond, 80*time.Millisecond, time.Second)
	for index, want := range []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond} {
		delay, err := policy.afterFailure(time.Millisecond)
		if err != nil || delay != want {
			t.Fatalf("failure %d = (%s, %v), want (%s, nil)", index+1, delay, err, want)
		}
	}
	delay, err := policy.afterFailure(time.Second)
	if err != nil || delay != 10*time.Millisecond || policy.rapidFailures != 1 {
		t.Fatalf("stable reset = (%s, %d, %v)", delay, policy.rapidFailures, err)
	}
}

func TestRunOpensCircuitAfterBoundedRapidNetworkFailures(t *testing.T) {
	eventSpool, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tokens := &failingTokenSource{}
	client, err := New(Options{
		URL: "wss://control.invalid/device", DeviceID: testDeviceID, Epoch: testEpoch,
		TokenSource: tokens, Spool: eventSpool,
		Handler:           func(context.Context, protocol.Envelope) error { return nil },
		HeartbeatInterval: time.Second, ReconnectMin: time.Millisecond, ReconnectMax: 2 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := client.Run(ctx); !errors.Is(err, ErrReconnectCircuit) {
		t.Fatalf("run error = %v", err)
	}
	if got := tokens.calls.Load(); got != maxRapidNetworkFailures+1 {
		t.Fatalf("token attempts = %d, want %d", got, maxRapidNetworkFailures+1)
	}
}

func TestRunReturnsFatalHandlerFailureWithoutReconnect(t *testing.T) {
	eventSpool, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handlerFailure := errors.New("local handler invariant failed")
	var connections atomic.Int32
	serverResult := make(chan error, 1)
	server := newHTTPTestServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connections.Add(1)
		connection, err := websocket.Accept(writer, request, nil)
		if err != nil {
			serverResult <- err
			return
		}
		defer connection.CloseNow()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		hello, helloPayload, err := readHello(ctx, connection)
		if err == nil {
			err = writeHelloAck(ctx, connection, hello, helloPayload, nil)
		}
		if err == nil {
			err = writeEnvelope(ctx, connection, testEnvelope(protocol.TypeCommand, 1, testCommandPayload()))
		}
		serverResult <- err
		if err == nil {
			_, _, _ = connection.Read(ctx)
		}
	}))
	defer server.Close()

	client := newTestClient(t, websocketTestURL(server.URL), eventSpool, func(context.Context, protocol.Envelope) error {
		return handlerFailure
	})
	client.options.ReconnectMin = time.Millisecond
	client.options.ReconnectMax = 2 * time.Millisecond
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := client.Run(ctx); !errors.Is(err, handlerFailure) {
		t.Fatalf("run error = %v", err)
	}
	if serverErr := <-serverResult; serverErr != nil {
		t.Fatal(serverErr)
	}
	if got := connections.Load(); got != 1 {
		t.Fatalf("fatal handler failure opened %d connections, want 1", got)
	}
}

func TestInboundPayloadIsValidatedBeforeHandler(t *testing.T) {
	eventSpool, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var handlerCalls atomic.Int32
	serverResult := make(chan error, 1)
	server := newHTTPTestServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(writer, request, nil)
		if err != nil {
			serverResult <- err
			return
		}
		defer connection.CloseNow()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		hello, helloPayload, err := readHello(ctx, connection)
		if err == nil {
			err = writeHelloAck(ctx, connection, hello, helloPayload, nil)
		}
		if err == nil {
			err = writeEnvelope(ctx, connection, testEnvelope(protocol.TypeCommand, 1, json.RawMessage(`{}`)))
		}
		serverResult <- err
		if err == nil {
			_, _, _ = connection.Read(ctx)
		}
	}))
	defer server.Close()

	client := newTestClient(t, websocketTestURL(server.URL), eventSpool, func(context.Context, protocol.Envelope) error {
		handlerCalls.Add(1)
		return nil
	})
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := client.runConnection(ctx); err == nil {
		t.Fatal("invalid command payload did not fail the connection")
	}
	if serverErr := <-serverResult; serverErr != nil {
		t.Fatal(serverErr)
	}
	if calls := handlerCalls.Load(); calls != 0 {
		t.Fatalf("invalid payload reached handler %d times", calls)
	}
}

func TestHandshakeHelloIsFirstFrameWithSequenceZero(t *testing.T) {
	eventSpool, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eventSpool.Append(func(sequence uint64) ([]byte, error) {
		return json.Marshal(testEnvelope(
			protocol.TypeEvent,
			sequence,
			json.RawMessage(`{"method":"turn/completed","params":{"value":"backlog"}}`),
		))
	}); err != nil {
		t.Fatal(err)
	}

	serverResult := make(chan error, 1)
	server := newHTTPTestServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(writer, request, nil)
		if err != nil {
			serverResult <- err
			return
		}
		defer connection.CloseNow()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		hello, helloPayload, err := readHello(ctx, connection)
		if err != nil {
			serverResult <- err
			return
		}
		if hello.Type != protocol.TypeHello || hello.Seq != 0 {
			serverResult <- fmt.Errorf("first frame = type %q seq %d", hello.Type, hello.Seq)
			return
		}
		if err := writeHelloAck(ctx, connection, hello, helloPayload, nil); err != nil {
			serverResult <- err
			return
		}
		backlog, err := readEnvelope(ctx, connection)
		if err != nil {
			serverResult <- err
			return
		}
		if backlog.Type != protocol.TypeEvent || backlog.Seq != 1 {
			serverResult <- fmt.Errorf("second frame = type %q seq %d", backlog.Type, backlog.Seq)
			return
		}
		serverResult <- nil
	}))
	defer server.Close()

	client := newTestClient(t, websocketTestURL(server.URL), eventSpool, func(context.Context, protocol.Envelope) error {
		return nil
	})
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	_ = client.runConnection(ctx)
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestHandshakeRejectsMismatchedHelloAcknowledgement(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*protocol.Envelope, *protocol.HelloAckPayload)
	}{
		{
			name: "protocol",
			mutate: func(_ *protocol.Envelope, payload *protocol.HelloAckPayload) {
				payload.ProtocolVersion = protocol.Version + 1
			},
		},
		{
			name: "schema",
			mutate: func(_ *protocol.Envelope, payload *protocol.HelloAckPayload) {
				payload.SchemaDigest = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
			},
		},
		{
			name: "payload epoch",
			mutate: func(_ *protocol.Envelope, payload *protocol.HelloAckPayload) {
				payload.Epoch = "other-epoch-0123456789abcdef"
			},
		},
		{
			name: "envelope epoch",
			mutate: func(envelope *protocol.Envelope, _ *protocol.HelloAckPayload) {
				envelope.Epoch = "other-epoch-0123456789abcdef"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			eventSpool, err := spool.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			serverResult := make(chan error, 1)
			server := newHTTPTestServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				connection, err := websocket.Accept(writer, request, nil)
				if err != nil {
					serverResult <- err
					return
				}
				defer connection.CloseNow()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				hello, helloPayload, err := readHello(ctx, connection)
				if err == nil {
					err = writeHelloAck(ctx, connection, hello, helloPayload, test.mutate)
				}
				serverResult <- err
			}))
			defer server.Close()

			client := newTestClient(t, websocketTestURL(server.URL), eventSpool, func(context.Context, protocol.Envelope) error {
				return nil
			})
			schemaFailures := 0
			client.options.OnSchemaFailure = func() { schemaFailures++ }
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			err = client.runConnection(ctx)
			if err == nil {
				t.Fatal("mismatched hello acknowledgement was accepted")
			}
			if serverErr := <-serverResult; serverErr != nil {
				t.Fatal(serverErr)
			}
			wantSchemaFailures := 0
			if test.name == "schema" {
				wantSchemaFailures = 1
			}
			if schemaFailures != wantSchemaFailures {
				t.Fatalf("schema failure callbacks = %d, want %d", schemaFailures, wantSchemaFailures)
			}
		})
	}
}

func TestRunReportsFixedReconnectReasonWithoutRawError(t *testing.T) {
	eventSpool, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	reasons := make(chan ReconnectReason, 1)
	client, err := New(Options{
		URL: "wss://control.example/device", DeviceID: testDeviceID, Epoch: testEpoch,
		TokenSource: &failingTokenSource{}, Spool: eventSpool,
		Handler:      func(context.Context, protocol.Envelope) error { return nil },
		ReconnectMin: time.Millisecond, ReconnectMax: time.Millisecond,
		OnReconnect: func(reason ReconnectReason) {
			reasons <- reason
			cancel()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- client.Run(ctx) }()
	select {
	case reason := <-reasons:
		if reason != ReconnectToken {
			t.Fatalf("reconnect reason = %d, want token", reason)
		}
	case <-time.After(time.Second):
		t.Fatal("reconnect metric callback was not invoked")
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("transport result = %v, want cancellation", err)
	}
}

func TestInboundCursorCommitsOnlyAfterHandlerSuccess(t *testing.T) {
	handlerFailure := errors.New("handler failed")
	tests := []struct {
		name       string
		handlerErr error
		wantCursor uint64
	}{
		{name: "failure", handlerErr: handlerFailure, wantCursor: 0},
		{name: "success", wantCursor: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			eventSpool, err := spool.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			handled := make(chan struct{}, 1)
			releaseServer := make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(releaseServer) }) }
			serverResult := make(chan error, 1)
			server := newHTTPTestServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				connection, err := websocket.Accept(writer, request, nil)
				if err != nil {
					serverResult <- err
					return
				}
				defer connection.CloseNow()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				hello, helloPayload, err := readHello(ctx, connection)
				if err == nil {
					err = writeHelloAck(ctx, connection, hello, helloPayload, nil)
				}
				if err == nil {
					command := testEnvelope(protocol.TypeCommand, 1, testCommandPayload())
					encoded, encodeErr := json.Marshal(command)
					if encodeErr != nil {
						err = encodeErr
					} else {
						err = connection.Write(ctx, websocket.MessageText, encoded)
					}
				}
				if err == nil {
					<-releaseServer
				}
				serverResult <- err
			}))
			defer server.Close()
			defer release()

			client := newTestClient(t, websocketTestURL(server.URL), eventSpool, func(context.Context, protocol.Envelope) error {
				handled <- struct{}{}
				return test.handlerErr
			})
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			runResult := make(chan error, 1)
			go func() { runResult <- client.runConnection(ctx) }()
			select {
			case <-handled:
			case <-ctx.Done():
				t.Fatal("handler was not called")
			}
			if test.wantCursor == 1 {
				waitForCursor(t, ctx, eventSpool, 1)
			} else if eventSpool.LastReceived() != 0 {
				t.Fatalf("cursor advanced after handler failure: %d", eventSpool.LastReceived())
			}
			cancel()
			<-runResult
			release()
			if serverErr := <-serverResult; serverErr != nil {
				t.Fatal(serverErr)
			}
			reopened, err := spool.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			if got := reopened.LastReceived(); got != test.wantCursor {
				t.Fatalf("durable cursor = %d, want %d", got, test.wantCursor)
			}
		})
	}
}

func TestCrossEpochReplaySkipsStaleCommandAndContinuesInSequence(t *testing.T) {
	eventSpool, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	staleCommand := testEnvelope(protocol.TypeCommand, 1, testCommandPayload())
	staleCommand.Epoch = "prior-epoch-0123456789abcdef"
	currentCommand := testEnvelope(protocol.TypeCommand, 2, testCommandPayload())
	serverRelease := make(chan struct{})
	serverResult := make(chan error, 1)
	server := sequencedEnvelopeServer(t, []protocol.Envelope{
		staleCommand,
		currentCommand,
	}, serverRelease, serverResult)
	defer server.Close()

	handled := make(chan protocol.Envelope, 2)
	client := newTestClient(t, websocketTestURL(server.URL), eventSpool, func(_ context.Context, envelope protocol.Envelope) error {
		handled <- envelope
		return nil
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	runResult := make(chan error, 1)
	go func() { runResult <- client.runConnection(ctx) }()
	waitForCursor(t, ctx, eventSpool, 2)
	select {
	case envelope := <-handled:
		if envelope.Seq != 2 || envelope.Epoch != testEpoch {
			t.Fatalf("handled envelope = %#v, want only current-epoch sequence 2", envelope)
		}
	case <-ctx.Done():
		t.Fatal("current-epoch command was not handled after stale replay")
	}
	select {
	case envelope := <-handled:
		t.Fatalf("stale command reached the handler: %#v", envelope)
	default:
	}
	cancel()
	<-runResult
	close(serverRelease)
	if serverErr := <-serverResult; serverErr != nil {
		t.Fatal(serverErr)
	}
}

func TestCrossEpochCommandCanReachOnlyTheRecoveryHandler(t *testing.T) {
	eventSpool, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	staleCommand := testEnvelope(protocol.TypeCommand, 1, testCommandPayload())
	staleCommand.Epoch = "prior-epoch-0123456789abcdef"
	serverRelease := make(chan struct{})
	serverResult := make(chan error, 1)
	server := sequencedEnvelopeServer(t, []protocol.Envelope{staleCommand}, serverRelease, serverResult)
	defer server.Close()
	recovered := make(chan protocol.Envelope, 1)
	semanticCalled := make(chan struct{}, 1)
	client := newTestClient(t, websocketTestURL(server.URL), eventSpool, func(context.Context, protocol.Envelope) error {
		semanticCalled <- struct{}{}
		return nil
	})
	client.options.StaleCommandHandler = func(_ context.Context, envelope protocol.Envelope) error {
		recovered <- envelope
		return nil
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	runResult := make(chan error, 1)
	go func() { runResult <- client.runConnection(ctx) }()
	waitForCursor(t, ctx, eventSpool, 1)
	select {
	case envelope := <-recovered:
		if envelope.Seq != 1 || envelope.Epoch == testEpoch {
			t.Fatalf("recovery envelope = %#v", envelope)
		}
	case <-ctx.Done():
		t.Fatal("stale command did not reach the recovery handler")
	}
	select {
	case <-semanticCalled:
		t.Fatal("stale command reached the current-epoch semantic handler")
	default:
	}
	cancel()
	<-runResult
	close(serverRelease)
	if serverErr := <-serverResult; serverErr != nil {
		t.Fatal(serverErr)
	}
}

func TestConnectionExitWaitsForInFlightHandler(t *testing.T) {
	eventSpool, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	serverRelease := make(chan struct{})
	serverResult := make(chan error, 1)
	server := sequencedEnvelopeServer(t, []protocol.Envelope{
		testEnvelope(protocol.TypeCommand, 1, testCommandPayload()),
	}, serverRelease, serverResult)
	defer server.Close()
	var releaseServer sync.Once
	releaseServerNow := func() { releaseServer.Do(func() { close(serverRelease) }) }
	defer releaseServerNow()

	handlerEntered := make(chan struct{})
	handlerRelease := make(chan struct{})
	disconnected := make(chan struct{})
	var releaseHandler sync.Once
	releaseHandlerNow := func() { releaseHandler.Do(func() { close(handlerRelease) }) }
	defer releaseHandlerNow()
	client := newTestClient(t, websocketTestURL(server.URL), eventSpool, func(context.Context, protocol.Envelope) error {
		close(handlerEntered)
		<-handlerRelease
		return nil
	})
	client.options.OnDisconnect = func() { close(disconnected) }
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	runResult := make(chan error, 1)
	go func() { runResult <- client.runConnection(ctx) }()
	select {
	case <-handlerEntered:
	case <-ctx.Done():
		t.Fatal("command handler was not entered")
	}
	cancel()
	select {
	case <-disconnected:
	case <-time.After(time.Second):
		t.Fatal("disconnect callback waited for the blocked command handler")
	}
	select {
	case err := <-runResult:
		t.Fatalf("connection returned before its in-flight handler stopped: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	releaseHandlerNow()
	select {
	case err := <-runResult:
		if err == nil {
			t.Fatal("canceled connection returned without an error")
		}
	case <-time.After(time.Second):
		t.Fatal("connection did not return after its handler stopped")
	}
	releaseServerNow()
	if serverErr := <-serverResult; serverErr != nil {
		t.Fatal(serverErr)
	}
}

func TestSocketFailureCancelsHandlerBeforeJoiningIt(t *testing.T) {
	eventSpool, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	serverRelease := make(chan struct{})
	serverResult := make(chan error, 1)
	server := sequencedEnvelopeServer(t, []protocol.Envelope{
		testEnvelope(protocol.TypeCommand, 1, testCommandPayload()),
	}, serverRelease, serverResult)
	defer server.Close()
	handlerEntered := make(chan struct{})
	handlerExited := make(chan struct{})
	client := newTestClient(t, websocketTestURL(server.URL), eventSpool, func(ctx context.Context, _ protocol.Envelope) error {
		close(handlerEntered)
		<-ctx.Done()
		close(handlerExited)
		return ctx.Err()
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	runResult := make(chan error, 1)
	go func() { runResult <- client.runConnection(ctx) }()
	select {
	case <-handlerEntered:
	case <-ctx.Done():
		t.Fatal("command handler was not entered")
	}
	close(serverRelease)
	if serverErr := <-serverResult; serverErr != nil {
		t.Fatal(serverErr)
	}
	select {
	case err := <-runResult:
		if err == nil {
			t.Fatal("socket failure returned without an error")
		}
	case <-time.After(time.Second):
		t.Fatal("socket failure did not cancel the handler before joining it")
	}
	select {
	case <-handlerExited:
	default:
		t.Fatal("connection returned before the canceled handler exited")
	}
}

func TestScheduledTokenExpiryIsRetryableWhenWriteLoopWins(t *testing.T) {
	eventSpool, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	client := newTestClient(t, "wss://control.example/device", eventSpool, func(context.Context, protocol.Envelope) error {
		return nil
	})
	connectionCtx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	err = client.writeLoop(connectionCtx, nil, 0, time.Hour)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("write-loop error = %v, want deadline exceeded", err)
	}
	failureErr := classifyEstablishedConnectionFailure(err, time.Minute, true)
	var failure *connectionFailure
	if !errors.As(failureErr, &failure) || !failure.retryable || failure.reason != ReconnectToken {
		t.Fatalf("classified failure = %#v, want retryable", failureErr)
	}
	if !errors.Is(failureErr, ErrRefreshToken) || !errors.Is(failureErr, context.DeadlineExceeded) {
		t.Fatalf("classified failure = %v, want refresh-token and deadline causes", failureErr)
	}
}

func TestTokenInsideRefreshWindowIsRejectedBeforeDial(t *testing.T) {
	eventSpool, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(Options{
		URL: "not-a-websocket-url", DeviceID: testDeviceID, Epoch: testEpoch,
		TokenSource: fixedTokenSource{token: auth.DeviceToken{
			Value: "near-expiry-token", ExpiresAt: time.Now().Add(10 * time.Second),
		}},
		Spool: eventSpool,
		Handler: func(context.Context, protocol.Envelope) error {
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	failureErr := client.runConnection(t.Context())
	var failure *connectionFailure
	if !errors.Is(failureErr, ErrRefreshToken) || !errors.As(failureErr, &failure) || !failure.retryable || failure.reason != ReconnectToken {
		t.Fatalf("near-expiry token failure = %#v, want retryable refresh", failureErr)
	}
}

type approvalBlockingRouter struct {
	broker   *approval.Broker
	approved chan struct{}
	release  <-chan struct{}
}

func (r *approvalBlockingRouter) Call(ctx context.Context, method string, _ json.RawMessage) (json.RawMessage, error) {
	if method != "turn/start" {
		return nil, fmt.Errorf("unexpected method %q", method)
	}
	result, rpcErr := r.broker.Request(ctx, "item/commandExecution/requestApproval", json.RawMessage(`{
		"threadId":"thread-1","turnId":"turn-1","command":"printf test","reason":"ordering test"
	}`))
	if rpcErr != nil {
		return nil, rpcErr
	}
	decision, ok := result.(map[string]string)
	if !ok || decision["decision"] != "accept" {
		return nil, errors.New("app-server approval was not accepted")
	}
	select {
	case r.approved <- struct{}{}:
	default:
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-r.release:
	}
	return json.RawMessage(`{"turn":{"id":"turn-1","status":"inProgress"}}`), nil
}

func TestApprovalDecisionBypassesInterleavedHeartbeatAckWithoutAdvancingCursorOutOfOrder(t *testing.T) {
	eventSpool, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	commands, err := localstate.OpenCommands(filepath.Join(t.TempDir(), "commands"))
	if err != nil {
		t.Fatal(err)
	}
	releaseCommand := make(chan struct{})
	approved := make(chan struct{}, 1)
	serverRelease := make(chan struct{})
	serverResult := make(chan error, 1)
	server := newHTTPTestServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(writer, request, nil)
		if err != nil {
			serverResult <- err
			return
		}
		defer connection.CloseNow()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hello, helloPayload, err := readHello(ctx, connection)
		if err == nil {
			err = writeHelloAck(ctx, connection, hello, helloPayload, nil)
		}
		if err == nil {
			commandPayload, encodeErr := protocol.MarshalPayload(protocol.CommandPayload{
				CommandID: "44444444-4444-4444-8444-444444444444", IdempotencyKey: "approval-ordering",
				Method: "turn/start", Params: json.RawMessage(`{"threadId":"thread-1","input":[{"type":"text","text":"test"}]}`),
				DeadlineAt: time.Now().Add(4 * time.Second),
			})
			if encodeErr != nil {
				err = encodeErr
			} else {
				err = writeEnvelope(ctx, connection, testEnvelope(protocol.TypeCommand, 1, commandPayload))
			}
		}
		var approvalRequest protocol.ApprovalRequestPayload
		if err == nil {
			outbound, readErr := readEnvelope(ctx, connection)
			if readErr != nil {
				err = readErr
			} else if outbound.Type != protocol.TypeApprovalRequest {
				err = fmt.Errorf("outbound type = %q, want approval_request", outbound.Type)
			} else {
				err = decodeStrict(outbound.Payload, &approvalRequest)
			}
		}
		if err == nil {
			heartbeatAckPayload, encodeErr := protocol.MarshalPayload(protocol.HeartbeatAckPayload{
				ReceivedSeq: 1,
			})
			if encodeErr != nil {
				err = encodeErr
			} else {
				err = writeEnvelope(ctx, connection, testEnvelope(protocol.TypeHeartbeatAck, 2, heartbeatAckPayload))
			}
		}
		if err == nil {
			decisionPayload, encodeErr := protocol.MarshalPayload(protocol.ApprovalDecisionPayload{
				ApprovalID: approvalRequest.ApprovalID, Decision: "approve", DecidedAt: time.Now().UTC(),
			})
			if encodeErr != nil {
				err = encodeErr
			} else {
				err = writeEnvelope(ctx, connection, testEnvelope(protocol.TypeApprovalDecision, 3, decisionPayload))
			}
		}
		if err == nil {
			outbound, readErr := readEnvelope(ctx, connection)
			if readErr != nil {
				err = readErr
			} else if outbound.Type != protocol.TypeCommandAck {
				err = fmt.Errorf("outbound type = %q, want command_ack", outbound.Type)
			}
		}
		serverResult <- err
		<-serverRelease
	}))
	defer server.Close()

	var client *Client
	broker := approval.New(4*time.Second, func(ctx context.Context, envelopeType string, payload any) error {
		return client.Emit(ctx, envelopeType, payload)
	})
	broker.SetEpoch(testEpoch)
	broker.SetConnected(true)
	router := &approvalBlockingRouter{broker: broker, approved: approved, release: releaseCommand}
	controller := &control.Handler{Epoch: testEpoch, Router: router, Broker: broker, Commands: commands}
	client = newTestClient(t, websocketTestURL(server.URL), eventSpool, controller.Handle)
	controller.Emitter = client

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	runResult := make(chan error, 1)
	go func() { runResult <- client.runConnection(ctx) }()
	select {
	case <-approved:
	case <-ctx.Done():
		t.Fatal("approval decision did not unblock the turn/start handler")
	}
	if got := eventSpool.LastReceived(); got != 0 {
		t.Fatalf("cursor advanced to %d before turn/start completed", got)
	}
	close(releaseCommand)
	waitForCursor(t, ctx, eventSpool, 3)
	if serverErr := <-serverResult; serverErr != nil {
		t.Fatal(serverErr)
	}
	cancel()
	<-runResult
	close(serverRelease)
}

func TestApprovalBypassIsSerialAndCommitsInSequenceOrder(t *testing.T) {
	eventSpool, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	releaseHead := make(chan struct{})
	releaseFirstApproval := make(chan struct{})
	started := make(chan uint64, 3)
	serverRelease := make(chan struct{})
	serverResult := make(chan error, 1)
	server := sequencedEnvelopeServer(t, []protocol.Envelope{
		testEnvelope(protocol.TypeCommand, 1, testCommandPayload()),
		testEnvelope(protocol.TypeApprovalDecision, 2, testApprovalDecisionPayload()),
		testEnvelope(protocol.TypeApprovalDecision, 3, testApprovalDecisionPayload()),
	}, serverRelease, serverResult)
	defer server.Close()
	client := newTestClient(t, websocketTestURL(server.URL), eventSpool, func(ctx context.Context, envelope protocol.Envelope) error {
		started <- envelope.Seq
		switch envelope.Seq {
		case 1:
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-releaseHead:
			}
		case 2:
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-releaseFirstApproval:
			}
		}
		return nil
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	runResult := make(chan error, 1)
	go func() { runResult <- client.runConnection(ctx) }()
	initial := map[uint64]bool{
		waitForSequence(t, ctx, started): true,
		waitForSequence(t, ctx, started): true,
	}
	if !initial[1] || !initial[2] || len(initial) != 2 {
		t.Fatalf("initial handler sequences = %#v, want {1, 2}", initial)
	}
	select {
	case got := <-started:
		t.Fatalf("later approval %d started before approval 2 completed", got)
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseFirstApproval)
	if got := waitForSequence(t, ctx, started); got != 3 {
		t.Fatalf("second bypass sequence = %d", got)
	}
	if got := eventSpool.LastReceived(); got != 0 {
		t.Fatalf("cursor advanced to %d while sequence 1 was incomplete", got)
	}
	close(releaseHead)
	waitForCursor(t, ctx, eventSpool, 3)
	cancel()
	<-runResult
	close(serverRelease)
	if serverErr := <-serverResult; serverErr != nil {
		t.Fatal(serverErr)
	}
}

func TestApprovalDoesNotCrossTokenRefreshBarrier(t *testing.T) {
	eventSpool, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	releaseHead := make(chan struct{})
	headStarted := make(chan struct{}, 1)
	approvalStarted := make(chan struct{}, 1)
	serverRelease := make(chan struct{})
	serverResult := make(chan error, 1)
	server := sequencedEnvelopeServer(t, []protocol.Envelope{
		testEnvelope(protocol.TypeCommand, 1, testCommandPayload()),
		testEnvelope(protocol.TypeTokenRefresh, 2, json.RawMessage(`{}`)),
		testEnvelope(protocol.TypeApprovalDecision, 3, testApprovalDecisionPayload()),
	}, serverRelease, serverResult)
	defer server.Close()
	client := newTestClient(t, websocketTestURL(server.URL), eventSpool, func(ctx context.Context, envelope protocol.Envelope) error {
		switch envelope.Seq {
		case 1:
			headStarted <- struct{}{}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-releaseHead:
				return nil
			}
		case 2:
			return ErrRefreshToken
		case 3:
			approvalStarted <- struct{}{}
		}
		return nil
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	runResult := make(chan error, 1)
	go func() { runResult <- client.runConnection(ctx) }()
	select {
	case <-headStarted:
	case <-ctx.Done():
		t.Fatal("head command did not start")
	}
	select {
	case <-approvalStarted:
		t.Fatal("approval crossed a token-refresh barrier")
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseHead)
	if err := <-runResult; !errors.Is(err, ErrRefreshToken) {
		t.Fatalf("run error = %v", err)
	}
	if got := eventSpool.LastReceived(); got != 2 {
		t.Fatalf("cursor = %d, want token-refresh barrier committed at 2", got)
	}
	select {
	case <-approvalStarted:
		t.Fatal("approval after token-refresh barrier was handled before reconnect")
	default:
	}
	close(serverRelease)
	if serverErr := <-serverResult; serverErr != nil {
		t.Fatal(serverErr)
	}
}

func TestApprovalBypassBackpressuresAtIncomingFrameLimit(t *testing.T) {
	eventSpool, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	envelopes := make([]protocol.Envelope, 0, maxBufferedIncomingFrames+1)
	envelopes = append(envelopes, testEnvelope(protocol.TypeCommand, 1, testCommandPayload()))
	for sequence := uint64(2); sequence <= maxBufferedIncomingFrames+1; sequence++ {
		envelopes = append(envelopes, testEnvelope(protocol.TypeApprovalDecision, sequence, testApprovalDecisionPayload()))
	}
	releaseHead := make(chan struct{})
	started := make(chan uint64, maxBufferedIncomingFrames+1)
	serverRelease := make(chan struct{})
	serverResult := make(chan error, 1)
	server := sequencedEnvelopeServer(t, envelopes, serverRelease, serverResult)
	defer server.Close()
	client := newTestClient(t, websocketTestURL(server.URL), eventSpool, func(ctx context.Context, envelope protocol.Envelope) error {
		started <- envelope.Seq
		if envelope.Seq == 1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-releaseHead:
			}
		}
		return nil
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	runResult := make(chan error, 1)
	go func() { runResult <- client.runConnection(ctx) }()
	initial := make(map[uint64]bool, maxBufferedIncomingFrames)
	for range maxBufferedIncomingFrames {
		initial[waitForSequence(t, ctx, started)] = true
	}
	for want := uint64(1); want <= maxBufferedIncomingFrames; want++ {
		if !initial[want] {
			t.Fatalf("initial handler sequences = %#v, missing %d", initial, want)
		}
	}
	select {
	case got := <-started:
		t.Fatalf("sequence %d crossed the %d-frame incoming bound", got, maxBufferedIncomingFrames)
	case <-time.After(100 * time.Millisecond):
	}
	if got := eventSpool.LastReceived(); got != 0 {
		t.Fatalf("cursor advanced to %d while bounded queue head was incomplete", got)
	}
	close(releaseHead)
	if got := waitForSequence(t, ctx, started); got != maxBufferedIncomingFrames+1 {
		t.Fatalf("post-backpressure handler sequence = %d", got)
	}
	waitForCursor(t, ctx, eventSpool, maxBufferedIncomingFrames+1)
	cancel()
	<-runResult
	close(serverRelease)
	if serverErr := <-serverResult; serverErr != nil {
		t.Fatal(serverErr)
	}
}

func TestFailedBypassClosesConnectionWithoutStartingLaterApproval(t *testing.T) {
	eventSpool, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handlerFailure := errors.New("approval handler failed")
	laterStarted := make(chan struct{}, 1)
	serverRelease := make(chan struct{})
	serverResult := make(chan error, 1)
	server := sequencedEnvelopeServer(t, []protocol.Envelope{
		testEnvelope(protocol.TypeCommand, 1, testCommandPayload()),
		testEnvelope(protocol.TypeApprovalDecision, 2, testApprovalDecisionPayload()),
		testEnvelope(protocol.TypeApprovalDecision, 3, testApprovalDecisionPayload()),
	}, serverRelease, serverResult)
	defer server.Close()
	client := newTestClient(t, websocketTestURL(server.URL), eventSpool, func(ctx context.Context, envelope protocol.Envelope) error {
		switch envelope.Seq {
		case 1:
			<-ctx.Done()
			return ctx.Err()
		case 2:
			return handlerFailure
		case 3:
			laterStarted <- struct{}{}
		}
		return nil
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err = client.runConnection(ctx)
	if !errors.Is(err, handlerFailure) {
		t.Fatalf("run error = %v", err)
	}
	if got := eventSpool.LastReceived(); got != 0 {
		t.Fatalf("cursor advanced to %d after failed bypass", got)
	}
	select {
	case <-laterStarted:
		t.Fatal("later approval started after an earlier bypass failed")
	default:
	}
	close(serverRelease)
	if serverErr := <-serverResult; serverErr != nil {
		t.Fatal(serverErr)
	}
}

func TestUncommittedBypassIsReplayedAfterReconnect(t *testing.T) {
	eventSpool, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	firstApprovalHandled := make(chan struct{})
	firstServerResult := make(chan error, 1)
	firstServer := sequencedEnvelopeServer(t, []protocol.Envelope{
		testEnvelope(protocol.TypeCommand, 1, testCommandPayload()),
		testEnvelope(protocol.TypeApprovalDecision, 2, testApprovalDecisionPayload()),
	}, firstApprovalHandled, firstServerResult)
	defer firstServer.Close()

	var mu sync.Mutex
	replay := false
	counts := map[uint64]int{}
	client := newTestClient(t, websocketTestURL(firstServer.URL), eventSpool, func(ctx context.Context, envelope protocol.Envelope) error {
		mu.Lock()
		counts[envelope.Seq]++
		isReplay := replay
		mu.Unlock()
		if !isReplay && envelope.Seq == 1 {
			<-ctx.Done()
			return ctx.Err()
		}
		if !isReplay && envelope.Seq == 2 {
			close(firstApprovalHandled)
		}
		return nil
	})
	firstCtx, firstCancel := context.WithTimeout(t.Context(), 5*time.Second)
	err = client.runConnection(firstCtx)
	firstCancel()
	if err == nil {
		t.Fatal("first connection unexpectedly succeeded")
	}
	if serverErr := <-firstServerResult; serverErr != nil {
		t.Fatal(serverErr)
	}
	if got := eventSpool.LastReceived(); got != 0 {
		t.Fatalf("cursor advanced to %d before reconnect", got)
	}

	secondServerRelease := make(chan struct{})
	secondServerResult := make(chan error, 1)
	secondServer := sequencedEnvelopeServer(t, []protocol.Envelope{
		testEnvelope(protocol.TypeCommand, 1, testCommandPayload()),
		testEnvelope(protocol.TypeApprovalDecision, 2, testApprovalDecisionPayload()),
	}, secondServerRelease, secondServerResult)
	defer secondServer.Close()
	mu.Lock()
	replay = true
	mu.Unlock()
	client.options.URL = websocketTestURL(secondServer.URL)
	secondCtx, secondCancel := context.WithTimeout(t.Context(), 5*time.Second)
	runResult := make(chan error, 1)
	go func() { runResult <- client.runConnection(secondCtx) }()
	waitForCursor(t, secondCtx, eventSpool, 2)
	secondCancel()
	<-runResult
	close(secondServerRelease)
	if serverErr := <-secondServerResult; serverErr != nil {
		t.Fatal(serverErr)
	}
	mu.Lock()
	defer mu.Unlock()
	if counts[1] != 2 || counts[2] != 2 {
		t.Fatalf("handler counts after replay = %#v", counts)
	}
}

func TestBackloggedApprovalBecomesSameSequenceErrorTombstone(t *testing.T) {
	eventSpool, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var original protocol.Envelope
	sequence, err := eventSpool.Append(func(sequence uint64) ([]byte, error) {
		original = testEnvelope(protocol.TypeApprovalRequest, sequence, json.RawMessage(`{"approval_id":"approval-1"}`))
		return json.Marshal(original)
	})
	if err != nil {
		t.Fatal(err)
	}
	records, err := eventSpool.Pending()
	if err != nil {
		t.Fatal(err)
	}
	client := newTestClient(t, "wss://control.example/device", eventSpool, func(context.Context, protocol.Envelope) error {
		return nil
	})
	projected, err := client.projectPendingRecord(records[0], true)
	if err != nil {
		t.Fatal(err)
	}
	var tombstone protocol.Envelope
	if err := decodeStrict(projected, &tombstone); err != nil {
		t.Fatal(err)
	}
	if tombstone.Type != protocol.TypeError || tombstone.Seq != sequence || tombstone.ID != original.ID {
		t.Fatalf("tombstone = %#v", tombstone)
	}
	var failure protocol.ProtocolError
	if err := decodeStrict(tombstone.Payload, &failure); err != nil {
		t.Fatal(err)
	}
	if failure.Code != "invalid_epoch" || failure.Retryable || !strings.Contains(failure.Message, "disconnected") {
		t.Fatalf("tombstone payload = %#v", failure)
	}
}

func TestBackloggedHeartbeatsBecomeSameSequenceTombstones(t *testing.T) {
	eventSpool, err := spool.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	client := newTestClient(t, "wss://control.example/device", eventSpool, func(context.Context, protocol.Envelope) error {
		return nil
	})
	for _, envelopeType := range []string{protocol.TypeHeartbeat, protocol.TypeHeartbeatAck} {
		payload := json.RawMessage(`{"status":"ok"}`)
		if envelopeType == protocol.TypeHeartbeatAck {
			payload = json.RawMessage(`{"received_seq":1}`)
		}
		envelope := testEnvelope(envelopeType, 1, payload)
		encoded, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		projected, err := client.projectPendingRecord(spool.Record{Sequence: 1, Data: encoded}, true)
		if err != nil {
			t.Fatal(err)
		}
		var tombstone protocol.Envelope
		if err := decodeStrict(projected, &tombstone); err != nil {
			t.Fatal(err)
		}
		if tombstone.Type != protocol.TypeError || tombstone.Seq != 1 {
			t.Fatalf("%s backlog was not tombstoned: %#v", envelopeType, tombstone)
		}
	}
}

func newTestClient(t *testing.T, url string, eventSpool *spool.Spool, handler HandlerFunc) *Client {
	t.Helper()
	client, err := New(Options{
		URL: url, DeviceID: testDeviceID, Epoch: testEpoch,
		TokenSource: staticTokenSource{}, Spool: eventSpool, Handler: handler,
		HeartbeatInterval: time.Hour,
		Hello: protocol.HelloPayload{
			ConnectorVersion: "0.1.0", CodexVersion: "0.147.0", SchemaDigest: testSchemaDigest,
			PublicKey: strings.Repeat("k", 40), Capabilities: []string{"thread/start"}, WorkspaceRoots: []string{"/work"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func websocketTestURL(httpURL string) string {
	return "ws" + strings.TrimPrefix(httpURL, "http")
}

func newHTTPTestServer(t *testing.T, handler http.Handler) (server *httptest.Server) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Skipf("loopback listener unavailable in this sandbox: %v", recovered)
		}
	}()
	return httptest.NewServer(handler)
}

func readHello(ctx context.Context, connection *websocket.Conn) (protocol.Envelope, protocol.HelloPayload, error) {
	envelope, err := readEnvelope(ctx, connection)
	if err != nil {
		return protocol.Envelope{}, protocol.HelloPayload{}, err
	}
	var payload protocol.HelloPayload
	if err := decodeStrict(envelope.Payload, &payload); err != nil {
		return protocol.Envelope{}, protocol.HelloPayload{}, err
	}
	return envelope, payload, nil
}

func readEnvelope(ctx context.Context, connection *websocket.Conn) (protocol.Envelope, error) {
	messageType, data, err := connection.Read(ctx)
	if err != nil {
		return protocol.Envelope{}, err
	}
	if messageType != websocket.MessageText {
		return protocol.Envelope{}, errors.New("received non-text test frame")
	}
	var envelope protocol.Envelope
	if err := decodeStrict(data, &envelope); err != nil {
		return protocol.Envelope{}, err
	}
	return envelope, nil
}

func writeEnvelope(ctx context.Context, connection *websocket.Conn, envelope protocol.Envelope) error {
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	return connection.Write(ctx, websocket.MessageText, encoded)
}

func sequencedEnvelopeServer(
	t *testing.T,
	envelopes []protocol.Envelope,
	release <-chan struct{},
	result chan<- error,
) *httptest.Server {
	t.Helper()
	return newHTTPTestServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(writer, request, nil)
		if err != nil {
			result <- err
			return
		}
		defer connection.CloseNow()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hello, helloPayload, err := readHello(ctx, connection)
		if err == nil {
			err = writeHelloAck(ctx, connection, hello, helloPayload, nil)
		}
		for _, envelope := range envelopes {
			if err != nil {
				break
			}
			err = writeEnvelope(ctx, connection, envelope)
		}
		if err == nil {
			<-release
		}
		result <- err
	}))
}

func writeHelloAck(
	ctx context.Context,
	connection *websocket.Conn,
	hello protocol.Envelope,
	helloPayload protocol.HelloPayload,
	mutate func(*protocol.Envelope, *protocol.HelloAckPayload),
) error {
	receivedSequence := uint64(0)
	payload := protocol.HelloAckPayload{
		ConnectionID: testConnectionID, ProtocolVersion: protocol.Version, DeviceID: hello.DeviceID,
		Epoch: hello.Epoch, SchemaDigest: helloPayload.SchemaDigest, ReceivedSeq: receivedSequence,
		HeartbeatTimeoutSeconds: 15,
	}
	payloadRaw, err := protocol.MarshalPayload(payload)
	if err != nil {
		return err
	}
	acknowledgement := protocol.Envelope{
		Version: protocol.Version, ID: testConnectionID, DeviceID: hello.DeviceID, Epoch: hello.Epoch,
		Seq: 0, Ack: &receivedSequence, Type: protocol.TypeHelloAck, SentAt: time.Now().UTC(), Payload: payloadRaw,
	}
	if mutate != nil {
		mutate(&acknowledgement, &payload)
		payloadRaw, err = protocol.MarshalPayload(payload)
		if err != nil {
			return err
		}
		acknowledgement.Payload = payloadRaw
	}
	encoded, err := json.Marshal(acknowledgement)
	if err != nil {
		return err
	}
	return connection.Write(ctx, websocket.MessageText, encoded)
}

func testEnvelope(envelopeType string, sequence uint64, payload json.RawMessage) protocol.Envelope {
	return protocol.Envelope{
		Version: protocol.Version, ID: "33333333-3333-4333-8333-333333333333", DeviceID: testDeviceID,
		Epoch: testEpoch, Seq: sequence, Type: envelopeType, SentAt: time.Now().UTC(), Payload: payload,
	}
}

func testCommandPayload() json.RawMessage {
	return json.RawMessage(`{
		"command_id":"44444444-4444-4444-8444-444444444444",
		"idempotency_key":"transport-test",
		"method":"thread/start",
		"params":{"cwd":"/work"},
		"deadline_at":"2030-01-01T00:00:00Z"
	}`)
}

func testApprovalDecisionPayload() json.RawMessage {
	return json.RawMessage(`{
		"approval_id":"55555555-5555-4555-8555-555555555555",
		"decision":"approve",
		"decided_at":"2026-07-23T00:00:00Z"
	}`)
}

func waitForCursor(t *testing.T, ctx context.Context, eventSpool *spool.Spool, want uint64) {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if eventSpool.LastReceived() == want {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("cursor did not advance to %d", want)
		case <-ticker.C:
		}
	}
}

func waitForSequence(t *testing.T, ctx context.Context, sequences <-chan uint64) uint64 {
	t.Helper()
	select {
	case sequence := <-sequences:
		return sequence
	case <-ctx.Done():
		t.Fatal("handler did not start before the test deadline")
		return 0
	}
}

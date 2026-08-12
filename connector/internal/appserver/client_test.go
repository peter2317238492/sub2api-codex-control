package appserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type testWriteCloser struct{ bytes.Buffer }

func (w *testWriteCloser) Close() error { return nil }

func validPermissionRequest(id int) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"item/permissions/requestApproval","params":{"threadId":"thread-1","turnId":"turn-1","itemId":"item-1","environmentId":null,"startedAtMs":1785945600000,"cwd":"/workspace","reason":null,"permissions":{"fileSystem":{"entries":[],"globScanMaxDepth":1},"network":{"enabled":false}}}}`, id)
}

func TestClientBootstrapsAndRoutesJSONRPC(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}
	script := filepath.Join(t.TempDir(), "fake-codex")
	contents := `#!/bin/sh
if test "$1" = "--version"; then
  printf '%s\n' 'codex-cli 0.147.0'
  exit 0
fi
test "$1" = "app-server" || exit 41
test "$2" = "--listen" || exit 42
test "$3" = "stdio://" || exit 43
IFS= read -r initialize || exit 44
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"codexHome":"/tmp/fake-codex-home","platformFamily":"unix","platformOs":"linux","userAgent":"fake"}}'
IFS= read -r initialized || exit 45
printf '%s\n' '{"jsonrpc":"2.0","method":"turn/started","params":{"threadId":"t","turn":{"id":"turn-1","items":[],"status":"inProgress"}},"emittedAtMs":1785945600000}'
IFS= read -r request || exit 46
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"data":[{"id":"model","model":"model","displayName":"Model","description":"Test model","isDefault":true,"hidden":false,"defaultReasoningEffort":"medium","supportedReasoningEfforts":[]}]}}'
while :; do sleep 1; done
`
	if err := os.WriteFile(script, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	notifications := make(chan string, 1)
	ctx, cancel := context.WithCancel(t.Context())
	client, err := Start(ctx, StartOptions{
		Binary: script, ExpectedVersion: "0.147.0", ConnectorVersion: "test", InitializeTimeout: 15 * time.Second,
		Handler: HandlerFuncs{NotificationFunc: func(method string, _ json.RawMessage) {
			notifications <- method
		}},
	})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer func() {
		client.Close()
		cancel()
		_ = client.Wait()
	}()
	select {
	case method := <-notifications:
		if method != "turn/started" {
			t.Fatalf("notification method = %q", method)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("notification was not routed")
	}
	result, err := client.Call(t.Context(), "model/list", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(result), `"defaultReasoningEffort":"medium"`) {
		t.Fatalf("result = %s", result)
	}
}

func TestStartRevalidatesVersionBeforeEveryChildStart(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess test in short mode")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-codex")
	audit := filepath.Join(dir, "audit")
	drifted := filepath.Join(dir, "drifted")
	contents := fmt.Sprintf(`#!/bin/sh
if test "$1" = "--version"; then
  printf 'version\n' >> %q
  if test -f %q; then
    printf 'codex-cli 9.9.9\n'
  else
    printf 'codex-cli 0.147.0\n'
  fi
  exit 0
fi
printf 'app-server\n' >> %q
IFS= read -r initialize || exit 40
printf '%%s\n' '{"jsonrpc":"2.0","id":1,"result":{"codexHome":"/tmp/fake-codex-home","platformFamily":"unix","platformOs":"linux","userAgent":"fake"}}'
IFS= read -r initialized || exit 41
while :; do sleep 1; done
`, audit, drifted, audit)
	if err := os.WriteFile(script, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}

	start := func() (*Client, error) {
		return Start(t.Context(), StartOptions{
			Binary: script, ExpectedVersion: "0.147.0", ConnectorVersion: "test",
			InitializeTimeout: 5 * time.Second,
		})
	}
	client, err := start()
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	_ = client.Wait()
	if err := os.WriteFile(drifted, []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if second, err := start(); err == nil || second != nil {
		if second != nil {
			second.Close()
			_ = second.Wait()
		}
		t.Fatalf("version drift was accepted: client=%v err=%v", second, err)
	}
	auditData, err := os.ReadFile(audit)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(auditData), "version\napp-server\nversion\n"; got != want {
		t.Fatalf("child invocation audit = %q, want %q", got, want)
	}
}

func TestStartRequiresExpectedVersion(t *testing.T) {
	client, err := Start(t.Context(), StartOptions{Binary: "codex"})
	if err == nil || client != nil {
		t.Fatalf("missing expected version = (%v, %v), want a closed failure", client, err)
	}
}

func TestVerifyVersionRequiresExactPinnedBanner(t *testing.T) {
	tests := []struct {
		name   string
		banner string
		valid  bool
	}{
		{name: "exact", banner: "codex-cli 0.147.0\n", valid: true},
		{name: "surrounding whitespace", banner: "  codex-cli 0.147.0\r\n", valid: true},
		{name: "extra version token", banner: "codex-cli 9.9 0.147.0\n"},
		{name: "extra line", banner: "codex-cli 0.147.0\n0.147.0\n"},
		{name: "v prefix", banner: "codex-cli v0.147.0\n"},
		{name: "other product", banner: "wrapper 0.147.0\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			script := filepath.Join(t.TempDir(), "fake-codex")
			contents := "#!/bin/sh\nprintf '%b' " + fmt.Sprintf("%q", test.banner) + "\n"
			if err := os.WriteFile(script, []byte(contents), 0o700); err != nil {
				t.Fatal(err)
			}
			err := VerifyVersion(t.Context(), script, "0.147.0")
			if (err == nil) != test.valid {
				t.Fatalf("valid = %v, want %v (err=%v)", err == nil, test.valid, err)
			}
			if !test.valid && !errors.Is(err, ErrVersionMismatch) {
				t.Fatalf("mismatch error = %v, want ErrVersionMismatch", err)
			}
		})
	}
}

func TestVerifyVersionIgnoresOfficialDiagnosticsOnStderr(t *testing.T) {
	script := filepath.Join(t.TempDir(), "fake-codex")
	contents := "#!/bin/sh\nprintf 'official diagnostic\\n' >&2\nprintf 'codex-cli 0.147.0\\n'\n"
	if err := os.WriteFile(script, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := VerifyVersion(t.Context(), script, "0.147.0"); err != nil {
		t.Fatalf("official stderr diagnostic invalidated the exact stdout banner: %v", err)
	}
}

func TestHandlerFuncsDeniesUnknownServerRequests(t *testing.T) {
	_, rpcErr := (HandlerFuncs{}).Request(t.Context(), "dynamicTool/call", json.RawMessage(`{}`))
	if rpcErr == nil || rpcErr.Code != -32601 {
		t.Fatalf("request error = %#v", rpcErr)
	}
}

func TestCallRejectsUnmappedMethodBeforeWrite(t *testing.T) {
	writer := &testWriteCloser{}
	contractFailures := 0
	client := &Client{
		ctx: context.Background(), stdin: writer, contract: mustContract(t),
		pending: make(map[string]pendingCall), done: make(chan struct{}),
		onContractFailure: func() { contractFailures++ },
	}
	if _, err := client.Call(t.Context(), "future/method", json.RawMessage(`{}`)); !errors.Is(err, ErrContractViolation) {
		t.Fatalf("unmapped call error = %v", err)
	}
	if writer.Len() != 0 {
		t.Fatal("unmapped method reached app-server stdin")
	}
	if contractFailures != 1 {
		t.Fatalf("contract failure callbacks = %d, want 1", contractFailures)
	}
}

func TestCallRejectsCanceledContextBeforeWrite(t *testing.T) {
	writer := &testWriteCloser{}
	client := &Client{
		ctx: context.Background(), stdin: writer, contract: mustContract(t),
		pending: make(map[string]pendingCall), done: make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := client.Call(ctx, "model/list", json.RawMessage(`{}`)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled call error = %v, want context canceled", err)
	}
	if writer.Len() != 0 || len(client.pending) != 0 {
		t.Fatalf("canceled call wrote %d bytes with %d pending requests", writer.Len(), len(client.pending))
	}
}

func TestContractViolationCancelsEpochBeforeMetricsCallback(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	callbackEntered := make(chan struct{})
	releaseCallback := make(chan struct{})
	client := &Client{
		ctx: ctx, cancel: cancel, stdin: &testWriteCloser{},
		pending:  make(map[string]pendingCall),
		requests: make(chan struct{}, maxConcurrentServerRequests), done: make(chan struct{}),
		onContractFailure: func() {
			close(callbackEntered)
			<-releaseCallback
		},
	}
	loopDone := make(chan struct{})
	go func() {
		client.readLoop(strings.NewReader("{\n"), mustContract(t))
		close(loopDone)
	}()
	select {
	case <-callbackEntered:
	case <-time.After(time.Second):
		t.Fatal("contract failure callback was not invoked")
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("contract failure callback ran before the app-server epoch was canceled")
	}
	close(releaseCallback)
	select {
	case <-loopDone:
	case <-time.After(time.Second):
		t.Fatal("read loop did not exit after the metrics callback completed")
	}
}

func TestCloseJoinsReadLoopAndRequestWorkers(t *testing.T) {
	tests := []struct {
		name  string
		input string
		make  func(chan<- struct{}, <-chan struct{}) Handler
	}{
		{
			name:  "notification",
			input: `{"method":"account/updated","params":{}}` + "\n",
			make: func(entered chan<- struct{}, release <-chan struct{}) Handler {
				return HandlerFuncs{NotificationFunc: func(string, json.RawMessage) {
					close(entered)
					<-release
				}}
			},
		},
		{
			name:  "request worker",
			input: validPermissionRequest(1) + "\n",
			make: func(entered chan<- struct{}, release <-chan struct{}) Handler {
				return HandlerFuncs{RequestFunc: func(context.Context, string, json.RawMessage) (any, *RPCError) {
					close(entered)
					<-release
					return map[string]any{"permissions": map[string]any{}, "scope": "turn", "strictAutoReview": true}, nil
				}}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			validator := mustContract(t)
			ctx, cancel := context.WithCancel(t.Context())
			processDone := make(chan struct{})
			close(processDone)
			readDone := make(chan struct{})
			entered := make(chan struct{})
			release := make(chan struct{})
			client := &Client{
				ctx: ctx, cancel: cancel, stdin: &testWriteCloser{}, handler: test.make(entered, release),
				contract: validator,
				pending:  make(map[string]pendingCall), requests: make(chan struct{}, maxConcurrentServerRequests),
				done: processDone, readDone: readDone, shutdownGracePeriod: time.Second,
			}
			go func() {
				defer close(readDone)
				client.readLoop(strings.NewReader(test.input), validator)
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("app-server handler was not entered")
			}

			closeDone := make(chan struct{})
			go func() {
				client.Close()
				close(closeDone)
			}()
			select {
			case <-closeDone:
				t.Fatal("Close returned before the app-server handler stopped")
			case <-time.After(50 * time.Millisecond):
			}
			close(release)
			select {
			case <-closeDone:
			case <-time.After(time.Second):
				t.Fatal("Close did not return after the app-server handler stopped")
			}
		})
	}
}

func TestReadLoopAcceptsPinnedMessagesWithoutJSONRPCMember(t *testing.T) {
	validator := mustContract(t)
	notifications := make(chan string, 1)
	responses := make(chan response, 1)
	client := &Client{
		ctx: context.Background(), stdin: &testWriteCloser{},
		handler: HandlerFuncs{NotificationFunc: func(method string, _ json.RawMessage) {
			notifications <- method
		}},
		pending:  map[string]pendingCall{"1": {method: "turn/interrupt", result: responses}},
		requests: make(chan struct{}, maxConcurrentServerRequests), done: make(chan struct{}),
	}
	client.readLoop(strings.NewReader(
		"{\"id\":1,\"result\":{}}\n"+
			"{\"method\":\"account/updated\",\"params\":{},\"emittedAtMs\":1785945600000}\n",
	), validator)
	select {
	case result := <-responses:
		if result.err != nil || string(result.result) != `{}` {
			t.Fatalf("response = %#v", result)
		}
	default:
		t.Fatal("response without jsonrpc member was rejected")
	}
	select {
	case method := <-notifications:
		if method != "account/updated" {
			t.Fatalf("notification method = %q", method)
		}
	default:
		t.Fatal("notification without jsonrpc member was rejected")
	}
}

func TestReadLoopRejectsExplicitUnsupportedJSONRPCVersion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &Client{
		ctx: ctx, cancel: cancel, stdin: &testWriteCloser{}, pending: make(map[string]pendingCall),
		requests: make(chan struct{}, maxConcurrentServerRequests), done: make(chan struct{}),
	}
	client.readLoop(strings.NewReader("{\"jsonrpc\":\"1.0\",\"method\":\"thread/started\",\"params\":{}}\n"), mustContract(t))
	select {
	case <-ctx.Done():
	default:
		t.Fatal("explicit unsupported jsonrpc version was accepted")
	}
}

func TestReadLoopRejectsResponseOutsideMethodSchema(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	responses := make(chan response, 1)
	client := &Client{
		ctx: ctx, cancel: cancel, stdin: &testWriteCloser{},
		pending:  map[string]pendingCall{"1": {method: "model/list", result: responses}},
		requests: make(chan struct{}, maxConcurrentServerRequests), done: make(chan struct{}),
	}
	client.readLoop(strings.NewReader(`{"id":1,"result":{"data":[{"id":"missing-required-fields"}]}}`+"\n"), mustContract(t))
	select {
	case got := <-responses:
		if !errors.Is(got.err, ErrContractViolation) {
			t.Fatalf("response error = %v", got.err)
		}
	default:
		t.Fatal("schema-invalid response was not failed")
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("schema-invalid response did not cancel the app-server epoch")
	}
}

func TestReadLoopRejectsMalformedServerRequestBeforeHandler(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	called := atomic.Bool{}
	client := &Client{
		ctx: ctx, cancel: cancel, stdin: &testWriteCloser{}, contract: mustContract(t),
		handler: HandlerFuncs{RequestFunc: func(context.Context, string, json.RawMessage) (any, *RPCError) {
			called.Store(true)
			return nil, nil
		}},
		pending: make(map[string]pendingCall), requests: make(chan struct{}, maxConcurrentServerRequests), done: make(chan struct{}),
	}
	client.readLoop(strings.NewReader(`{"id":1,"method":"item/permissions/requestApproval","params":{"threadId":"thread-1"}}`+"\n"), client.contract)
	if called.Load() {
		t.Fatal("schema-invalid server request reached the handler")
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("schema-invalid server request did not cancel the app-server epoch")
	}
}

func TestInvalidServerResponseCancelsWithoutWriting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	writer := &testWriteCloser{}
	validator := mustContract(t)
	client := &Client{
		ctx: ctx, cancel: cancel, stdin: writer, contract: validator,
		handler: HandlerFuncs{RequestFunc: func(context.Context, string, json.RawMessage) (any, *RPCError) {
			return map[string]bool{"ok": true}, nil
		}},
		pending: make(map[string]pendingCall), requests: make(chan struct{}, maxConcurrentServerRequests), done: make(chan struct{}),
	}
	client.readLoop(strings.NewReader(validPermissionRequest(1)+"\n"), validator)
	client.requestWorkers.Wait()
	if writer.Len() != 0 {
		t.Fatalf("schema-invalid handler result was written: %s", writer.String())
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("schema-invalid handler result did not cancel the app-server epoch")
	}
}

func TestReadLoopRejectsUnknownNotificationBeforeHandler(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	called := atomic.Bool{}
	client := &Client{
		ctx: ctx, cancel: cancel, stdin: &testWriteCloser{},
		handler: HandlerFuncs{NotificationFunc: func(string, json.RawMessage) { called.Store(true) }},
		pending: make(map[string]pendingCall), requests: make(chan struct{}, maxConcurrentServerRequests), done: make(chan struct{}),
	}
	client.readLoop(strings.NewReader(`{"method":"future/notification","params":{}}`+"\n"), mustContract(t))
	if called.Load() {
		t.Fatal("unknown notification reached the handler")
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("unknown notification did not cancel the app-server epoch")
	}
}

func TestReadLoopRejectsKnownNotificationMissingRequiredFields(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	called := atomic.Bool{}
	client := &Client{
		ctx: ctx, cancel: cancel, stdin: &testWriteCloser{},
		handler: HandlerFuncs{NotificationFunc: func(string, json.RawMessage) { called.Store(true) }},
		pending: make(map[string]pendingCall), requests: make(chan struct{}, maxConcurrentServerRequests), done: make(chan struct{}),
	}
	client.readLoop(strings.NewReader(`{"method":"turn/started","params":{"threadId":"thread-1","turn":{"id":"turn-1","status":"inProgress"}}}`+"\n"), mustContract(t))
	if called.Load() {
		t.Fatal("schema-invalid known notification reached the handler")
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("schema-invalid known notification did not cancel the epoch")
	}
}

func TestReadLoopRejectsInvalidNotificationEnvelopeFields(t *testing.T) {
	for _, raw := range []string{
		`{"method":"account/updated","params":{},"emittedAtMs":"not-an-integer"}`,
		`{"method":"account/updated","params":{},"unexpected":true}`,
	} {
		ctx, cancel := context.WithCancel(context.Background())
		called := atomic.Bool{}
		client := &Client{
			ctx: ctx, cancel: cancel, stdin: &testWriteCloser{},
			handler:  HandlerFuncs{NotificationFunc: func(string, json.RawMessage) { called.Store(true) }},
			pending:  make(map[string]pendingCall),
			requests: make(chan struct{}, maxConcurrentServerRequests), done: make(chan struct{}),
		}
		client.readLoop(strings.NewReader(raw+"\n"), mustContract(t))
		if called.Load() {
			t.Fatalf("invalid notification reached the handler: %s", raw)
		}
		select {
		case <-ctx.Done():
		default:
			t.Fatalf("invalid notification did not cancel the epoch: %s", raw)
		}
		cancel()
	}
}

func TestReadLoopRejectsHybridResponseEnvelope(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	responses := make(chan response, 1)
	client := &Client{
		ctx: ctx, cancel: cancel, stdin: &testWriteCloser{},
		pending:  map[string]pendingCall{"1": {method: "turn/interrupt", result: responses}},
		requests: make(chan struct{}, maxConcurrentServerRequests), done: make(chan struct{}),
	}
	client.readLoop(strings.NewReader(`{"id":1,"result":{},"error":{"code":-1,"message":"hybrid"}}`+"\n"), mustContract(t))
	select {
	case got := <-responses:
		if !errors.Is(got.err, ErrContractViolation) {
			t.Fatalf("hybrid response error = %v", got.err)
		}
	default:
		t.Fatal("hybrid response was not failed")
	}
}

func TestReadLoopRejectsDuplicateResponseDiscriminator(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	responses := make(chan response, 1)
	client := &Client{
		ctx: ctx, cancel: cancel, stdin: &testWriteCloser{},
		pending:  map[string]pendingCall{"1": {method: "turn/interrupt", result: responses}},
		requests: make(chan struct{}, maxConcurrentServerRequests), done: make(chan struct{}),
	}
	client.readLoop(strings.NewReader(`{"id":1,"result":null,"result":{}}`+"\n"), mustContract(t))
	select {
	case got := <-responses:
		if !errors.Is(got.err, ErrContractViolation) {
			t.Fatalf("duplicate response error = %v", got.err)
		}
	default:
		t.Fatal("duplicate response discriminator was not failed")
	}
}

func TestReadLoopRejectsUnknownResponseID(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &Client{
		ctx: ctx, cancel: cancel, stdin: &testWriteCloser{}, pending: make(map[string]pendingCall),
		requests: make(chan struct{}, maxConcurrentServerRequests), done: make(chan struct{}),
	}
	client.readLoop(strings.NewReader(`{"id":99,"result":{}}`+"\n"), mustContract(t))
	select {
	case <-ctx.Done():
	default:
		t.Fatal("unknown response id did not cancel the app-server epoch")
	}
}

func TestReadLoopRejectsUnclassifiedMessage(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &Client{
		ctx: ctx, cancel: cancel, stdin: &testWriteCloser{}, pending: make(map[string]pendingCall),
		requests: make(chan struct{}, maxConcurrentServerRequests), done: make(chan struct{}),
	}
	client.readLoop(strings.NewReader(`{}`+"\n"), mustContract(t))
	select {
	case <-ctx.Done():
	default:
		t.Fatal("unclassified app-server message did not cancel the epoch")
	}
}

func TestMarshalHandlerResultReturnsInternalErrorInsteadOfPanicking(t *testing.T) {
	result, rpcErr := marshalResult(make(chan int))
	if result != nil || rpcErr == nil || rpcErr.Code != -32603 {
		t.Fatalf("marshal result = %s, error = %#v", result, rpcErr)
	}
}

func TestServerRequestConcurrencyIsBounded(t *testing.T) {
	release := make(chan struct{})
	completed := make(chan struct{}, maxConcurrentServerRequests)
	var started atomic.Int32
	writer := &testWriteCloser{}
	client := &Client{
		ctx: context.Background(), stdin: writer, contract: mustContract(t),
		handler: HandlerFuncs{RequestFunc: func(context.Context, string, json.RawMessage) (any, *RPCError) {
			started.Add(1)
			<-release
			completed <- struct{}{}
			return map[string]any{"permissions": map[string]any{}, "scope": "turn", "strictAutoReview": true}, nil
		}},
		pending: make(map[string]pendingCall), requests: make(chan struct{}, maxConcurrentServerRequests), done: make(chan struct{}),
	}
	var input strings.Builder
	for index := 1; index <= maxConcurrentServerRequests+1; index++ {
		input.WriteString(validPermissionRequest(index))
		input.WriteByte('\n')
	}
	client.readLoop(strings.NewReader(input.String()), mustContract(t))
	deadline := time.Now().Add(time.Second)
	for started.Load() != maxConcurrentServerRequests && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if started.Load() != maxConcurrentServerRequests {
		t.Fatalf("started requests = %d", started.Load())
	}
	if !strings.Contains(writer.String(), "too many concurrent app-server requests") {
		t.Fatalf("overload response was not written: %s", writer.String())
	}
	close(release)
	for range maxConcurrentServerRequests {
		select {
		case <-completed:
		case <-time.After(time.Second):
			t.Fatal("bounded requests did not complete")
		}
	}
	deadline = time.Now().Add(time.Second)
	for len(client.requests) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(client.requests) != 0 {
		t.Fatal("app-server request workers did not drain")
	}
}

func mustContract(t *testing.T) *contractValidator {
	t.Helper()
	validator, err := loadFrozenContract()
	if err != nil {
		t.Fatal(err)
	}
	return validator
}

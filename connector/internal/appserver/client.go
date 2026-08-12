package appserver

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxAppServerMessageBytes    = 4 << 20
	maxConcurrentServerRequests = 8
	versionCheckTimeout         = 10 * time.Second
	defaultShutdownGracePeriod  = 2 * time.Second
	forcedShutdownWait          = 2 * time.Second
)

type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("JSON-RPC error %d: %s", e.Code, e.Message)
}

type Handler interface {
	Notification(method string, params json.RawMessage)
	Request(ctx context.Context, method string, params json.RawMessage) (any, *RPCError)
}

type HandlerFuncs struct {
	NotificationFunc func(string, json.RawMessage)
	RequestFunc      func(context.Context, string, json.RawMessage) (any, *RPCError)
}

func (h HandlerFuncs) Notification(method string, params json.RawMessage) {
	if h.NotificationFunc != nil {
		h.NotificationFunc(method, params)
	}
}

func (h HandlerFuncs) Request(ctx context.Context, method string, params json.RawMessage) (any, *RPCError) {
	if h.RequestFunc == nil {
		return nil, &RPCError{Code: -32601, Message: "server request is not allowed"}
	}
	return h.RequestFunc(ctx, method, params)
}

type StartOptions struct {
	Binary              string
	ExpectedVersion     string
	ConnectorVersion    string
	Stderr              io.Writer
	Handler             Handler
	InitializeTimeout   time.Duration
	ShutdownGracePeriod time.Duration
	OnContractFailure   func()
}

type Client struct {
	ctx      context.Context
	cancel   context.CancelFunc
	stdin    io.WriteCloser
	handler  Handler
	contract *contractValidator

	writeMu             sync.Mutex
	mu                  sync.Mutex
	pending             map[string]pendingCall
	requests            chan struct{}
	waitErr             error
	done                chan struct{}
	readDone            chan struct{}
	requestWorkers      sync.WaitGroup
	nextID              atomic.Uint64
	processID           int
	shutdownGracePeriod time.Duration

	contractFailureOnce sync.Once
	closeOnce           sync.Once
	onContractFailure   func()
}

type wireMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

type response struct {
	result json.RawMessage
	err    error
}

var ErrVersionMismatch = errors.New("Codex version mismatch")

type pendingCall struct {
	method string
	result chan response
}

func VerifyVersion(ctx context.Context, binary, expected string) error {
	if binary == "" {
		binary = "codex"
	}
	command := exec.CommandContext(ctx, binary, "--version")
	command.Stderr = io.Discard
	output, err := command.Output()
	if err != nil {
		return fmt.Errorf("read Codex version: %w", err)
	}
	if strings.TrimSpace(string(output)) != "codex-cli "+expected {
		return fmt.Errorf("%w: expected codex-cli %s", ErrVersionMismatch, expected)
	}
	return nil
}

func Start(parent context.Context, options StartOptions) (*Client, error) {
	if options.Binary == "" {
		options.Binary = "codex"
	}
	if options.ExpectedVersion == "" {
		return nil, errors.New("expected Codex version is required")
	}
	if options.InitializeTimeout <= 0 {
		options.InitializeTimeout = 15 * time.Second
	}
	if options.ShutdownGracePeriod <= 0 {
		options.ShutdownGracePeriod = defaultShutdownGracePeriod
	}
	validator, err := loadFrozenContract()
	if err != nil {
		if options.OnContractFailure != nil {
			options.OnContractFailure()
		}
		return nil, err
	}
	versionCtx, versionCancel := context.WithTimeout(parent, versionCheckTimeout)
	err = VerifyVersion(versionCtx, options.Binary, options.ExpectedVersion)
	versionCancel()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	command := exec.CommandContext(ctx, options.Binary, "app-server", "--listen", "stdio://")
	processTree, err := prepareAppServerProcess(command)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("prepare Codex app-server process tree: %w", err)
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		_ = processTree.close()
		cancel()
		return nil, err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = processTree.close()
		cancel()
		return nil, err
	}
	stderrCapture := newChildStderrCapture(options.Stderr)
	command.Stderr = stderrCapture
	if err := command.Start(); err != nil {
		_ = processTree.close()
		cancel()
		return nil, fmt.Errorf("start codex app-server: %w", err)
	}
	if err := processTree.attach(command.Process); err != nil {
		_ = stdin.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
		_ = processTree.close()
		cancel()
		return nil, fmt.Errorf("isolate Codex app-server process tree: %w", err)
	}
	if err := ctx.Err(); err != nil {
		_ = processTree.kill()
		_ = command.Wait()
		_ = processTree.close()
		cancel()
		return nil, fmt.Errorf("start Codex app-server: %w", err)
	}
	client := &Client{
		ctx: ctx, cancel: cancel, stdin: stdin, handler: options.Handler, contract: validator,
		pending: make(map[string]pendingCall), requests: make(chan struct{}, maxConcurrentServerRequests),
		done: make(chan struct{}), readDone: make(chan struct{}),
		processID: command.Process.Pid, shutdownGracePeriod: options.ShutdownGracePeriod,
		onContractFailure: options.OnContractFailure,
	}
	go func() {
		defer close(client.readDone)
		client.readLoop(stdout, validator)
	}()
	go func() {
		err := command.Wait()
		err = errors.Join(err, processTree.close())
		stderrCapture.report()
		client.mu.Lock()
		client.waitErr = err
		client.mu.Unlock()
		close(client.done)
	}()
	initCtx, initCancel := context.WithTimeout(ctx, options.InitializeTimeout)
	defer initCancel()
	initializeParams, err := json.Marshal(map[string]any{
		"clientInfo": map[string]string{
			"name": "sub2api-codex-connector", "title": "Sub2API Codex Connector", "version": options.ConnectorVersion,
		},
		"capabilities": map[string]any{},
	})
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("encode app-server initialize params: %w", err)
	}
	_, err = client.Call(initCtx, "initialize", initializeParams)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("initialize codex app-server: %w", err)
	}
	if err := client.Notify("initialized", json.RawMessage(`{}`)); err != nil {
		client.Close()
		return nil, fmt.Errorf("notify app-server initialized: %w", err)
	}
	return client, nil
}

func (c *Client) Call(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
	if method == "" {
		return nil, errors.New("JSON-RPC method is empty")
	}
	if c.contract == nil || c.contract.results[method] == nil {
		c.cancelBeforeReportingContractFailure()
		return nil, ErrContractViolation
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	id := c.nextID.Add(1)
	idRaw := json.RawMessage(strconv.FormatUint(id, 10))
	key := string(idRaw)
	result := make(chan response, 1)
	c.mu.Lock()
	c.pending[key] = pendingCall{method: method, result: result}
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, key)
		c.mu.Unlock()
	}()
	if err := c.writeContext(ctx, wireMessage{JSONRPC: "2.0", ID: idRaw, Method: method, Params: params}); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		c.mu.Lock()
		err := c.waitErr
		c.mu.Unlock()
		if err == nil {
			err = errors.New("app-server stopped")
		}
		return nil, err
	case response := <-result:
		return response.result, response.err
	}
}

func (c *Client) Notify(method string, params json.RawMessage) error {
	return c.write(wireMessage{JSONRPC: "2.0", Method: method, Params: params})
}

func (c *Client) Wait() error {
	<-c.done
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.waitErr
}

// ProcessID returns the Connector-owned app-server process ID for local
// lifecycle and listener admission checks. It never identifies unrelated Codex processes.
func (c *Client) ProcessID() int { return c.processID }

func (c *Client) Close() {
	c.closeOnce.Do(func() {
		c.writeMu.Lock()
		_ = c.stdin.Close()
		c.writeMu.Unlock()

		timer := time.NewTimer(c.shutdownGracePeriod)
		select {
		case <-c.done:
			if !timer.Stop() {
				<-timer.C
			}
			c.cancel()
		case <-timer.C:
			c.cancel()
		}

		forceTimer := time.NewTimer(forcedShutdownWait)
		select {
		case <-c.done:
			if !forceTimer.Stop() {
				<-forceTimer.C
			}
		case <-forceTimer.C:
		}
		c.waitForHandlers()
	})
}

func (c *Client) waitForHandlers() {
	if c.readDone != nil {
		<-c.readDone
	}
	c.requestWorkers.Wait()
}

func (c *Client) readLoop(stdout io.Reader, validator *contractValidator) {
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64<<10), maxAppServerMessageBytes)
	for scanner.Scan() {
		raw := append(json.RawMessage(nil), scanner.Bytes()...)
		var message wireMessage
		if err := json.Unmarshal(raw, &message); err != nil || (message.JSONRPC != "" && message.JSONRPC != "2.0") {
			c.cancelBeforeReportingContractFailure()
			return
		}
		if message.Method != "" {
			if hasID(message.ID) {
				if validator == nil || validator.validateServerRequest(raw) != nil {
					c.cancelBeforeReportingContractFailure()
					return
				}
				select {
				case c.requests <- struct{}{}:
					c.requestWorkers.Add(1)
					go func(request wireMessage) {
						defer c.requestWorkers.Done()
						defer func() { <-c.requests }()
						c.handleRequest(request, validator)
					}(message)
				default:
					c.writeServerResponse(message.Method, wireMessage{
						JSONRPC: "2.0", ID: message.ID,
						Error: &RPCError{Code: -32000, Message: "too many concurrent app-server requests"},
					}, validator)
				}
			} else {
				if validator == nil || validator.validateNotification(raw) != nil {
					c.cancelBeforeReportingContractFailure()
					return
				}
				if c.handler != nil {
					c.handler.Notification(message.Method, nonemptyParams(message.Params))
				}
			}
			continue
		}
		if hasID(message.ID) {
			c.mu.Lock()
			pending, found := c.pending[string(message.ID)]
			if found {
				delete(c.pending, string(message.ID))
			}
			c.mu.Unlock()
			if !found {
				c.cancelBeforeReportingContractFailure()
				return
			}
			method := pending.method
			if validator == nil || validator.validateResponse(method, raw, message.Result, message.Error) != nil {
				pending.result <- response{err: ErrContractViolation}
				c.cancelBeforeReportingContractFailure()
				return
			}
			if message.Error != nil {
				pending.result <- response{err: message.Error}
			} else {
				pending.result <- response{result: message.Result}
			}
		} else {
			c.cancelBeforeReportingContractFailure()
			return
		}
	}
	if scanner.Err() != nil {
		c.cancel()
	}
}

func (c *Client) cancelBeforeReportingContractFailure() {
	if c.cancel != nil {
		c.cancel()
	}
	c.reportContractFailure()
}

func (c *Client) reportContractFailure() {
	c.contractFailureOnce.Do(func() {
		if c.onContractFailure != nil {
			c.onContractFailure()
		}
	})
}

func (c *Client) handleRequest(message wireMessage, validator *contractValidator) {
	if c.handler == nil {
		c.writeServerResponse(message.Method, wireMessage{JSONRPC: "2.0", ID: message.ID, Error: &RPCError{Code: -32601, Message: "server request is not allowed"}}, validator)
		return
	}
	result, rpcErr := c.handler.Request(c.ctx, message.Method, nonemptyParams(message.Params))
	response := wireMessage{JSONRPC: "2.0", ID: message.ID, Error: rpcErr}
	if rpcErr == nil {
		encoded, encodeErr := marshalResult(result)
		if encodeErr != nil {
			response.Error = encodeErr
		} else {
			response.Result = encoded
		}
	}
	c.writeServerResponse(message.Method, response, validator)
}

func (c *Client) writeServerResponse(method string, response wireMessage, validator *contractValidator) {
	encoded, err := json.Marshal(response)
	if err != nil || validator == nil || validator.validateServerResponse(method, encoded, response.Result, response.Error) != nil {
		c.cancelBeforeReportingContractFailure()
		return
	}
	_ = c.writeEncoded(encoded)
}

func (c *Client) write(message wireMessage) error {
	return c.writeContext(context.Background(), message)
}

func (c *Client) writeContext(ctx context.Context, message wireMessage) error {
	data, err := json.Marshal(message)
	if err != nil {
		return err
	}
	return c.writeEncodedContext(ctx, data)
}

func (c *Client) writeEncoded(data []byte) error {
	return c.writeEncodedContext(context.Background(), data)
}

func (c *Client) writeEncodedContext(ctx context.Context, data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-c.done:
		return errors.New("app-server is not running")
	default:
	}
	data = append(data, '\n')
	if _, err := c.stdin.Write(data); err != nil {
		c.cancel()
		return err
	}
	return nil
}

func hasID(id json.RawMessage) bool {
	return len(id) > 0 && string(id) != "null"
}

func nonemptyParams(params json.RawMessage) json.RawMessage {
	if len(params) == 0 {
		return json.RawMessage(`{}`)
	}
	return params
}

func marshalResult(value any) (json.RawMessage, *RPCError) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, &RPCError{Code: -32603, Message: "handler returned a non-JSON result"}
	}
	return data, nil
}

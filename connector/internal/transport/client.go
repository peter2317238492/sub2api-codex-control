package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/auth"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/protocol"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/spool"
)

type HandlerFunc func(context.Context, protocol.Envelope) error

type ReconnectReason uint8

const (
	ReconnectToken ReconnectReason = iota + 1
	ReconnectDial
	ReconnectHandshake
	ReconnectConnectionIO
)

const (
	networkOperationTimeout   = 15 * time.Second
	maxBufferedIncomingFrames = 32
)

type Options struct {
	URL                 string
	DeviceID            string
	Epoch               string
	TokenSource         auth.TokenSource
	Spool               *spool.Spool
	HeartbeatInterval   time.Duration
	ReconnectMin        time.Duration
	ReconnectMax        time.Duration
	Hello               protocol.HelloPayload
	Handler             HandlerFunc
	StaleCommandHandler HandlerFunc
	OnConnected         func()
	OnDisconnect        func()
	OnReconnect         func(ReconnectReason)
	OnSpoolChanged      func()
	OnSchemaFailure     func()
}

type Client struct {
	options Options
	notify  chan struct{}
	emitMu  sync.Mutex
}

func New(options Options) (*Client, error) {
	if options.URL == "" || options.DeviceID == "" || len(options.Epoch) < 16 || options.TokenSource == nil || options.Spool == nil || options.Handler == nil {
		return nil, errors.New("transport options are incomplete")
	}
	if options.HeartbeatInterval <= 0 {
		options.HeartbeatInterval = 20 * time.Second
	}
	if options.ReconnectMin <= 0 {
		options.ReconnectMin = time.Second
	}
	if options.ReconnectMax < options.ReconnectMin {
		options.ReconnectMax = 30 * time.Second
	}
	return &Client{options: options, notify: make(chan struct{}, 1)}, nil
}

func (c *Client) Emit(ctx context.Context, envelopeType string, payload any) error {
	return c.EmitForEpoch(ctx, c.options.Epoch, envelopeType, payload)
}

// EmitForEpoch preserves the epoch of a recovered terminal command result.
// Only the journal-backed stale command recovery path uses a non-current epoch.
func (c *Client) EmitForEpoch(ctx context.Context, epoch, envelopeType string, payload any) error {
	if len(epoch) < 16 {
		return errors.New("outbound envelope epoch is invalid")
	}
	canaryLocked := productionCanaryLockEmit(envelopeType)
	defer productionCanaryUnlockEmit(canaryLocked)
	c.emitMu.Lock()
	defer c.emitMu.Unlock()
	payloadRaw, err := protocol.MarshalPayload(payload)
	if err != nil {
		return err
	}
	if len(payloadRaw) > protocol.MaxProjectedPayloadBytes {
		return fmt.Errorf("outbound payload exceeds %d bytes", protocol.MaxProjectedPayloadBytes)
	}
	id, err := protocol.NewID()
	if err != nil {
		return err
	}
	ack := c.options.Spool.LastReceived()
	_, err = c.options.Spool.Append(func(sequence uint64) ([]byte, error) {
		envelope := protocol.Envelope{
			Version: protocol.Version, ID: id, DeviceID: c.options.DeviceID, Epoch: epoch,
			Seq: sequence, Ack: &ack, Type: envelopeType, SentAt: time.Now().UTC(), Payload: payloadRaw,
		}
		if err := envelope.ValidateWire(); err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(envelope)
		if err != nil {
			return nil, err
		}
		if len(encoded) > protocol.MaxFrameBytes {
			return nil, fmt.Errorf("outbound envelope exceeds %d bytes", protocol.MaxFrameBytes)
		}
		return encoded, nil
	})
	if err != nil {
		return err
	}
	productionCanaryAfterSpool(envelopeType)
	if c.options.OnSpoolChanged != nil {
		c.options.OnSpoolChanged()
	}
	select {
	case c.notify <- struct{}{}:
	default:
	}
	return nil
}

func (c *Client) Run(ctx context.Context) error {
	reconnects := newReconnectPolicy(
		c.options.ReconnectMin,
		c.options.ReconnectMax,
		2*c.options.HeartbeatInterval,
	)
	for {
		err := c.runConnection(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var failure *connectionFailure
		if !errors.As(err, &failure) || !failure.retryable {
			return err
		}
		if errors.Is(err, ErrRefreshToken) {
			c.options.TokenSource.Invalidate()
		}
		delay, reconnectErr := reconnects.afterFailure(failure.connectedFor)
		if reconnectErr != nil {
			return reconnectErr
		}
		if c.options.OnReconnect != nil {
			c.options.OnReconnect(failure.reason)
		}
		timer := time.NewTimer(jitter(delay))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

var ErrRefreshToken = errors.New("refresh device token")

func (c *Client) runConnection(ctx context.Context) error {
	tokenCtx, cancelToken := context.WithTimeout(ctx, networkOperationTimeout)
	token, err := c.options.TokenSource.Token(tokenCtx)
	cancelToken()
	if err != nil {
		return classifyConnectionFailureWithReason(retryableOperation(err), 0, ReconnectToken)
	}
	tokenRefreshDeadline := token.ExpiresAt.Add(-15 * time.Second)
	if !tokenRefreshDeadline.After(time.Now()) {
		return classifyConnectionFailureWithReason(ErrRefreshToken, 0, ReconnectToken)
	}
	header := make(http.Header)
	header.Set("Authorization", "Bearer "+token.Value)
	dialCtx, cancelDial := context.WithTimeout(ctx, networkOperationTimeout)
	connection, response, err := websocket.Dial(dialCtx, c.options.URL, &websocket.DialOptions{HTTPHeader: header})
	cancelDial()
	if err != nil {
		if response != nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
				c.options.TokenSource.Invalidate()
				return classifyConnectionFailureWithReason(ErrRefreshToken, 0, ReconnectToken)
			}
			if response.StatusCode >= 400 && response.StatusCode < 500 &&
				response.StatusCode != http.StatusRequestTimeout &&
				response.StatusCode != http.StatusTooEarly &&
				response.StatusCode != http.StatusTooManyRequests {
				return classifyConnectionFailureWithReason(err, 0, ReconnectDial)
			}
		}
		return classifyConnectionFailureWithReason(retryableOperation(err), 0, ReconnectDial)
	}
	connection.SetReadLimit(protocol.MaxFrameBytes)
	connectionCtx, cancel := context.WithDeadline(ctx, tokenRefreshDeadline)
	defer cancel()
	defer connection.CloseNow()
	var disconnectOnce sync.Once
	disconnect := func() {
		disconnectOnce.Do(func() {
			if c.options.OnDisconnect != nil {
				c.options.OnDisconnect()
			}
		})
	}
	defer disconnect()
	handshakeCtx, cancelHandshake := context.WithTimeout(connectionCtx, networkOperationTimeout)
	heartbeatTimeout, err := c.handshake(handshakeCtx, connection)
	cancelHandshake()
	if err != nil {
		if errors.Is(err, ErrSchemaMismatch) && c.options.OnSchemaFailure != nil {
			c.options.OnSchemaFailure()
		}
		tokenDeadlineReached := ctx.Err() == nil && errors.Is(connectionCtx.Err(), context.DeadlineExceeded)
		if tokenDeadlineReached {
			return classifyEstablishedConnectionFailure(err, 0, true)
		}
		return classifyConnectionFailureWithReason(err, 0, ReconnectHandshake)
	}
	connectedAt := time.Now()
	heartbeatInterval := c.options.HeartbeatInterval
	if serverInterval := heartbeatTimeout / 3; serverInterval > 0 && serverInterval < heartbeatInterval {
		heartbeatInterval = serverInterval
	}
	backlogCutoff := c.options.Spool.LastAssigned()
	if c.options.OnConnected != nil {
		c.options.OnConnected()
	}
	errorsChannel := make(chan error, 2)
	var handlerWorkers sync.WaitGroup
	go func() { errorsChannel <- c.readLoop(connectionCtx, connection, &handlerWorkers) }()
	go func() { errorsChannel <- c.writeLoop(connectionCtx, connection, backlogCutoff, heartbeatInterval) }()
	err = <-errorsChannel
	tokenDeadlineReached := ctx.Err() == nil && errors.Is(connectionCtx.Err(), context.DeadlineExceeded)
	cancel()
	disconnect()
	<-errorsChannel
	handlerWorkers.Wait()
	return classifyEstablishedConnectionFailure(err, time.Since(connectedAt), tokenDeadlineReached)
}

func classifyEstablishedConnectionFailure(err error, connectedFor time.Duration, tokenDeadlineReached bool) error {
	if tokenDeadlineReached {
		err = fmt.Errorf("%w: %w", ErrRefreshToken, err)
	}
	if errors.Is(err, ErrRefreshToken) {
		return classifyConnectionFailureWithReason(err, connectedFor, ReconnectToken)
	}
	return classifyConnectionFailureWithReason(err, connectedFor, ReconnectConnectionIO)
}

func (c *Client) writeLoop(ctx context.Context, connection *websocket.Conn, backlogCutoff uint64, heartbeatInterval time.Duration) error {
	var lastSent uint64
	flush := func() error {
		productionCanaryLockFlush()
		defer productionCanaryUnlockFlush()
		records, err := c.options.Spool.Pending()
		if err != nil {
			return err
		}
		for _, record := range records {
			if record.Sequence <= lastSent {
				continue
			}
			data, err := c.projectPendingRecord(record, record.Sequence <= backlogCutoff)
			if err != nil {
				return err
			}
			if err := connection.Write(ctx, websocket.MessageText, data); err != nil {
				return connectionIOError(err)
			}
			lastSent = record.Sequence
		}
		return nil
	}
	if err := flush(); err != nil {
		return err
	}
	heartbeats := time.NewTicker(heartbeatInterval)
	defer heartbeats.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-heartbeats.C:
			if err := c.Emit(ctx, protocol.TypeHeartbeat, map[string]string{"status": "ok"}); err != nil {
				return err
			}
			if err := flush(); err != nil {
				return err
			}
		case <-c.notify:
			if err := flush(); err != nil {
				return err
			}
		}
	}
}

func (c *Client) readLoop(ctx context.Context, connection *websocket.Conn, handlerWorkers *sync.WaitGroup) error {
	type readResult struct {
		envelope protocol.Envelope
		err      error
	}
	type handlerResult struct {
		sequence uint64
		err      error
	}
	type pendingFrame struct {
		envelope  protocol.Envelope
		started   bool
		completed bool
	}
	reads := make(chan readResult, 1)
	go func() {
		for {
			envelope, err := c.readEnvelope(ctx, connection)
			select {
			case reads <- readResult{envelope: envelope, err: err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()

	results := make(chan handlerResult, maxBufferedIncomingFrames)
	queue := make([]*pendingFrame, 0, maxBufferedIncomingFrames)
	bySequence := make(map[uint64]*pendingFrame, maxBufferedIncomingFrames)
	lastReceived := c.options.Spool.LastReceived()
	if lastReceived >= protocol.MaxSequence {
		return errors.New("incoming wire sequence space is exhausted")
	}
	nextSequence := lastReceived + 1
	var approvalInFlight uint64
	start := func(frame *pendingFrame) {
		if frame.started {
			return
		}
		frame.started = true
		if frame.envelope.Type == protocol.TypeApprovalDecision {
			approvalInFlight = frame.envelope.Seq
		}
		handlerWorkers.Add(1)
		go func() {
			defer handlerWorkers.Done()
			handler := c.options.Handler
			if frame.envelope.Epoch != c.options.Epoch {
				handler = c.options.StaleCommandHandler
			}
			result := handlerResult{
				sequence: frame.envelope.Seq,
				err:      handler(ctx, frame.envelope),
			}
			select {
			case results <- result:
			case <-ctx.Done():
			}
		}()
	}
	startNextApproval := func() {
		if approvalInFlight != 0 || len(queue) == 0 {
			return
		}
		startAt := 0
		if queue[0].envelope.Type != protocol.TypeApprovalDecision {
			// Only a command can synchronously block on an app-server approval.
			// The scan below may cross a heartbeat acknowledgement because its
			// handler is a no-op; every other non-decision frame remains a barrier.
			if queue[0].envelope.Type != protocol.TypeCommand || !queue[0].started || queue[0].completed {
				return
			}
			startAt = 1
		}
		for _, frame := range queue[startAt:] {
			if frame.completed && frame.envelope.Epoch != c.options.Epoch {
				continue
			}
			if frame.envelope.Type == protocol.TypeHeartbeatAck && !frame.started && !frame.completed {
				continue
			}
			if frame.envelope.Type != protocol.TypeApprovalDecision {
				return
			}
			if !frame.started {
				start(frame)
				return
			}
		}
	}
	startHead := func() {
		if len(queue) == 0 || queue[0].started {
			return
		}
		if queue[0].envelope.Type == protocol.TypeApprovalDecision {
			startNextApproval()
			return
		}
		start(queue[0])
	}
	drain := func() error {
		for len(queue) > 0 && queue[0].completed {
			head := queue[0]
			if err := c.options.Spool.CommitIncoming(head.envelope.Seq); err != nil {
				return err
			}
			delete(bySequence, head.envelope.Seq)
			queue = queue[1:]
		}
		startHead()
		return nil
	}

	for {
		var incoming <-chan readResult
		if len(queue) < maxBufferedIncomingFrames {
			incoming = reads
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case result := <-results:
			frame := bySequence[result.sequence]
			if frame == nil {
				return fmt.Errorf("handler completed unknown incoming sequence %d", result.sequence)
			}
			if frame.completed {
				return fmt.Errorf("handler completed incoming sequence %d more than once", result.sequence)
			}
			frame.completed = true
			if frame.envelope.Type == protocol.TypeApprovalDecision {
				if approvalInFlight != result.sequence {
					return fmt.Errorf("approval handler completed out of order at incoming sequence %d", result.sequence)
				}
				approvalInFlight = 0
			}
			if result.err != nil {
				// A failed speculative approval must not permit any later semantic
				// effects. Token refresh is the sole handler error that consumes its
				// frame, and it can only be the non-speculative queue head.
				if errors.Is(result.err, ErrRefreshToken) && len(queue) > 0 && queue[0] == frame {
					if err := c.options.Spool.CommitIncoming(frame.envelope.Seq); err != nil {
						return err
					}
				}
				return result.err
			}
			if err := drain(); err != nil {
				return err
			}
			startNextApproval()
		case result := <-incoming:
			if result.err != nil {
				return result.err
			}
			envelope := result.envelope
			if envelope.Ack != nil {
				if err := c.options.Spool.Ack(*envelope.Ack); err != nil {
					return err
				}
				if c.options.OnSpoolChanged != nil {
					c.options.OnSpoolChanged()
				}
			}
			if envelope.Seq <= c.options.Spool.LastReceived() {
				continue
			}
			if envelope.Seq != nextSequence {
				return fmt.Errorf("incoming sequence gap: received %d before %d", envelope.Seq, nextSequence)
			}
			if nextSequence == protocol.MaxSequence {
				nextSequence = protocol.MaxSequence + 1
			} else {
				nextSequence++
			}
			// Server outbox sequences are durable across app-server epochs. A prior
			// epoch frame advances the cursor without semantic handling. Commands may
			// use the separate journal-only recovery handler to finish a durable ACK.
			staleEpoch := envelope.Epoch != c.options.Epoch
			recoverStaleCommand := staleEpoch && envelope.Type == protocol.TypeCommand && c.options.StaleCommandHandler != nil
			frame := &pendingFrame{envelope: envelope, completed: staleEpoch && !recoverStaleCommand}
			queue = append(queue, frame)
			bySequence[envelope.Seq] = frame
			if err := drain(); err != nil {
				return err
			}
			startNextApproval()
		}
	}
}

func (c *Client) readEnvelope(ctx context.Context, connection *websocket.Conn) (protocol.Envelope, error) {
	messageType, data, err := connection.Read(ctx)
	if err != nil {
		return protocol.Envelope{}, connectionIOError(err)
	}
	if messageType != websocket.MessageText {
		return protocol.Envelope{}, errors.New("device channel only accepts text JSON envelopes")
	}
	var envelope protocol.Envelope
	if err := decodeStrict(data, &envelope); err != nil {
		return protocol.Envelope{}, fmt.Errorf("decode control envelope: %w", err)
	}
	if err := envelope.ValidateWire(); err != nil {
		return protocol.Envelope{}, err
	}
	if envelope.DeviceID != c.options.DeviceID {
		return protocol.Envelope{}, errors.New("control envelope targets a different device")
	}
	if envelope.Seq == 0 {
		return protocol.Envelope{}, errors.New("handshake envelope received after admission")
	}
	return envelope, nil
}

func (c *Client) handshake(ctx context.Context, connection *websocket.Conn) (time.Duration, error) {
	hello := c.options.Hello
	hello.ResumedFromSeq = c.options.Spool.LastAcked()
	payload, err := protocol.MarshalPayload(hello)
	if err != nil {
		return 0, err
	}
	id, err := protocol.NewID()
	if err != nil {
		return 0, err
	}
	ack := c.options.Spool.LastReceived()
	envelope := protocol.Envelope{
		Version: protocol.Version, ID: id, DeviceID: c.options.DeviceID, Epoch: c.options.Epoch,
		Seq: 0, Ack: &ack, Type: protocol.TypeHello, SentAt: time.Now().UTC(), Payload: payload,
	}
	if err := envelope.ValidateWire(); err != nil {
		return 0, err
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return 0, err
	}
	if len(encoded) > protocol.MaxFrameBytes {
		return 0, errors.New("hello envelope exceeds the protocol frame limit")
	}
	if err := connection.Write(ctx, websocket.MessageText, encoded); err != nil {
		return 0, connectionIOError(err)
	}
	messageType, data, err := connection.Read(ctx)
	if err != nil {
		return 0, connectionIOError(err)
	}
	if messageType != websocket.MessageText {
		return 0, errors.New("hello acknowledgement must be a text JSON envelope")
	}
	var acknowledgement protocol.Envelope
	if err := decodeStrict(data, &acknowledgement); err != nil {
		return 0, fmt.Errorf("decode hello acknowledgement: %w", err)
	}
	if err := acknowledgement.ValidateWire(); err != nil {
		return 0, err
	}
	if acknowledgement.Type != protocol.TypeHelloAck || acknowledgement.Seq != 0 ||
		acknowledgement.DeviceID != c.options.DeviceID || acknowledgement.Epoch != c.options.Epoch || acknowledgement.Ack == nil {
		return 0, errors.New("hello acknowledgement does not match this connection")
	}
	var helloAck protocol.HelloAckPayload
	if err := decodeStrict(acknowledgement.Payload, &helloAck); err != nil {
		return 0, fmt.Errorf("decode hello acknowledgement payload: %w", err)
	}
	if helloAck.SchemaDigest != hello.SchemaDigest {
		return 0, ErrSchemaMismatch
	}
	if helloAck.ProtocolVersion != protocol.Version || helloAck.DeviceID != c.options.DeviceID ||
		helloAck.Epoch != c.options.Epoch ||
		!protocol.IsUUID(helloAck.ConnectionID) || helloAck.ReceivedSeq != *acknowledgement.Ack ||
		helloAck.HeartbeatTimeoutSeconds < 5 || helloAck.HeartbeatTimeoutSeconds > 300 {
		return 0, errors.New("hello acknowledgement failed protocol, identity, epoch, or schema validation")
	}
	if err := c.options.Spool.Ack(helloAck.ReceivedSeq); err != nil {
		return 0, fmt.Errorf("apply hello acknowledgement: %w", err)
	}
	if c.options.OnSpoolChanged != nil {
		c.options.OnSpoolChanged()
	}
	return time.Duration(helloAck.HeartbeatTimeoutSeconds) * time.Second, nil
}

var ErrSchemaMismatch = errors.New("device transport schema digest mismatch")

func (c *Client) projectPendingRecord(record spool.Record, backlog bool) ([]byte, error) {
	var envelope protocol.Envelope
	if err := decodeStrict(record.Data, &envelope); err != nil {
		return nil, fmt.Errorf("decode spooled envelope %d: %w", record.Sequence, err)
	}
	if envelope.Seq != record.Sequence || envelope.DeviceID != c.options.DeviceID {
		return nil, fmt.Errorf("spooled envelope %d has inconsistent identity", record.Sequence)
	}
	staleEpoch := envelope.Epoch != c.options.Epoch
	legacyHandshake := envelope.Type == protocol.TypeHello || envelope.Type == protocol.TypeHelloAck
	staleApproval := backlog && envelope.Type == protocol.TypeApprovalRequest
	staleHeartbeat := backlog && (envelope.Type == protocol.TypeHeartbeat || envelope.Type == protocol.TypeHeartbeatAck)
	oversized := len(record.Data) > protocol.MaxFrameBytes
	if !legacyHandshake && !staleApproval && !staleHeartbeat && !oversized &&
		(!staleEpoch || envelope.Type == protocol.TypeEvent || envelope.Type == protocol.TypeCommandAck || envelope.Type == protocol.TypeError) {
		if err := envelope.ValidateWire(); err != nil {
			return nil, err
		}
		return record.Data, nil
	}
	message := "stale non-audit frame discarded during reconnect"
	code := "invalid_epoch"
	if staleApproval {
		message = "approval request canceled when the device channel disconnected"
	}
	if staleHeartbeat {
		message = "stale heartbeat discarded during reconnect"
	}
	if oversized {
		message = "oversized legacy frame discarded during reconnect"
		code = "invalid_envelope"
	}
	payload, err := protocol.MarshalPayload(protocol.ProtocolError{Code: code, Message: message, Retryable: false})
	if err != nil {
		return nil, err
	}
	envelope.Type = protocol.TypeError
	envelope.Payload = payload
	if envelope.Seq == 0 {
		envelope.Seq = record.Sequence
	}
	if err := envelope.ValidateWire(); err != nil {
		return nil, err
	}
	return json.Marshal(envelope)
}

func decodeStrict(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON value has trailing data")
		}
		return err
	}
	return nil
}

func jitter(base time.Duration) time.Duration {
	// Time-derived bounded jitter is sufficient here; it is not used for security.
	nanos := time.Now().UnixNano()
	percent := 80 + nanos%41
	return time.Duration(int64(base) * percent / 100)
}

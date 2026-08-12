package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/peter2317238492/sub2api-codex-control/connector/internal/approval"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/localstate"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/policy"
	"github.com/peter2317238492/sub2api-codex-control/connector/internal/protocol"
)

var ErrRefreshToken = errors.New("control server requested a device token refresh")

const (
	maxIdempotencyKeyLength  = 128
	maxCommandMethodLength   = 128
	maxCommandHorizon        = 2 * time.Minute
	maxProtocolCodeLength    = 128
	maxProtocolMessageLength = 4096
)

type EnvelopeEmitter interface {
	Emit(context.Context, string, any) error
}

type epochEnvelopeEmitter interface {
	EmitForEpoch(context.Context, string, string, any) error
}

type Handler struct {
	Epoch          string
	Router         CommandRouter
	Broker         *approval.Broker
	Commands       *localstate.CommandStore
	Emitter        EnvelopeEmitter
	Now            func() time.Time
	OnPolicyDenial func(string) error
}

type CommandRouter interface {
	Call(context.Context, string, json.RawMessage) (json.RawMessage, error)
}

func (h *Handler) Handle(ctx context.Context, envelope protocol.Envelope) error {
	now := h.Now
	if now == nil {
		now = time.Now
	}
	switch envelope.Type {
	case protocol.TypeCommand:
		return h.handleCommand(ctx, envelope, now)
	case protocol.TypeApprovalDecision:
		if envelope.Epoch != h.Epoch {
			return h.emitError(ctx, "invalid_epoch", "approval decision belongs to a stale app-server epoch", false)
		}
		var payload protocol.ApprovalDecisionPayload
		if err := decodeStrict(envelope.Payload, &payload); err != nil {
			return h.emitError(ctx, "invalid_envelope", "approval decision payload is invalid", false)
		}
		if err := h.Broker.Resolve(envelope.Epoch, payload); err != nil {
			return h.emitError(ctx, "conflict", "approval decision could not be applied", false)
		}
		return nil
	case protocol.TypeHeartbeat:
		return h.Emitter.Emit(ctx, protocol.TypeHeartbeatAck, map[string]uint64{"received_seq": envelope.Seq})
	case protocol.TypeTokenRefresh:
		return ErrRefreshToken
	case protocol.TypeHelloAck, protocol.TypeHeartbeatAck:
		return nil
	default:
		return h.emitError(ctx, "invalid_envelope", "server sent an envelope type that devices do not accept", false)
	}
}

func (h *Handler) handleCommand(ctx context.Context, envelope protocol.Envelope, now func() time.Time) error {
	var command protocol.CommandPayload
	if err := decodeStrict(envelope.Payload, &command); err != nil {
		return h.emitError(ctx, "invalid_envelope", "command payload is not valid for the remote-control protocol", false)
	}
	if !protocol.IsUUID(command.CommandID) {
		return h.emitError(ctx, "invalid_envelope", "command id must be a UUID", false)
	}
	checkedAt := now()
	if command.IdempotencyKey == "" || utf8.RuneCountInString(command.IdempotencyKey) > maxIdempotencyKeyLength ||
		command.Method == "" || utf8.RuneCountInString(command.Method) > maxCommandMethodLength ||
		command.DeadlineAt.IsZero() || command.DeadlineAt.After(checkedAt.Add(maxCommandHorizon)) {
		return h.emitCommandAck(ctx, protocol.CommandAckPayload{
			CommandID: command.CommandID, State: "denied",
			Error: &protocol.ProtocolError{Code: "invalid_envelope", Message: "command payload is incomplete", Retryable: false},
		})
	}
	fingerprint := commandFingerprint(command)
	if envelope.Epoch != h.Epoch {
		return h.replayStaleCommand(ctx, command, fingerprint, envelope.Epoch)
	}
	begin, err := h.Commands.Begin(command.IdempotencyKey, fingerprint, command.CommandID, envelope.Epoch)
	if err != nil {
		return err
	}
	switch begin.State {
	case localstate.CommandTerminal:
		var acknowledgement protocol.CommandAckPayload
		if err := json.Unmarshal(begin.Ack, &acknowledgement); err != nil {
			return err
		}
		if err := h.recordPolicyDenial(command.CommandID, acknowledgement); err != nil {
			return err
		}
		return h.Emitter.Emit(ctx, protocol.TypeCommandAck, acknowledgement)
	case localstate.CommandIndeterminate:
		ack := protocol.CommandAckPayload{
			CommandID: command.CommandID, State: "failed",
			Error: &protocol.ProtocolError{
				Code: "indeterminate", Message: begin.Reason + "; the connector will not replay a possibly completed mutation", Retryable: false,
			},
		}
		return h.resolveIndeterminateAndEmit(ctx, command, fingerprint, envelope.Epoch, ack)
	case localstate.CommandConflict:
		return h.emitCommandAck(ctx, protocol.CommandAckPayload{
			CommandID: command.CommandID, State: "denied",
			Error: &protocol.ProtocolError{Code: "conflict", Message: begin.Reason, Retryable: false},
		})
	case localstate.CommandExecuting:
		// The durable executing record is in place before app-server dispatch.
	default:
		return errors.New("command journal returned an unknown state")
	}
	checkedAt = now()
	if !checkedAt.Before(command.DeadlineAt) {
		return h.completeAndEmit(ctx, command, fingerprint, envelope.Epoch, protocol.CommandAckPayload{
			CommandID: command.CommandID, State: "expired",
			Error: &protocol.ProtocolError{Code: "expired", Message: "command deadline has passed", Retryable: false},
		})
	}
	if reason := policy.DenialReason(command.Method); reason != "" {
		return h.completeAndEmit(ctx, command, fingerprint, envelope.Epoch, protocol.CommandAckPayload{
			CommandID: command.CommandID, State: "denied",
			Error: &protocol.ProtocolError{Code: "policy_denied", Message: reason, Retryable: false},
		})
	}
	callCtx, cancel := context.WithDeadline(ctx, command.DeadlineAt)
	defer cancel()
	result, err := h.Router.Call(callCtx, command.Method, command.Params)
	if err != nil {
		state := "failed"
		code := "upstream_error"
		retryable := true
		message := "Codex app-server request failed"
		if policy.IsDenied(err) {
			state = "denied"
			code = "policy_denied"
			retryable = false
			message = "command parameters were denied by the remote-control policy"
		} else if mutationMethod(command.Method) {
			code = "indeterminate"
			retryable = false
			message = "Codex may have applied the mutation before the result became unavailable; it will not be replayed"
		} else if errors.Is(err, context.DeadlineExceeded) {
			state = "expired"
			code = "expired"
			retryable = false
			message = "Codex app-server request exceeded the command deadline"
		}
		return h.completeAndEmit(ctx, command, fingerprint, envelope.Epoch, protocol.CommandAckPayload{
			CommandID: command.CommandID, State: state,
			Error: &protocol.ProtocolError{Code: code, Message: message, Retryable: retryable},
		})
	}
	projected, err := policy.ProjectResult(command.Method, result)
	if err != nil {
		code := "invalid_upstream"
		message := "Codex app-server returned a result outside the remote-control contract"
		if mutationMethod(command.Method) {
			code = "indeterminate"
			message = "Codex may have applied the mutation but returned an invalid result; it will not be replayed"
		}
		return h.completeAndEmit(ctx, command, fingerprint, envelope.Epoch, protocol.CommandAckPayload{
			CommandID: command.CommandID, State: "failed",
			Error: &protocol.ProtocolError{
				Code: code, Message: message, Retryable: false,
			},
		})
	}
	return h.completeAndEmit(ctx, command, fingerprint, envelope.Epoch, protocol.CommandAckPayload{
		CommandID: command.CommandID, State: "completed", Result: projected,
	})
}

func (h *Handler) replayStaleCommand(
	ctx context.Context,
	command protocol.CommandPayload,
	fingerprint string,
	staleEpoch string,
) error {
	replay, err := h.Commands.Replay(command.IdempotencyKey, fingerprint, command.CommandID)
	if err != nil {
		return err
	}
	switch replay.State {
	case localstate.CommandTerminal:
		var acknowledgement protocol.CommandAckPayload
		if err := json.Unmarshal(replay.Ack, &acknowledgement); err != nil {
			return err
		}
		if acknowledgement.CommandID != command.CommandID {
			return errors.New("durable terminal acknowledgement has an inconsistent command identity")
		}
		if err := h.recordPolicyDenial(command.CommandID, acknowledgement); err != nil {
			return err
		}
		return h.emitForEpoch(ctx, staleEpoch, protocol.TypeCommandAck, acknowledgement)
	case localstate.CommandIndeterminate:
		ack := protocol.CommandAckPayload{
			CommandID: command.CommandID, State: "failed",
			Error: &protocol.ProtocolError{
				Code: "indeterminate", Message: replay.Reason + "; the connector will not replay a possibly completed mutation", Retryable: false,
			},
		}
		return h.resolveIndeterminateAndEmit(ctx, command, fingerprint, staleEpoch, ack)
	case localstate.CommandConflict:
		return h.emitCommandAckForEpoch(ctx, staleEpoch, protocol.CommandAckPayload{
			CommandID: command.CommandID, State: "denied",
			Error: &protocol.ProtocolError{Code: "invalid_epoch", Message: "command belongs to a stale app-server epoch", Retryable: true},
		})
	default:
		return errors.New("command journal returned an unknown stale replay state")
	}
}

func (h *Handler) completeAndEmit(
	ctx context.Context,
	command protocol.CommandPayload,
	fingerprint string,
	epoch string,
	ack protocol.CommandAckPayload,
) error {
	ack = normalizeCommandAck(ack)
	data, err := json.Marshal(ack)
	if err != nil {
		return err
	}
	if err := h.Commands.Complete(command.IdempotencyKey, fingerprint, command.CommandID, epoch, data); err != nil {
		return err
	}
	if err := h.recordPolicyDenial(command.CommandID, ack); err != nil {
		return err
	}
	return h.emitForEpoch(ctx, epoch, protocol.TypeCommandAck, ack)
}

func (h *Handler) recordPolicyDenial(commandID string, ack protocol.CommandAckPayload) error {
	if ack.State != "denied" || ack.Error == nil || ack.Error.Code != "policy_denied" || h.OnPolicyDenial == nil {
		return nil
	}
	return h.OnPolicyDenial(localstate.PolicyDenialReceiptKey(commandID))
}

func (h *Handler) resolveIndeterminateAndEmit(
	ctx context.Context,
	command protocol.CommandPayload,
	fingerprint string,
	epoch string,
	ack protocol.CommandAckPayload,
) error {
	ack = normalizeCommandAck(ack)
	data, err := json.Marshal(ack)
	if err != nil {
		return err
	}
	if err := h.Commands.ResolveIndeterminate(command.IdempotencyKey, fingerprint, command.CommandID, epoch, data); err != nil {
		return err
	}
	return h.emitForEpoch(ctx, epoch, protocol.TypeCommandAck, ack)
}

func (h *Handler) emitCommandAck(ctx context.Context, ack protocol.CommandAckPayload) error {
	return h.Emitter.Emit(ctx, protocol.TypeCommandAck, normalizeCommandAck(ack))
}

func (h *Handler) emitCommandAckForEpoch(ctx context.Context, epoch string, ack protocol.CommandAckPayload) error {
	return h.emitForEpoch(ctx, epoch, protocol.TypeCommandAck, normalizeCommandAck(ack))
}

func (h *Handler) emitForEpoch(ctx context.Context, epoch, envelopeType string, value any) error {
	if epoch == h.Epoch {
		return h.Emitter.Emit(ctx, envelopeType, value)
	}
	emitter, ok := h.Emitter.(epochEnvelopeEmitter)
	if !ok {
		return errors.New("stale command acknowledgement emitter cannot preserve its app-server epoch")
	}
	return emitter.EmitForEpoch(ctx, epoch, envelopeType, value)
}

func commandFingerprint(command protocol.CommandPayload) string {
	value := append([]byte(command.Method+"\n"), command.Params...)
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func mutationMethod(method string) bool {
	switch method {
	case "thread/start", "thread/resume", "turn/start", "turn/steer", "turn/interrupt":
		return true
	default:
		return false
	}
}

func (h *Handler) emitError(ctx context.Context, code, message string, retryable bool) error {
	protocolError := normalizeProtocolError(&protocol.ProtocolError{Code: code, Message: message, Retryable: retryable})
	return h.Emitter.Emit(ctx, protocol.TypeError, *protocolError)
}

func normalizeCommandAck(ack protocol.CommandAckPayload) protocol.CommandAckPayload {
	ack.Error = normalizeProtocolError(ack.Error)
	return ack
}

func normalizeProtocolError(protocolError *protocol.ProtocolError) *protocol.ProtocolError {
	if protocolError == nil {
		return nil
	}
	result := *protocolError
	result.Code = truncateRunes(strings.TrimSpace(result.Code), maxProtocolCodeLength)
	if result.Code == "" {
		result.Code = "internal_error"
	}
	result.Message = strings.Map(func(character rune) rune {
		if character == '\n' || character == '\r' || character == '\t' {
			return ' '
		}
		if character < 0x20 || character == 0x7f {
			return -1
		}
		return character
	}, result.Message)
	result.Message = truncateRunes(strings.TrimSpace(result.Message), maxProtocolMessageLength)
	if result.Message == "" {
		result.Message = "remote-control operation failed"
	}
	return &result
}

func truncateRunes(value string, maximum int) string {
	if utf8.RuneCountInString(value) <= maximum {
		return value
	}
	return string([]rune(value)[:maximum])
}

func decodeStrict(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("payload contains trailing JSON")
		}
		return err
	}
	return nil
}

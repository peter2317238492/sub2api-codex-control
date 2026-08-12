package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	Version                         = 1
	MaxFrameBytes                   = 256 << 10
	MaxProjectedPayloadBytes        = 224 << 10
	MaxSequence              uint64 = 1<<63 - 1
)

const (
	TypeHello            = "hello"
	TypeHelloAck         = "hello_ack"
	TypeHeartbeat        = "heartbeat"
	TypeHeartbeatAck     = "heartbeat_ack"
	TypeCommand          = "command"
	TypeCommandAck       = "command_ack"
	TypeEvent            = "event"
	TypeApprovalRequest  = "approval_request"
	TypeApprovalDecision = "approval_decision"
	TypeTokenRefresh     = "token_refresh"
	TypeError            = "error"
)

var validTypes = map[string]struct{}{
	TypeHello: {}, TypeHelloAck: {}, TypeHeartbeat: {}, TypeHeartbeatAck: {},
	TypeCommand: {}, TypeCommandAck: {}, TypeEvent: {}, TypeApprovalRequest: {},
	TypeApprovalDecision: {}, TypeTokenRefresh: {}, TypeError: {},
}

var validRPCMethods = map[string]struct{}{
	"model/list": {}, "thread/start": {}, "thread/list": {}, "thread/read": {},
	"thread/resume": {}, "turn/start": {}, "turn/steer": {}, "turn/interrupt": {},
}

var validProtocolErrorCodes = map[string]struct{}{
	"invalid_envelope": {}, "unsupported_version": {}, "unauthorized": {},
	"policy_denied": {}, "invalid_epoch": {}, "expired": {}, "conflict": {},
	"upstream_error": {}, "invalid_upstream": {}, "indeterminate": {}, "internal_error": {},
}

var validCommandAckStates = map[string]struct{}{
	"accepted": {}, "running": {}, "completed": {}, "failed": {}, "expired": {}, "denied": {},
}

type Envelope struct {
	Version  int             `json:"version"`
	ID       string          `json:"id"`
	DeviceID string          `json:"device_id"`
	Epoch    string          `json:"epoch"`
	Seq      uint64          `json:"seq"`
	Ack      *uint64         `json:"ack,omitempty"`
	Type     string          `json:"type"`
	SentAt   time.Time       `json:"sent_at"`
	Payload  json.RawMessage `json:"payload"`
}

func (e Envelope) Validate() error {
	if e.Version != Version {
		return fmt.Errorf("unsupported protocol version %d", e.Version)
	}
	if !IsUUID(e.ID) || !IsUUID(e.DeviceID) || utf8.RuneCountInString(e.Epoch) < 16 ||
		utf8.RuneCountInString(e.Epoch) > 128 || e.SentAt.IsZero() {
		return errors.New("envelope is missing a required field")
	}
	if e.Seq > MaxSequence || (e.Ack != nil && *e.Ack > MaxSequence) {
		return errors.New("envelope sequence exceeds the signed BIGINT range")
	}
	if _, ok := validTypes[e.Type]; !ok {
		return fmt.Errorf("unknown envelope type %q", e.Type)
	}
	if len(e.Payload) == 0 || !json.Valid(e.Payload) {
		return errors.New("envelope payload is not valid JSON")
	}
	if e.Type == TypeHello || e.Type == TypeHelloAck {
		if e.Seq != 0 {
			return errors.New("hello handshake envelopes must use sequence zero")
		}
	} else if e.Seq == 0 {
		return errors.New("sequenced envelopes must use a positive sequence")
	}
	return nil
}

// ValidateWire applies the envelope and discriminator-selected payload contract.
// Runtime call sites may retain staged handling by using Validate alone.
func (e Envelope) ValidateWire() error {
	if err := e.Validate(); err != nil {
		return err
	}
	return e.ValidatePayload()
}

// ValidatePayload strictly decodes the payload selected by the envelope type.
func (e Envelope) ValidatePayload() error {
	switch e.Type {
	case TypeHello:
		var payload HelloPayload
		if err := decodeRequiredPayload(e.Payload, &payload,
			"connector_version", "codex_version", "schema_digest", "public_key", "capabilities", "workspace_roots"); err != nil {
			return err
		}
		if payload.ConnectorVersion == "" || utf8.RuneCountInString(payload.ConnectorVersion) > 64 ||
			payload.CodexVersion == "" || utf8.RuneCountInString(payload.CodexVersion) > 64 ||
			utf8.RuneCountInString(payload.SchemaDigest) < 16 || utf8.RuneCountInString(payload.SchemaDigest) > 256 ||
			utf8.RuneCountInString(payload.PublicKey) < 40 || utf8.RuneCountInString(payload.PublicKey) > 256 ||
			len(payload.Capabilities) == 0 || len(payload.Capabilities) > 32 ||
			len(payload.WorkspaceRoots) == 0 || len(payload.WorkspaceRoots) > 32 ||
			payload.ResumedFromSeq > MaxSequence {
			return errors.New("hello payload is incomplete")
		}
		seenCapabilities := make(map[string]struct{}, len(payload.Capabilities))
		for _, method := range payload.Capabilities {
			if _, ok := validRPCMethods[method]; !ok {
				return fmt.Errorf("hello capability %q is not allowed", method)
			}
			if _, duplicate := seenCapabilities[method]; duplicate {
				return fmt.Errorf("hello capability %q is duplicated", method)
			}
			seenCapabilities[method] = struct{}{}
		}
		seenRoots := make(map[string]struct{}, len(payload.WorkspaceRoots))
		for _, root := range payload.WorkspaceRoots {
			if root == "" || len([]byte(root)) > 4096 || !strings.HasPrefix(root, "/") ||
				strings.HasPrefix(root, "//") || root == "/" || path.Clean(root) != root ||
				strings.IndexFunc(root, func(character rune) bool { return character < 0x20 }) >= 0 {
				return errors.New("hello workspace root is invalid")
			}
			if _, duplicate := seenRoots[root]; duplicate {
				return errors.New("hello workspace roots contain a duplicate")
			}
			seenRoots[root] = struct{}{}
		}
		return nil
	case TypeHelloAck:
		var payload HelloAckPayload
		if err := decodeRequiredPayload(e.Payload, &payload,
			"connection_id", "protocol_version", "device_id", "epoch", "schema_digest", "received_seq", "heartbeat_timeout_seconds"); err != nil {
			return err
		}
		if !IsUUID(payload.ConnectionID) || payload.ProtocolVersion != Version || !IsUUID(payload.DeviceID) ||
			utf8.RuneCountInString(payload.Epoch) < 16 || utf8.RuneCountInString(payload.Epoch) > 128 ||
			utf8.RuneCountInString(payload.SchemaDigest) < 16 || utf8.RuneCountInString(payload.SchemaDigest) > 256 ||
			payload.ReceivedSeq > MaxSequence ||
			payload.HeartbeatTimeoutSeconds < 5 || payload.HeartbeatTimeoutSeconds > 300 {
			return errors.New("hello acknowledgement payload is invalid")
		}
		return nil
	case TypeHeartbeat:
		var payload HeartbeatPayload
		if err := decodeRequiredPayload(e.Payload, &payload, "status"); err != nil {
			return err
		}
		if payload.Status != "ok" {
			return errors.New("heartbeat status must be ok")
		}
		return nil
	case TypeHeartbeatAck:
		var payload HeartbeatAckPayload
		if err := decodeRequiredPayload(e.Payload, &payload, "received_seq"); err != nil {
			return err
		}
		if payload.ReceivedSeq > MaxSequence {
			return errors.New("heartbeat acknowledgement sequence exceeds the signed BIGINT range")
		}
		return nil
	case TypeCommand:
		var payload CommandPayload
		if err := decodeRequiredPayload(e.Payload, &payload,
			"command_id", "idempotency_key", "method", "params", "deadline_at"); err != nil {
			return err
		}
		if !IsUUID(payload.CommandID) || payload.IdempotencyKey == "" || utf8.RuneCountInString(payload.IdempotencyKey) > 128 ||
			payload.DeadlineAt.IsZero() {
			return errors.New("command payload is incomplete")
		}
		if _, ok := validRPCMethods[payload.Method]; !ok {
			return fmt.Errorf("command method %q is not allowed", payload.Method)
		}
		var params map[string]any
		if err := json.Unmarshal(payload.Params, &params); err != nil || params == nil {
			return errors.New("command params must be an object")
		}
		return nil
	case TypeCommandAck:
		var payload CommandAckPayload
		if err := decodeRequiredPayload(e.Payload, &payload, "command_id", "state"); err != nil {
			return err
		}
		if !IsUUID(payload.CommandID) {
			return errors.New("command acknowledgement id must be a UUID")
		}
		if _, ok := validCommandAckStates[payload.State]; !ok {
			return fmt.Errorf("unknown command acknowledgement state %q", payload.State)
		}
		fields, err := payloadObject(e.Payload)
		if err != nil {
			return err
		}
		_, hasResult := fields["result"]
		_, hasError := fields["error"]
		switch payload.State {
		case "accepted", "running":
			if hasResult || hasError {
				return errors.New("non-terminal command acknowledgements cannot carry result or error")
			}
		case "completed":
			if !hasResult || hasError {
				return errors.New("completed command acknowledgements require result and forbid error")
			}
		case "failed", "expired", "denied":
			if !hasError || payload.Error == nil || hasResult {
				return errors.New("failed command acknowledgements require error and forbid result")
			}
		}
		return validateProtocolError(payload.Error)
	case TypeEvent:
		var payload EventPayload
		if err := decodeRequiredPayload(e.Payload, &payload, "method", "params"); err != nil {
			return err
		}
		if payload.Method == "" || utf8.RuneCountInString(payload.Method) > 128 || payload.Params == nil {
			return errors.New("event payload is incomplete")
		}
		return nil
	case TypeApprovalRequest:
		var payload ApprovalRequestPayload
		if err := decodeRequiredPayload(e.Payload, &payload,
			"approval_id", "command_id", "kind", "summary", "details", "expires_at"); err != nil {
			return err
		}
		if !IsUUID(payload.ApprovalID) || payload.CommandID == "" || utf8.RuneCountInString(payload.CommandID) > 255 ||
			(payload.Kind != "command" && payload.Kind != "file_change" && payload.Kind != "permission") ||
			payload.Summary == "" || utf8.RuneCountInString(payload.Summary) > 512 || payload.Details == nil || payload.ExpiresAt.IsZero() {
			return errors.New("approval request payload is incomplete")
		}
		return nil
	case TypeApprovalDecision:
		var payload ApprovalDecisionPayload
		if err := decodeRequiredPayload(e.Payload, &payload, "approval_id", "decision", "decided_at"); err != nil {
			return err
		}
		if !IsUUID(payload.ApprovalID) || (payload.Decision != "approve" && payload.Decision != "deny") || payload.DecidedAt.IsZero() {
			return errors.New("approval decision payload is invalid")
		}
		return nil
	case TypeTokenRefresh:
		var payload TokenRefreshPayload
		return decodeRequiredPayload(e.Payload, &payload)
	case TypeError:
		var payload ProtocolError
		if err := decodeRequiredPayload(e.Payload, &payload, "code", "message", "retryable"); err != nil {
			return err
		}
		return validateProtocolError(&payload)
	default:
		return fmt.Errorf("unknown envelope type %q", e.Type)
	}
}

func IsUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F')) {
			return false
		}
	}
	return true
}

func MarshalPayload(value any) (json.RawMessage, error) {
	data, err := json.Marshal(value)
	return json.RawMessage(data), err
}

func NewID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}

type HelloPayload struct {
	ConnectorVersion string   `json:"connector_version"`
	CodexVersion     string   `json:"codex_version"`
	SchemaDigest     string   `json:"schema_digest"`
	PublicKey        string   `json:"public_key"`
	Capabilities     []string `json:"capabilities"`
	WorkspaceRoots   []string `json:"workspace_roots"`
	ResumedFromSeq   uint64   `json:"resumed_from_seq"`
}

type HelloAckPayload struct {
	ConnectionID            string `json:"connection_id"`
	ProtocolVersion         int    `json:"protocol_version"`
	DeviceID                string `json:"device_id"`
	Epoch                   string `json:"epoch"`
	SchemaDigest            string `json:"schema_digest"`
	ReceivedSeq             uint64 `json:"received_seq"`
	HeartbeatTimeoutSeconds int    `json:"heartbeat_timeout_seconds"`
}

type HeartbeatPayload struct {
	Status string `json:"status"`
}

type HeartbeatAckPayload struct {
	ReceivedSeq uint64 `json:"received_seq"`
}

type CommandPayload struct {
	CommandID      string          `json:"command_id"`
	IdempotencyKey string          `json:"idempotency_key"`
	Method         string          `json:"method"`
	Params         json.RawMessage `json:"params"`
	DeadlineAt     time.Time       `json:"deadline_at"`
}

type CommandAckPayload struct {
	CommandID string         `json:"command_id"`
	State     string         `json:"state"`
	Result    any            `json:"result,omitempty"`
	Error     *ProtocolError `json:"error,omitempty"`
}

type EventPayload struct {
	Method string         `json:"method"`
	Params map[string]any `json:"params"`
}

type ApprovalRequestPayload struct {
	ApprovalID string         `json:"approval_id"`
	CommandID  string         `json:"command_id"`
	Kind       string         `json:"kind"`
	Summary    string         `json:"summary"`
	Details    map[string]any `json:"details"`
	ExpiresAt  time.Time      `json:"expires_at"`
}

type ApprovalDecisionPayload struct {
	ApprovalID string    `json:"approval_id"`
	Decision   string    `json:"decision"`
	DecidedAt  time.Time `json:"decided_at"`
}

type ProtocolError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

type TokenRefreshPayload struct{}

func validateProtocolError(payload *ProtocolError) error {
	if payload == nil {
		return nil
	}
	if _, ok := validProtocolErrorCodes[payload.Code]; !ok {
		return fmt.Errorf("unknown protocol error code %q", payload.Code)
	}
	if strings.TrimSpace(payload.Message) == "" || utf8.RuneCountInString(payload.Message) > 4096 {
		return errors.New("protocol error message is invalid")
	}
	return nil
}

func decodeRequiredPayload(data []byte, destination any, required ...string) error {
	object, err := payloadObject(data)
	if err != nil {
		return err
	}
	for _, field := range required {
		value, ok := object[field]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("envelope payload is missing %q", field)
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("envelope payload contains trailing JSON")
		}
		return err
	}
	return nil
}

func payloadObject(data []byte) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil || object == nil {
		return nil, errors.New("envelope payload must be an object")
	}
	return object, nil
}

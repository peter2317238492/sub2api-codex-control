package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type wireFixture struct {
	ProtocolVersion int `json:"protocol_version"`
	Limits          struct {
		MaxSequence               string `json:"max_sequence"`
		MaxEpochCodePoints        int    `json:"max_epoch_code_points"`
		MaxWorkspaceRootUTF8Bytes int    `json:"max_workspace_root_utf8_bytes"`
	} `json:"limits"`
	Valid []struct {
		Name     string          `json:"name"`
		Envelope json.RawMessage `json:"envelope"`
	} `json:"valid"`
	Invalid []struct {
		Name     string          `json:"name"`
		Envelope json.RawMessage `json:"envelope"`
	} `json:"invalid"`
}

func TestEnvelopeValidationFailsClosed(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	envelope := Envelope{
		Version: Version, ID: id, DeviceID: "11111111-1111-4111-8111-111111111111", Epoch: "epoch-0123456789abcdef",
		Seq: 1, Type: TypeEvent, SentAt: time.Now(), Payload: json.RawMessage(`{}`),
	}
	if err := envelope.Validate(); err != nil {
		t.Fatal(err)
	}
	envelope.Type = "raw"
	if err := envelope.Validate(); err == nil {
		t.Fatal("unknown envelope type was accepted")
	}
}

func TestPayloadBudgetReservesThirtyTwoKiBForEnvelopeMetadata(t *testing.T) {
	if MaxFrameBytes != 256<<10 || MaxProjectedPayloadBytes != 224<<10 ||
		MaxFrameBytes-MaxProjectedPayloadBytes != 32<<10 {
		t.Fatalf("wire budgets = frame %d, payload %d", MaxFrameBytes, MaxProjectedPayloadBytes)
	}
}

func TestOnlyHandshakeEnvelopesUseSequenceZero(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	base := Envelope{
		Version: Version, ID: id, DeviceID: "11111111-1111-4111-8111-111111111111", Epoch: "epoch-0123456789abcdef",
		SentAt: time.Now(), Payload: json.RawMessage(`{}`),
	}
	base.Type = TypeHello
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	base.Seq = 1
	if err := base.Validate(); err == nil {
		t.Fatal("sequenced hello was accepted")
	}
	base.Type = TypeEvent
	base.Seq = 0
	if err := base.Validate(); err == nil {
		t.Fatal("unsequenced event was accepted")
	}
}

func TestHelloPayloadCarriesWorkspaceRoots(t *testing.T) {
	payload := HelloPayload{
		ConnectorVersion: "0.1.0",
		CodexVersion:     "0.147.0",
		SchemaDigest:     "digest",
		PublicKey:        "public-key",
		Capabilities:     []string{"thread/start"},
		WorkspaceRoots:   []string{"/Users/example/Projects"},
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	roots, ok := decoded["workspace_roots"].([]any)
	if !ok || len(roots) != 1 || roots[0] != "/Users/example/Projects" {
		t.Fatalf("workspace_roots = %#v", decoded["workspace_roots"])
	}
	if resumed, ok := decoded["resumed_from_seq"].(float64); !ok || resumed != 0 {
		t.Fatalf("resumed_from_seq = %#v", decoded["resumed_from_seq"])
	}
}

func TestSharedWireFixturesMatchGoProtocolTypes(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "..", "packages", "control-protocol", "fixtures", "wire-envelopes.json")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var fixture wireFixture
	if err := decodeStrictFixture(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.ProtocolVersion != Version {
		t.Fatalf("fixture protocol version = %d, want %d", fixture.ProtocolVersion, Version)
	}
	for _, test := range fixture.Valid {
		t.Run("valid/"+test.Name, func(t *testing.T) {
			var envelope Envelope
			if err := decodeStrictFixture(test.Envelope, &envelope); err != nil {
				t.Fatal(err)
			}
			if err := envelope.ValidateWire(); err != nil {
				t.Fatalf("valid fixture rejected: %v", err)
			}
		})
	}
	for _, test := range fixture.Invalid {
		t.Run("invalid/"+test.Name, func(t *testing.T) {
			var envelope Envelope
			if err := decodeStrictFixture(test.Envelope, &envelope); err == nil && envelope.ValidateWire() == nil {
				t.Fatal("invalid fixture was accepted")
			}
		})
	}
}

func TestSharedSignedSequenceAndStringBoundaries(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "..", "packages", "control-protocol", "fixtures", "wire-envelopes.json")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var fixture wireFixture
	if err := decodeStrictFixture(data, &fixture); err != nil {
		t.Fatal(err)
	}
	fixtureMax, err := strconv.ParseUint(fixture.Limits.MaxSequence, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if fixtureMax != MaxSequence || fixtureMax+1 != uint64(1)<<63 {
		t.Fatalf("fixture max sequence = %d, protocol max = %d", fixtureMax, MaxSequence)
	}

	marshal := func(value any) json.RawMessage {
		encoded, marshalErr := MarshalPayload(value)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return encoded
	}
	base := Envelope{
		Version: Version, ID: "00000000-0000-4000-8000-000000000099",
		DeviceID: "11111111-1111-4111-8111-111111111111", Epoch: strings.Repeat("e", fixture.Limits.MaxEpochCodePoints),
		Seq: MaxSequence, SentAt: time.Now(), Payload: marshal(HeartbeatPayload{Status: "ok"}), Type: TypeHeartbeat,
	}
	maximumAck := MaxSequence
	base.Ack = &maximumAck
	if err := base.ValidateWire(); err != nil {
		t.Fatalf("signed BIGINT maxima rejected: %v", err)
	}
	base.Seq = MaxSequence + 1
	if err := base.ValidateWire(); err == nil {
		t.Fatal("sequence above signed BIGINT maximum was accepted")
	}
	base.Seq = 1
	overflowAck := MaxSequence + 1
	base.Ack = &overflowAck
	if err := base.ValidateWire(); err == nil {
		t.Fatal("ack above signed BIGINT maximum was accepted")
	}
	base.Ack = nil
	base.Epoch += "e"
	if err := base.ValidateWire(); err == nil {
		t.Fatal("129-code-point epoch was accepted")
	}

	rootAtLimit := "/" + strings.Repeat("😀", 1023) + "aaa"
	rootOverLimit := rootAtLimit + "a"
	if len([]byte(rootAtLimit)) != fixture.Limits.MaxWorkspaceRootUTF8Bytes ||
		len([]byte(rootOverLimit)) != fixture.Limits.MaxWorkspaceRootUTF8Bytes+1 {
		t.Fatal("workspace root boundary fixture is not exact")
	}
	hello := HelloPayload{
		ConnectorVersion: "0.1.0", CodexVersion: "0.147.0", SchemaDigest: strings.Repeat("a", 64),
		PublicKey: strings.Repeat("A", 43), Capabilities: []string{"model/list"},
		WorkspaceRoots: []string{rootAtLimit}, ResumedFromSeq: MaxSequence,
	}
	base.Seq, base.Type, base.Epoch, base.Payload = 0, TypeHello, "epoch-0123456789abcdef", marshal(hello)
	if err := base.ValidateWire(); err != nil {
		t.Fatalf("exact workspace/resume boundary rejected: %v", err)
	}
	hello.ResumedFromSeq = MaxSequence + 1
	base.Payload = marshal(hello)
	if err := base.ValidateWire(); err == nil {
		t.Fatal("resume cursor above signed BIGINT maximum was accepted")
	}
	hello.ResumedFromSeq, hello.WorkspaceRoots = 0, []string{rootOverLimit}
	base.Payload = marshal(hello)
	if err := base.ValidateWire(); err == nil {
		t.Fatal("workspace root above UTF-8 byte maximum was accepted")
	}
	hello.WorkspaceRoots = []string{"/workspace/../escape"}
	base.Payload = marshal(hello)
	if err := base.ValidateWire(); err == nil {
		t.Fatal("non-canonical workspace root was accepted")
	}

	helloAck := HelloAckPayload{
		ConnectionID: "22222222-2222-4222-8222-222222222222", ProtocolVersion: Version,
		DeviceID: base.DeviceID, Epoch: base.Epoch, SchemaDigest: strings.Repeat("a", 64),
		ReceivedSeq: MaxSequence, HeartbeatTimeoutSeconds: 60,
	}
	base.Type, base.Payload = TypeHelloAck, marshal(helloAck)
	if err := base.ValidateWire(); err != nil {
		t.Fatalf("hello_ack receive cursor maximum rejected: %v", err)
	}
	helloAck.ReceivedSeq = MaxSequence + 1
	base.Payload = marshal(helloAck)
	if err := base.ValidateWire(); err == nil {
		t.Fatal("hello_ack receive cursor above maximum was accepted")
	}

	base.Seq, base.Type = 1, TypeHeartbeatAck
	base.Payload = marshal(HeartbeatAckPayload{ReceivedSeq: MaxSequence})
	if err := base.ValidateWire(); err != nil {
		t.Fatalf("heartbeat_ack receive cursor maximum rejected: %v", err)
	}
	base.Payload = marshal(HeartbeatAckPayload{ReceivedSeq: MaxSequence + 1})
	if err := base.ValidateWire(); err == nil {
		t.Fatal("heartbeat_ack receive cursor above maximum was accepted")
	}
}

func TestSharedWireFixtureCarriesRequiredHelloAckAndErrorCodes(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "..", "packages", "control-protocol", "fixtures", "wire-envelopes.json")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var fixture wireFixture
	if err := decodeStrictFixture(data, &fixture); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, test := range fixture.Valid {
		var envelope Envelope
		if err := decodeStrictFixture(test.Envelope, &envelope); err != nil {
			t.Fatal(err)
		}
		switch test.Name {
		case "hello_ack":
			var payload HelloAckPayload
			if err := decodeStrictFixture(envelope.Payload, &payload); err != nil {
				t.Fatal(err)
			}
			if !IsUUID(payload.ConnectionID) || payload.HeartbeatTimeoutSeconds != 60 {
				t.Fatalf("hello_ack payload drifted: %#v", payload)
			}
			seen[test.Name] = true
		case "command_ack_indeterminate":
			var payload CommandAckPayload
			if err := decodeStrictFixture(envelope.Payload, &payload); err != nil {
				t.Fatal(err)
			}
			if payload.Error == nil || payload.Error.Code != "indeterminate" {
				t.Fatalf("command_ack payload drifted: %#v", payload)
			}
			seen[test.Name] = true
		case "error":
			var payload ProtocolError
			if err := decodeStrictFixture(envelope.Payload, &payload); err != nil {
				t.Fatal(err)
			}
			if payload.Code != "invalid_upstream" {
				t.Fatalf("error payload drifted: %#v", payload)
			}
			seen[test.Name] = true
		}
	}
	for _, name := range []string{"hello_ack", "command_ack_indeterminate", "error"} {
		if !seen[name] {
			t.Fatalf("shared fixture is missing %s", name)
		}
	}
}

func decodeStrictFixture(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

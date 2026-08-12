import Ajv2020, { type AnySchema, type ErrorObject } from "ajv/dist/2020";
import addFormats from "ajv-formats";
import { describe, expect, it } from "vitest";

import budgetVectors from "../fixtures/json-budget-vectors.json";
import wireFixture from "../fixtures/wire-envelopes.json";
import envelopeSchema from "../schema/control-envelope.schema.json";
import {
  ALLOWED_RPC_METHODS,
  CONTROL_PROTOCOL_VERSION,
  PROTOCOL_ERROR_CODES,
  type CommandAckPayload,
  type ControlEnvelope,
  type ControlEnvelopeOf,
  type DeviceHelloAckPayload,
  type EnvelopeType,
} from "../src/index";
import { ensureAsciiJsonByteLength } from "../src/policy";

const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
ajv.addKeyword({
  keyword: "x-maxEnsureAsciiJsonBytes",
  schemaType: "number",
  validate: (limit: number, value: unknown) => ensureAsciiJsonByteLength(value) <= limit,
});
ajv.addKeyword({
  keyword: "x-maxEnsureAsciiStringContentBytes",
  schemaType: "number",
  type: "string",
  validate: (limit: number, value: string) => ensureAsciiJsonByteLength(value) - 2 <= limit,
});
ajv.addKeyword({
  keyword: "x-maxUtf8Bytes",
  schemaType: "number",
  type: "string",
  validate: (limit: number, value: string) => new TextEncoder().encode(value).byteLength <= limit,
});
ajv.addKeyword({
  keyword: "x-canonicalWorkspaceRoot",
  schemaType: "boolean",
  type: "string",
  validate: (required: boolean, value: string) => {
    if (!required) return true;
    if (!value.startsWith("/") || value.startsWith("//") || value === "/" || /[\u0000-\u001f]/u.test(value)) {
      return false;
    }
    return value
      .slice(1)
      .split("/")
      .every((segment) => segment !== "" && segment !== "." && segment !== "..");
  },
});
const validateEnvelope = ajv.compile(envelopeSchema as AnySchema);

type Assert<T extends true> = T;
type IsEqual<TLeft, TRight> =
  (<T>() => T extends TLeft ? 1 : 2) extends <T>() => T extends TRight ? 1 : 2 ? true : false;
type IsRequired<T, K extends keyof T> = {} extends Pick<T, K> ? false : true;
type _ConnectionIdIsRequired = Assert<IsRequired<DeviceHelloAckPayload, "connection_id">>;
type _HeartbeatTimeoutIsRequired = Assert<IsRequired<DeviceHelloAckPayload, "heartbeat_timeout_seconds">>;

const completedAckTypeGuard = {
  command_id: "33333333-3333-4333-8333-333333333333",
  state: "completed",
  result: {},
} satisfies CommandAckPayload;
// @ts-expect-error completed acknowledgements require a result
const incompleteCompletedAckTypeGuard: CommandAckPayload = {
  command_id: "33333333-3333-4333-8333-333333333333",
  state: "completed",
};
void completedAckTypeGuard;
void incompleteCompletedAckTypeGuard;

function validationMessage(errors: ErrorObject[] | null | undefined): string {
  return errors?.map((error) => `${error.instancePath || "/"} ${error.message ?? "invalid"}`).join("; ") ?? "";
}

function expandVector(vector: { unit: string; repeat: number; suffix?: string }): string {
  return vector.unit.repeat(vector.repeat) + (vector.suffix ?? "");
}

describe("control wire contract", () => {
  it("accepts every shared valid wire fixture through the discriminated JSON Schema", () => {
    for (const fixture of wireFixture.valid) {
      const valid = validateEnvelope(fixture.envelope);
      expect(valid, `${fixture.name}: ${validationMessage(validateEnvelope.errors)}`).toBe(true);
    }
  });

  it("rejects every shared invalid wire fixture", () => {
    for (const fixture of wireFixture.invalid) {
      expect(validateEnvelope(fixture.envelope), fixture.name).toBe(false);
    }
  });

  it("covers every envelope discriminator exactly once in the primary fixture set", () => {
    const expected = [
      "hello",
      "hello_ack",
      "heartbeat",
      "heartbeat_ack",
      "command",
      "command_ack",
      "event",
      "approval_request",
      "approval_decision",
      "token_refresh",
      "error",
    ] as const satisfies readonly EnvelopeType[];
    type _EnvelopeTypesAreExhaustive = Assert<IsEqual<(typeof expected)[number], EnvelopeType>>;
    const envelopeTypesAreExhaustive: _EnvelopeTypesAreExhaustive = true;
    const primary = wireFixture.valid.slice(0, expected.length).map(({ envelope }) => envelope.type);
    expect(primary).toEqual(expected);
    expect(new Set(primary).size).toBe(expected.length);
    expect(envelopeTypesAreExhaustive).toBe(true);
  });

  it("decodes the drift-sensitive payloads into the TypeScript discriminated union", () => {
    const envelopes = wireFixture.valid.map(({ envelope }) => envelope as ControlEnvelope);
    const helloAck = envelopes.find((envelope) => envelope.type === "hello_ack");
    const commandFailure = envelopes.find(
      (envelope): envelope is ControlEnvelopeOf<"command_ack"> =>
        envelope.type === "command_ack" && envelope.payload.state === "failed",
    );
    const protocolError = envelopes.find((envelope) => envelope.type === "error");

    expect(helloAck?.payload.connection_id).toBe("22222222-2222-4222-8222-222222222222");
    expect(helloAck?.payload.heartbeat_timeout_seconds).toBe(60);
    expect(commandFailure?.payload.error?.code).toBe("indeterminate");
    expect(protocolError?.payload.code).toBe("invalid_upstream");
    expect(wireFixture.protocol_version).toBe(CONTROL_PROTOCOL_VERSION);
    expect(ALLOWED_RPC_METHODS).toEqual(envelopeSchema.$defs.allowedRpcMethod.enum);
    expect(PROTOCOL_ERROR_CODES).toEqual(envelopeSchema.$defs.protocolErrorCode.enum);
    expect(envelopeSchema.properties.type.enum).toEqual([
      "hello",
      "hello_ack",
      "heartbeat",
      "heartbeat_ack",
      "command",
      "command_ack",
      "event",
      "approval_request",
      "approval_decision",
      "token_refresh",
      "error",
    ]);
  });

  it("pins signed BIGINT sequences plus epoch and workspace-root boundaries", () => {
    const maxSequence = BigInt(wireFixture.limits.max_sequence);
    expect(maxSequence).toBe((1n << 63n) - 1n);
    expect(maxSequence + 1n).toBe(1n << 63n);
    expect(envelopeSchema.properties.seq.maximum).toBe(Number(maxSequence));
    expect(envelopeSchema.properties.ack.maximum).toBe(Number(maxSequence));

    const heartbeat = wireFixture.valid.find(({ name }) => name === "heartbeat")!.envelope;
    expect(validateEnvelope({ ...heartbeat, seq: 100_000_000_000_000_000_000 })).toBe(false);
    expect(validateEnvelope({ ...heartbeat, ack: 100_000_000_000_000_000_000 })).toBe(false);

    for (const name of ["hello", "hello_ack", "heartbeat_ack"] as const) {
      const source = wireFixture.valid.find((fixture) => fixture.name === name)!.envelope;
      const cursorField = name === "hello" ? "resumed_from_seq" : "received_seq";
      expect(
        validateEnvelope({
          ...source,
          payload: { ...source.payload, [cursorField]: 100_000_000_000_000_000_000 },
        }),
        name,
      ).toBe(false);
    }

    const epochLimit = wireFixture.limits.max_epoch_code_points;
    expect(validateEnvelope({ ...heartbeat, epoch: "e".repeat(epochLimit) })).toBe(true);
    expect(validateEnvelope({ ...heartbeat, epoch: "e".repeat(epochLimit + 1) })).toBe(false);

    const hello = wireFixture.valid.find(({ name }) => name === "hello")!.envelope;
    const rootAtLimit = `/${"😀".repeat(1_023)}aaa`;
    const rootOverLimit = `${rootAtLimit}a`;
    expect(new TextEncoder().encode(rootAtLimit).byteLength).toBe(
      wireFixture.limits.max_workspace_root_utf8_bytes,
    );
    expect(new TextEncoder().encode(rootOverLimit).byteLength).toBe(
      wireFixture.limits.max_workspace_root_utf8_bytes + 1,
    );
    expect(
      validateEnvelope({ ...hello, payload: { ...hello.payload, workspace_roots: [rootAtLimit] } }),
    ).toBe(true);
    expect(
      validateEnvelope({ ...hello, payload: { ...hello.payload, workspace_roots: [rootOverLimit] } }),
    ).toBe(false);
    expect(
      validateEnvelope({ ...hello, payload: { ...hello.payload, workspace_roots: ["/workspace/../escape"] } }),
    ).toBe(false);
  });

  it("enforces the shared ASCII, CJK, and emoji text byte boundary through Ajv", () => {
    const command = wireFixture.valid.find(({ name }) => name === "command")!.envelope;
    for (const vector of budgetVectors.string_content) {
      const text = expandVector(vector);
      expect(ensureAsciiJsonByteLength(text) - 2, vector.name).toBe(vector.expected_bytes);
      expect(vector.expected_bytes, vector.name).toBe(vector.allowed ? 200_000 : 200_001);
      const envelope = {
        ...command,
        payload: {
          ...command.payload,
          method: "turn/start",
          params: { threadId: "managed-thread-1", input: [{ type: "text", text }] },
        },
      };
      expect(validateEnvelope(envelope), `${vector.name}: ${validationMessage(validateEnvelope.errors)}`).toBe(
        vector.allowed,
      );
    }
  });

  it("enforces shared params and projected JSON budgets at exactly 224 KiB", () => {
    const command = wireFixture.valid.find(({ name }) => name === "command")!.envelope;
    const commandAck = wireFixture.valid.find(({ name }) => name === "command_ack")!.envelope;
    for (const vector of budgetVectors.json_documents) {
      const value = { [vector.key]: expandVector(vector) };
      expect(ensureAsciiJsonByteLength(value), vector.name).toBe(vector.expected_bytes);
      expect(vector.expected_bytes, vector.name).toBe(vector.allowed ? 229_376 : 229_377);

      const commandEnvelope = { ...command, payload: { ...command.payload, params: value } };
      expect(
        validateEnvelope(commandEnvelope),
        `params ${vector.name}: ${validationMessage(validateEnvelope.errors)}`,
      ).toBe(vector.allowed);

      const acknowledgementEnvelope = {
        ...commandAck,
        payload: { command_id: commandAck.payload.command_id, state: "completed", result: value },
      };
      expect(
        validateEnvelope(acknowledgementEnvelope),
        `projected ${vector.name}: ${validationMessage(validateEnvelope.errors)}`,
      ).toBe(vector.allowed);
    }
  });

  it("enforces the encoded envelope boundary at exactly 256 KiB", () => {
    const approval = wireFixture.valid.find(({ name }) => name === "approval_request")!.envelope;
    const baseEnvelope = {
      ...approval,
      payload: { ...approval.payload, details: { padding: "" } },
    };
    const baseBytes = ensureAsciiJsonByteLength(baseEnvelope);
    const atLimit = {
      ...baseEnvelope,
      payload: { ...baseEnvelope.payload, details: { padding: "a".repeat(262_144 - baseBytes) } },
    };
    const overLimit = {
      ...atLimit,
      payload: { ...atLimit.payload, details: { padding: `${atLimit.payload.details.padding}a` } },
    };
    expect(ensureAsciiJsonByteLength(atLimit)).toBe(262_144);
    expect(ensureAsciiJsonByteLength(overLimit)).toBe(262_145);
    expect(validateEnvelope(atLimit), validationMessage(validateEnvelope.errors)).toBe(true);
    expect(validateEnvelope(overLimit)).toBe(false);
  });
});

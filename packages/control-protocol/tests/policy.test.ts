import { describe, expect, it } from "vitest";

import budgetVectors from "../fixtures/json-budget-vectors.json";
import policyFixture from "../fixtures/rpc-policy.json";

import {
  assertAllowedRpcMethod,
  ensureAsciiJsonByteLength,
  goJsonByteLength,
  isAllowedRpcMethod,
  projectRemoteRpcParams,
  RPC_POLICY_DESCRIPTOR,
  rpcPolicyReason,
} from "../src/policy";

describe("RPC policy", () => {
  it("matches the shared cross-language method fixture", () => {
    expect(RPC_POLICY_DESCRIPTOR).toEqual(policyFixture);
  });
  it("allows only the managed thread surface", () => {
    expect(isAllowedRpcMethod("thread/start")).toBe(true);
    expect(isAllowedRpcMethod("turn/interrupt")).toBe(true);
  });

  it.each([
    "thread/shellCommand",
    "command/exec",
    "fs/readFile",
    "process/start",
    "config/write",
    "plugin/install",
    "plugin/search",
    "account/login",
    "thread/section/move",
    "threadSection/create",
    "threadSection/delete",
    "threadSection/list",
    "threadSection/update",
    "unknown/raw",
  ])("fails closed for %s", (method) => {
    expect(rpcPolicyReason(method)).not.toBeNull();
    expect(() => assertAllowedRpcMethod(method)).toThrow(/RPC policy denied/);
  });
});

describe("RPC parameter projection", () => {
  it("projects thread/start into a fresh safe object", () => {
    expect(() =>
      projectRemoteRpcParams(
        "thread/start",
        { cwd: "/work/app", model: "gpt-5", config: { sandbox_mode: "danger-full-access" } },
        { allowedCwds: ["/work/app"] },
      ),
    ).toThrow(/config/);

    expect(
      projectRemoteRpcParams("thread/start", { cwd: "/work/app", model: "gpt-5" }, { allowedCwds: ["/work/app"] }),
    ).toEqual({ cwd: "/work/app", model: "gpt-5" });
  });

  it("rejects dangerous override fields even on allowed methods", () => {
    expect(() =>
      projectRemoteRpcParams("turn/start", {
        threadId: "thread-1",
        input: [{ type: "text", text: "hello" }],
        sandboxPolicy: { type: "dangerFullAccess" },
      }),
    ).toThrow(/sandboxPolicy/);
  });

  it("accepts omitted or empty text_elements and reconstructs the canonical shape", () => {
    expect(
      projectRemoteRpcParams(
        "turn/start",
        { threadId: "thread-1", input: [{ type: "text", text: "check status" }] },
        { boundThreadIds: ["thread-1"] },
      ),
    ).toEqual({
      threadId: "thread-1",
      input: [{ type: "text", text: "check status", text_elements: [] }],
    });
    expect(
      projectRemoteRpcParams(
        "turn/start",
        { threadId: "thread-1", input: [{ type: "text", text: "check status", text_elements: [] }] },
        { boundThreadIds: ["thread-1"] },
      ),
    ).toEqual({
      threadId: "thread-1",
      input: [{ type: "text", text: "check status", text_elements: [] }],
    });
    for (const textElements of [null, [{ byteRange: { start: 0, end: 1 } }]]) {
      expect(() =>
        projectRemoteRpcParams(
          "turn/start",
          { threadId: "thread-1", input: [{ type: "text", text: "check status", text_elements: textElements }] },
          { boundThreadIds: ["thread-1"] },
        ),
      ).toThrow(/text input only/);
    }
  });

  it("rejects type drift, hidden input fields, and contract limit expansion", () => {
    expect(() =>
      projectRemoteRpcParams(
        "thread/read",
        { threadId: "thread-1", includeTurns: "true" },
        { boundThreadIds: ["thread-1"] },
      ),
    ).toThrow(/boolean/);
    expect(() =>
      projectRemoteRpcParams(
        "turn/start",
        { threadId: "thread-1", input: [{ type: "text", text: "hello", path: "/etc/passwd" }] },
        { boundThreadIds: ["thread-1"] },
      ),
    ).toThrow(/text input only/);
    expect(() => projectRemoteRpcParams("model/list", { limit: 101 }, { maxPageSize: 1_000 })).toThrow(/100/);
    expect(() =>
      projectRemoteRpcParams(
        "thread/list",
        { searchTerm: "x".repeat(513) },
        { allowedCwds: ["/work/app"] },
      ),
    ).toThrow(/512/);
  });

  it("counts text limits in Unicode code points", () => {
    expect(
      projectRemoteRpcParams(
        "turn/start",
        { threadId: "thread-1", input: [{ type: "text", text: "😀" }] },
        { boundThreadIds: ["thread-1"], maxTextLength: 1 },
      ),
    ).toEqual({
      threadId: "thread-1",
      input: [{ type: "text", text: "😀", text_elements: [] }],
    });
    expect(() =>
      projectRemoteRpcParams(
        "turn/start",
        { threadId: "thread-1", input: [{ type: "text", text: "😀😀" }] },
        { boundThreadIds: ["thread-1"], maxTextLength: 1 },
      ),
    ).toThrow(/1 characters/);
  });

  it("matches the shared compact ensure_ascii boundary vectors", () => {
    expect(budgetVectors.encoding).toBe("compact-ensure-ascii");
    for (const vector of budgetVectors.string_content) {
      const text = vector.unit.repeat(vector.repeat) + vector.suffix;
      expect(ensureAsciiJsonByteLength(text) - 2, vector.name).toBe(vector.expected_bytes);
      const project = () =>
        projectRemoteRpcParams(
          "turn/start",
          { threadId: "thread-1", input: [{ type: "text", text }] },
          { boundThreadIds: ["thread-1"] },
        );
      if (vector.allowed) {
        expect(project().input).toEqual([{ type: "text", text, text_elements: [] }]);
      } else {
        expect(project).toThrow();
      }
    }
    for (const sample of budgetVectors.escape_samples) {
      expect(ensureAsciiJsonByteLength(sample.value) - 2, sample.name).toBe(sample.expected_bytes);
    }
    for (const vector of budgetVectors.json_documents) {
      const document = { [vector.key]: vector.unit.repeat(vector.repeat) + vector.suffix };
      const size = ensureAsciiJsonByteLength(document);
      expect(size, vector.name).toBe(vector.expected_bytes);
      expect(size <= RPC_POLICY_DESCRIPTOR.max_ensure_ascii_params_bytes, vector.name).toBe(vector.allowed);
    }
  });

  it("reserves enough envelope space for maximal legal turn params", () => {
    const opaque = "😀".repeat(RPC_POLICY_DESCRIPTOR.max_opaque_length);
    const text = "a".repeat(RPC_POLICY_DESCRIPTOR.max_text_length);
    const params = projectRemoteRpcParams(
      "turn/steer",
      {
        threadId: opaque,
        clientUserMessageId: opaque,
        expectedTurnId: opaque,
        input: [{ type: "text", text }],
      },
      { boundThreadIds: [opaque], activeTurnId: opaque },
    );
    expect(ensureAsciiJsonByteLength(params)).toBeLessThanOrEqual(
      RPC_POLICY_DESCRIPTOR.max_ensure_ascii_params_bytes,
    );
    const envelope = {
      version: 1,
      id: "11111111-1111-4111-8111-111111111111",
      device_id: "22222222-2222-4222-8222-222222222222",
      epoch: "😀".repeat(128),
      seq: 9_999_999_999_999_999,
      ack: 9_999_999_999_999_999,
      type: "command",
      sent_at: "2026-07-23T23:59:59.999999+00:00",
      payload: {
        command_id: "33333333-3333-4333-8333-333333333333",
        idempotency_key: "😀".repeat(128),
        method: "turn/steer",
        params,
        deadline_at: "2026-07-23T23:59:59.999999+00:00",
      },
    };
    expect(ensureAsciiJsonByteLength(envelope)).toBeLessThanOrEqual(RPC_POLICY_DESCRIPTOR.max_frame_bytes);
  });

  it("also caps the Connector's HTML-escaped Go JSON", () => {
    for (const character of ["<", ">", "&"]) {
      expect(() =>
        projectRemoteRpcParams(
          "turn/start",
          { threadId: "thread-1", input: [{ type: "text", text: character.repeat(200_000) }] },
          { boundThreadIds: ["thread-1"] },
        ),
      ).toThrow(/Go JSON budget/);
    }
    expect(goJsonByteLength({ value: "<>&界😀\u2028" })).toBe(12 + 18 + 3 + 4 + 6);
  });

  it("rejects local paths and stale turn identifiers", () => {
    expect(() =>
      projectRemoteRpcParams(
        "turn/start",
        {
          threadId: "thread-1",
          input: [{ type: "localImage", path: "/etc/passwd" }],
        },
        { boundThreadIds: ["thread-1"] },
      ),
    ).toThrow(/text input only/);
    expect(() =>
      projectRemoteRpcParams(
        "turn/interrupt",
        { threadId: "thread-1", turnId: "turn-old" },
        { boundThreadIds: ["thread-1"], activeTurnId: "turn-current" },
      ),
    ).toThrow(/no longer active/);
  });

  it("constrains list pagination and cwd", () => {
    expect(() => projectRemoteRpcParams("model/list", { limit: 101 })).toThrow(/between 1 and 100/);
    expect(() =>
      projectRemoteRpcParams("thread/list", { cwd: "/outside" }, { allowedCwds: ["/work/app"] }),
    ).toThrow(/outside/);
    expect(
      projectRemoteRpcParams(
        "thread/list",
        { cwd: ["/work/lab", "/work/app", "/work/lab"] },
        { allowedCwds: ["/work/app", "/work/lab"] },
      ),
    ).toEqual({ cwd: ["/work/lab", "/work/app"] });
    expect(projectRemoteRpcParams("thread/list", { cwd: "/work/app" }, { allowedCwds: ["/work/app"] })).toEqual({
      cwd: ["/work/app"],
    });
    expect(() =>
      projectRemoteRpcParams("thread/list", { cwd: [] }, { allowedCwds: ["/work/app"] }),
    ).toThrow(/1 to 32/);
  });

  it("requires device ownership context for managed paths and threads", () => {
    expect(() => projectRemoteRpcParams("thread/start", { cwd: "/work/app" })).toThrow(/allowlist/);
    expect(() => projectRemoteRpcParams("thread/read", { threadId: "thread-1" })).toThrow(/not bound/);
    expect(() => projectRemoteRpcParams("thread/list", {})).toThrow(/workspace roots/);
    expect(() =>
      projectRemoteRpcParams(
        "thread/list",
        {},
        { allowedCwds: Array.from({ length: 33 }, (_, index) => `/work/${index}`) },
      ),
    ).toThrow(/workspace roots/);
    expect(projectRemoteRpcParams("thread/list", {}, { allowedCwds: ["/work/app", "/work/lab"] })).toEqual({
      cwd: ["/work/app", "/work/lab"],
    });
    expect(() =>
      projectRemoteRpcParams(
        "thread/list",
        {},
        { allowedCwds: Array.from({ length: 32 }, (_, index) => "😀".repeat(4_096) + index) },
      ),
    ).toThrow(/ensure_ascii budget/);
  });
});

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const lock = JSON.parse(readFileSync(resolve(root, "versions.lock.json"), "utf8"));

const codexBin = process.env.CODEX_BIN || "codex";
const codexOutput = execFileSync(codexBin, ["--version"], { encoding: "utf8" }).trim();
const expectedCodex = `codex-cli ${lock.codex.cli_version}`;
if (codexOutput !== expectedCodex) {
  throw new Error(`Codex version mismatch: expected ${expectedCodex}, received ${codexOutput}`);
}

const schema = readFileSync(resolve(root, lock.codex.schema_file));
const schemaDigest = createHash("sha256").update(schema).digest("hex");
if (schemaDigest !== lock.codex.schema_sha256) {
  throw new Error(`Codex schema digest mismatch: expected ${lock.codex.schema_sha256}, received ${schemaDigest}`);
}

const controlSchema = readFileSync(resolve(root, lock.control_protocol.schema_file));
const controlSchemaDigest = createHash("sha256").update(controlSchema).digest("hex");
if (controlSchemaDigest !== lock.control_protocol.schema_sha256) {
  throw new Error(
    `Control protocol schema digest mismatch: expected ${lock.control_protocol.schema_sha256}, received ${controlSchemaDigest}`,
  );
}
if (!controlSchema.toString("utf8").includes('"maximum": 9223372036854775807')) {
  throw new Error("Control protocol schema is missing the signed BIGINT sequence ceiling");
}

const wireFixtureData = readFileSync(resolve(root, lock.control_protocol.wire_fixture_file));
const wireFixtureDigest = createHash("sha256").update(wireFixtureData).digest("hex");
if (wireFixtureDigest !== lock.control_protocol.wire_fixture_sha256) {
  throw new Error(
    `Control wire fixture digest mismatch: expected ${lock.control_protocol.wire_fixture_sha256}, received ${wireFixtureDigest}`,
  );
}
const wireFixture = JSON.parse(wireFixtureData);
if (wireFixture.protocol_version !== lock.control_protocol.version) {
  throw new Error(
    `Control wire fixture version mismatch: expected ${lock.control_protocol.version}, received ${wireFixture.protocol_version}`,
  );
}
if (
  wireFixture.limits?.max_sequence !== "9223372036854775807" ||
  wireFixture.limits?.max_epoch_code_points !== 128 ||
  wireFixture.limits?.max_workspace_root_utf8_bytes !== 4096
) {
  throw new Error("Control wire fixture limits do not match the shared persistence and string boundaries");
}
const expectedEnvelopeTypes = [
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
];
const fixtureEnvelopeTypes = new Set(wireFixture.valid.map(({ envelope }) => envelope.type));
const missingEnvelopeTypes = expectedEnvelopeTypes.filter((type) => !fixtureEnvelopeTypes.has(type));
const unexpectedEnvelopeTypes = [...fixtureEnvelopeTypes].filter((type) => !expectedEnvelopeTypes.includes(type));
if (missingEnvelopeTypes.length || unexpectedEnvelopeTypes.length) {
  throw new Error(
    `Control wire fixture discriminator mismatch: missing=${missingEnvelopeTypes.join(",") || "none"} unexpected=${unexpectedEnvelopeTypes.join(",") || "none"}`,
  );
}
for (const requiredCase of [
  "hello_ack_missing_connection_id",
  "hello_ack_missing_heartbeat_timeout_seconds",
  "command_ack_unknown_state",
  "command_ack_unknown_error_code",
  "error_unknown_code",
  "envelope_epoch_too_long",
  "error_blank_message",
  "envelope_compact_uuid",
  "envelope_numeric_sent_at",
]) {
  if (!wireFixture.invalid.some(({ name }) => name === requiredCase)) {
    throw new Error(`Control wire fixture is missing drift guard ${requiredCase}`);
  }
}

for (const [label, file, expectedDigest] of [
  ["Control RPC policy", lock.control_protocol.policy_file, lock.control_protocol.policy_sha256],
  [
    "Control JSON budget vectors",
    lock.control_protocol.budget_vectors_file,
    lock.control_protocol.budget_vectors_sha256,
  ],
]) {
  const bytes = readFileSync(resolve(root, file));
  const digest = createHash("sha256").update(bytes).digest("hex");
  if (digest !== expectedDigest) {
    throw new Error(`${label} digest mismatch: expected ${expectedDigest}, received ${digest}`);
  }
}

const authContractBytes = readFileSync(resolve(root, lock.sub2api.auth_contract_file));
const authContractDigest = createHash("sha256").update(authContractBytes).digest("hex");
if (authContractDigest !== lock.sub2api.auth_contract_sha256) {
  throw new Error(
    `Sub2API auth contract digest mismatch: expected ${lock.sub2api.auth_contract_sha256}, received ${authContractDigest}`,
  );
}
const authContract = JSON.parse(authContractBytes.toString("utf8"));
const matchesExactFlatObject = (actual, expected) =>
  actual !== null &&
  typeof actual === "object" &&
  !Array.isArray(actual) &&
  Object.keys(actual).length === Object.keys(expected).length &&
  Object.entries(expected).every(([key, value]) => actual[key] === value);
const expectedAuthContract = {
  runtimeVersion: lock.sub2api.runtime_version,
  runtimeCommit: lock.sub2api.runtime_commit,
  accessTokenKey: lock.sub2api.frontend_access_token_key,
  refreshTokenKey: lock.sub2api.frontend_refresh_token_key,
  expiresAtKey: lock.sub2api.frontend_token_expires_at_key,
  identityPath: lock.sub2api.auth_me_path,
  refreshPath: lock.sub2api.auth_refresh_path,
  logoutPath: lock.sub2api.auth_logout_path,
};
const actualAuthContract = {
  runtimeVersion: authContract.runtime?.version,
  runtimeCommit: authContract.runtime?.commit,
  accessTokenKey: authContract.local_storage?.access_token,
  refreshTokenKey: authContract.local_storage?.refresh_token,
  expiresAtKey: authContract.local_storage?.expires_at,
  identityPath: authContract.endpoints?.identity?.path,
  refreshPath: authContract.endpoints?.refresh?.path,
  logoutPath: authContract.endpoints?.logout?.path,
};
if (JSON.stringify(actualAuthContract) !== JSON.stringify(expectedAuthContract)) {
  throw new Error("Sub2API auth contract fields do not match versions.lock.json");
}
if (
  !matchesExactFlatObject(authContract.endpoints?.identity?.session_binding_mismatch_error, {
    status: 401,
    code: "SESSION_BINDING_MISMATCH",
  }) ||
  !matchesExactFlatObject(authContract.endpoints?.identity?.session_binding_request, {
    client_ip_header: "X-Forwarded-For",
    user_agent_header: "User-Agent",
  })
) {
  throw new Error("Sub2API session-binding rejection and request-header contract is invalid");
}
if (
  authContract.endpoints?.refresh?.method !== "POST" ||
  authContract.endpoints?.logout?.method !== "POST" ||
  JSON.stringify(authContract.endpoints?.refresh?.request_required) !== JSON.stringify(["refresh_token"]) ||
  JSON.stringify(authContract.endpoints?.refresh?.response_envelope) !==
    JSON.stringify({
      required: ["code", "message", "data"],
      code: 0,
      message: "success",
      data_required: ["access_token", "refresh_token", "expires_in", "token_type"],
    }) ||
  authContract.endpoints?.refresh?.token_type !== "Bearer" ||
  JSON.stringify(authContract.endpoints?.logout?.request_required) !== JSON.stringify(["refresh_token"]) ||
  !authContract.endpoints?.refresh?.rotates_refresh_token ||
  JSON.stringify(authContract.control_boundary?.accepted_sub2api_fields) !== JSON.stringify(["access_token"]) ||
  JSON.stringify(authContract.control_boundary?.forbidden_sub2api_fields) !== JSON.stringify(["refresh_token"])
) {
  throw new Error("Sub2API refresh, logout, or Control exchange boundary contract is invalid");
}

const runtimeVersion = process.env.SUB2API_RUNTIME_VERSION_OUTPUT;
if (runtimeVersion) {
  if (!runtimeVersion.includes(`Sub2API ${lock.sub2api.runtime_version}`)) {
    throw new Error(`Sub2API version mismatch: expected ${lock.sub2api.runtime_version}`);
  }
  if (!runtimeVersion.includes(lock.sub2api.runtime_commit)) {
    throw new Error(`Sub2API commit mismatch: expected ${lock.sub2api.runtime_commit}`);
  }
}

const runtimeDigest = process.env.SUB2API_RUNTIME_SHA256;
if (runtimeDigest && runtimeDigest !== lock.sub2api.runtime_binary_sha256) {
  throw new Error(
    `Sub2API binary digest mismatch: expected ${lock.sub2api.runtime_binary_sha256}, received ${runtimeDigest}`,
  );
}

process.stdout.write(
  `Contracts verified: Codex ${lock.codex.cli_version}, schema ${schemaDigest.slice(0, 12)}, control v${lock.control_protocol.version} ${controlSchemaDigest.slice(0, 12)}, Sub2API ${lock.sub2api.runtime_version} auth ${authContractDigest.slice(0, 12)} pinned\n`,
);

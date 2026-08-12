import http from "node:http";

const now = new Date();
const json = (response, status, body) => {
  const data = JSON.stringify(body);
  response.writeHead(status, {
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(data),
    "Content-Type": "application/json",
  });
  response.end(data);
};

const devices = [
  {
    id: "device-1",
    name: "Studio Mac",
    status: "online",
    connector_version: "0.1.0",
    codex_version: "0.147.0",
    last_seen_at: now.toISOString(),
    workspace_roots: ["/Users/alice/Projects", "/Users/alice/Labs"],
  },
  {
    id: "device-2",
    name: "Travel MacBook",
    status: "offline",
    connector_version: "0.1.0",
    codex_version: "0.147.0",
    last_seen_at: new Date(now.getTime() - 3_600_000).toISOString(),
    workspace_roots: ["/Users/alice/Work"],
  },
];

const threads = [
  {
    id: "thread-1",
    device_id: "device-1",
    title: "Review session exchange policy",
    cwd: "/Users/alice/Projects/control",
    model: "gpt-5.6-codex",
    updated_at: now.toISOString(),
    status: "running",
  },
  {
    id: "thread-2",
    device_id: "device-1",
    title: "Connector reconnect tests",
    cwd: "/Users/alice/Labs/connector",
    model: "gpt-5.5-codex",
    updated_at: new Date(now.getTime() - 3_300_000).toISOString(),
    status: "idle",
  },
];

const threadDetail = {
  ...threads[0],
  messages: [
    {
      id: "message-1",
      role: "user",
      text: "Check that refresh tokens never reach the Control API.",
      created_at: new Date(now.getTime() - 110_000).toISOString(),
    },
    {
      id: "message-2",
      role: "assistant",
      text: "The exchange accepts only { access_token }. The database stores an HMAC digest of the Control session and no Sub2API token fields.",
      created_at: new Date(now.getTime() - 92_000).toISOString(),
    },
  ],
};

const sessionSnapshot = () => ({
  id: `session-${Date.now()}`,
  user: { id: "user-1", username: "alice", email: null, display_name: null },
  issued_at: new Date().toISOString(),
  expires_at: new Date(Date.now() + 600_000).toISOString(),
  reauth_at: new Date(Date.now() + 600_000).toISOString(),
  csrf_header_name: "x-csrf-token",
});

const readBody = async (request) => {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
};

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url ?? "/", "http://127.0.0.1:8090");
  if (request.headers.upgrade?.toLowerCase() === "websocket") {
    json(response, 401, { detail: "mock_websocket_offline" });
    return;
  }
  if (request.method === "GET" && url.pathname === "/v1/session") {
    json(response, 200, sessionSnapshot());
    return;
  }
  if (request.method === "GET" && url.pathname === "/v1/bootstrap") {
    json(response, 200, {
      event_cursor: "0",
      devices,
      threads,
      approvals: [
        {
          approval_id: "approval-1",
          command_id: "command-1",
          kind: "permission",
          summary: "Allow workspace write access",
          details: { cwd: "/Users/alice/Projects/control", permissions: "workspace-write" },
          expires_at: new Date(now.getTime() + 95_000).toISOString(),
          device_id: "device-1",
          device_name: "Studio Mac",
          created_at: now.toISOString(),
        },
      ],
      models_by_device: {
        "device-1": [
          { id: "gpt-5.6-codex", display_name: "GPT-5.6 Codex" },
          { id: "gpt-5.5-codex", display_name: "GPT-5.5 Codex" },
        ],
        "device-2": [],
      },
    });
    return;
  }
  if (request.method === "GET" && url.pathname === "/v1/devices") {
    json(response, 200, { items: devices });
    return;
  }
  if (request.method === "GET" && url.pathname === "/v1/approvals") {
    json(response, 200, {
      items: [
        {
          approval_id: "approval-1",
          command_id: "command-1",
          kind: "permission",
          summary: "Allow workspace write access",
          details: { cwd: "/Users/alice/Projects/control", permissions: "workspace-write" },
          expires_at: new Date(now.getTime() + 95_000).toISOString(),
          device_id: "device-1",
          device_name: "Studio Mac",
          created_at: now.toISOString(),
        },
      ],
    });
    return;
  }
  if (request.method === "GET" && url.pathname === "/v1/devices/device-1/threads") {
    json(response, 200, { items: threads });
    return;
  }
  if (request.method === "GET" && url.pathname === "/v1/devices/device-1/models") {
    json(response, 200, {
      items: [
        { id: "gpt-5.6-codex", display_name: "GPT-5.6 Codex" },
        { id: "gpt-5.5-codex", display_name: "GPT-5.5 Codex" },
      ],
    });
    return;
  }
  if (request.method === "GET" && url.pathname === "/v1/threads/thread-1") {
    json(response, 200, { event_cursor: "0", thread: threadDetail });
    return;
  }
  if (request.method === "GET" && url.pathname === "/v1/threads/thread-2") {
    json(response, 200, { event_cursor: "0", thread: { ...threads[1], messages: [] } });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/auth/refresh") {
    await readBody(request);
    json(response, 200, {
      access_token: "mock-rotated-access-token",
      refresh_token: "mock-rotated-refresh-token",
      expires_in: 3600,
      token_type: "Bearer",
    });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/v1/auth/logout") {
    await readBody(request);
    response.writeHead(204, { "Cache-Control": "no-store" });
    response.end();
    return;
  }
  if (request.method === "POST" && url.pathname === "/v1/session/exchange") {
    await readBody(request);
    json(response, 201, sessionSnapshot());
    return;
  }
  if (request.method === "POST" && url.pathname === "/v1/session/logout") {
    await readBody(request);
    response.writeHead(204, { "Cache-Control": "no-store" });
    response.end();
    return;
  }
  if (request.method === "POST") {
    json(response, 202, { status: "accepted" });
    return;
  }
  json(response, 404, { detail: "not_found" });
});

server.listen(8090, "127.0.0.1", () => {
  process.stdout.write("mock Control API listening on http://127.0.0.1:8090\n");
});

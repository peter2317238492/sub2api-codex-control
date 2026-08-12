# Sub2API Codex Control

[English](README.md)

Sub2API Codex Control 是一个与 Sub2API 同源部署的 Codex 远程控制平面。浏览器根据现有
Sub2API 登录状态换取短期、可撤销的 Control 会话；每台设备上的 Connector 主动建立出站
WSS 连接，并通过标准输入输出调用固定版本的 Codex app-server。Connector 不开放设备入站
端口，也不修改 Codex 配置。

## 发布状态

首个公开版本**仅提供源代码**。当前没有可下载、受支持的预编译 Connector，也没有已发布
的签名 Control 镜像。只有针对同一源码版本的签名、来源证明和 SBOM 全部生成并验证通过后，
生产安装才会开放。自行构建的二进制或镜像不是官方发布产物。

仓库包含隔离的全栈 E2E 测试，但测试使用模拟 Sub2API 权限服务和遵循协议的假 Codex
app-server。测试通过只能证明仓库内的集成路径可用，不能证明真实 Sub2API 账号、真实 Codex
或生产环境已经可用。

## 拓扑

Control 与 Sub2API 共用一个 HTTPS 域名：

| 路径 | 用途 |
| --- | --- |
| `/` 和 `/api/` | 现有 Sub2API 页面和 API |
| `/codex/` | Control PWA |
| `/codex-api/` | Control HTTP API |
| `/codex-ws/browser` | 浏览器 WebSocket |
| `/codex-ws/device` | Connector 出站 WebSocket |

Control 服务只绑定宿主机回环端口 `18090`、`18091` 和 `18093`，`18092` 仅供一次性测试
边缘使用。UFW 不应开放这些端口、PostgreSQL 或 Redis。公网只需要 TCP `443`；TCP `80`
仅在 HTTP 跳转或 ACME 校验确有需要时开放。SSH 应限制到管理员来源网段。

## 验证源码

需要 Git、带 Compose v2 的 Docker Engine、Go 1.24 或更高版本、Go race detector 支持的
C 工具链、Python 3、OpenSSL，以及 `amd64` 或 `arm64` Docker daemon。测试会创建一次性
的容器、网络、卷和凭据，应在隔离的开发机运行，不要在生产服务器运行。

```sh
git clone https://github.com/peter2317238492/sub2api-codex-control.git
cd sub2api-codex-control
install -d -m 0700 "$HOME/.local/state/sub2api-codex-control/e2e-reports"
CONTROL_E2E_REPORT_DIR="$HOME/.local/state/sub2api-codex-control/e2e-reports" \
  ./tests/e2e/run-local.sh
```

验收报告会写到仓库外部。即使测试成功，它仍然只是隔离测试证据。

## 从源码构建 Connector

Connector 应以拥有 Codex 和已授权工作区的普通用户身份运行。当前协议严格要求
`codex-cli 0.147.0`。

```sh
cd connector
go test ./...
CGO_ENABLED=0 go build -trimpath -buildvcs=false \
  -o sub2api-codex-connector ./cmd/connector
./sub2api-codex-connector \
  -config /absolute/path/to/connector.json -pair-only
```

`-pair-only` 会等待已登录 PWA 的管理员认领私密配对码，然后退出。创建配置或长期运行
Connector 前，请先阅读安装和使用教程。

## 文档

- [安装](docs/installation.zh-CN.md) / [Installation](docs/installation.md)
- [使用](docs/usage.zh-CN.md) / [Usage](docs/usage.md)
- [运维](docs/operations.zh-CN.md) / [Operations](docs/operations.md)
- [安全决策](docs/adr/)
- [生产运维手册](docs/runbooks/README.md)
- [Connector 安全边界](connector/README.md)

## 安全不变量

- 浏览器和 Control 数据库不会收到 Sub2API 上游供应商密钥。
- Sub2API refresh token 不会发送到或存储在 Control API 中。
- Connector 只主动建立出站连接，不开放监听端口。
- 远程 RPC 使用明确白名单；原始透传、账号、配置、插件、进程和任意文件系统方法默认拒绝。
- 工作区根目录是设备本地白名单，远程沙箱权限最高只能为 `workspace-write`。
- 审批最长 120 秒过期；缺失、超时或失联时默认拒绝。

## 许可与独立性

项目使用 [Apache License 2.0](LICENSE) 开源。署名和第三方依赖许可见 [NOTICE](NOTICE)
与 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

这是独立社区项目，不隶属于 OpenAI 或 Sub2API 项目，也未获得其背书或赞助。OpenAI、
Codex 和 Sub2API 名称归各自权利人所有。
